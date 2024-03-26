import Elasticsearch from '@elastic/elasticsearch'
import { interactionEvent, type InteractionEvent } from '@txstate-mws/fastify-shared'
import type { FastifyBaseLogger, FastifyInstance, FastifyRequest } from 'fastify'
import type { IncomingHttpHeaders } from 'http'
import { Cache, isBlank, pick } from 'txstate-utils'
import { type IBrowser, UAParser, type IDevice, type IOS } from 'ua-parser-js'
import { HttpError, type FastifyTxStateAuthInfo } from '.'

export interface StoredInteractionEvent extends InteractionEvent {
  '@timestamp': string
  // a name to identify the app
  appName: string
  // the value of the NODE_ENV environment variable, usually 'development', 'qual',
  // 'staging', 'production', etc
  environment: string

  // Output of https://github.com/faisalman/ua-parser-js#-getbrowseridata
  browser: IBrowser

  // Output of https://github.com/faisalman/ua-parser-js#-getdeviceidata
  device: IDevice

  // Output of https://github.com/faisalman/ua-parser-js#-getosidata
  os: IOS

  user: {
    // Remote IP of the client
    remoteip: string

    // The value of the _ga cookie, if set. This is the domain wide tracking cookie Google Analytics sets. It's useful for tracking the browser/device.
    ga?: string
  } & FastifyTxStateAuthInfo
}

interface QueuedEventItem {
  event: InteractionEvent
  ua: string
  gaCookie: string
  remoteIp: string
  time: string
  auth: any
}

export class AnalyticsClient {
  async push (events: StoredInteractionEvent[]) {
    for (const event of events) console.info('analytics event:', JSON.stringify(pick(event, 'eventType', 'screen', 'action', 'target')))
  }
}

export class LoggingAnalyticsClient extends AnalyticsClient {
  constructor (protected logger: FastifyBaseLogger) { super() }
  async push (events: StoredInteractionEvent[]) {
    for (const event of events) this.logger.info({ analyticsEvent: event })
  }
}

export class ElasticAnalyticsClient extends AnalyticsClient {
  private readonly elasticClient: Elasticsearch.Client

  constructor () {
    super()
    this.elasticClient = new Elasticsearch.Client({
      node: process.env.ELASTICSEARCH_URL,
      auth: {
        username: process.env.ELASTICSEARCH_USER ?? 'elastic',
        password: process.env.ELASTICSEARCH_PASS ?? 'not_provided'
      }
    })
  }

  async push (events: StoredInteractionEvent[]) {
    if (events.length) await this.elasticClient.bulk({ body: events.reduce<any>((acc, event) => { acc.push({ index: { _index: process.env.ELASTICSEARCH_USEREVENTS_INDEX ?? 'interaction-analytics' } }, event); return acc }, []) })
  }
}

export function analyticsPlugin (fastify: FastifyInstance, opts: { appName: string, analyticsClient?: AnalyticsClient, authorize?: (req: FastifyRequest) => boolean }, done: (err?: Error) => void) {
  const environment = process.env.NODE_ENV!
  if (isBlank(environment)) throw new Error('Must set NODE_ENV when reporting analytics.')

  const eventQueue: QueuedEventItem[] = []
  const analyticsClient = opts.analyticsClient ?? (
    isBlank(process.env.ELASTICSEARCH_URL)
      ? environment === 'development'
        ? new AnalyticsClient()
        : new LoggingAnalyticsClient(fastify.log)
      : new ElasticAnalyticsClient()
  )

  const UACache = new Cache(async (ua: string) => {
    const parser = new UAParser(ua)
    return parser.getResult()
  }, { freshseconds: 86400, staleseconds: 864000 })

  async function flushQueue () {
    const eventQueueSlice = [...eventQueue]
    try {
      eventQueue.length = 0

      const eventsToStore: StoredInteractionEvent[] = []

      for (const queueItem of eventQueueSlice) {
        const uaInfo = await UACache.get(queueItem.ua)
        eventsToStore.push({
          ...queueItem.event,

          '@timestamp': queueItem.time,
          appName: opts.appName,
          environment,
          ...pick(uaInfo, 'browser', 'device', 'os'),

          user: {
            remoteip: queueItem.remoteIp,
            ga: queueItem.gaCookie,
            ...queueItem.auth
          }
        })
      }

      if (eventsToStore.length) await analyticsClient.push(eventsToStore)
    } catch (e) {
      eventQueue.push(...eventQueueSlice)
      console.error(e)
    } finally {
      setTimeout(() => { void flushQueue() }, 5000)
    }
  }
  setTimeout(() => { void flushQueue() }, 5000)

  function queueEvents (auth: any, headers: IncomingHttpHeaders, remoteIp: string, events: InteractionEvent[]) {
    for (const event of events) {
      eventQueue.push({
        event,
        remoteIp,
        ua: headers['user-agent'] ?? '',
        time: new Date().toISOString(),
        gaCookie: headers.cookie?.replace(/^.*?(?:_ga=([^;]+))?.*$/, '$1') ?? '',
        auth
      })
    }
  }

  fastify.post<{ Body: InteractionEvent[] }>('/analytics', { schema: { body: { type: 'array', items: interactionEvent }, response: { 202: { type: 'string', enum: ['OK'] } } } }, async (req, res) => {
    const { auth } = req
    if (opts.authorize && !opts.authorize(req)) throw new HttpError(401)
    queueEvents(auth ?? { username: 'unauthenticated' }, req.headers, req.ip, req.body)
    res.statusCode = 202
    return 'OK'
  })
  done()
}
