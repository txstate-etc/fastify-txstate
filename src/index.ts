import { type FastifyInstance, type FastifyRequest, type FastifyReply, type FastifyServerOptions, fastify, type FastifyLoggerOptions } from 'fastify'
import fs from 'fs'
import http from 'http'
import type http2 from 'http2'
import { getReasonPhrase } from 'http-status-codes'

type ErrorHandler = (error: Error, req: FastifyRequest, res: FastifyReply) => Promise<void>

export interface FastifyTxStateOptions extends Partial<FastifyServerOptions> {
  https?: http2.SecureServerOptions
  validOrigins?: string[]
  validOriginHosts?: string[]
  validOriginSuffixes?: string[]
  skipOriginCheck?: boolean
  checkOrigin?: (req: FastifyRequest) => boolean
}

declare module 'fastify' {
  interface FastifyReply {
    extraLogInfo: any
  }
}

export const devLogger = {
  level: 'info',
  info: (msg: any) => { console.info(msg.req ? `${msg.req.method} ${msg.req.url}` : msg.res ? `${msg.res.statusCode} - ${msg.responseTime}` : msg) },
  error: console.error,
  debug: console.debug,
  fatal: console.error,
  warn: console.warn,
  trace: console.trace,
  silent: (msg: any) => {},
  child (bindings: any, options?: any) { return this }
}

export const prodLogger: FastifyLoggerOptions = {
  level: 'info',
  serializers: {
    req (req) {
      return {
        method: req.method,
        url: req.url.replace(/token=[\w.]+/, 'token=redacted'),
        remoteAddress: req.ip,
        traceparent: req.headers.traceparent
      }
    },
    res (res) {
      return {
        statusCode: res.statusCode,
        url: res.request?.url.replace(/token=[\w.]+/, 'token=redacted'),
        length: res.getHeader('content-length'),
        ...res.extraLogInfo
      }
    }
  }
}

export default class Server {
  protected https = false
  protected errorHandlers: ErrorHandler[] = []
  protected healthMessage?: string
  protected shuttingDown = false
  protected sigHandler: (signal: any) => void
  protected validOrigins: Record<string, boolean> = {}
  protected validOriginHosts: Record<string, boolean> = {}
  protected validOriginSuffixes = new Set<string>()
  public app: FastifyInstance

  constructor (config: FastifyTxStateOptions & {
    http2?: true
  } = {}) {
    try {
      const key = fs.readFileSync('/securekeys/private.key')
      const cert = fs.readFileSync('/securekeys/cert.pem')
      config.https = {
        ...config.https,
        allowHTTP1: true,
        key,
        cert,
        minVersion: 'TLSv1.2'
      }
      config.http2 = true
      this.https = true
    } catch (e) {
      this.https = false
      delete config.https
    }
    if (typeof config.logger === 'undefined') {
      config.logger = process.env.NODE_ENV === 'development'
        ? devLogger
        : prodLogger
    }
    if (process.env.TRUST_PROXY != null) {
      if (['true', '1'].includes(process.env.TRUST_PROXY)) config.trustProxy = true
      else config.trustProxy = process.env.TRUST_PROXY
    }
    this.app = fastify(config)
    if (!config.skipOriginCheck && !process.env.SKIP_ORIGIN_CHECK) {
      this.setValidOrigins([...(config.validOrigins ?? []), ...(process.env.VALID_ORIGINS?.split(',') ?? [])])
      this.setValidOriginHosts([...(config.validOriginHosts ?? []), ...(process.env.VALID_ORIGIN_HOSTS?.split(',') ?? [])])
      this.setValidOriginSuffixes([...(config.validOriginSuffixes ?? []), ...(process.env.VALID_ORIGIN_SUFFIXES?.split(',') ?? [])])
      this.app.addHook('preHandler', async (req, res) => {
        (res as any).extraLogInfo = {}
        if (!req.headers.origin) return
        let passed = this.validOrigins[req.headers.origin]
        if (!passed && req.headers.origin === 'null') passed = process.env.NODE_ENV === 'development'
        else if (!passed) {
          const parsedOrigin = new URL(req.headers.origin)
          if (req.hostname.replace(/:\d+$/, '') === parsedOrigin.hostname) passed = true
          if (this.validOriginHosts[parsedOrigin.hostname]) passed = true

          if (!passed && this.validOriginSuffixes.size > 0) {
            const originParts = parsedOrigin.hostname.split('.')
            for (let i = 0; i < originParts.length; i++) {
              const suffix = originParts.slice(i).join('.')
              if (this.validOriginSuffixes.has(suffix)) passed = true
            }
          }
        }
        if (!passed && config.checkOrigin?.(req)) passed = true
        if (!passed) {
          await res.status(403).send('Origin check failed. Suspected XSRF attack.')
          return res
        } else {
          void res.header('Access-Control-Allow-Origin', req.headers.origin)
          void res.header('Access-Control-Max-Age', '600') // ask browser to skip pre-flights for 10 minutes after a yes
          if (req.headers['access-control-request-headers']) void res.header('Access-Control-Allow-Headers', req.headers['access-control-request-headers'])
        }
      })
      this.app.options('*', async (req, res) => {
        await res.send()
      })
    }
    this.app.addHook('onSend', this.https && process.env.NODE_ENV !== 'development'
      ? async (_, resp) => {
        resp.removeHeader('X-Powered-By')
        void resp.header('Strict-Transport-Security', 'max-age=31536000')
        if (resp.getHeader('content-type') === 'text/html') void resp.type('text/html; charset=utf-8')
      }
      : async (_, resp) => {
        resp.removeHeader('X-Powered-By')
        if (resp.getHeader('content-type') === 'text/html') void resp.type('text/html; charset=utf-8')
      })
    this.app.setNotFoundHandler((req, res) => { void res.status(404).send('Not Found.') })
    this.app.setErrorHandler(async (err, req, res) => {
      req.log.warn(err)
      for (const errorHandler of this.errorHandlers) {
        if (!res.sent) await errorHandler(err, req, res)
      }
      if (!res.sent) {
        if (err instanceof FailedValidationError) {
          await res.status(err.statusCode).send(err.errors)
        } else if (err instanceof HttpError) {
          await res.status(err.statusCode).send(err.message)
        } else if (err.statusCode) {
          await res.status(err.statusCode).send(new HttpError(err.statusCode).message)
        } else {
          await res.status(500).send('Internal Server Error.')
        }
      }
    })
    this.app.get('/health', { logLevel: 'warn' }, async (req, res) => {
      if (this.shuttingDown) {
        res.log.info('Returning 503 on /health because we are shutting down/restarting.')
        await res.status(503).send('Service is shutting down/restarting.')
      } else if (this.healthMessage) {
        res.log.info('Returning 500 on health with the message:', this.healthMessage)
        await res.status(500).send(this.healthMessage)
      } else await res.status(200).send('OK')
    })
    this.sigHandler = () => {
      this.close().then(() => {
        process.exit()
      }).catch(e => { console.error(e) })
    }
    process.on('SIGTERM', this.sigHandler)
    process.on('SIGINT', this.sigHandler)
  }

  public async start (port?: number) {
    const customPort = port ?? parseInt(process.env.PORT ?? '0')
    if (customPort) {
      await this.app.listen({ port: customPort, host: '0.0.0.0' })
    } else if (this.https) {
      // redirect 80 to 443
      http.createServer((req, res) => {
        res.writeHead(301, { Location: 'https://' + (req?.headers?.host?.replace(/:\d+$/, '') ?? '') + (req.url ?? '') })
        res.end()
      }).listen(80)
      await this.app.listen({ port: 443, host: '0.0.0.0' })
    } else {
      await this.app.listen({ port: 80, host: '0.0.0.0' })
    }
  }

  public addErrorHandler (handler: ErrorHandler) {
    this.errorHandlers.push(handler)
  }

  public setUnhealthy (message: string) {
    this.healthMessage = message
  }

  public setHealthy () {
    this.healthMessage = undefined
  }

  public setValidOrigins (origins: string[]) {
    this.validOrigins = origins.reduce((validOrigins: Record<string, boolean>, origin) => ({ ...validOrigins, [origin]: true }), {})
  }

  public setValidOriginHosts (hosts: string[]) {
    this.validOriginHosts = hosts.reduce((validHosts: Record<string, boolean>, host) => ({ ...validHosts, [host]: true }), {})
  }

  public setValidOriginSuffixes (suffixes: string[]) {
    this.validOriginSuffixes.clear()
    for (const s of suffixes) this.validOriginSuffixes.add(s)
  }

  public async close (softSeconds?: number) {
    if (typeof softSeconds === 'undefined') softSeconds = parseInt(process.env.LOAD_BALANCE_TIMEOUT ?? '0')
    process.removeListener('SIGTERM', this.sigHandler)
    process.removeListener('SIGINT', this.sigHandler)
    if (softSeconds) {
      this.shuttingDown = true
      await new Promise(resolve => setTimeout(resolve, softSeconds! * 1000))
    }
    await this.app.close()
  }
}

export class HttpError extends Error {
  public statusCode: number
  constructor (statusCode: number, message?: string) {
    if (!message) {
      if (statusCode === 401) message = 'Authentication is required.'
      else if (statusCode === 403) message = 'You are not authorized for that.'
      else message = getReasonPhrase(statusCode)
    }
    super(message)
    this.statusCode = statusCode
  }
}

type ValidationErrors = Record<string, string[]>
export class FailedValidationError extends HttpError {
  public errors: ValidationErrors
  constructor (errors: ValidationErrors) {
    super(422, 'Validation failure.')
    this.errors = errors
  }
}
