import { FastifyInstance, FastifyRequest, FastifyReply, FastifyServerOptions, fastify } from 'fastify'
import fs from 'fs'
import http from 'http'
import http2 from 'http2'
import { getReasonPhrase } from 'http-status-codes'

type ErrorHandler = (error: Error, req: FastifyRequest, res: FastifyReply) => Promise<void>

export interface FastifyTxStateOptions extends Partial<FastifyServerOptions> {
  https?: http2.SecureServerOptions
  validOriginHosts?: string[]
  skipOriginCheck?: boolean
}

export default class Server {
  protected https = false
  protected errorHandlers: ErrorHandler[] = []
  protected healthMessage?: string
  protected shuttingDown = false
  protected sigHandler: (signal: any) => void
  protected validOriginHosts: Record<string, boolean> = {}
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
      config.logger = {
        level: 'info',
        prettyPrint: process.env.NODE_ENV === 'development'
      }
    }
    if (process.env.TRUST_PROXY) config.trustProxy = true
    this.app = fastify(config)
    if (!config.skipOriginCheck && !process.env.SKIP_ORIGIN_CHECK) {
      this.setValidOriginHosts([...(config.validOriginHosts ?? []), ...(process.env.VALID_ORIGIN_HOSTS?.split(',') ?? [])])
      this.app.addHook('preHandler', async (req, res) => {
        if (!req.headers.origin) return
        const parsedOrigin = new URL(req.headers.origin)
        if (req.hostname.replace(/:\d+$/, '') !== parsedOrigin.hostname && !this.validOriginHosts[parsedOrigin.hostname]) {
          await res.status(403).send('Origin check failed. Suspected XSRF attack.')
          return res
        }
        // eslint-disable-next-line @typescript-eslint/no-floating-promises
        res.header('Access-Control-Allow-Origin', req.headers.origin)
      })
    }
    this.app.addHook('onSend', async (req, resp, payload) => {
      resp.removeHeader('X-Powered-By')
    })
    // eslint-disable-next-line @typescript-eslint/no-misused-promises
    this.app.setNotFoundHandler(async (req, res) => {
      await res.status(404).send('Not Found.')
    })
    // eslint-disable-next-line @typescript-eslint/no-misused-promises
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
    this.app.get('/health', async (req, res) => {
      if (this.shuttingDown) await res.status(503).send('Service is shutting down/restarting.')
      else if (this.healthMessage) await res.status(500).send(this.healthMessage)
      else await res.status(200).send('OK')
    })
    this.sigHandler = () => {
      this.close().then(() => {
        process.exit()
      }).catch(e => console.error(e))
    }
    process.on('SIGTERM', this.sigHandler)
    process.on('SIGINT', this.sigHandler)
  }

  public async start (port?: number) {
    const customPort = port ?? parseInt(process.env.PORT ?? '0')
    if (customPort) {
      await this.app.listen(customPort, '0.0.0.0')
    } else if (this.https) {
      // redirect 80 to 443
      http.createServer((req, res) => {
        res.writeHead(301, { Location: 'https://' + (req?.headers?.host?.replace(/:\d+$/, '') ?? '') + (req.url ?? '') })
        res.end()
      }).listen(80)
      await this.app.listen(443, '0.0.0.0')
    } else {
      await this.app.listen(80, '0.0.0.0')
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

  public setValidOriginHosts (hosts: string[]) {
    this.validOriginHosts = hosts.reduce((validOrigins: Record<string, boolean>, origin) => ({ ...validOrigins, [origin]: true }), {})
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

interface ValidationErrors { [keys: string]: string[] }
export class FailedValidationError extends HttpError {
  public errors: ValidationErrors
  constructor (errors: ValidationErrors) {
    super(422, 'Validation failure.')
    this.errors = errors
  }
}
