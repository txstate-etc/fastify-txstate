import fastify from 'fastify'
import fs from 'fs'
import http, { ServerResponse } from 'http'
import HttpStatus from 'http-status-codes'

type ErrorHandler = (error: Error, req: fastify.FastifyRequest, res: fastify.FastifyReply<ServerResponse>) => Promise<void>

export default class Server {
  protected https = false
  protected errorHandlers: ErrorHandler[] = []
  protected healthMessage?: string
  protected shuttingDown = false
  protected sigHandler: (signal: any) => void
  public app: fastify.FastifyInstance

  constructor (config: Partial<fastify.ServerOptionsAsSecureHttp2> = {}) {
    try {
      const key = fs.readFileSync('/securekeys/private.key')
      const cert = fs.readFileSync('/securekeys/cert.pem')
      config.https = {
        allowHTTP1: true,
        key,
        cert,
        minVersion: 'TLSv1.2'
      }
      config.http2 = true
      this.https = true
    } catch (e) {
      this.https = false
    }
    if (typeof config.logger === 'undefined') config.logger = true
    this.app = fastify(config)
    this.app.addHook('onSend', async (req, resp, payload) => {
      resp.removeHeader('X-Powered-By')
    })
    // eslint-disable-next-line @typescript-eslint/no-misused-promises
    this.app.setErrorHandler(async (err, req, res) => {
      req.log.warn(err)
      for (const errorHandler of this.errorHandlers) {
        if (!res.sent) await errorHandler(err, req, res)
      }
      if (!res.sent) {
        if (err instanceof FailedValidationError) {
          res.status(err.statusCode).send(err.errors)
        } else if (err instanceof HttpError) {
          res.status(err.statusCode).send(err.message)
        } else {
          res.status(500).send('Internal Server Error.')
        }
      }
    })
    this.app.get('/health', async (req, res) => {
      if (this.shuttingDown) res.status(503).send('Service is shutting down/restarting.')
      else if (this.healthMessage) res.status(500).send(this.healthMessage)
      else res.status(200).send('OK')
    })
    this.sigHandler = () => {
      this.close().then(() => {
        process.exit()
      }).catch(e => console.error(e))
    }
  }

  public async start (port?: number) {
    const customPort = port ?? parseInt(process.env.PORT ?? '0')
    if (customPort) {
      await this.app.listen(customPort, '::')
    } else if (this.https) {
      // redirect 80 to 443
      http.createServer((req, res) => {
        res.writeHead(301, { Location: 'https://' + (req?.headers?.host?.replace(/:\d+$/, '') ?? '') + (req.url ?? '') })
        res.end()
      }).listen(80)
      await this.app.listen(443, '::')
    } else {
      await this.app.listen(80, '::')
    }
    process.on('SIGTERM', this.sigHandler)
    process.on('SIGINT', this.sigHandler)
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
      if (statusCode === 401) message = 'Authentication failed.'
      else if (statusCode === 403) message = 'You are not authorized for that.'
      else message = HttpStatus.getStatusText(statusCode)
    }
    super(message)
    this.statusCode = statusCode
  }
}

type ValidationErrors = { [keys: string]: string[] }
export class FailedValidationError extends HttpError {
  public errors: ValidationErrors
  constructor (errors: ValidationErrors) {
    super(422, 'Validation failure.')
    this.errors = errors
  }
}
