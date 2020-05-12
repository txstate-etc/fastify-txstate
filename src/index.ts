import fastify from 'fastify'
import fs from 'fs'
import http, { ServerResponse } from 'http'
import HttpStatus from 'http-status-codes'

type ErrorHandler = (error: Error, req: fastify.FastifyRequest, res: fastify.FastifyReply<ServerResponse>) => Promise<void>

export default class Server {
  protected https = false
  protected errorHandlers: ErrorHandler[] = []
  public app: fastify.FastifyInstance
  constructor(config: Partial<fastify.ServerOptionsAsSecureHttp2> = {}) {
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
    if (!config.logger) config.logger = true
    this.app = fastify(config)
    this.app.addHook('onSend', async (req, resp, payload) => {
      resp.removeHeader('X-Powered-By')
    })
    this.app.setErrorHandler(async (err, req, res) => {
      for (const errorHandler of this.errorHandlers) {
        if (!res.sent) await errorHandler(err, req, res)
      }
      if (!res.sent) {
        if (err instanceof RequestError) {
          res.status(err.code).send(err.message)
        } else {
          res.status(500).send('Internal Server Error.')
        }
      }
    })
  }

  public async start (port?: number) {
    const customPort = port ?? parseInt(process.env.PORT ?? '0')
    if (customPort) {
      await this.app.listen(customPort, '::')
    } else if (this.https) {
      // redirect 80 to 443
      http.createServer((req, res) => {
        res.writeHead(301, { Location: 'https://' + req?.headers?.host?.replace(/:\d+$/, '') + req.url })
        res.end()
      }).listen(80)
      await this.app.listen(443, '::')
    } else {
      await this.app.listen(80, '::')
    }
  }

  public async addErrorHandler (handler: ErrorHandler) {
    this.errorHandlers.push(handler)
  }

  public async close () {
    return this.app.server.close()
  }
}

export class RequestError extends Error {
  public code: number
  public extra: any
  constructor (code: number, message?: string, extra?: any) {
    if (!message) {
      if (code === 401) message = 'Login is required.'
      else if (code === 403) message = 'You are not authorized for that.'
      else message = HttpStatus.getStatusText(code)
    }
    super(message)
    this.code = code
    this.extra = extra
  }
}
