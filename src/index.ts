import fastify from 'fastify'
import fs from 'fs'
import http from 'http'

export default class Server {
  protected https = false
  public app: fastify.FastifyInstance
  constructor(config: fastify.ServerOptionsAsSecureHttp2) {
    try {
      const key = fs.readFileSync('/securekeys/private.key')
      const cert = fs.readFileSync('/securekeys/cert.pem')
      config.https = {
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
    this.app.addHook('onSend', async (req, resp, payload, next) => {
      resp.removeHeader('X-Powered-By')
      next()
    })
  }

  public async start () {
    if (process.env.PORT) {
      await this.app.listen(process.env.PORT)
    } else if (this.https) {
      // redirect 80 to 443
      http.createServer((req, res) => {
        res.writeHead(301, { Location: 'https://' + req?.headers?.host?.replace(/:\d+$/, '') + req.url })
        res.end()
      }).listen(80)
      await this.app.listen(443)
    } else {
      await this.app.listen(80)
    }
  }
}
