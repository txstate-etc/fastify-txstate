import Ajv from 'ajv'
import swagger, { type FastifyDynamicSwaggerOptions } from '@fastify/swagger'
import swaggerUI, { type FastifySwaggerUiOptions } from '@fastify/swagger-ui'
import type { JsonSchemaToTsProvider } from '@fastify/type-provider-json-schema-to-ts'
import { validatedResponse } from '@txstate-mws/fastify-shared'
import ajvErrors from 'ajv-errors'
import ajvFormats from 'ajv-formats'
import { type FastifyInstance, type FastifyRequest, type FastifyReply, type FastifyServerOptions, fastify, type FastifyLoggerOptions, type FastifyBaseLogger, type RawServerDefault, type FastifySchema } from 'fastify'
import { type FastifySchemaValidationError } from 'fastify/types/schema'
import type { JSONSchema } from 'json-schema-to-ts'
import fs from 'node:fs'
import http from 'node:http'
import type http2 from 'node:http2'
import type { OpenAPIV3 } from 'openapi-types'
import { clone, destroyNulls, set, sleep, stringifyDates, toArray } from 'txstate-utils'
import { FailedValidationError, HttpError, ValidationError, ValidationErrors, fstValidationToMessage } from './error'

type ErrorHandler = (error: Error, req: FastifyRequest, res: FastifyReply) => Promise<void>

export interface FastifyTxStateAuthInfo {
  /**
   * The primary identifier for the user that is making the request, after processing
   * their session token / JWT.
   */
  username: string
  /**
   * This should be an identifier for the particular session, so that the same user
   * on different devices/browsers/tabs can be distinguished from one another.
   *
   * It should NOT be usable as a cookie or bearer token, as it will appear in logs. If you
   * use JSON Web Tokens, an easy thing is to combine the username with the `iat` issued
   * date to create something unique but not useful to attackers.
   *
   * For lookup tokens, you can do the same `${username}-${createdAt}` after looking up
   * the session in your database.
   *
   * If all else fails, you can sha256 the session token with a salt.
   */
  sessionId: string
  /**
   * Some authentication systems allow administrators to impersonate regular users, so that
   * they can see what that user sees and troubleshoot issues. We still want to log the administrator
   * with any actions they take while impersonating someone, for auditing purposes, so you should
   * fill this field when applicable.
   *
   * This will also be available at `req.auth.impersonatedBy`, so it is possible for your API
   * to implement complicated authorization rules based on whether a user is being impersonated.
   * It sort of defeats the purpose of impersonation, but used sparingly it could prevent administrators
   * from making mistakes.
   */
  impersonatedBy?: string
  /**
   * If your API may be accessed by a different client application, such that the user is actually logged
   * into that application instead of yours, but you accept that application's session tokens, filling
   * this field can help log requests that are authenticated with the other application's token.
   */
  clientId?: string
}

export interface FastifyTxStateOptions extends Partial<FastifyServerOptions> {
  https?: http2.SecureServerOptions
  validOrigins?: string[]
  validOriginHosts?: string[]
  validOriginSuffixes?: string[]
  skipOriginCheck?: boolean
  checkOrigin?: (req: FastifyRequest) => boolean
  /**
   * Run an asynchronous function to check the health of the service.
   *
   * Return a non-empty error message to trigger unhealthy status.
   *
   * Setting a health message with setUnhealthy will override this and prevent it from being executed.
   */
  checkHealth?: () => Promise<string | { status?: number, message?: string } | undefined>
  /**
   * Run an async function to get authentication information out of the request
   * object. Should return an object with at least a username and sessionid (see FastifyTxStateAuthInfo
   * for further detail).
   *
   * The return object will be added to the request object as `req.auth` for later
   * use in your route handlers. It will also be added to the logs in production.
   *
   * IMPORTANT: It is not advisable to return excessive amounts of data here, nor anything
   * particularly sensitive, since it will all be included in every log entry.
   *
   * If this function throws, the client will receive a 401 response.
   */
  authenticate?: (req: FastifyRequest) => Promise<FastifyTxStateAuthInfo | undefined>
}

declare module 'fastify' {
  interface FastifyRequest {
    auth?: FastifyTxStateAuthInfo
  }
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
        url: req.url.replace(/(token|unifiedJwt)=[\w.]+/i, '$1=redacted'),
        remoteAddress: req.ip,
        traceparent: req.headers.traceparent
      }
    },
    res (res) {
      return {
        statusCode: res.statusCode,
        url: res.request?.url.replace(/(token|unifiedJwt)=[\w.]+/i, '$1=redacted'),
        length: Number(toArray(res.getHeader?.('content-length'))[0]),
        ...res.extraLogInfo,
        auth: res.request?.auth ?? res.extraLogInfo.auth
      }
    }
  }
}

export type FastifyInstanceTyped = FastifyInstance<RawServerDefault, http.IncomingMessage, http.ServerResponse<http.IncomingMessage>, FastifyBaseLogger, JsonSchemaToTsProvider>
export type TxServer = Server
export default class Server {
  protected https = false
  protected errorHandlers: ErrorHandler[] = []
  protected healthMessage?: string
  protected healthCallback?: () => Promise<string | { status?: number, message?: string } | undefined>
  protected shuttingDown = false
  protected sigHandler: (signal: any) => void
  protected validOrigins: Record<string, boolean> = {}
  protected validOriginHosts: Record<string, boolean> = {}
  protected validOriginSuffixes = new Set<string>()
  public app: FastifyInstanceTyped

  constructor (protected config: FastifyTxStateOptions & {
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
    config.ajv = { ...config.ajv, plugins: [...(config.ajv?.plugins ?? []), ajvErrors, [ajvFormats, { mode: 'fast' }]], customOptions: { ...config.ajv?.customOptions, allErrors: true, strictSchema: false, coerceTypes: true } }

    this.healthCallback = config.checkHealth
    this.app = fastify(config)
    this.app.addHook('onRoute', route => {
      if (!route.schema?.body) return
      const missingResponse = route.schema?.response == null
      const response400 = set(validatedResponse.properties.messages, 'description', 'Basic validation failure. This means that the UI provided input that failed validation as defined in the openapi specification published by the API. The UI is at fault and should be re-coded to avoid sending invalid data.')
      let newSchema = set<Record<string, any>>(route.schema ?? {}, 'response.400', response400)
      const response422 = set(validatedResponse, 'description', 'Validation failure. This means that the user provided an invalid object. The user should be shown their error so that they can correct it.')
      newSchema = set(newSchema, 'response.422', response422)
      if (missingResponse) {
        newSchema.response['200'] = {
          description: 'Success. Return type has not been specified.',
          type: 'object'
        }
      }
      route.schema = newSchema
    })

    this.app.addHook('preValidation', (req, res, done) => {
      if (req.body != null && req.routeOptions.schema?.body) destroyNulls(req.body)
      done()
    })

    // use Ajv to validate responses instead of @fastify/json-fast-stringify since ajv does
    // a better job with recursive types and we don't want to have different behavior between
    // input and output validation
    const ajv = new Ajv(config.ajv.customOptions)
    for (const pluginConfig of config.ajv.plugins ?? []) {
      const [plugin, opts] = toArray(pluginConfig)
      plugin(ajv, opts)
    }
    this.app.setSerializerCompiler((route) => {
      const schema: JSONSchema | undefined = route.schema
      const validate = schema == null ? ajv.compile({ type: 'object' }) : ajv.compile(schema)
      return data => {
        /**
         * Ajv unfortunately treats optional properties as non-nullable, so they're allowed to
         * be undefined but not allowed to be null. Worse, with `coerceTypes`, null will be converted
         * to empty string or 0 or false. This is silly behavior, so we're converting all nulls to
         * undefined before we validate.
         */
        if (schema != null) destroyNulls(stringifyDates(data))
        if (!validate(data)) throw new Error('Output validation failed. ' + validate.errors?.[0].instancePath + ': ' + validate.errors?.[0].message)
        return JSON.stringify(data)
      }
    })

    this.app.addHook('onRequest', (req, res, done) => {
      res.extraLogInfo = {}
      done()
    })

    if (!config.skipOriginCheck && !process.env.SKIP_ORIGIN_CHECK) {
      this.setValidOrigins([...(config.validOrigins ?? []), ...(process.env.VALID_ORIGINS?.split(',') ?? [])])
      this.setValidOriginHosts([...(config.validOriginHosts ?? []), ...(process.env.VALID_ORIGIN_HOSTS?.split(',') ?? [])])
      this.setValidOriginSuffixes([...(config.validOriginSuffixes ?? []), ...(process.env.VALID_ORIGIN_SUFFIXES?.split(',') ?? [])])
      this.app.addHook('onRequest', async (req, res) => {
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
          if (req.headers['access-control-request-method']) void res.header('access-control-allow-methods', req.headers['access-control-request-method'])
          if (req.headers['access-control-request-headers']) void res.header('Access-Control-Allow-Headers', req.headers['access-control-request-headers'])
        }
      })
      this.app.options('*', async (req, res) => {
        await res.send()
      })
    }
    if (config.authenticate) {
      const authenticatedMethods: Record<string, boolean | undefined> = {
        GET: true,
        POST: true,
        PUT: true,
        PATCH: true,
        DELETE: true
      }
      this.app.addHook('onRequest', async (req, res) => {
        if (!authenticatedMethods[req.method] || req.routeOptions.url === '/health') return
        try {
          req.auth = await config.authenticate!(req)
        } catch (e: any) {
          await res.status(401).send('Failed to authenticate.')
          return res
        }
      })
    }
    this.app.addHook('onSend', this.https && process.env.NODE_ENV !== 'development'
      ? async (_, resp) => {
        void resp.removeHeader('X-Powered-By')
        void resp.header('Strict-Transport-Security', 'max-age=31536000')
        if (resp.getHeader('content-type') === 'text/html') void resp.type('text/html; charset=utf-8')
      }
      : async (_, resp) => {
        void resp.removeHeader('X-Powered-By')
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
        } else if (err instanceof ValidationError) {
          await res.status(err.statusCode).send({ success: false, messages: [{ message: err.message, path: err.path, type: err.type ?? 'error' }] })
        } else if (err instanceof ValidationErrors) {
          await res.status(err.statusCode).send({ success: false, messages: err.errors })
        } else if (err instanceof HttpError) {
          await res.status(err.statusCode).send(err.message)
        } else if (err.code === 'FST_ERR_VALIDATION') {
          const developerErrors: FastifySchemaValidationError[] = []
          const userErrors: FastifySchemaValidationError[] = []
          for (const v of err.validation ?? []) {
            if (v.keyword === 'errorMessage') {
              for (const ov of v.params.errors as FastifySchemaValidationError[]) {
                if (['type', 'additionalProperties', 'minProperties'].includes(ov.keyword)) developerErrors.push({ ...ov, message: v.message })
                else userErrors.push({ ...ov, message: v.message })
              }
            } else {
              if (['type', 'additionalProperties', 'minProperties'].includes(v.keyword)) developerErrors.push(v)
              else userErrors.push(v)
            }
          }
          if (userErrors.length) await res.status(422).send({ success: false, messages: userErrors.map(fstValidationToMessage) })
          else await res.status(400).send(developerErrors.map(fstValidationToMessage))
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
        void res.status(503)
        return 'MAINTENANCE'
      } else if (this.healthMessage) {
        res.log.info(this.healthMessage)
        void res.status(500)
        return this.healthMessage
      } else if (this.healthCallback) {
        const resp = await this.healthCallback()
        const [status, msg] = typeof resp === 'string' ? [500, resp] : [resp?.status, resp?.message]
        if (!!msg || !!status) {
          res.log.info(resp, 'Health check callback failed.')
          void res.status(status ?? 500)
          return msg ?? 'FAIL'
        }
      }
      return 'OK'
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
    await this.app.ready()
    this.app.swagger?.()
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
    for (const s of suffixes) this.validOriginSuffixes.add(s.replace(/^\./, ''))
  }

  public async swagger (opts?: { path?: string, openapi?: FastifyDynamicSwaggerOptions['openapi'], ui?: FastifySwaggerUiOptions }) {
    let openapi = opts?.openapi ?? {}
    if (this.config.authenticate != null) {
      openapi = set(openapi, 'components.securitySchemes', {
        unifiedAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
          description:
`Enter a token obtained from the TxState Unified Authentication service. An easy way to do
this is log into this application and use dev tools to pull your token from the Authorization header.`
        } satisfies OpenAPIV3.SecuritySchemeObject
      })
      // Apply the security globally to all operations
      openapi.security = [{ unifiedAuth: [] }]
    }
    function findRefs (obj: Record<string, any> | null | undefined, id?: string) {
      if (obj == null) return undefined
      if (obj.$id?.length) id = obj.$id
      if (obj.$ref === '#' && id?.length) {
        obj.type = 'string'
        obj.enum = [id]
        delete obj.$ref
      } else {
        for (const val of Object.values(obj)) {
          if (typeof val === 'object' && !(val instanceof Date)) findRefs(val as Record<string, any>, id)
        }
      }
      return obj
    }
    await this.app.register(swagger, {
      openapi,
      transform ({ schema, url, route, swaggerObject, openapiObject }) {
        const newSchema = findRefs(clone(schema))
        return { schema: newSchema as FastifySchema, url, route, swaggerObject, openapiObject }
      }
    })
    await this.app.register(swaggerUI, { ...opts?.ui, routePrefix: opts?.path ?? opts?.ui?.routePrefix ?? '/docs' })
  }

  public async close (softSeconds?: number) {
    if (typeof softSeconds === 'undefined') softSeconds = parseInt(process.env.LOAD_BALANCE_TIMEOUT ?? '0')
    process.removeListener('SIGTERM', this.sigHandler)
    process.removeListener('SIGINT', this.sigHandler)
    if (softSeconds) {
      this.shuttingDown = true
      await sleep(softSeconds)
    }
    await this.app.close()
  }
}

export * from './analytics'
export * from './error'
export * from './unified-auth'
