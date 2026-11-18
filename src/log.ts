import type { FastifyBaseLogger } from 'fastify'
import { AsyncLocalStorage } from 'node:async_hooks'
import { Writable } from 'node:stream'
import pino from 'pino'
import { omit, toArray } from 'txstate-utils'

interface PinoLogEntry {
  req?: { method: string, url: string }
  res?: { statusCode: number }
  responseTime?: number
  err?: unknown
  msg?: string
}

/* eslint-disable no-console -- devLogger intentionally writes to console */
export const devLogger = pino({
  level: 'info'
}, new Writable({
  write (chunk: Buffer, _encoding: string, callback: () => void) {
    const obj = JSON.parse(String(chunk)) as PinoLogEntry
    if (obj.req) console.info(`${obj.req.method} ${obj.req.url}`)
    else if (obj.res) console.info(`${obj.res.statusCode} - ${obj.responseTime}`)
    else if (obj.err) console.error(obj.err)
    else console.info(obj.msg || obj)
    callback()
  }
}))
/* eslint-enable no-console */

/* eslint-disable @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call -- pino serializer params are typed as any */
export const prodLogger = pino({
  level: 'info',
  serializers: {
    req (req: any) {
      return {
        method: req.method,
        url: req.url.replace(/(?<param>token|unifiedJwt)=[\w.]+/iv, '$<param>=redacted'),
        remoteAddress: req.ip,
        traceparent: req.headers.traceparent
      }
    },
    res (res: any) {
      return {
        statusCode: res.statusCode,
        url: res.request?.url.replace(/(?<param>token|unifiedJwt)=[\w.]+/iv, '$<param>=redacted'),
        length: Number(toArray(res.getHeader?.('content-length'))[0]),
        ...omit(res.extraLogInfo, 'auth'),
        auth: omit(res.request?.auth ?? res.extraLogInfo?.auth ?? {}, 'token', 'accessToken', 'issuerConfig')
      }
    }
  }
})
/* eslint-enable @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call */

let rootLogger: FastifyBaseLogger = process.env.NODE_ENV === 'development' ? devLogger : prodLogger

/** Server points this at its own logger, so a custom loggerInstance is honored */
export function setRootLogger (logger: FastifyBaseLogger) {
  rootLogger = logger
}

/** holds the request, not its logger, so a hook that replaces req.log is honored */
export const logContext = new AsyncLocalStorage<{ log: FastifyBaseLogger }>()

/** a logContext store for a job: the root logger with the job's bindings added */
export function jobLogger (bindings: Record<string, unknown>) {
  return { log: rootLogger.child(bindings) }
}

/**
 * A logger you can import anywhere. Inside a request it is that request's `req.log`, and inside
 * a `traceJob` it is the server's logger with the job's name and trace ids added. Anywhere else
 * it is the server's logger, or the default one for NODE_ENV when there is no Server.
 */
// eslint-disable-next-line @typescript-eslint/consistent-type-assertions -- the target is never used; every access goes to the active logger
export const log = new Proxy({} as FastifyBaseLogger, {
  get (_target, prop) {
    const logger = logContext.getStore()?.log ?? rootLogger
    const value: unknown = Reflect.get(logger, prop, logger)
    return typeof value === 'function' ? (value as (...args: unknown[]) => unknown).bind(logger) : value
  },
  set (_target, prop, value) {
    return Reflect.set(logContext.getStore()?.log ?? rootLogger, prop, value)
  }
})
