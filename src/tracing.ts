import { context, createTraceState, INVALID_SPAN_CONTEXT, isSpanContextValid, propagation, ROOT_CONTEXT, SpanKind, SpanStatusCode, trace as apiTrace, TraceFlags, type Context, type ContextManager, type Histogram, type Link, type Span as ApiSpan, type SpanContext, type SpanOptions, type SpanStatus, type TextMapPropagator, type TimeInput, type Tracer as ApiTracer, type TracerProvider } from '@opentelemetry/api'
import type { FastifyInstance, FastifyRequest } from 'fastify'
import { AsyncLocalStorage } from 'node:async_hooks'
import { randomBytes } from 'node:crypto'
import { subscribe, tracingChannel } from 'node:diagnostics_channel'
import type { ClientRequest, IncomingMessage } from 'node:http'
import { toArray } from 'txstate-utils'
import { SpanFlags, type InstrumentationScope, type SpanEventData, type SpanLinkData } from './otlp.encode.ts'
import { emitException, envString, exceptionAttributes, exportSpan, metrics, scopeFor, startTelemetry, telemetryEnabled, toNano, type Attributes } from './telemetry.ts'

/**
 * Distributed tracing, exported as OTLP spans through telemetry.ts. Nothing is patched: incoming
 * requests are traced with Fastify hooks, and outgoing work by subscribing to the diagnostics_channel
 * events that fetch (undici), node:http, mysql2, postgres.js, node:sqlite and mongoose already publish. Our own libraries join in the
 * same way, by publishing a TracingChannel listed in DB_CHANNELS rather than depending on us.
 *
 * We also register as @opentelemetry/api's global tracer provider, context manager and W3C
 * propagator, so libraries and app code that make spans through the API land in the same traces.
 * Ours are the only parts of the SDK they need; if another SDK registered first, it keeps them.
 *
 * Our own instrumentation only makes spans under an active one, so background jobs and the
 * exporter's own requests go untraced unless the app wraps them in a span of its own. Sampling
 * follows the SDK's OTEL_TRACES_SAMPLER and OTEL_TRACES_SAMPLER_ARG, except the remote samplers
 * (jaeger_remote, xray); the default, parentbased_always_on, records every trace unless the
 * caller's traceparent says it didn't sample.
 */

export { SpanKind, SpanStatusCode, type Span, type SpanOptions, type Tracer } from '@opentelemetry/api'

const sampler = { parentBased: true, ratio: 1 }

/** TraceIdRatioBased: deterministic on the trace id's random low bits, so every service agrees */
function sampleTrace (traceId: string) {
  return parseInt(traceId.slice(-13), 16) / 2 ** 52 < sampler.ratio
}

function configureSampler () {
  const name = envString('OTEL_TRACES_SAMPLER')?.trim().toLowerCase()
  if (name == null) return
  const samplers: Record<string, { parentBased: boolean, ratio?: number }> = {
    always_on: { parentBased: false, ratio: 1 },
    always_off: { parentBased: false, ratio: 0 },
    traceidratio: { parentBased: false },
    parentbased_always_on: { parentBased: true, ratio: 1 },
    parentbased_always_off: { parentBased: true, ratio: 0 },
    parentbased_traceidratio: { parentBased: true }
  }
  const chosen = samplers[name] as typeof samplers[string] | undefined
  if (!chosen) {
    console.warn(`OTEL_TRACES_SAMPLER '${name}' is not supported; using parentbased_always_on.`) // eslint-disable-line no-console -- no logger at startup
    return
  }
  sampler.parentBased = chosen.parentBased
  if (chosen.ratio != null) {
    sampler.ratio = chosen.ratio
    return
  }
  const arg = envString('OTEL_TRACES_SAMPLER_ARG')
  const ratio = Number(arg)
  if (arg == null) sampler.ratio = 1
  else if (Number.isNaN(ratio) || ratio < 0 || ratio > 1) console.warn(`OTEL_TRACES_SAMPLER_ARG '${arg}' is not a ratio between 0 and 1; using 1.`) // eslint-disable-line no-console -- no logger at startup
  else sampler.ratio = ratio
}

/** like the SDK, a number below the epoch time the process started is a performance.now() reading */
function timeNano (time?: TimeInput) {
  time ??= performance.now()
  if (typeof time === 'number' && time < performance.timeOrigin) time += performance.timeOrigin
  return toNano(time)
}

/** OTLP flags: the W3C trace flags, plus whether the context came from another process */
function otlpFlags ({ traceFlags, isRemote }: SpanContext) {
  return (traceFlags & 0xff) | SpanFlags.CONTEXT_HAS_IS_REMOTE | (isRemote ? SpanFlags.CONTEXT_IS_REMOTE : 0)
}

function isTimeInput (value: unknown): value is TimeInput {
  return typeof value === 'number' || value instanceof Date || Array.isArray(value)
}

class Span implements ApiSpan {
  private readonly context: SpanContext
  private readonly parentSpanId?: string
  private readonly flags: number
  private readonly startTimeUnixNano: bigint
  private readonly events: SpanEventData[] = []
  private readonly links: SpanLinkData[] = []
  private status: SpanStatus = { code: SpanStatusCode.UNSET }
  private ended = false

  private readonly scope?: InstrumentationScope

  constructor (private name: string, private readonly kind: SpanKind, private readonly attributes: Attributes, { parent, scope, startTime, links }: { parent?: SpanContext, scope?: InstrumentationScope, startTime?: TimeInput, links?: Link[] } = {}) {
    const traceId = parent?.traceId ?? randomBytes(16).toString('hex')
    // a local parent already made the decision for its whole trace
    const sampled = parent && (!parent.isRemote || sampler.parentBased) ? (parent.traceFlags & TraceFlags.SAMPLED) !== 0 : sampleTrace(traceId)
    this.context = { traceId, spanId: randomBytes(8).toString('hex'), traceFlags: sampled ? TraceFlags.SAMPLED : TraceFlags.NONE, traceState: parent?.traceState }
    this.parentSpanId = parent?.spanId
    this.flags = otlpFlags({ ...this.context, isRemote: parent?.isRemote })
    this.scope = scope
    this.startTimeUnixNano = timeNano(startTime)
    if (links) this.addLinks(links)
  }

  get sampled () {
    return (this.context.traceFlags & TraceFlags.SAMPLED) !== 0
  }

  spanContext () {
    return this.context
  }

  isRecording () {
    return this.sampled && !this.ended
  }

  setAttribute (key: string, value: unknown) {
    if (!this.ended) this.attributes[key] = value as Attributes[string]
    return this
  }

  setAttributes (attributes: Record<string, unknown>) {
    if (!this.ended) Object.assign(this.attributes, attributes)
    return this
  }

  addEvent (name: string, attributesOrStartTime?: Record<string, unknown> | TimeInput, startTime?: TimeInput) {
    if (this.ended) return this
    const [attributes, time] = isTimeInput(attributesOrStartTime) ? [{}, attributesOrStartTime] : [attributesOrStartTime ?? {}, startTime]
    this.events.push({ name, timeUnixNano: timeNano(time), attributes: attributes as Attributes })
    return this
  }

  addLink (link: Link) {
    if (!this.ended && isSpanContextValid(link.context)) {
      this.links.push({ traceId: link.context.traceId, spanId: link.context.spanId, traceState: link.context.traceState?.serialize(), attributes: (link.attributes ?? {}) as Attributes, flags: otlpFlags(link.context) })
    }
    return this
  }

  addLinks (links: Link[]) {
    for (const link of links) this.addLink(link)
    return this
  }

  /** per the spec, OK is final, and UNSET can't overwrite anything */
  setStatus ({ code, message }: SpanStatus) {
    if (this.ended || code === SpanStatusCode.UNSET || this.status.code === SpanStatusCode.OK) return this
    this.status = { code, message: code === SpanStatusCode.ERROR ? message : undefined }
    return this
  }

  setError (errorType: string) {
    this.setStatus({ code: SpanStatusCode.ERROR })
    this.attributes['error.type'] = errorType
  }

  updateName (name: string) {
    if (!this.ended) this.name = name
    return this
  }

  /** accepts anything, since a thrown value can be; the API asks for an Error or a string */
  recordException (exception: unknown, time?: TimeInput) {
    this.addEvent('exception', exceptionAttributes(exception), time)
  }

  end (endTime?: TimeInput) {
    if (this.ended) return
    this.ended = true
    if (!this.sampled) return
    exportSpan({
      traceId: this.context.traceId,
      spanId: this.context.spanId,
      parentSpanId: this.parentSpanId,
      traceState: this.context.traceState?.serialize() || undefined,
      flags: this.flags,
      name: this.name,
      kind: this.kind + 1, // OTLP saves 0 for UNSPECIFIED
      startTimeUnixNano: this.startTimeUnixNano,
      endTimeUnixNano: timeNano(endTime),
      attributes: this.attributes,
      events: this.events,
      links: this.links,
      statusCode: this.status.code,
      statusMessage: this.status.message
    }, this.scope)
  }
}

/** a tracer handed out through @opentelemetry/api; its spans are exported under its own scope */
class Tracer implements ApiTracer {
  constructor (private readonly scope: InstrumentationScope) {}

  startSpan (name: string, options: SpanOptions = {}, ctx = context.active()): ApiSpan {
    // checked per span, since tracers are usually made at import time, before startTelemetry
    if (!telemetryEnabled('traces')) return apiTrace.wrapSpanContext(INVALID_SPAN_CONTEXT)
    const parent = options.root ? undefined : apiTrace.getSpanContext(ctx)
    return new Span(name, options.kind ?? SpanKind.INTERNAL, { ...(options.attributes as Attributes | undefined) }, {
      parent: parent && isSpanContextValid(parent) ? parent : undefined,
      scope: this.scope,
      startTime: options.startTime,
      links: options.links
    })
  }

  startActiveSpan<F extends (span: ApiSpan) => unknown> (name: string, fn: F): ReturnType<F>
  startActiveSpan<F extends (span: ApiSpan) => unknown> (name: string, options: SpanOptions, fn: F): ReturnType<F>
  startActiveSpan<F extends (span: ApiSpan) => unknown> (name: string, options: SpanOptions, ctx: Context, fn: F): ReturnType<F>
  startActiveSpan<F extends (span: ApiSpan) => unknown> (name: string, ...args: [F] | [SpanOptions, F] | [SpanOptions, Context, F]) {
    const fn = args.at(-1) as F
    const options = args.length > 1 ? args[0] as SpanOptions : undefined
    const ctx = args.length > 2 ? args[1] as Context : context.active()
    const span = this.startSpan(name, options, ctx)
    return context.with(apiTrace.setSpan(ctx, span), () => fn(span) as ReturnType<F>)
  }
}

const tracerProvider: TracerProvider = {
  getTracer (name, version) { return new Tracer(scopeFor(name, version)) }
}

/** like @opentelemetry/api's trace: name the tracer after your app or library */
export const trace = {
  getTracer: (name: string, version?: string): ApiTracer => tracerProvider.getTracer(name, version),
  /** the current request's or job's span, to add attributes to */
  getActiveSpan: (): ApiSpan | undefined => apiTrace.getActiveSpan()
}

/** the SDK's AsyncLocalStorageContextManager, except that bind() only wraps functions, not EventEmitters */
class AsyncLocalStorageContextManager implements ContextManager {
  private readonly storage = new AsyncLocalStorage<Context>()

  active () {
    return this.storage.getStore() ?? ROOT_CONTEXT
  }

  with<A extends unknown[], F extends (...args: A) => ReturnType<F>> (ctx: Context, fn: F, thisArg?: ThisParameterType<F>, ...args: A): ReturnType<F> {
    return this.storage.run(ctx, () => fn.apply(thisArg, args))
  }

  bind<T> (ctx: Context, target: T): T {
    if (typeof target !== 'function') return target
    const { storage } = this
    const fn = target as (...args: unknown[]) => unknown
    return function (this: unknown, ...args: unknown[]) { return storage.run(ctx, () => fn.apply(this, args)) } as T
  }

  attach (ctx: Context) {
    const previous = this.active()
    this.storage.enterWith(ctx)
    return { dispose: () => { this.storage.enterWith(previous) } }
  }

  enable () {
    return this
  }

  disable () {
    this.storage.disable()
    return this
  }
}

const traceparentRegex = /^(?<version>[\da-f]{2})-(?<traceId>[\da-f]{32})-(?<spanId>[\da-f]{16})-(?<flags>[\da-f]{2})(?<rest>-.*)?$/v
const allZeros = /^0+$/v

/** W3C Trace Context: an invalid traceparent is ignored, and so is tracestate along with it */
function parseTraceparent (traceparent: string | string[] | undefined, tracestate: string | string[] | undefined): SpanContext | undefined {
  if (typeof traceparent !== 'string') return undefined
  const groups = traceparentRegex.exec(traceparent.trim())?.groups
  if (!groups) return undefined
  // a future version may append fields, which we must not interpret; version 00 may not
  if (groups.version === 'ff' || (groups.version === '00' && groups.rest) || allZeros.test(groups.traceId) || allZeros.test(groups.spanId)) return undefined
  const traceState = toArray(tracestate).join(',').trim()
  return { traceId: groups.traceId, spanId: groups.spanId, traceFlags: parseInt(groups.flags, 16) & TraceFlags.SAMPLED, traceState: traceState ? createTraceState(traceState) : undefined, isRemote: true } // eslint-disable-line @typescript-eslint/no-deprecated -- the replacement is in @opentelemetry/core; this stays for all of 1.x
}

/** W3C traceparent and tracestate for an outgoing request made under this span context */
function propagationHeaders ({ traceId, spanId, traceFlags, traceState }: SpanContext) {
  const state = traceState?.serialize()
  return {
    traceparent: `00-${traceId}-${spanId}-${traceFlags & TraceFlags.SAMPLED ? '01' : '00'}`,
    ...(state ? { tracestate: state } : {})
  }
}

/** for libraries that propagate through the API themselves, like a message queue client */
const w3cPropagator: TextMapPropagator = {
  inject (ctx, carrier, setter) {
    const spanContext = apiTrace.getSpanContext(ctx)
    if (!spanContext || !isSpanContextValid(spanContext)) return
    for (const [name, value] of Object.entries(propagationHeaders(spanContext))) setter.set(carrier, name, value)
  },
  extract (ctx, carrier, getter) {
    const parent = parseTraceparent(getter.get(carrier, 'traceparent'), getter.get(carrier, 'tracestate'))
    return parent ? apiTrace.setSpanContext(ctx, parent) : ctx
  },
  fields () {
    return ['traceparent', 'tracestate']
  }
}

function registerGlobals () {
  const registered = [
    apiTrace.setGlobalTracerProvider(tracerProvider),
    context.setGlobalContextManager(new AsyncLocalStorageContextManager().enable()),
    propagation.setGlobalPropagator(w3cPropagator)
  ]
  if (registered.includes(false)) console.warn('Another OpenTelemetry SDK registered with @opentelemetry/api first; spans made through the API will go to it rather than fastify-txstate\'s exporter.') // eslint-disable-line no-console -- no logger at startup
}

function activeSpanContext () {
  const spanContext = apiTrace.getSpanContext(context.active())
  return spanContext && isSpanContextValid(spanContext) ? spanContext : undefined
}

const HTTP_METHODS = new Set(['CONNECT', 'DELETE', 'GET', 'HEAD', 'OPTIONS', 'PATCH', 'POST', 'PUT', 'QUERY', 'TRACE'])

function methodAttributes (method: string) {
  const known = HTTP_METHODS.has(method)
  return {
    spanName: known ? method : 'HTTP',
    attributes: { 'http.request.method': known ? method : '_OTHER', 'http.request.method_original': known ? undefined : method }
  }
}

const sensitiveParams = /(?<param>token|unifiedJwt)=[^&#]*/giv
function redact (url: string) {
  return url.replace(sensitiveParams, '$<param>=REDACTED')
}

function startClientSpan (method: string, url: URL) {
  const parent = activeSpanContext()
  if (!parent) return undefined
  url.username = ''
  url.password = ''
  const { spanName, attributes } = methodAttributes(method)
  return new Span(spanName, SpanKind.CLIENT, {
    ...attributes,
    'server.address': url.hostname,
    'server.port': Number(url.port) || (url.protocol === 'https:' ? 443 : 80),
    'url.full': redact(url.href)
  }, { parent })
}

function endClientSpanWithError (span: Span | undefined, error: Error & { code?: string }) {
  if (!span) return
  // the caller cancelling isn't a failure
  if (error.name !== 'AbortError') {
    span.setError(error.code ?? error.constructor.name)
    span.recordException(error)
  }
  span.end()
}

function traceFetch () {
  const spans = new WeakMap<object, Span>()
  interface UndiciRequest { origin: string | URL, method: string, path: string, headers: string[], addHeader: (name: string, value: string) => void }
  subscribe('undici:request:create', msg => {
    const { request } = msg as { request: UndiciRequest }
    const span = startClientSpan(request.method, new URL(request.path, request.origin))
    if (!span) return
    spans.set(request, span)
    // a caller forwarding its own traceparent wins; two would be invalid
    if (request.headers.some((h, i) => i % 2 === 0 && h.toLowerCase() === 'traceparent')) return
    for (const [name, value] of Object.entries(propagationHeaders(span.spanContext()))) request.addHeader(name, value)
  })
  subscribe('undici:request:headers', msg => {
    const { request, response } = msg as { request: object, response: { statusCode: number } }
    const span = spans.get(request)
    if (!span) return
    span.setAttributes({ 'http.response.status_code': response.statusCode })
    if (response.statusCode >= 400) span.setError(String(response.statusCode))
  })
  subscribe('undici:request:trailers', msg => {
    spans.get((msg as { request: object }).request)?.end()
  })
  subscribe('undici:request:error', msg => {
    const { request, error } = msg as { request: object, error: Error }
    endClientSpanWithError(spans.get(request), error)
  })
}

function traceHttpClient () {
  const spans = new WeakMap<ClientRequest, Span>()
  // created, not start: by start the headers have been sent
  subscribe('http.client.request.created', msg => {
    const { request } = msg as { request: ClientRequest }
    const host = request.getHeader('host') ?? request.host
    const span = startClientSpan(request.method, new URL(request.path, `${request.protocol}//${String(host)}`))
    if (!span) return
    spans.set(request, span)
    if (request.hasHeader('traceparent')) return
    for (const [name, value] of Object.entries(propagationHeaders(span.spanContext()))) request.setHeader(name, value)
  })
  subscribe('http.client.response.finish', msg => {
    const { request, response } = msg as { request: ClientRequest, response: IncomingMessage }
    const span = spans.get(request)
    if (!span) return
    const status = response.statusCode ?? 0
    span.setAttributes({ 'http.response.status_code': status })
    if (status >= 400) span.setError(String(status))
    // published when the response headers arrive; the body is still to come
    response.once('close', () => { span.end() })
  })
  subscribe('http.client.request.error', msg => {
    const { request, error } = msg as { request: ClientRequest, error: Error }
    endClientSpanWithError(spans.get(request), error)
  })
}

/**
 * The context a database library publishes on its TracingChannel. mysql2 defines this shape; our
 * own libraries publish the same one.
 */
interface DbQueryContext {
  query: string
  database?: string
  serverAddress?: string
  serverPort?: number
  /** oracle-async adds the binds a query opted in with `traceBinds`; mysql2 never sends this */
  parameters?: Record<string, unknown>
  error?: Error & { code?: string, errno?: number }
}

/** db.query.parameter.<key>, which the semconv defines as a string */
function parameterAttributes (parameters: Record<string, unknown> | undefined) {
  const attributes: Record<string, string> = {}
  for (const [key, value] of Object.entries(parameters ?? {})) {
    attributes[`db.query.parameter.${key}`] = value instanceof Date ? value.toISOString() : String(value)
  }
  return attributes
}

const DB_CHANNELS = [
  // mysql2 inlines the values into query text before publishing it
  { channel: 'mysql2:query', system: 'mysql', parameterized: false },
  { channel: 'mysql2:execute', system: 'mysql', parameterized: true },
  { channel: 'oracle-async:query', system: 'oracle.db', parameterized: true }
]

const MAX_QUERY_TEXT = 10000
const sqlLiterals = /'(?:[^'\\]|\\.|'')*'|"(?:[^"\\]|\\.|"")*"|\b0x[\da-f]+\b|\b\d+(?:\.\d+)?(?:e[+\-]?\d+)?\b/giv
const sqlOperation = /^\W*(?<operation>[a-z]+)/iv
const sqlTargets = /\b(?:from|into|update|join|table)\s+(?<target>[`"\w.$]+)/giv
const identifierQuotes = /[`"]/gv

/** db.query.summary: the operation and the tables it touches, e.g. SELECT users orders */
function summarizeSql (sql: string) {
  const operation = sqlOperation.exec(sql)?.groups?.operation.toUpperCase()
  if (!operation) return undefined
  const targets = new Set(Array.from(sql.matchAll(sqlTargets), m => m.groups!.target.replace(identifierQuotes, '')))
  return [operation, ...targets].join(' ').slice(0, 255)
}

/** A client span for each call a library wraps in TracingChannel#tracePromise, ended when it settles. */
function traceChannel<T extends { error?: Error }> (channel: string, startSpan: (ctx: T, parent: SpanContext) => Span, describeError: (error: NonNullable<T['error']>) => { type: string, status?: string | number }, finish?: (ctx: T, span: Span) => void) {
  const spans = new WeakMap<T, Span>()
  const endSpan = (ctx: T) => {
    const span = spans.get(ctx)
    if (!span) return
    spans.delete(ctx)
    finish?.(ctx, span)
    span.end()
  }
  tracingChannel<T>(channel).subscribe({
    start (ctx) {
      const parent = activeSpanContext()
      if (parent) spans.set(ctx, startSpan(ctx, parent))
    },
    end (ctx) {
      // a synchronous throw never reaches asyncStart
      if (ctx.error) endSpan(ctx)
    },
    asyncStart (ctx) {
      endSpan(ctx)
    },
    asyncEnd () { /* the span already ended at asyncStart */ },
    error (ctx) {
      const span = spans.get(ctx)
      if (!span || !ctx.error) return
      const { type, status } = describeError(ctx.error)
      span.setError(type)
      if (status != null) span.setAttributes({ 'db.response.status_code': String(status) })
      span.recordException(ctx.error)
    }
  })
}

const describeSqlError = (error: NonNullable<DbQueryContext['error']>) => ({ type: error.code ?? error.constructor.name, status: error.errno })

function traceDatabases () {
  for (const { channel, system, parameterized } of DB_CHANNELS) {
    traceChannel<DbQueryContext>(channel, (ctx, parent) => {
      const summary = summarizeSql(ctx.query)
      // the semconv asks that query text which wasn't parameterized be sanitized
      const text = parameterized ? ctx.query : ctx.query.replace(sqlLiterals, '?')
      return new Span(summary ?? (ctx.database || system), SpanKind.CLIENT, {
        'db.system.name': system,
        'db.namespace': ctx.database || undefined,
        'db.query.summary': summary,
        'db.query.text': text.slice(0, MAX_QUERY_TEXT),
        'server.address': ctx.serverAddress,
        'server.port': ctx.serverPort,
        ...parameterAttributes(ctx.parameters)
      }, { parent })
    }, describeSqlError)
  }
}

/** The context postgres.js (4.0+) publishes; query, host and port arrive once the query is sent. */
interface PostgresContext {
  query: string | null
  database?: string
  host: string | null
  port: number | null
  /** the rows; count is rows affected, which an UPDATE without RETURNING reports but doesn't return */
  result?: unknown[]
  /** a PostgresError has a SQLSTATE code and a severity; a network error has only the code */
  error?: Error & { code?: string, severity?: string }
}

const describePostgresError = (error: NonNullable<PostgresContext['error']>) => ({ type: error.code ?? error.constructor.name, status: error.severity ? error.code : undefined })

function tracePostgres () {
  traceChannel<PostgresContext>('postgres:query', (ctx, parent) => new Span(ctx.database || 'postgresql', SpanKind.CLIENT, {
    'db.system.name': 'postgresql',
    'db.namespace': ctx.database || undefined
  }, { parent }), describePostgresError, (ctx, span) => {
    // parameters are left out: postgres.js only sends them with debug: true, and then sends every one
    const summary = ctx.query ? summarizeSql(ctx.query) : undefined
    if (summary) span.updateName(summary)
    span.setAttributes({
      'db.query.summary': summary,
      'db.query.text': ctx.query?.slice(0, MAX_QUERY_TEXT),
      'db.response.returned_rows': Array.isArray(ctx.result) ? ctx.result.length : undefined,
      'server.address': ctx.host ?? undefined,
      'server.port': ctx.port ?? undefined
    })
  })
}

/** What node:sqlite (Node 26+) publishes after each statement runs; failed statements are not published. */
interface SqliteQueryMessage {
  /** with the values inlined */
  sql: string
  database: { location?: () => string | null }
  /** nanoseconds */
  duration: number
}

function traceSqlite () {
  subscribe('sqlite.db.query', msg => {
    // the statement ran synchronously, so the caller's span is still active
    const parent = activeSpanContext()
    if (!parent) return
    const { sql, database, duration } = msg as SqliteQueryMessage
    const endTime = performance.now()
    const summary = summarizeSql(sql)
    new Span(summary ?? 'sqlite', SpanKind.CLIENT, {
      'db.system.name': 'sqlite',
      'db.namespace': database.location?.() ?? undefined,
      'db.query.summary': summary,
      'db.query.text': sql.replace(sqlLiterals, '?').slice(0, MAX_QUERY_TEXT)
    }, { parent, startTime: endTime - duration / 1e6 }).end(endTime)
  })
}

/** The context mongoose (9.7+) publishes on its TracingChannels. */
interface MongooseContext {
  operation: string
  collection?: string
  database?: string
  serverAddress?: string
  serverPort?: number
  error?: Error & { code?: number | string, codeName?: string }
}

// mongoose:cursor:next is left out: it fires once per batch. args is left out: filters carry values.
const MONGOOSE_CHANNELS = ['mongoose:query', 'mongoose:aggregate', 'mongoose:model:save', 'mongoose:model:insertMany', 'mongoose:model:bulkWrite']

const describeMongooseError = (error: NonNullable<MongooseContext['error']>) => ({ type: error.codeName ?? error.constructor.name, status: error.code })

function traceMongoose () {
  for (const channel of MONGOOSE_CHANNELS) {
    traceChannel<MongooseContext>(channel, (ctx, parent) => new Span(`${ctx.operation} ${ctx.collection ?? ctx.database ?? 'mongodb'}`, SpanKind.CLIENT, {
      'db.system.name': 'mongodb',
      'db.namespace': ctx.database || undefined,
      'db.collection.name': ctx.collection,
      'db.operation.name': ctx.operation,
      'server.address': ctx.serverAddress,
      'server.port': ctx.serverPort
    }, { parent }), describeMongooseError)
  }
}

/** Times each call a library wraps in TracingChannel#tracePromise, whether or not it has a span. */
function timeChannel<T extends { error?: Error }> (duration: Histogram, channel: string, attributes: (ctx: T) => Attributes, describeError: (error: NonNullable<T['error']>) => { type: string }) {
  const starts = new WeakMap<T, number>()
  const finish = (ctx: T) => {
    const start = starts.get(ctx)
    if (start == null) return
    starts.delete(ctx)
    duration.record((performance.now() - start) / 1000, { ...attributes(ctx), 'error.type': ctx.error ? describeError(ctx.error).type : undefined })
  }
  tracingChannel<T>(channel).subscribe({
    start (ctx) { starts.set(ctx, performance.now()) },
    // a synchronous throw never reaches asyncStart
    end (ctx) { if (ctx.error) finish(ctx) },
    asyncStart: finish
  })
}

let measuringDatabases = false
/**
 * db.client.operation.duration, when metrics are enabled. db.query.summary is left off: each
 * distinct summary would be its own histogram series, exported for the life of the process.
 */
export function measureDatabases () {
  if (measuringDatabases || !telemetryEnabled('metrics')) return
  measuringDatabases = true
  const duration = metrics.getMeter('fastify-txstate').createHistogram('db.client.operation.duration', {
    description: 'Duration of database client operations.',
    unit: 's',
    advice: { explicitBucketBoundaries: [0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5, 10] }
  })
  for (const { channel, system } of DB_CHANNELS) {
    timeChannel<DbQueryContext>(duration, channel, ctx => ({ 'db.system.name': system, 'db.namespace': ctx.database || undefined, 'server.address': ctx.serverAddress, 'server.port': ctx.serverPort }), describeSqlError)
  }
  timeChannel<PostgresContext>(duration, 'postgres:query', ctx => ({ 'db.system.name': 'postgresql', 'db.namespace': ctx.database || undefined, 'server.address': ctx.host ?? undefined, 'server.port': ctx.port ?? undefined }), describePostgresError)
  for (const channel of MONGOOSE_CHANNELS) {
    timeChannel<MongooseContext>(duration, channel, ctx => ({ 'db.system.name': 'mongodb', 'db.namespace': ctx.database || undefined, 'server.address': ctx.serverAddress, 'server.port': ctx.serverPort }), describeMongooseError)
  }
  subscribe('sqlite.db.query', msg => {
    const { database, duration: nanos } = msg as SqliteQueryMessage
    duration.record(nanos / 1e9, { 'db.system.name': 'sqlite', 'db.namespace': database.location?.() ?? undefined })
  })
}

let subscribed = false
function instrument () {
  if (subscribed) return
  subscribed = true
  configureSampler()
  registerGlobals()
  traceFetch()
  traceHttpClient()
  traceDatabases()
  tracePostgres()
  traceSqlite()
  traceMongoose()
}

// probes and beacons would bury the real traffic, in traces and request metrics; the analytics plugin adds its route here
export const untracedRoutes = new Set(['/health'])
const requestSpans = new WeakMap<FastifyRequest, Span>()

/**
 * Traces every request to this Fastify instance, and the outgoing work it does, when telemetry is
 * enabled. Server calls this from its constructor, ahead of its other onRequest hooks, so they and
 * everything after them run inside the request's span.
 */
export function traceRequests (app: FastifyInstance) {
  if (!telemetryEnabled('traces')) return
  instrument()
  app.addHook('onRequest', (req, res, done) => {
    const route = req.routeOptions.url
    if (route && untracedRoutes.has(route)) { done(); return }
    const parent = parseTraceparent(req.headers.traceparent, req.headers.tracestate)
    const { spanName, attributes } = methodAttributes(req.method)
    const [path, query] = req.url.split('?', 2) as [string, string | undefined]
    const span = new Span(route ? `${spanName} ${route}` : spanName, SpanKind.SERVER, {
      ...attributes,
      'http.route': route,
      'url.path': path,
      'url.query': query == null ? undefined : redact(query),
      'server.address': req.hostname,
      'server.port': req.port ?? undefined,
      'client.address': req.ip,
      'user_agent.original': req.headers['user-agent']
    }, { parent })
    requestSpans.set(req, span)
    const { traceId, spanId } = span.spanContext()
    req.log = req.log.child({ trace_id: traceId, span_id: spanId })
    res.log = req.log
    context.with(apiTrace.setSpan(ROOT_CONTEXT, span), done)
  })
  app.addHook('onResponse', (req, res, done) => {
    const span = requestSpans.get(req)
    if (span) {
      span.setAttributes({ 'http.response.status_code': res.statusCode, 'user.name': req.auth?.username })
      if (res.statusCode >= 500) span.setError(String(res.statusCode))
      span.end()
    }
    done()
  })
  app.addHook('onRequestAbort', (req, done) => {
    requestSpans.get(req)?.end()
    done()
  })
}

/**
 * Records each error that ends in a 5xx on its request's span and as an
 * http.server.request.exception log record. Server calls this too.
 */
export function recordRequestErrors (app: FastifyInstance) {
  if (!telemetryEnabled('traces') && !telemetryEnabled('logs')) return
  const errors = new WeakMap<FastifyRequest, Error>()
  app.addHook('onError', (req, res, err, done) => {
    errors.set(req, err)
    done()
  })
  // an error handler may still turn the error into a 4xx, which is the client's problem
  app.addHook('onResponse', (req, res, done) => {
    const err = errors.get(req)
    if (err && res.statusCode >= 500) {
      const span = requestSpans.get(req)
      span?.recordException(err)
      context.with(span ? apiTrace.setSpan(ROOT_CONTEXT, span) : context.active(), () => {
        emitException(err, 'http.server.request.exception', { 'http.request.method': methodAttributes(req.method).attributes['http.request.method'], 'http.route': req.routeOptions.url })
      })
    }
    done()
  })
}

/**
 * Runs a background task, like a cron job, as the root span of its own trace, so its outgoing
 * calls and queries are traced too. A failure is sent as an exception log record and marks the
 * span failed, then rethrown, so the caller's catch only needs to protect the scheduler.
 */
export async function traceJob<T> (name: string, task: () => T | Promise<T>, attributes?: Attributes): Promise<T> {
  startTelemetry()
  if (telemetryEnabled('traces')) instrument()
  measureDatabases()
  const span = telemetryEnabled('traces') ? new Span(name, SpanKind.INTERNAL, { ...attributes }) : undefined
  return await context.with(span ? apiTrace.setSpan(ROOT_CONTEXT, span) : ROOT_CONTEXT, async () => {
    try {
      return await task()
    } catch (e: unknown) {
      span?.setError(exceptionAttributes(e)['exception.type'] as string | undefined ?? '_OTHER')
      span?.recordException(e)
      emitException(e, 'exception', attributes)
      throw e
    } finally {
      span?.end()
    }
  })
}

/**
 * Runs a chunk of a request or job as a child of the active span, ending it when fn finishes,
 * sync or async. A failure marks the span failed and is rethrown for the caller to handle or log;
 * no log record is sent. With no active span, fn runs untraced; use traceJob to start a trace.
 */
export function withSpan<T> (name: string, fn: (span: ApiSpan) => T, attributes?: Attributes): T {
  const parent = apiTrace.getSpanContext(context.active())
  if (!telemetryEnabled('traces') || !parent || !isSpanContextValid(parent)) return fn(apiTrace.wrapSpanContext(INVALID_SPAN_CONTEXT))
  const span = new Span(name, SpanKind.INTERNAL, { ...attributes }, { parent })
  const fail = (e: unknown) => {
    span.setError(exceptionAttributes(e)['exception.type'] as string | undefined ?? '_OTHER')
    span.recordException(e)
    span.end()
  }
  return context.with(apiTrace.setSpan(context.active(), span), () => {
    let result: T
    try {
      result = fn(span)
    } catch (e: unknown) {
      fail(e)
      throw e
    }
    if (!(result instanceof Promise)) {
      span.end()
      return result
    }
    const pending: Promise<unknown> = result
    return (async () => {
      try {
        const value = await pending
        span.end()
        return value
      } catch (e: unknown) {
        fail(e)
        throw e
      }
    })() as T
  })
}

/** http.server.request.duration and http.server.active_requests, per the HTTP semantic conventions, when metrics are enabled; Server calls this too */
export function measureRequests (app: FastifyInstance) {
  if (!telemetryEnabled('metrics')) return
  const duration = metrics.getMeter('fastify-txstate').createHistogram('http.server.request.duration', {
    description: 'Duration of HTTP server requests.',
    unit: 's',
    advice: { explicitBucketBoundaries: [0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1, 2.5, 5, 7.5, 10] }
  })
  const active = metrics.getMeter('fastify-txstate').createUpDownCounter('http.server.active_requests', {
    description: 'Number of active HTTP server requests.',
    unit: '{request}'
  })
  const activeAttributes = new WeakMap<FastifyRequest, Attributes>()
  app.addHook('onRequest', (req, res, done) => {
    const route = req.routeOptions.url
    if (!route || !untracedRoutes.has(route)) {
      const attributes = { 'http.request.method': methodAttributes(req.method).attributes['http.request.method'], 'url.scheme': req.protocol }
      activeAttributes.set(req, attributes)
      active.add(1, attributes)
    }
    done()
  })
  // an aborted request can reach both hooks, so only the first one counts it done
  const finished = (req: FastifyRequest) => {
    const attributes = activeAttributes.get(req)
    if (!attributes) return
    activeAttributes.delete(req)
    active.add(-1, attributes)
  }
  app.addHook('onRequestAbort', (req, done) => {
    finished(req)
    done()
  })
  app.addHook('onResponse', (req, res, done) => {
    finished(req)
    const route = req.routeOptions.url
    if (!route || !untracedRoutes.has(route)) {
      // elapsedTime runs from onRequest, in milliseconds
      duration.record(res.elapsedTime / 1000, {
        'http.request.method': methodAttributes(req.method).attributes['http.request.method'],
        'http.route': route,
        'http.response.status_code': res.statusCode,
        'error.type': res.statusCode >= 500 ? String(res.statusCode) : undefined
      })
    }
    done()
  })
}
