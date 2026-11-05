/* eslint-disable no-console -- runs outside any request, so there's no fastify logger to use */
import { context, logs as apiLogs, metrics as apiMetrics, SeverityNumber, SpanStatusCode, trace, type BatchObservableCallback, type Counter, type Logger, type Meter, type MetricOptions, type Observable, type ObservableCallback, type ObservableResult, type TimeInput } from '@opentelemetry/api'
import { randomUUID } from 'node:crypto'
import { promisify } from 'node:util'
import { gzip } from 'node:zlib'
import { sleep } from 'txstate-utils'
import { decodeExportResponse, decodeStatusMessage, encodeLogsRequest, encodeMetricsRequest, encodeTracesRequest, type AttributeValue, type Attributes, type InstrumentationScope, type LogRecordData, type MetricData, type ScopeGroup, type SpanData } from './otlp.encode.ts'

/**
 * A minimal OpenTelemetry exporter: every instrument in @opentelemetry/api, cumulative, plus log records and the
 * spans tracing.ts records, sent gzipped OTLP/HTTP protobuf. We register as @opentelemetry/api's
 * global meter and logger providers, so apps and libraries record through its `metrics.getMeter()`
 * and `logs.getLogger()`; our `metrics` and `logs` exports hand out the same objects. It reads the official SDK's environment variables, parsed the way
 * opentelemetry-js parses them: OTEL_EXPORTER_OTLP_ENDPOINT (or a per-signal
 * OTEL_EXPORTER_OTLP_{TRACES,METRICS,LOGS}_ENDPOINT), OTEL_EXPORTER_OTLP_HEADERS (merged with
 * per-signal _HEADERS), OTEL_SERVICE_NAME, OTEL_RESOURCE_ATTRIBUTES, OTEL_SDK_DISABLED,
 * OTEL_METRIC_EXPORT_INTERVAL and OTEL_{TRACES,METRICS,LOGS}_EXPORTER. One addition of ours, OTLP_PASSWORD, sends basic auth with
 * the service name as the username, unless the _HEADERS variables set Authorization. NODE_ENV becomes
 * deployment.environment.name and CI_GIT_VERSION (our Concourse pipelines' build arg) becomes service.version,
 * unless OTEL_RESOURCE_ATTRIBUTES sets them. Unlike the SDK, an unset endpoint means a silent no-op
 * rather than localhost, so instruments can be used anywhere without checking whether telemetry is on.
 *
 * Each instrument tracks at most 2000 attribute sets, the spec's default cardinality limit; past
 * that, new sets are counted together in one series marked otel.metric.overflow.
 *
 * Transient failures are retried with backoff within the export timeout, per the OTLP spec; after
 * that the data is dropped. That costs nothing for metrics, since cumulative sums carry their
 * totals in every export, but a dropped log batch is lost.
 */

export type { Attributes, AttributeValue } from './otlp.encode.ts'
export { SeverityNumber, ValueType } from '@opentelemetry/api'

export type TelemetrySignal = 'metrics' | 'logs' | 'traces'

export type { BatchObservableCallback, BatchObservableResult, Counter, Gauge, Histogram, Logger, LogRecord, Meter, MetricOptions, Observable, ObservableCallback, ObservableCounter, ObservableGauge, ObservableResult, ObservableUpDownCounter, TimeInput, UpDownCounter } from '@opentelemetry/api'

// the spec's default export timeout, covering every attempt of one export and the waits between them
const EXPORT_TIMEOUT_MS = 10000
const DEFAULT_METRIC_EXPORT_INTERVAL_MS = 60000
// the spec's batch processor defaults
const LOG_EXPORT_DELAY_MS = 1000
const SPAN_EXPORT_DELAY_MS = 5000
const BATCH_SIZE = 512
const QUEUE_SIZE = 2048
// k8s gives a pod 30s to stop, but a crashing process shouldn't sit on a dead collector that long
const CRASH_FLUSH_TIMEOUT_MS = 3000

const RETRYABLE_STATUS = new Set([429, 502, 503, 504])
const USER_AGENT = `fastify-txstate-otlp-exporter/1.0 node/${process.versions.node}`

const urls: Partial<Record<TelemetrySignal, string>> = {}
const headers: Partial<Record<TelemetrySignal, Record<string, string>>> = {}
let resource: Attributes = {}
const processStartNano = nowNano()

interface InstrumentStorage {
  scope: InstrumentationScope
  name: string
  description: string
  unit: string
}
interface Point { attributes: Attributes, value: number }
// counters and up-down counters
const sums = new Map<string, InstrumentStorage & { monotonic: boolean, series: Map<string, Point> }>()
// synchronous gauges, which keep the last value recorded
const gauges = new Map<string, InstrumentStorage & { series: Map<string, Point> }>()
type ObservableStorage = InstrumentStorage & { kind: 'sum' | 'gauge', monotonic: boolean, callbacks: Set<ObservableCallback> }
const observables = new Map<string, ObservableStorage>()
const observableStorage = new WeakMap<Observable, ObservableStorage>()
const batchCallbacks = new Map<BatchObservableCallback, Observable[]>()
interface HistogramSeries { attributes: Attributes, count: number, sum: number, min: number, max: number, bucketCounts: number[] }
const histograms = new Map<string, InstrumentStorage & { bounds: number[], series: Map<string, HistogramSeries> }>()
// the spec's default explicit bucket boundaries
const DEFAULT_HISTOGRAM_BOUNDARIES = [0, 5, 10, 25, 50, 75, 100, 250, 500, 750, 1000, 2500, 5000, 7500, 10000]

const scopes = new Map<string, InstrumentationScope>()
/** one object per name and version, so records from the same meter, logger or tracer group together */
export function scopeFor (name: string, version?: string) {
  const key = JSON.stringify([name, version])
  let scope = scopes.get(key)
  if (!scope) {
    scope = { name, version }
    scopes.set(key, scope)
  }
  return scope
}
const libraryScope = scopeFor('fastify-txstate')

function groupByScope<T> (entries: Iterable<[InstrumentationScope, T]>) {
  const groups = new Map<InstrumentationScope, T[]>()
  for (const [scope, item] of entries) {
    const items = groups.get(scope)
    if (items) items.push(item)
    else groups.set(scope, [item])
  }
  return Array.from(groups, ([scope, items]): ScopeGroup<T> => ({ scope, items }))
}

/** attribute sets that differ only in key order or undefined values are the same series */
function seriesKey (attributes: Attributes) {
  return JSON.stringify(Object.entries(attributes).filter(([, v]) => v !== undefined).sort(([a], [b]) => a.localeCompare(b)))
}

const CARDINALITY_LIMIT = 2000
const OVERFLOW_ATTRIBUTES: Attributes = { 'otel.metric.overflow': true }
const OVERFLOW_KEY = seriesKey(OVERFLOW_ATTRIBUTES)
const overflowed = new Set<string>()

/** past the limit, a new attribute set goes to the overflow series; sets already seen keep their own, per the spec */
function cardinalityKey (series: Map<string, unknown>, attributes: Attributes, name: string) {
  const key = seriesKey(attributes)
  if (series.has(key) || series.size - (series.has(OVERFLOW_KEY) ? 1 : 0) < CARDINALITY_LIMIT) return key
  if (!overflowed.has(name)) {
    overflowed.add(name)
    console.warn(`OpenTelemetry metric ${name} has passed ${CARDINALITY_LIMIT} attribute sets; new ones are counted under otel.metric.overflow. Look for an unbounded attribute, like an id or a full URL.`)
  }
  return OVERFLOW_KEY
}

/** the series for these attributes, created at zero */
function pointFor (series: Map<string, Point>, attributes: Attributes, name: string) {
  const key = cardinalityKey(series, attributes, name)
  let point = series.get(key)
  if (!point) {
    point = { attributes: key === OVERFLOW_KEY ? OVERFLOW_ATTRIBUTES : attributes, value: 0 }
    series.set(key, point)
  }
  return point
}
let started = false
const timers: NodeJS.Timeout[] = []

function nowNano () {
  return BigInt(Date.now()) * 1_000_000n
}

export function toNano (time: TimeInput) {
  if (Array.isArray(time)) return BigInt(time[0]) * 1_000_000_000n + BigInt(time[1])
  return BigInt(Math.round((typeof time === 'number' ? time : time.getTime()) * 1000)) * 1000n
}

/** Retry-After is either a number of seconds or an HTTP date */
function retryAfterMs (header: string | null) {
  if (!header) return undefined
  const seconds = Number(header)
  const ms = Number.isNaN(seconds) ? Date.parse(header) - Date.now() : seconds * 1000
  return Number.isNaN(ms) ? undefined : Math.max(0, ms)
}

/** OTLP failure bodies are protobuf google.rpc.Status messages, but a proxy in between may send anything */
async function describeFailure (resp: Response) {
  const bytes = new Uint8Array(await resp.arrayBuffer().catch(() => new ArrayBuffer(0)))
  let detail = ''
  if (resp.headers.get('content-type')?.includes('protobuf')) {
    try {
      detail = decodeStatusMessage(bytes)
    } catch {
      // not a Status after all; the status code will have to do
    }
  } else detail = new TextDecoder().decode(bytes).slice(0, 500)
  return `HTTP ${resp.status}${detail ? `: ${detail}` : ''}`
}

const failing: Partial<Record<TelemetrySignal, boolean>> = {}
const lastPartialSuccess: Partial<Record<TelemetrySignal, string>> = {}

/** a 200 can still carry rejections or warnings, which mean the collector didn't like something we sent */
async function checkPartialSuccess (signal: TelemetrySignal, resp: Response) {
  if (!resp.headers.get('content-type')?.includes('protobuf')) return
  let partial
  try {
    partial = decodeExportResponse(new Uint8Array(await resp.arrayBuffer()))
  } catch {
    return
  }
  // the spec says to leave partial_success unset on full success, but the Collector sends it empty
  const message = partial && (partial.rejected || partial.errorMessage) ? `${partial.rejected} rejected${partial.errorMessage ? `: ${partial.errorMessage}` : ''}` : undefined
  // the same complaint usually comes back on every export, so only report changes
  if (message && message !== lastPartialSuccess[signal]) console.warn(`OpenTelemetry ${signal} export partially accepted, ${message}`)
  lastPartialSuccess[signal] = message
}

async function send (signal: TelemetrySignal, payload: Uint8Array<ArrayBuffer>) {
  const url = urls[signal]!
  const body = new Uint8Array(await promisify(gzip)(payload))
  const deadline = Date.now() + EXPORT_TIMEOUT_MS
  let problem: string
  for (let attempt = 0; ; attempt++) {
    let wait: number | undefined
    try {
      const resp = await fetch(url, {
        method: 'POST',
        headers: { ...headers[signal], 'Content-Type': 'application/x-protobuf', 'Content-Encoding': 'gzip', 'User-Agent': USER_AGENT },
        body,
        signal: AbortSignal.timeout(Math.max(1, deadline - Date.now()))
      })
      if (resp.ok) {
        await checkPartialSuccess(signal, resp)
        if (failing[signal]) console.info(`OpenTelemetry ${signal} export recovered.`)
        failing[signal] = false
        return
      }
      problem = await describeFailure(resp)
      if (!RETRYABLE_STATUS.has(resp.status)) break
      wait = retryAfterMs(resp.headers.get('retry-after'))
    } catch (e: unknown) {
      // no response at all: refused, reset, or out of time, all of which the spec counts as transient
      problem = e instanceof Error ? e.message : String(e)
    }
    // exponential backoff with full jitter, from 0.5s doubling up to 30s
    wait ??= Math.random() * Math.min(30000, 500 * 2 ** attempt)
    if (Date.now() + wait >= deadline) break
    await sleep(wait)
  }
  // log only the first failure of a streak, so an unreachable collector doesn't flood the logs
  if (!failing[signal]) console.error(`OpenTelemetry ${signal} export to ${url} failed, dropping data until it recovers: ${problem}`)
  failing[signal] = true
}

async function exportMetrics () {
  if (!urls.metrics) return
  const time = nowNano()
  const metrics: [InstrumentationScope, MetricData][] = []
  for (const { scope, name, description, unit, monotonic, series } of sums.values()) {
    if (!series.size) continue
    metrics.push([scope, { name, description, unit, kind: 'sum', monotonic, points: Array.from(series.values(), s => ({ ...s, startTimeUnixNano: processStartNano, timeUnixNano: time })) }])
  }
  for (const { scope, name, description, unit, series } of gauges.values()) {
    if (!series.size) continue
    metrics.push([scope, { name, description, unit, kind: 'gauge', points: Array.from(series.values(), s => ({ ...s, timeUnixNano: time })) }])
  }
  for (const { scope, name, description, unit, bounds, series } of histograms.values()) {
    if (!series.size) continue
    metrics.push([scope, { name, description, unit, kind: 'histogram', points: Array.from(series.values(), s => ({ ...s, bucketCounts: [...s.bucketCounts], explicitBounds: bounds, startTimeUnixNano: processStartNano, timeUnixNano: time })) }])
  }
  // a later observation of the same attributes replaces the earlier one, as in the SDK
  const observed = new Map<ObservableStorage, Map<string, Point>>()
  function observe (storage: ObservableStorage, value: number, attributes: Record<string, unknown> = {}) {
    if (!Number.isFinite(value)) return
    let series = observed.get(storage)
    if (!series) {
      series = new Map()
      observed.set(storage, series)
    }
    pointFor(series, attributes as Attributes, storage.name).value = value
  }
  for (const storage of observables.values()) {
    const result: ObservableResult = { observe (value, attributes) { observe(storage, value, attributes) } }
    for (const callback of storage.callbacks) {
      try {
        await callback(result)
      } catch (e: unknown) {
        console.error(`OpenTelemetry instrument ${storage.name} callback failed:`, e)
      }
    }
  }
  for (const [observeBatch, instruments] of batchCallbacks) {
    // a batch callback may only observe the instruments it was registered with
    const allowed = new Set(instruments.map(o => observableStorage.get(o)))
    try {
      await observeBatch({
        observe (instrument, value, attributes) {
          const storage = observableStorage.get(instrument)
          if (storage && allowed.has(storage)) observe(storage, value, attributes)
        }
      })
    } catch (e: unknown) {
      console.error('OpenTelemetry batch observable callback failed:', e)
    }
  }
  for (const [{ scope, name, description, unit, kind, monotonic }, series] of observed) {
    const points = Array.from(series.values(), o => ({ ...o, timeUnixNano: time }))
    metrics.push([scope, kind === 'sum'
      ? { name, description, unit, kind, monotonic, points: points.map(p => ({ ...p, startTimeUnixNano: processStartNano })) }
      : { name, description, unit, kind, points }])
  }
  if (metrics.length) await send('metrics', encodeMetricsRequest(resource, groupByScope(metrics)))
}

class BatchQueue<T> {
  private items: [InstrumentationScope, T][] = []
  private dropped = 0

  constructor (private signal: 'logs' | 'traces', private encode: (resource: Attributes, groups: ScopeGroup<T>[]) => Uint8Array<ArrayBuffer>) {}

  push (scope: InstrumentationScope, item: T) {
    if (this.items.length >= QUEUE_SIZE) this.dropped += 1
    else this.items.push([scope, item])
  }

  async export () {
    if (!urls[this.signal]) return
    if (this.dropped) {
      console.warn(`OpenTelemetry ${this.signal} queue was full; dropped ${this.dropped} items.`)
      this.dropped = 0
    }
    while (this.items.length) {
      const batch = this.items.slice(0, BATCH_SIZE)
      this.items = this.items.slice(BATCH_SIZE)
      await send(this.signal, this.encode(resource, groupByScope(batch)))
    }
  }
}

const logQueue = new BatchQueue<LogRecordData>('logs', encodeLogsRequest)
const spanQueue = new BatchQueue<SpanData>('traces', encodeTracesRequest)

function every (ms: number, task: () => Promise<void>) {
  let running = false
  const timer = setInterval(() => {
    if (running) return // a slow collector shouldn't stack up overlapping exports
    running = true
    task().catch(console.error).finally(() => { running = false })
  }, ms)
  timer.unref()
  timers.push(timer)
}

/** blank counts as unset, per the spec */
export function envString (name: string) {
  const value = process.env[name]
  return value == null || value.trim() === '' ? undefined : value
}

/**
 * opentelemetry-js's parseKeyPairsIntoRecord, the W3C Baggage format: comma separated key=value
 * pairs split on the first =, metadata after ; dropped, keys and values percent-decoded.
 */
function parseKeyPairs (value: string | undefined) {
  const result: Record<string, string> = {}
  for (const entry of value?.split(',') ?? []) {
    const pair = entry.split(';', 1)[0]
    const separator = pair.indexOf('=')
    if (separator <= 0) continue
    const key = pair.slice(0, separator).trim()
    const val = pair.slice(separator + 1).trim()
    if (!key || !val) continue
    try {
      result[decodeURIComponent(key)] = decodeURIComponent(val)
    } catch {
      // bad percent-encoding drops the entry, as in the SDK
    }
  }
  return result
}

/** a per-signal endpoint is used as given; the general one gets v1/{signal} appended */
function endpointFor (signal: TelemetrySignal) {
  const specific = envString(`OTEL_EXPORTER_OTLP_${signal.toUpperCase()}_ENDPOINT`)
  const general = envString('OTEL_EXPORTER_OTLP_ENDPOINT')
  const url = specific ?? (general == null ? undefined : `${general.endsWith('/') ? general : general + '/'}v1/${signal}`)
  if (url == null) return undefined
  try {
    return new URL(url).toString()
  } catch {
    console.warn(`OpenTelemetry ${signal} export URL '${url}' is not a valid URL; ${signal} will not be exported.`)
    return undefined
  }
}

function metricExportInterval () {
  const value = envString('OTEL_METRIC_EXPORT_INTERVAL')
  if (value == null) return DEFAULT_METRIC_EXPORT_INTERVAL_MS
  const ms = Number(value)
  if (Number.isFinite(ms) && ms > 0) return ms
  console.warn(`OTEL_METRIC_EXPORT_INTERVAL '${value}' is not a positive number of milliseconds; using ${DEFAULT_METRIC_EXPORT_INTERVAL_MS}.`)
  return DEFAULT_METRIC_EXPORT_INTERVAL_MS
}

/** OTEL_{SIGNAL}_EXPORTER defaults to otlp, the only exporter we have */
function exporterEnabled (signal: TelemetrySignal) {
  const name = `OTEL_${signal.toUpperCase()}_EXPORTER`
  const exporters = envString(name)?.split(',').map(e => e.trim().toLowerCase())
  if (!exporters || exporters.includes('otlp')) return true
  if (!exporters.includes('none')) console.warn(`${name} names no exporter we support (only otlp and none); ${signal} will not be exported.`)
  return false
}

/**
 * Reads the OTEL_ environment variables described above and starts the export timers. Without
 * an endpoint it does nothing and every instrument stays a no-op. Server calls this
 * automatically; repeat calls do nothing.
 */
export function startTelemetry () {
  if (started) return
  started = true
  if (envString('OTEL_SDK_DISABLED')?.trim().toLowerCase() === 'true') return
  const resourceAttributes: Attributes = parseKeyPairs(envString('OTEL_RESOURCE_ATTRIBUTES'))
  const serviceName = envString('OTEL_SERVICE_NAME') ?? resourceAttributes['service.name'] as string | undefined ?? 'unknown_service:node'
  const password = envString('OTLP_PASSWORD')
  const generalHeaders = parseKeyPairs(envString('OTEL_EXPORTER_OTLP_HEADERS'))
  for (const signal of ['metrics', 'logs', 'traces'] as const) {
    if (!exporterEnabled(signal)) continue
    urls[signal] = endpointFor(signal)
    const signalHeaders = { ...generalHeaders, ...parseKeyPairs(envString(`OTEL_EXPORTER_OTLP_${signal.toUpperCase()}_HEADERS`)) }
    // fetch would join a differently cased duplicate into one broken value
    if (password && !Object.keys(signalHeaders).some(k => k.toLowerCase() === 'authorization')) {
      signalHeaders.Authorization = `Basic ${Buffer.from(`${serviceName}:${password}`).toString('base64')}`
    }
    headers[signal] = signalHeaders
  }
  if (!urls.metrics && !urls.logs && !urls.traces) return
  resource = {
    'deployment.environment.name': envString('NODE_ENV'),
    'service.version': envString('CI_GIT_VERSION'),
    ...resourceAttributes,
    'service.name': serviceName,
    // keeps each instance's cumulative series apart, or a backend would merge them into nonsense
    'service.instance.id': randomUUID()
  }
  if (urls.metrics) every(metricExportInterval(), exportMetrics)
  if (urls.logs) every(LOG_EXPORT_DELAY_MS, async () => { await logQueue.export() })
  if (urls.traces) every(SPAN_EXPORT_DELAY_MS, async () => { await spanQueue.export() })
  process.on('uncaughtException', onUncaughtException)
  console.info(`OpenTelemetry export enabled: ${Object.entries(urls).map(([signal, url]) => `${signal} to ${url}`).join(', ')}`)
}

let crashing = false
/**
 * Listening replaces Node's crash, so we print and exit with code 1 ourselves after the flush.
 * Unhandled rejections arrive here too under Node's default --unhandled-rejections=throw.
 */
function onUncaughtException (err: Error) {
  emitException(err, 'exception')
  // another listener means the app chose to survive this, and the timers will export it
  if (process.listenerCount('uncaughtException') > 1) return
  if (crashing) return
  crashing = true
  console.error(err)
  void Promise.race([flushTelemetry().catch(console.error), sleep(CRASH_FLUSH_TIMEOUT_MS)]).finally(() => process.exit(1))
}

/** whether startTelemetry found somewhere to send this signal */
export function telemetryEnabled (signal: TelemetrySignal) {
  return urls[signal] != null
}

/** stops the timers and sends whatever is pending; called when the server shuts down */
export async function flushTelemetry () {
  for (const timer of timers) clearInterval(timer)
  timers.length = 0
  await Promise.all([exportMetrics(), logQueue.export(), spanQueue.export()])
}

function instrumentKey (scope: InstrumentationScope, name: string) {
  // instrument names are case-insensitive
  return JSON.stringify([scope.name, scope.version, name.toLowerCase()])
}

function storageFor<T extends InstrumentStorage> (map: Map<string, T>, base: InstrumentStorage, extra: Omit<T, keyof InstrumentStorage>) {
  const key = instrumentKey(base.scope, base.name)
  // creating the same instrument again shares its series, as in the SDK
  let storage = map.get(key)
  if (!storage) {
    storage = Object.assign(base, extra) as T
    map.set(key, storage)
  }
  return storage
}

/** the context argument the API's instruments accept is for exemplars, which we don't record */
function getMeter (scopeName: string, version?: string): Meter {
  const scope = scopeFor(scopeName, version)
  const base = (name: string, options: MetricOptions = {}): InstrumentStorage => ({ scope, name, description: options.description ?? '', unit: options.unit ?? '' })
  const sum = (name: string, options: MetricOptions | undefined, monotonic: boolean): Counter => {
    const { series } = storageFor(sums, base(name, options), { monotonic, series: new Map() })
    return {
      add (value, attributes = {}) {
        // counters only go up; the SDK drops negative increments too
        if (!urls.metrics || !Number.isFinite(value) || (monotonic && value < 0)) return
        pointFor(series, attributes as Attributes, name).value += value
      }
    }
  }
  const observable = (name: string, options: MetricOptions | undefined, kind: 'sum' | 'gauge', monotonic: boolean): Observable => {
    const storage = storageFor(observables, base(name, options), { kind, monotonic, callbacks: new Set() })
    const instrument: Observable = {
      addCallback (callback) { storage.callbacks.add(callback) },
      removeCallback (callback) { storage.callbacks.delete(callback) }
    }
    observableStorage.set(instrument, storage)
    return instrument
  }
  return {
    /** a monotonic sum, exported with cumulative temporality */
    createCounter: (name, options) => sum(name, options, true),
    /** a sum that can go down, like items in a queue */
    createUpDownCounter: (name, options) => sum(name, options, false),
    /** the last value recorded for each attribute set */
    createGauge (name, options) {
      const { series } = storageFor(gauges, base(name, options), { series: new Map() })
      return {
        record (value, attributes) {
          if (!urls.metrics || !Number.isFinite(value)) return
          pointFor(series, (attributes ?? {}) as Attributes, name).value = value
        }
      }
    },
    /** counts each value into a bucket, exported with cumulative temporality */
    createHistogram (name, options = {}) {
      const { bounds, series } = storageFor(histograms, base(name, options), {
        bounds: Array.from(new Set(options.advice?.explicitBucketBoundaries ?? DEFAULT_HISTOGRAM_BOUNDARIES)).filter(Number.isFinite).sort((a, b) => a - b),
        series: new Map()
      })
      return {
        record (value, attributes) {
          // the SDK drops negative values too, since they'd make sum meaningless
          if (!urls.metrics || !(value >= 0)) return
          const attrs = (attributes ?? {}) as Attributes
          const key = cardinalityKey(series, attrs, name)
          let s = series.get(key)
          if (!s) {
            s = { attributes: key === OVERFLOW_KEY ? OVERFLOW_ATTRIBUTES : attrs, count: 0, sum: 0, min: value, max: value, bucketCounts: new Array<number>(bounds.length + 1).fill(0) }
            series.set(key, s)
          }
          s.count += 1
          s.sum += value
          s.min = Math.min(s.min, value)
          s.max = Math.max(s.max, value)
          // bounds are inclusive upper limits; past the last, the overflow bucket
          const bucket = bounds.findIndex(b => value <= b)
          s.bucketCounts[bucket === -1 ? bounds.length : bucket] += 1
        }
      }
    },
    /**
     * The observable instruments are read at export time: their callbacks run once per export
     * interval on each instance, and only while metrics export is enabled.
     */
    createObservableGauge: (name, options) => observable(name, options, 'gauge', false),
    /** the callback reports the running total, like CPU time used */
    createObservableCounter: (name, options) => observable(name, options, 'sum', true),
    createObservableUpDownCounter: (name, options) => observable(name, options, 'sum', false),
    addBatchObservableCallback (callback, instruments) { batchCallbacks.set(callback, instruments) },
    removeBatchObservableCallback (callback) { batchCallbacks.delete(callback) }
  }
}

function getLogger (scopeName: string, version?: string): Logger {
  const scope = scopeFor(scopeName, version)
  return {
    emit (record) {
      if (!urls.logs) return
      const observedTimeUnixNano = record.observedTimestamp == null ? nowNano() : toNano(record.observedTimestamp)
      // as in the SDK, a record carries the trace and span ids of its context, or the active one
      const span = trace.getSpanContext(record.context ?? context.active())
      logQueue.push(scope, {
        timeUnixNano: record.timestamp == null ? observedTimeUnixNano : toNano(record.timestamp),
        observedTimeUnixNano,
        severityNumber: record.severityNumber,
        severityText: record.severityText,
        eventName: record.eventName,
        body: record.body as AttributeValue,
        // the exception's attributes, unless the record set its own
        attributes: { ...(record.exception == null ? {} : exceptionAttributes(record.exception)), ...record.attributes as Attributes },
        traceId: span?.traceId,
        spanId: span?.spanId,
        flags: span?.traceFlags
      })
    },
    enabled () {
      return urls.logs != null
    }
  }
}

// at import, not in startTelemetry: the API hands out a permanent no-op meter until a provider is
// registered, and libraries make theirs at import too; our instruments check urls when they record
if (envString('OTEL_SDK_DISABLED')?.trim().toLowerCase() !== 'true') {
  if (!apiMetrics.setGlobalMeterProvider({ getMeter })) console.warn('Another OpenTelemetry SDK registered a meter provider with @opentelemetry/api first; metrics made through the API will go to it.')
  if (!apiLogs.setGlobalLoggerProvider({ getLogger })) console.warn('Another OpenTelemetry SDK registered a logger provider with @opentelemetry/api first; logs made through the API will go to it.')
}

/** like @opentelemetry/api's metrics: name the meter after your app or library */
export const metrics = { getMeter }

/** like @opentelemetry/api's logs: name the logger after your app or library */
export const logs = { getLogger }

/** queues a finished span for export; tracing.ts is the only caller */
export function exportSpan (span: SpanData, scope = libraryScope) {
  if (urls.traces) spanQueue.push(scope, span)
}

/** the semconv's exception.* attributes, from anything that might be thrown */
export function exceptionAttributes (exception: unknown): Attributes {
  const e = (typeof exception === 'object' && exception != null ? exception : { message: String(exception) }) as { name?: string, code?: string | number, message?: string, stack?: string }
  return {
    'exception.type': exception instanceof Error ? exception.constructor.name : e.name ?? e.code?.toString(),
    'exception.message': e.message,
    'exception.stacktrace': e.stack
  }
}

const exceptionLogger = getLogger('fastify-txstate')

/** an unhandled exception as a log record, per the semconv; tracing.ts and reportError are the callers */
export function emitException (exception: unknown, eventName: string, attributes?: Attributes) {
  const exceptionAttrs = exceptionAttributes(exception)
  // the semconv leaves body unset, but log viewers show it as the line
  exceptionLogger.emit({ eventName, severityNumber: SeverityNumber.ERROR, severityText: 'ERROR', body: exceptionAttrs['exception.message'], attributes: { ...attributes, ...exceptionAttrs } })
}

/**
 * Reports an error the app caught itself, like a failed cron task: it goes to the console, out as
 * an OTLP `exception` log record, and onto the active span, if any, which is marked failed.
 * Errors that make a request fail with a 5xx are reported automatically.
 */
export function reportError (exception: unknown, attributes?: Attributes) {
  console.error(exception)
  emitException(exception, 'exception', attributes)
  const span = trace.getActiveSpan()
  if (!span) return
  span.setStatus({ code: SpanStatusCode.ERROR })
  span.setAttribute('error.type', exceptionAttributes(exception)['exception.type'] ?? '_OTHER')
  span.recordException(exception as Error)
}
