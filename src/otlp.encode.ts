/**
 * Protobuf encoding for the slice of OTLP we send: export requests for metrics (sums,
 * gauges and explicit-bucket histograms), logs and traces, plus decoding for the two small messages a collector replies with. Field
 * numbers come from opentelemetry-proto v1.11 (opentelemetry/proto/{common,resource,metrics,logs,
 * trace,collector}/v1) and google/rpc/status.proto. A few wire-format helpers are all it takes.
 *
 * Protobuf rather than JSON because it's the spec's default OTLP/HTTP encoding and the one every
 * receiver accepts; Elastic APM Server, notably, rejects JSON.
 */

/** an OTLP AnyValue: arrays and maps may nest, null and undefined are left out of attributes */
export type AttributeValue = string | number | boolean | Uint8Array | null | undefined | readonly AttributeValue[] | { readonly [key: string]: AttributeValue }
export type Attributes = Record<string, AttributeValue>

export interface NumberDataPoint {
  attributes: Attributes
  /** nanoseconds since the epoch; for cumulative sums, when the series started counting */
  startTimeUnixNano?: bigint
  timeUnixNano: bigint
  value: number
}

export interface HistogramDataPoint {
  attributes: Attributes
  startTimeUnixNano: bigint
  timeUnixNano: bigint
  count: number
  sum: number
  min: number
  max: number
  /** one more than explicitBounds: the last counts values above the highest bound */
  bucketCounts: number[]
  /** ascending upper bounds, each inclusive */
  explicitBounds: number[]
}

export type MetricData = {
  name: string
  description: string
  unit: string
} & ({ kind: 'sum', monotonic: boolean, points: NumberDataPoint[] } | { kind: 'gauge', points: NumberDataPoint[] } | { kind: 'histogram', points: HistogramDataPoint[] })

export interface LogRecordData {
  timeUnixNano: bigint
  /** when the record was collected, if later than timeUnixNano */
  observedTimeUnixNano?: bigint
  severityNumber?: number
  severityText?: string
  eventName?: string
  body?: AttributeValue
  attributes: Attributes
  /** the span active when the record was emitted, as 32 and 16 lowercase hex characters */
  traceId?: string
  spanId?: string
  /** W3C trace flags */
  flags?: number
}

export interface SpanEventData {
  name: string
  timeUnixNano: bigint
  attributes: Attributes
}

export interface SpanLinkData {
  traceId: string
  spanId: string
  traceState?: string
  attributes: Attributes
  /** W3C trace flags, plus SpanFlags.CONTEXT_HAS_IS_REMOTE and CONTEXT_IS_REMOTE */
  flags: number
}

export interface SpanData {
  /** 32 lowercase hex characters */
  traceId: string
  /** 16 lowercase hex characters */
  spanId: string
  parentSpanId?: string
  traceState?: string
  /** W3C trace flags in the low byte, plus the SpanFlags bits saying whether the parent is remote */
  flags: number
  name: string
  /** opentelemetry.proto.trace.v1.Span.SpanKind, which is @opentelemetry/api's SpanKind plus one */
  kind: number
  startTimeUnixNano: bigint
  endTimeUnixNano: bigint
  attributes: Attributes
  events: SpanEventData[]
  links: SpanLinkData[]
  /** opentelemetry.proto.trace.v1.Status.StatusCode, the same numbers as @opentelemetry/api's SpanStatusCode */
  statusCode: number
  statusMessage?: string
}

/** opentelemetry.proto.trace.v1.SpanFlags */
export const SpanFlags = { SAMPLED: 0x01, CONTEXT_HAS_IS_REMOTE: 0x100, CONTEXT_IS_REMOTE: 0x200 } as const

const WIRE_VARINT = 0
const WIRE_FIXED64 = 1
const WIRE_LEN = 2
const WIRE_FIXED32 = 5

const AGGREGATION_TEMPORALITY_CUMULATIVE = 2

const utf8 = new TextEncoder()

class ProtoWriter {
  private chunks: Uint8Array[] = []
  private length = 0

  private push (bytes: Uint8Array) {
    this.chunks.push(bytes)
    this.length += bytes.length
  }

  private rawVarint (n: bigint) {
    const bytes: number[] = []
    // negative int64s go out as their 64-bit two's complement, ten bytes long
    let v = BigInt.asUintN(64, n)
    while (v > 0x7fn) {
      bytes.push(Number(v & 0x7fn) | 0x80)
      v >>= 7n
    }
    bytes.push(Number(v))
    this.push(Uint8Array.from(bytes))
  }

  private tag (field: number, wireType: number) {
    this.rawVarint(BigInt((field << 3) | wireType))
  }

  // no proto3 zero-value skipping: oneof members (AnyValue, as_double) must be written even when empty

  varint (field: number, n: number | bigint | boolean) {
    this.tag(field, WIRE_VARINT)
    this.rawVarint(typeof n === 'boolean' ? (n ? 1n : 0n) : BigInt(n))
    return this
  }

  fixed64 (field: number, n: bigint) {
    this.tag(field, WIRE_FIXED64)
    const bytes = new Uint8Array(8)
    new DataView(bytes.buffer).setBigUint64(0, BigInt.asUintN(64, n), true)
    this.push(bytes)
    return this
  }

  fixed32 (field: number, n: number) {
    this.tag(field, WIRE_FIXED32)
    const bytes = new Uint8Array(4)
    new DataView(bytes.buffer).setUint32(0, n >>> 0, true)
    this.push(bytes)
    return this
  }

  double (field: number, n: number) {
    this.tag(field, WIRE_FIXED64)
    const bytes = new Uint8Array(8)
    new DataView(bytes.buffer).setFloat64(0, n, true)
    this.push(bytes)
    return this
  }

  /** a packed repeated fixed64 */
  packedFixed64 (field: number, values: number[]) {
    const bytes = new Uint8Array(values.length * 8)
    const view = new DataView(bytes.buffer)
    values.forEach((n, i) => { view.setBigUint64(i * 8, BigInt(n), true) })
    return this.bytes(field, bytes)
  }

  /** a packed repeated double */
  packedDouble (field: number, values: number[]) {
    const bytes = new Uint8Array(values.length * 8)
    const view = new DataView(bytes.buffer)
    values.forEach((n, i) => { view.setFloat64(i * 8, n, true) })
    return this.bytes(field, bytes)
  }

  bytes (field: number, bytes: Uint8Array) {
    this.tag(field, WIRE_LEN)
    this.rawVarint(BigInt(bytes.length))
    this.push(bytes)
    return this
  }

  string (field: number, s: string) {
    return this.bytes(field, utf8.encode(s))
  }

  message (field: number, build: (w: ProtoWriter) => void) {
    const child = new ProtoWriter()
    build(child)
    return this.bytes(field, child.finish())
  }

  finish () {
    const out = new Uint8Array(this.length)
    let offset = 0
    for (const chunk of this.chunks) {
      out.set(chunk, offset)
      offset += chunk.length
    }
    return out
  }
}

function isPlainObject (value: object): value is Record<string, unknown> {
  const proto: unknown = Object.getPrototypeOf(value)
  return proto === Object.prototype || proto === null
}

/**
 * opentelemetry.proto.common.v1.AnyValue. Takes unknown because @opentelemetry/api lets callers pass
 * anything; a value OTLP has no type for goes out as its string form.
 */
function writeAnyValue (w: ProtoWriter, value: unknown) {
  if (value == null) return // AnyValue with nothing set means empty
  if (typeof value === 'string') w.string(1, value)
  else if (typeof value === 'boolean') w.varint(2, value)
  else if (typeof value === 'number') {
    if (Number.isSafeInteger(value)) w.varint(3, value)
    else w.double(4, value)
  } else if (typeof value === 'bigint' && BigInt.asIntN(64, value) === value) w.varint(3, value)
  else if (value instanceof Uint8Array) w.bytes(7, value)
  else if (Array.isArray(value)) w.message(5, a => { for (const item of value) a.message(1, v => { writeAnyValue(v, item) }) })
  else if (typeof value === 'object' && isPlainObject(value)) w.message(6, kvlist => { writeAttributes(kvlist, 1, value) })
  else w.string(1, String(value)) // eslint-disable-line @typescript-eslint/no-base-to-string -- see above
}

/** repeated opentelemetry.proto.common.v1.KeyValue; null and undefined values are left out */
function writeAttributes (w: ProtoWriter, field: number, attributes: Record<string, unknown>) {
  for (const [key, value] of Object.entries(attributes)) {
    if (value == null) continue
    w.message(field, kv => {
      kv.string(1, key)
      kv.message(2, v => { writeAnyValue(v, value) })
    })
  }
}

export interface InstrumentationScope {
  name: string
  version?: string
}

export interface ScopeGroup<T> {
  scope: InstrumentationScope
  items: T[]
}

/**
 * The shared outer shape of every export request: resource_X = 1 { resource = 1, scope_X = 2 },
 * ScopeX { scope = 1, X = 2 }, InstrumentationScope { name = 1, version = 2 }
 */
function writeRequest<T> (resource: Attributes, groups: ScopeGroup<T>[], writeItem: (x: ProtoWriter, item: T) => void) {
  const w = new ProtoWriter()
  w.message(1, rx => {
    rx.message(1, r => { writeAttributes(r, 1, resource) })
    for (const { scope, items } of groups) {
      rx.message(2, sx => {
        sx.message(1, s => {
          s.string(1, scope.name)
          if (scope.version) s.string(2, scope.version)
        })
        for (const item of items) sx.message(2, x => { writeItem(x, item) })
      })
    }
  })
  return w.finish()
}

/** opentelemetry.proto.metrics.v1.Metric */
function writeMetric (m: ProtoWriter, metric: MetricData) {
  m.string(1, metric.name)
  m.string(2, metric.description)
  m.string(3, metric.unit)
  if (metric.kind === 'histogram') {
    m.message(9, data => {
      for (const point of metric.points) {
        // HistogramDataPoint
        data.message(1, p => {
          p.fixed64(2, point.startTimeUnixNano)
          p.fixed64(3, point.timeUnixNano)
          p.fixed64(4, BigInt(point.count))
          p.double(5, point.sum)
          p.packedFixed64(6, point.bucketCounts)
          p.packedDouble(7, point.explicitBounds)
          writeAttributes(p, 9, point.attributes)
          p.double(11, point.min)
          p.double(12, point.max)
        })
      }
      data.varint(2, AGGREGATION_TEMPORALITY_CUMULATIVE)
    })
    return
  }
  // Gauge = 5, Sum = 7; both hold data_points = 1
  m.message(metric.kind === 'sum' ? 7 : 5, data => {
    for (const point of metric.points) {
      data.message(1, p => {
        if (point.startTimeUnixNano != null) p.fixed64(2, point.startTimeUnixNano)
        p.fixed64(3, point.timeUnixNano)
        p.double(4, point.value)
        writeAttributes(p, 7, point.attributes)
      })
    }
    if (metric.kind === 'sum') {
      data.varint(2, AGGREGATION_TEMPORALITY_CUMULATIVE)
      data.varint(3, metric.monotonic)
    }
  })
}

/** opentelemetry.proto.logs.v1.LogRecord */
function writeLogRecord (r: ProtoWriter, record: LogRecordData) {
  r.fixed64(1, record.timeUnixNano)
  r.fixed64(11, record.observedTimeUnixNano ?? record.timeUnixNano)
  if (record.severityNumber != null) r.varint(2, record.severityNumber)
  if (record.severityText != null) r.string(3, record.severityText)
  if (record.body != null) r.message(5, v => { writeAnyValue(v, record.body) })
  writeAttributes(r, 6, record.attributes)
  if (record.flags) r.fixed32(8, record.flags)
  if (record.traceId) r.bytes(9, Buffer.from(record.traceId, 'hex'))
  if (record.spanId) r.bytes(10, Buffer.from(record.spanId, 'hex'))
  if (record.eventName != null) r.string(12, record.eventName)
}

/** opentelemetry.proto.trace.v1.Span */
function writeSpan (s: ProtoWriter, span: SpanData) {
  s.bytes(1, Buffer.from(span.traceId, 'hex'))
  s.bytes(2, Buffer.from(span.spanId, 'hex'))
  if (span.traceState) s.string(3, span.traceState)
  if (span.parentSpanId) s.bytes(4, Buffer.from(span.parentSpanId, 'hex'))
  s.string(5, span.name)
  s.varint(6, span.kind)
  s.fixed64(7, span.startTimeUnixNano)
  s.fixed64(8, span.endTimeUnixNano)
  writeAttributes(s, 9, span.attributes)
  for (const event of span.events) {
    s.message(11, e => {
      e.fixed64(1, event.timeUnixNano)
      e.string(2, event.name)
      writeAttributes(e, 3, event.attributes)
    })
  }
  for (const link of span.links) {
    s.message(13, l => {
      l.bytes(1, Buffer.from(link.traceId, 'hex'))
      l.bytes(2, Buffer.from(link.spanId, 'hex'))
      if (link.traceState) l.string(3, link.traceState)
      writeAttributes(l, 4, link.attributes)
      l.fixed32(6, link.flags)
    })
  }
  if (span.statusCode) {
    s.message(15, st => {
      if (span.statusMessage) st.string(2, span.statusMessage)
      st.varint(3, span.statusCode)
    })
  }
  s.fixed32(16, span.flags)
}

/** opentelemetry.proto.collector.metrics.v1.ExportMetricsServiceRequest */
export function encodeMetricsRequest (resource: Attributes, groups: ScopeGroup<MetricData>[]) {
  return writeRequest(resource, groups, writeMetric)
}

/** opentelemetry.proto.collector.logs.v1.ExportLogsServiceRequest */
export function encodeLogsRequest (resource: Attributes, groups: ScopeGroup<LogRecordData>[]) {
  return writeRequest(resource, groups, writeLogRecord)
}

/** opentelemetry.proto.collector.trace.v1.ExportTraceServiceRequest */
export function encodeTracesRequest (resource: Attributes, groups: ScopeGroup<SpanData>[]) {
  return writeRequest(resource, groups, writeSpan)
}

/** reads a message's top-level fields, keeping the last value of each: varints as bigints, length-delimited fields as bytes */
function readFields (bytes: Uint8Array) {
  const fields = new Map<number, bigint | Uint8Array>()
  let pos = 0
  const varint = () => {
    let result = 0n
    for (let shift = 0n; ; shift += 7n) {
      if (pos >= bytes.length) throw new Error('Truncated protobuf message.')
      const b = bytes[pos]
      pos += 1
      result |= BigInt(b & 0x7f) << shift
      if (!(b & 0x80)) return result
    }
  }
  while (pos < bytes.length) {
    const tag = Number(varint())
    const field = tag >>> 3
    const wireType = tag & 7
    if (wireType === WIRE_VARINT) fields.set(field, varint())
    else if (wireType === WIRE_FIXED64) pos += 8
    else if (wireType === WIRE_LEN) {
      const len = Number(varint())
      if (pos + len > bytes.length) throw new Error('Truncated protobuf message.')
      fields.set(field, bytes.subarray(pos, pos + len))
      pos += len
    } else if (wireType === WIRE_FIXED32) pos += 4
    else throw new Error(`Unsupported protobuf wire type ${wireType}.`)
  }
  return fields
}

const utf8Decoder = new TextDecoder()
function readString (value: bigint | Uint8Array | undefined) {
  return value instanceof Uint8Array ? utf8Decoder.decode(value) : ''
}

/**
 * The partial_success of an Export{Metrics,Logs,Trace}ServiceResponse, which share a shape:
 * { rejected_<signal> = 1 (int64), error_message = 2 }. Undefined on full success.
 */
export function decodeExportResponse (bytes: Uint8Array) {
  const partial = readFields(bytes).get(1)
  if (!(partial instanceof Uint8Array)) return undefined
  const fields = readFields(partial)
  const rejected = fields.get(1)
  return { rejected: typeof rejected === 'bigint' ? Number(rejected) : 0, errorMessage: readString(fields.get(2)) }
}

/** the message of a google.rpc.Status { code = 1, message = 2, details = 3 }, the body of any failed OTLP/HTTP export */
export function decodeStatusMessage (bytes: Uint8Array) {
  return readString(readFields(bytes).get(2))
}
