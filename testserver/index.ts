import fastifyMultipart from '@fastify/multipart'
import { context, logs as apiLogs, metrics as apiMetrics, propagation, SpanStatusCode, trace as apiTrace } from '@opentelemetry/api'
import type { FromSchema } from 'json-schema-to-ts'
import { createHash } from 'node:crypto'
import { channel, tracingChannel } from 'node:diagnostics_channel'
import { get as httpGet } from 'node:http'
import { access, mkdir, utimes, writeFile } from 'node:fs/promises'
import { dirname } from 'node:path'
import { PassThrough, Readable } from 'node:stream'
import { isBlank, randomid, rescue, sleep } from 'txstate-utils'
import Server, { FileSystemHandler, HttpError, SeverityNumber, SpanKind, analyticsPlugin, fileHandler, formDataFieldsFromParts, formDataFilesFromParts, jwtAuthenticate, logs, metrics, postFormData, registerUaCookieRoutes, reportError, requireCookieAuthUa, trace, traceJob } from '../src/index.ts'

class CustomError extends Error {}

// what a library recording through @opentelemetry/api gets, made before Server starts telemetry
const libMeter = apiMetrics.getMeter('testlib', '0.1.0')
const libQueued = libMeter.createUpDownCounter('testlib.queued', { unit: '{job}' })
const libTemperature = libMeter.createGauge('testlib.temperature', { unit: 'Cel' })
const libCpu = libMeter.createObservableCounter('testlib.cpu.time', { unit: 's' })
libCpu.addCallback(result => { result.observe(12.5) })
const libConnections = libMeter.createObservableUpDownCounter('testlib.connections', { unit: '{connection}' })
// libCpu isn't registered with this callback, so its observation is ignored
libMeter.addBatchObservableCallback(result => {
  result.observe(libConnections, 4, { 'testlib.pool': 'main' })
  result.observe(libCpu, 999)
}, [libConnections])
const libLogger = apiLogs.getLogger('testlib', '0.1.0')

const server = new Server({
  trustProxy: true,
  validOrigins: ['http://validorigin.com'],
  validOriginHosts: ['subd.validhost.com'],
  validOriginSuffixes: ['proxiedhost.com'],
  checkOrigin: req => req.headers['x-auto-cors-pass'] === '1',
  authenticate: jwtAuthenticate()
})
server.addErrorHandler(async (err, req, res) => {
  if (err instanceof CustomError) await res.status(422).send('My Custom Error')
})
registerUaCookieRoutes(server.app)

const typedInput = {
  type: 'object',
  properties: {
    str: {
      type: 'string',
      description: 'This is a string. There are many like it. This one is yours.'
    },
    num: { type: 'number' },
    int: { type: 'integer', errorMessage: 'The "int" property must be an integer.' },
    array: { type: 'array', items: { type: 'integer' } }
  },
  examples: [{ num: 12 }],
  required: ['str'],
  additionalProperties: false
} as const
const typedInputRecursive = {
  ...typedInput,
  $id: '#typedInput',
  properties: {
    ...typedInput.properties,
    more: { type: 'array', items: { $ref: '#' } }
  }
} as const
export type TypedInput = FromSchema<typeof typedInput>
export type TypedInputRecursive = TypedInput & { more?: TypedInputRecursive[] }
// what an app's own instrumentation looks like
const meter = metrics.getMeter('testserver', '1.2.3')
const telemetryHits = meter.createCounter('testserver.telemetry.hits', { description: 'Requests to /telemetry', unit: '{request}' })
meter.createObservableGauge('testserver.queue.depth', { description: 'Jobs waiting', unit: '{job}' }).addCallback(result => {
  result.observe(7, { 'testserver.queue': 'email' })
})
const logger = logs.getLogger('testserver', '1.2.3')
const cardinality = meter.createCounter('testserver.cardinality')
const duration = meter.createHistogram('testserver.duration', { description: 'How long the job took', unit: 's', advice: { explicitBucketBoundaries: [0.1, 1, 10] } })
const appTracer = trace.getTracer('testserver', '1.2.3')
// what a library using @opentelemetry/api gets, since fastify-txstate registers as its global provider
const tracer = apiTrace.getTracer('testserver', '1.2.3')

server.swagger().then(async () => {
  await server.app.register(analyticsPlugin, { appName: 'testserver' })
  await server.app.register(fastifyMultipart)
  await fileHandler.init()

  server.app.get('/test', async (req, res) => ({ hello: 'world' }))
  server.app.get('/403', async (req, res) => {
    throw new HttpError(403, 'Not Authorized')
  })
  server.app.get('/409', async (req, res) => {
    throw new HttpError(409)
  })
  server.app.get('/422', async (req, res) => {
    throw new CustomError('My Custom Error')
  })
  server.app.get('/500', async (req, res) => {
    throw new Error('Random Error')
  })
  server.app.get('/shutdown', async (req, res) => {
    await res.send('OK')
    await server.close(0.5)
    process.exit()
  })
  // regression: an async handler that calls res.send(stream) without returning the reply
  // used to double-send whenever our onSend hooks were async, because the handler resolved
  // before the first send flushed headers — fastify then ended the raw response mid-stream
  server.app.get('/streamlate', async (req, res) => {
    const stream = new PassThrough()
    void res.header('Content-Type', 'text/plain; charset=utf-8').send(stream)
    for (let i = 0; i < 5; i++) stream.write(`row ${i}\n`)
    stream.end()
  })
  server.app.get('/proxy', async (req, res) => ({ protocol: req.protocol, host: req.host, hostname: req.hostname }))
  // the test container echoes request headers back, so the test can see what we propagated
  server.app.get('/tracing', async (req, res) => {
    const viaFetch = await (await fetch('http://fastify-test:4318/echo')).json() as Record<string, string>
    const viaHttp = await new Promise<Record<string, string>>((resolve, reject) => {
      httpGet('http://fastify-test:4318/echo?token=secret', resp => {
        let body = ''
        resp.on('data', (chunk: Buffer) => { body += chunk.toString() })
        resp.on('end', () => { resolve(JSON.parse(body)) })
      }).on('error', reject)
    })
    return { fetch: viaFetch.traceparent, http: viaHttp.traceparent }
  })
  // publishes what mysql2 does, with the values already inlined into the query
  server.app.get('/tracing/db', async (req, res) => {
    await tracingChannel('mysql2:query').tracePromise(async () => { await sleep(5) }, { query: "SELECT * FROM `users` u JOIN roles r ON r.userId = u.id WHERE u.name = 'o\\'brien' AND u.age > 21", values: [], database: 'app', serverAddress: 'db', serverPort: 3306 })
    return {}
  })
  // publishes what postgres.js does: the text, host and port only arrive once the query is sent
  server.app.get('/tracing/postgres', async (req, res) => {
    // tracePromise sets result to what the function returns, as postgres.js does
    const select = { query: null as string | null, database: 'app', host: null as string | null, port: null as number | null }
    await tracingChannel('postgres:query').tracePromise(async () => {
      await sleep(5)
      Object.assign(select, { query: 'select * from "users" where name = $1', host: 'pg', port: 5432 })
      return [{}, {}]
    }, select)
    // count is rows affected; none come back
    await tracingChannel('postgres:query').tracePromise(async () => { await sleep(5); return [] }, { query: 'update users set active = false', database: 'app', host: 'pg', port: 5432, count: 5000 })
    const duplicate = Object.assign(new Error('duplicate key value violates unique constraint'), { code: '23505', severity: 'ERROR' })
    await rescue(tracingChannel('postgres:query').tracePromise(async () => { await sleep(5); throw duplicate }, { query: 'insert into users (name) values ($1)', database: 'app', host: 'pg', port: 5432 }))
    return {}
  })
  // publishes what node:sqlite does once a 5ms statement has run, with the values inlined
  server.app.get('/tracing/sqlite', async (req, res) => {
    channel('sqlite.db.query').publish({ sql: "SELECT * FROM users WHERE name = 'o''brien'", database: { location: () => '/data/app.db' }, duration: 5_000_000 })
    return {}
  })
  // publishes what mongoose does: a find, then a save that hits a duplicate key
  server.app.get('/tracing/mongo', async (req, res) => {
    const conn = { database: 'app', serverAddress: 'mongo', serverPort: 27017 }
    await tracingChannel('mongoose:query').tracePromise(async () => { await sleep(5) }, { operation: 'find', collection: 'users', ...conn, args: { filter: { name: 'secret' } } })
    const duplicate = Object.assign(new Error('E11000 duplicate key error'), { code: 11000, codeName: 'DuplicateKey' })
    await rescue(tracingChannel('mongoose:model:save').tracePromise(async () => { await sleep(5); throw duplicate }, { operation: 'save', collection: 'users', ...conn, args: {} }))
    return {}
  })
  // what a library that makes spans through @opentelemetry/api does
  server.app.get('/tracing/api', async (req, res) => await tracer.startActiveSpan('testserver.work', { attributes: { 'testserver.tags': ['a', 'b'] } }, async span => {
    await fetch('http://fastify-test:4318/echo')
    const carrier: Record<string, string> = {}
    propagation.inject(context.active(), carrier)
    span.setStatus({ code: SpanStatusCode.ERROR, message: 'partly failed' })
    span.end()
    return { injected: carrier.traceparent }
  }))
  // what an app's own span looks like, e.g. ai-broker recording a model call
  server.app.get('/tracing/app', async (req, res) => await appTracer.startActiveSpan('chat test-model', { kind: SpanKind.CLIENT, attributes: { 'gen_ai.operation.name': 'chat', 'gen_ai.request.model': 'test-model' } }, async span => {
    try {
      await fetch('http://fastify-test:4318/echo')
      span.setAttributes({ 'gen_ai.usage.input_tokens': 1200, 'gen_ai.usage.output_tokens': 300 })
      return {}
    } finally {
      span.end()
    }
  }))
  // 2005 attribute sets: 2000 get series of their own, the last 5 share the overflow series
  server.app.get('/telemetry/cardinality', async (req, res) => {
    for (let i = 0; i < 2005; i++) cardinality.add(1, { 'testserver.id': i })
    cardinality.add(1, { 'testserver.id': 0 })
    return {}
  })
  server.app.get('/telemetry/histogram', async (req, res) => {
    for (const seconds of [0.05, 0.5, 1, 20]) duration.record(seconds, { 'testserver.kind': 'test' })
    return {}
  })
  server.app.get('/telemetry/api', async (req, res) => {
    libQueued.add(5)
    libQueued.add(-2)
    libTemperature.record(30)
    libTemperature.record(21.5)
    libLogger.emit({ eventName: 'testlib.failed', severityNumber: SeverityNumber.ERROR, exception: new TypeError('bad input'), attributes: { 'testlib.step': 'parse' } })
    return {}
  })
  server.app.get('/telemetry', async (req, res) => {
    telemetryHits.add(1, { 'testserver.kind': 'test' })
    logger.emit({ eventName: 'testserver.hit', severityNumber: SeverityNumber.WARN, severityText: 'WARN', body: 'hit the telemetry route', attributes: { 'testserver.kind': 'test' } })
    return {}
  })
  // an app catching its own error and reporting it
  server.app.get('/telemetry/report', async (req, res) => {
    reportError(new CustomError('could not reach the mail server'), { 'testserver.kind': 'test' })
    return {}
  })
  // what a cron task looks like, run here so the test can trigger it
  server.app.get('/telemetry/job', async (req, res) => {
    try {
      await traceJob('testserver.cleanup', async () => {
        await fetch('http://fastify-test:4318/echo')
        throw new Error('cleanup failed')
      }, { 'testserver.job': 'cleanup' })
    } catch {
      return { rethrown: true }
    }
    return { rethrown: false }
  })
  server.app.get('/logging', async (req, res) => {
    res.extraLogInfo = { hello: 'world' }
    return { success: true }
  })
  server.app.get<{ Querystring: { id: number } }>('/coerce', { schema: { querystring: { type: 'object', properties: { id: { type: 'number' } }, required: ['id'] }, response: { 200: { type: 'object', properties: { id: { type: 'number' } } } } } }, (req, res) => ({ id: req.query.id }))
  server.app.post<{ Body: TypedInputRecursive }>('/typed', { schema: { body: typedInputRecursive, response: { 200: { type: 'string' } } } }, (req, res) => req.body.str)
  server.app.post<{ Body: TypedInputRecursive }>('/numtyped', { schema: { body: typedInputRecursive, response: { 200: { type: 'object', properties: { num: { type: 'number' } } } } } }, (req, res) => ({ num: req.body.num }))
  server.app.post<{ Body: TypedInputRecursive }>('/badtyped', { schema: { body: typedInputRecursive, response: { 200: { type: 'integer' } } } }, (req, res) => 5.5)
  // regression: routes with a body schema and no response schema used to crash the server at boot
  server.app.post<{ Body: TypedInput }>('/bodyonly', { schema: { body: typedInput } }, (req, res) => ({ str: req.body.str }))
  // regression: an explicitly declared response.400 used to be overwritten with the ValidatedResponse schema
  server.app.post<{ Body: { grant_type: string } }>('/custom400', {
    schema: {
      body: { type: 'object', properties: { grant_type: { type: 'string' } }, required: ['grant_type'] },
      response: { 400: { type: 'object', properties: { error: { type: 'string' }, error_description: { type: 'string' } } } }
    }
  }, async (req, res) => await res.status(400).send({ error: 'invalid_grant', error_description: 'The provided grant is invalid.' }))
  server.app.post<{ Body: { mydate: string } }>('/datetime', { schema: { body: { type: 'object', properties: { mydate: { type: 'string', format: 'date-time' } }, required: ['mydate'], additionalProperties: false }, response: { 200: { type: 'object', properties: { yourdate: { type: 'string', format: 'date-time' } } } } } }, (req, res) => {
    const date = new Date(req.body.mydate)
    return { yourdate: date.toISOString() }
  })
  server.app.post('/protected', async (req, res) => {
    if (isBlank(req.auth?.username)) throw new HttpError(401, 'Authentication is required.')
    return { authenticated: req.auth!.username, sessionCreatedAt: req.auth!.sessionCreatedAt }
  })
  server.app.post('/protectedCookie', async (req, res) => {
    if (await requireCookieAuthUa(req, res)) return
    return { authenticated: req.auth?.username }
  })
  server.app.post('/acceptupload', async (req, res) => {
    let contentLength = 0
    let files = 0
    let textFields = 0
    for await (const part of req.parts()) {
      if (part.type === 'file') {
        files += 1
        for await (const chunk of part.file) {
          contentLength += chunk.length
        }
      } else {
        textFields += 1
      }
    }
    return { received: contentLength, files, textFields }
  })
  server.app.post('/proxymultipart', async (req, res) => {
    if (req.isMultipart()) {
      const resp = await postFormData('http://fastify-http/acceptupload', formDataFieldsFromParts(req.parts()))
      return await resp.json()
    } else {
      throw new HttpError(400, 'Expected multipart/form-data')
    }
  })
  server.app.post('/proxymultipartfiles', async (req, res) => {
    if (req.isMultipart()) {
      const resp = await postFormData('http://fastify-http/acceptupload', formDataFilesFromParts(req.parts()))
      return await resp.json()
    } else {
      throw new HttpError(400, 'Expected multipart/form-data')
    }
  })
  server.app.post('/filestorage/upload', async (req, res) => {
    const results = []
    for await (const part of req.parts()) {
      if (part.type === 'file') {
        const { checksum, size } = await fileHandler.put(part.file)
        results.push({ checksum, size, filename: part.filename })
      }
    }
    return results
  })
  server.app.post<{ Body: { content: string, checksum?: string } }>('/filestorage/legacyupload', async (req, res) => {
    const checksum = req.body.checksum ?? createHash('sha256').update(req.body.content).digest('base64url')
    const legacypath = `/files/storage/${checksum.slice(0, 1)}/${checksum.slice(1, 2)}/${checksum.slice(2)}`
    await mkdir(dirname(legacypath), { recursive: true })
    await writeFile(legacypath, req.body.content)
    return { checksum }
  })
  server.app.post<{ Params: { checksum: string } }>('/filestorage/migrate/:checksum', async (req, res) => ({ migrated: await fileHandler.migrateLegacyFile(req.params.checksum) }))
  server.app.post<{ Params: { checksum: string } }>('/filestorage/remove/:checksum', async (req, res) => { await fileHandler.remove(req.params.checksum); return {} })
  server.app.post('/filestorage/migrateall', async (req, res) => ({ migrated: await fileHandler.migrateLegacyFiles() }))
  server.app.post<{ Body: { ageMs: number[], olderThanMs?: number, viaInit?: boolean } }>('/filestorage/cleanuptmp', async (req, res) => {
    // a private tmpdir so concurrent uploads from other tests can't be affected
    const handler = new FileSystemHandler({ tmpdir: `/files/cleanuptest/${randomid(8)}`, permdir: '/files/storage' })
    await mkdir(handler.options.tmpdir, { recursive: true })
    const names = req.body.ageMs.map(() => randomid(12))
    for (let i = 0; i < names.length; i++) {
      const filepath = `${handler.options.tmpdir}${names[i]}`
      await writeFile(filepath, 'partial upload')
      const time = new Date(Date.now() - req.body.ageMs[i])
      await utimes(filepath, time, time)
    }
    await writeFile(`${handler.options.tmpdir}notours.txt`, 'unrelated')
    await utimes(`${handler.options.tmpdir}notours.txt`, new Date(0), new Date(0))
    const deleted = req.body.viaInit ? undefined : await handler.cleanupTmp({ olderThanMs: req.body.olderThanMs })
    if (req.body.viaInit) await handler.init()
    const remaining = await Promise.all([...names, 'notours.txt'].map(async name => (await rescue(access(`${handler.options.tmpdir}${name}`), false)) !== false))
    return { deleted, remaining }
  })
  server.app.post('/filestorage/removeprune', async (req, res) => {
    // a private permdir so files from other tests can't share our folders
    const handler = new FileSystemHandler({ tmpdir: '/files/tmp', permdir: `/files/prunetest/${randomid(8)}` })
    await handler.init()
    const { checksum } = await handler.put(Readable.from([Buffer.from('prune me')]))
    const hex = Buffer.from(checksum, 'base64url').toString('hex')
    const top = `${handler.options.permdir}${hex.slice(0, 2)}`
    const exists = async (path: string) => (await rescue(access(path), false)) !== false
    // a sibling that shares the top folder but not the second
    const siblingHex = hex.slice(0, 2) + (hex.slice(2, 4) === 'ff' ? '00' : 'ff') + hex.slice(4)
    await mkdir(`${top}/${siblingHex.slice(2, 4)}`, { recursive: true })
    await writeFile(`${top}/${siblingHex.slice(2, 4)}/${siblingHex.slice(4)}`, 'sibling')
    await handler.remove(checksum)
    const afterFirst = { leaf: await exists(`${top}/${hex.slice(2, 4)}`), top: await exists(top) }
    await handler.remove(siblingHex)
    const afterSecond = { top: await exists(top), permdir: await exists(handler.options.permdir) }
    return { afterFirst, afterSecond }
  })
  server.app.post('/filestorage/migrateprune', async (req, res) => {
    const handler = new FileSystemHandler({ tmpdir: '/files/tmp', permdir: `/files/prunetest/${randomid(8)}` })
    await handler.init()
    const checksum = createHash('sha256').update('migrate and prune me').digest('base64url')
    const top = `${handler.options.permdir}${checksum.slice(0, 1)}`
    await mkdir(`${top}/${checksum.slice(1, 2)}`, { recursive: true })
    await writeFile(`${top}/${checksum.slice(1, 2)}/${checksum.slice(2)}`, 'migrate and prune me')
    const migrated = await handler.migrateLegacyFile(checksum)
    const exists = async (path: string) => (await rescue(access(path), false)) !== false
    return { migrated, legacyTop: await exists(top), stored: await handler.exists(checksum) }
  })
  server.app.get('/filestorage/checksums', async (req, res) => {
    const checksums: string[] = []
    for await (const checksum of fileHandler.checksums()) checksums.push(checksum)
    return checksums
  })
  server.app.get<{ Params: { checksum: string }, Querystring: { start?: string, end?: string } }>('/filestorage/download/:checksum', async (req, res) => {
    const { checksum } = req.params
    if (!(await fileHandler.exists(checksum))) throw new HttpError(404, 'File not found')
    const { start, end } = req.query
    const stream = fileHandler.get(checksum, start == null ? undefined : { start: Number(start), end: end == null ? undefined : Number(end) })
    return await res.send(stream)
  })
})
  .then(async () => { await server.start() })
  .catch((e: unknown) => { console.error(e) })
