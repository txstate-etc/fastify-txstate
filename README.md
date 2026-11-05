# fastify-txstate
A small wrapper for fastify providing a set of common conventions & utility functions for presenting an HTTP server.

> **v4 upgrades to fastify 5 and drops CommonJS, among other things.** See the [changelog](https://github.com/txstate-etc/fastify-txstate/blob/master/CHANGELOG.md) for upgrade notes.

# Basic Usage
```javascript
import Server from 'fastify-txstate'
const server = new Server()
server.app.get('/yourpath', async (req, res) => {
  return { hello: 'world' }
})
server.start().then(() => {
  console.log('started!')
}).catch(e => console.error(e))
```
* If you need special configuration for fastify, pass it to `new Server({ /* any valid fastify config */ })`.
* `server.app` is the fastify instance.
# Error Handling
Some resources are available to make error handling easy.
## HttpError
This class is available to throw simple errors while processing a request:
```javascript
import { HttpError } from 'fastify-txstate'
server.app.get('/yourpath', async (req, res) => {
  if (!req.params.id) throw new HttpError(400, 'Please provide an id.')
  /* ... */
})
```
This will result in a 400 error being returned to the client, with a plain text body: `Please provide an id.`

You may skip the message string and a default will be used, e.g. `throw new HttpError(401)` sends a plain text body: `Authentication is required.`
## ValidationErrors
This class helps an API communicate with its client about errors that occured during a validation or writing operation. The constructor takes three arguments: a message to be displayed to the user, a dot-separated path to the property of the input object that the message is related to, and a message type, which could be 'error', 'info', 'warning', 'success', or 'system' (system is for errors that the user is not responsible for like a database being offline).
```javascript
import { ValidationErrors } from 'fastify-txstate'
import { hasFatalErrors } from '@txstate-mws/fastify-shared'
server.app.post('/saveathing', async (req, res) => {
  const thing = req.body
  const messages = []
  if (!thing.title) messages.push({ message: 'Title is required.', path: 'title', type: 'error' })
  if (!thing?.address?.zip) messages.push({ message: 'Zip code is required.', path: 'address.zip', type: 'error' })
  if (hasFatalErrors(messages)) throw new ValidationErrors(messages)
  /* continue processing request */
})
```
The client will receive HTTP status 422 and a JSON body that looks like this:
```json
{
  "success": false,
  "messages": [
    { "type": "error", "message": "Zip code is required.", "path": "address.zip" }
  ]
}
```
This format is well supported by our @txstate-mws/svelte-forms library, so it should be easy to pass the errors into your form.

### ValidationError
`ValidationErrors` is preferred since it will show multiple errors at once, instead of making the user fix errors one at a time and not know how far they are from being done. If you just need to throw a quick single error, `throw new ValidationError('Wrong!', 'answer')` is also available.

# Route Schemas
We configure the `@fastify/type-provider-json-schema-to-ts` type provider, so when you define a schema with `as const`, TypeScript infers request and response types automatically:
```javascript
const createUserBody = {
  type: 'object',
  properties: {
    name: { type: 'string' },
    email: { type: 'string' },
    age: { type: 'integer', minimum: 0 }
  },
  additionalProperties: false
} as const

server.app.post('/users', {
  schema: {
    body: createUserBody,
    response: { 200: validatedResponse, 422: validatedResponse }
  }
}, async (req, res) => {
  // req.body is fully typed — name, email, age are all inferred
})
```

When a route has a `body` schema, we automatically add 400 and 422 response schemas for validation errors, so those don't need to be specified manually.

## Schema Validation vs. Business Validation
An important design point: **schema validation is for catching client bugs, not user mistakes.** When the schema rejects a request, the user gets a generic 400 — not a friendly inline message on a form field. If you want the user to see "Name is required" next to the name input, don't put `required: ['name']` in the schema. Instead, make it optional in the schema and check it in your route handler with a `ValidationMessage` (see [Error Handling](#error-handling)). Reserve schema-level `required`, `pattern`, and `format` for things the client is responsible for, like ensuring dates are in ISO format.

## Ajv Configuration
We configure Ajv with `allErrors`, `ajv-formats` (for `date-time`, `email`, `uri`, etc.), and `ajv-errors` (for custom `errorMessage` strings). `strictSchema` is off, so OpenAPI properties like `example` and `description` won't cause errors.

### Type coercion
Querystrings, URL params, and headers always arrive as strings. To let `?id=123` validate against a schema like `{ type: 'number' }`, we run those parts (plus response validation) through a validator that *coerces* values — the string `"123"` is converted to the number `123` to satisfy the schema. Request bodies are validated strictly: a JSON `"123"` will be rejected by a `number` field rather than silently converted, since that would hide bugs in your client code.

Pass `coerceAll: false` to disable coercion everywhere, or `coerceAll: true` to coerce bodies too. If you need finer control (e.g. strict response validation, or one part coerced and another not), two Ajv instances are exposed — `server.ajvStrict` (no coercion) and `server.ajvCoerce` (coercion on) — already wired with formats/errors plugins. Swap them in via `setValidatorCompiler` or the included `buildSerializerCompiler` helper:
```typescript
const server = new Server()
// Validate responses strictly while keeping querystring coercion on:
server.app.setSerializerCompiler(server.buildSerializerCompiler(server.ajvStrict))
```

## SchemaObject Type
If you define schemas as standalone objects, you can take advantage of the `SchemaObject` exported by `@txstate-mws/fastify-shared`. It extends JSON Schema with OpenAPI properties (`example`, `description`) and `ajv-errors` support (`errorMessage`), so that you can customize the swagger documentation. Add `as const satisfies SchemaObject` to the end of your object before you start filling it with properties and you'll
get autocomplete support in your IDE and confidence that your schema is compliant.
```typescript
import type { SchemaObject } from '@txstate-mws/fastify-shared'

const addressSchema = {
  type: 'object',
  properties: {
    street: { type: 'string', example: '123 Main St' },
    city: { type: 'string', example: 'San Marcos' },
    zip: { type: 'string', description: '5-digit US zip code' }
  },
  additionalProperties: false
} as const satisfies SchemaObject
```

## Response Serialization
Responses are validated through Ajv (not fast-json-stringify), so input and output validation behave identically. If a response doesn't match its schema, the server throws an error rather than sending malformed data. Null values are converted to `undefined` before validation, and Date objects are automatically stringified to ISO format.

## Swagger / OpenAPI
Call `server.swagger()` before registering routes to enable auto-generated documentation:
```javascript
const server = new Server()
await server.swagger({ path: '/docs' })
// register routes after this
```
Route schemas are exposed in the OpenAPI spec automatically. The `example` and `description` properties appear in the Swagger UI. If authentication is configured, security schemes are added automatically.

## Custom Error Handling
If you would like special treatment for certain errors, `addErrorHandler` provides an easy way:
```javascript
server.addErrorHandler(async (err, req, res) => {
  if (err instanceof MyCustomErrorClass) {
    res.status(500).send('You done messed up.')
  }
})
```
In this case we only need custom error handling for a specific class of Error. Calling `res.send()` in your handler is how you signal that the error has been intercepted. If you do not call `res.send()`, the default error handling will kick in, so you can still throw `HttpError` or `ValidationErrors` and have them handled properly.

You may call `addErrorHandler` multiple times; they will be executed in order and bail out when one calls `res.send()`.
## Opt-Out of Error Handling
If you want all the error handling to yourself, you may use fastify's `setErrorHandler` method to override all of `fastify-txstate`'s behavior:
```javascript
server.app.setErrorHandler((err, req, res) => {
  /* whatever you want */
})
```
# SSL
SSL and HTTP2 support is enabled automatically if you provide a key and cert at `/securekeys/private.key` and `/securekeys/cert.pem`, respectively.

* If you do not provide a custom port, and SSL key and cert are not present, port 80 will be used.
* If you do not provide a custom port, and SSL key and cert are present, port 443 will be used and http traffic on port 80 will be redirected to https.
* You can set a custom port with e.g. `server.start(8080)`, or you can set the `PORT` environment variable. If the SSL key and cert are present, your custom port will expect https.

# Health checks / load-balanced restart
A health check is automatically available at `/health`. You may use `server.setUnhealthy('your message')` and `server.setHealthy()` to alter the response. When a SIGINT or SIGTERM is issued (e.g. during an intentional restart), you have the option of delaying for a few seconds to allow the load-balancer to see that you are down. Do this by setting the `LOAD_BALANCE_TIMEOUT` environment variable in seconds.

During this period, `/health` will return HTTP 503, but all other requests will process normally. After the period, the service shuts down as requested. This gives load balancers time to switch all incoming traffic to another service, ensuring no clients see an error during the restart.

# Origin Checking
To help prevent XSRF attacks, we automatically reject requests that send an origin header that doesn't match the host (sub)domain. Only domain is compared, not protocol or port. This is especially helpful in large organizations where untrusted web sites run under different subdomains. SameSite cookies can help with attacks from other domains, but attacks on the same subdomain can still succeed.

There are several ways to allow additional origins. Each is available as a constructor config option and an environment variable (comma-separated).

| Config | Env Var | Match behavior |
|--------|---------|----------------|
| `validOrigins` | `VALID_ORIGINS` | Exact origin match including scheme and port (e.g. `https://app.example.com`) |
| `validOriginHosts` | `VALID_ORIGIN_HOSTS` | Hostname match, ignoring scheme and port (e.g. `app.example.com`) |
| `validOriginSuffixes` | `VALID_ORIGIN_SUFFIXES` | Domain suffix match — allows any subdomain (e.g. `example.com` allows `foo.example.com`, `bar.baz.example.com`) |
| `checkOrigin` | — | Custom function `(req) => boolean` for arbitrary logic. Runs after the other checks; return true to allow. |

All methods are additive — an origin is allowed if it passes any check.

You can disable origin checks entirely with the `skipOriginCheck` configuration or `SKIP_ORIGIN_CHECK` environment variable.

# Reverse Proxy
If your application is behind a reverse proxy, you'll want to set the `trustProxy` configuration to true so that variables like `request.protocol` get set correctly. You can also set the `TRUST_PROXY` environment variable. `true` or `1` will translate to `{ trustProxy: true }`; anything else will be passed unchanged as a string.

# Logging
We try to set up logging well by default, including things like the HTTP traceparent header, and putting the url in both the incoming and outgoing access log entries so that it's easy to grep for certain routes/params.

Development and production logs are different, based on the `NODE_ENV` environment variable. The development logger is designed to be extremely brief and not in JSON format, so that you can see errors clearly.

If you want to provide your own logger, you can pass a pino instance via the `loggerInstance` option in the server constructor configuration. The `devLogger` and `prodLogger` are also exported if you'd like to use them as a starting point.

You can also simply add information to the `reply.extraLogInfo` object and it will automatically appear in the outgoing access log in production.

# OpenTelemetry
Set `OTEL_EXPORTER_OTLP_ENDPOINT` and the server starts sending traces, metrics and logs to it. There's no SDK to install and nothing to register. Leave it unset and everything in this section quietly does nothing, so instrumentation can stay in your code everywhere and only costs anything in environments that have a collector.

A few opinions drive how it works:
* Configure it with the same `OTEL_` environment variables the official SDK reads, so its documentation still applies.
* Never patch anyone's code. A library that publishes [diagnostics channels](https://nodejs.org/api/diagnostics_channel.html) gets traced, and one that doesn't, doesn't (see the note about Postgres below).
* Only trace work that belongs to something. A query that runs outside any request or job does not become its own one-span trace cluttering up your backend.

## Environment Variables
| Variable | Description |
|----------|-------------|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Where to send everything, e.g. `https://otel.example.edu`. We append `/v1/traces` etc. |
| `OTEL_EXPORTER_OTLP_{TRACES,METRICS,LOGS}_ENDPOINT` | Override the endpoint for one signal. This one is used as-is, with nothing appended. |
| `OTLP_PASSWORD` | Sends basic auth, with the service name as the username. Ours, not the SDK's. |
| `OTEL_EXPORTER_OTLP_HEADERS` | Extra headers as `key=value,key=value`, plus per-signal `_HEADERS` variants. An `Authorization` header here wins over `OTLP_PASSWORD`. |
| `OTEL_SERVICE_NAME` | Your app's name in the backend. Please set it, otherwise you're `unknown_service:node`. |
| `OTEL_RESOURCE_ATTRIBUTES` | Extra `key=value,key=value` attributes on everything you send. |
| `OTEL_{TRACES,METRICS,LOGS}_EXPORTER` | `none` turns off one signal. |
| `OTEL_METRIC_EXPORT_INTERVAL` | Milliseconds between metric exports. Defaults to 60000. |
| `OTEL_TRACES_SAMPLER`, `OTEL_TRACES_SAMPLER_ARG` | The SDK's samplers, except the remote ones. The default records every trace unless the caller's `traceparent` says it wasn't sampled. |
| `OTEL_SDK_DISABLED` | `true` turns everything off, even with an endpoint set. |

`NODE_ENV` becomes `deployment.environment.name` and `CI_GIT_VERSION` becomes `service.version`, unless `OTEL_RESOURCE_ATTRIBUTES` sets them. The hostname becomes `host.name`, and inside Kubernetes it's also sent as `k8s.pod.name`, along with `k8s.namespace.name`, so your traces and metrics join up with the cluster's own pod metrics.

## What You Get Automatically
* A span for every request, continuing the caller's trace if it sent a `traceparent` header. `/health` and `/analytics` are left out, because probes and beacons would bury the real traffic. Add your own with `untracedRoutes.add('/metrics')`.
* Child spans for outgoing `fetch` and `node:http` calls, which also send a `traceparent` so the next service joins the same trace.
* Child spans for database queries from mysql2, [oracle-async](https://github.com/txstate-etc/oracle-async), [postgres.js](https://github.com/porsager/postgres) (4.0+), `node:sqlite` (Node 26+) and mongoose (9.7+).
* A span for each `FileSystemHandler.put`, with the file's size.
* The `http.server.request.duration` and `http.server.active_requests` metrics, so you get request rates, error rates and latency percentiles per route, plus how many requests are in flight.
* V8 heap usage per heap space (`v8js.memory.heap.used` and friends), resident memory (`process.memory.usage`) and garbage collection pauses (`v8js.gc.duration`), so you can spot a memory leak or GC pressure before the pod gets OOM-killed.
* Event loop delay (`nodejs.eventloop.delay.p99` and friends) and utilization (`nodejs.eventloop.utilization`). Delay tells you when something is blocking the thread and making every request wait; utilization near 1 means the process is saturated even if CPU looks low.
* Every error that ends in a 5xx, sent as a log record attached to its trace.
* `trace_id` and `span_id` on every log line written during a request, so you can jump from a log line to its trace.

### Note about what ends up in your traces
Query text is recorded, but bind values aren't. mysql2's `query()` and `node:sqlite` put the values directly into the SQL text before we see it, so we replace every literal with `?`. That's why `execute()` is preferable to `query()` in mysql2 if you want readable spans. mongoose filters and documents are never recorded. `token` and `unifiedJwt` query parameters are redacted from recorded URLs.

Sometimes you really do need a bind value, say to find the one slow book among thousands of identical `SELECT * FROM books WHERE id = ?` spans. oracle-async lets you opt in per query with `traceBinds`; see its README.

SQLite spans have two weaknesses. `node:sqlite` only reports a statement after it succeeds, so failed statements get no span at all. It also only reports durations to the millisecond, so most of your SQLite spans will say 0ms.

### Note about Postgres
Use [postgres.js](https://github.com/porsager/postgres) rather than `pg` (node-postgres). postgres.js publishes diagnostics channels, so its queries are traced automatically. `pg` doesn't, so it needs to be patched by [`@opentelemetry/instrumentation-pg`](https://www.npmjs.com/package/@opentelemetry/instrumentation-pg). If something forces `pg` on you:

```bash
npm install @opentelemetry/instrumentation @opentelemetry/instrumentation-pg
```

```javascript
// instrumentation.js
import { registerInstrumentations } from '@opentelemetry/instrumentation'
import { PgInstrumentation } from '@opentelemetry/instrumentation-pg'
registerInstrumentations({ instrumentations: [new PgInstrumentation({ requireParentSpan: true })] })
```

Start with `node --import ./instrumentation.js index.js`. It has to load before anything imports `pg`, so registering it inside `index.js` won't work.

## Background Jobs
A cron job or queue worker doesn't run inside a request, so by our "only trace work that belongs to something" rule, its queries and outgoing calls aren't traced. Wrap it in `traceJob` and it gets a trace of its own:

```javascript
import { traceJob } from 'fastify-txstate'

setInterval(() => {
  traceJob('sync-overdue-books', async () => {
    const books = await db.getall('SELECT * FROM books WHERE due < NOW()') // traced
    await fetch('https://notify.example.edu', { method: 'POST', body: JSON.stringify(books) }) // traced
  }).catch(() => { /* already reported */ })
}, 60_000)
```

If the job throws, the error is sent as a log record, the span is marked failed, and then the error is rethrown. You still need the `catch`, but only to keep the rejection from crashing your process. There's no need to log it again.

## Recording Your Own Telemetry
We export `metrics`, `logs` and `trace`, which work exactly like the same names from `@opentelemetry/api`, so the upstream documentation applies. In fact we register ourselves with `@opentelemetry/api`, so you (and any library you use) can import from there instead and it all ends up in the same place.

If something else, like the official SDK, registers with `@opentelemetry/api` before we do, it wins and we print a warning. Our automatic request and database spans still go out through our exporter, but anything recorded through the API goes to the other SDK.

### Metrics
Most of what you'll add is metrics: counters for things that happen, gauges for levels you can look at, and the occasional histogram.

```javascript
import { metrics } from 'fastify-txstate'
const meter = metrics.getMeter('my-app')

// a counter, for things that happen
const checkouts = meter.createCounter('library.checkouts')
checkouts.add(1, { 'library.branch': 'alkek' })

// a gauge you set whenever you happen to learn the value
const shelfSpace = meter.createGauge('library.shelf.free', { unit: 'm' })
shelfSpace.record(12.5, { 'library.branch': 'alkek' })

// an observable gauge, when it's easier to go look; the callback runs once per export
meter.createObservableGauge('library.holds.waiting').addCallback(async result => {
  result.observe(await countWaitingHolds())
})

// a histogram, when you care about the distribution, like how long something took
const importDuration = meter.createHistogram('library.import.duration', { unit: 's' })
importDuration.record(seconds)
```

### Note about metric attributes
Each metric keeps at most 2000 different combinations of attribute values. Past that, new combinations are lumped together under `otel.metric.overflow` and we print a warning. If you ever see that warning, you almost certainly put something unbounded in an attribute, like a book id or a full URL, and every value is becoming its own time series. Put things like that on spans instead, where they're free.

### Logs and Errors
```javascript
import { logs, SeverityNumber, recordError } from 'fastify-txstate'

// structured log records, stamped with the current trace
const logger = logs.getLogger('my-app')
logger.emit({ eventName: 'library.hold.expired', severityNumber: SeverityNumber.INFO, attributes: { 'library.book.id': book.id } })

// an error you caught and handled, but someone should still know about
try {
  await refreshCatalog()
} catch (e) {
  console.error(e) // or your own logger
  recordError(e) // out as a log record, and marks the active span failed
}
```

Errors that end in a 5xx are already recorded, so `recordError` is only for the ones you catch. It doesn't log to the console, so keep logging the error the way you normally would.

### Spans
You'll rarely need a span of your own, since requests, outgoing calls and queries already get one. If you just want more detail on the request's span, add attributes to it:

```javascript
import { trace } from 'fastify-txstate'
trace.getActiveSpan()?.setAttributes({ 'library.book.id': book.id })
```

Make a new span when a chunk of work deserves its own bar in the trace, like generating a big PDF:

```javascript
const tracer = trace.getTracer('my-app')
const pdf = await tracer.startActiveSpan('render-catalog-pdf', async span => {
  try {
    return await renderCatalog()
  } finally {
    span.end() // NOTE: a span you start, you must end, or it is never sent
  }
})
```

If it's an LLM call, follow the [GenAI semantic conventions](https://opentelemetry.io/docs/specs/semconv/gen-ai/gen-ai-spans/) so LLM-aware views in your backend recognize it.

## Outside of Server
`Server` starts telemetry in its constructor and flushes it when it closes. In a standalone script, like a one-off migration, call `startTelemetry()` yourself (`traceJob` does it for you) and `await flushTelemetry()` before exiting. Otherwise the last few seconds of spans and logs leave with the process. `telemetryEnabled('traces')` tells you whether a signal has somewhere to go.

An uncaught exception, or an unhandled rejection under Node's default settings, is sent as an `exception` log record. Then up to 3 seconds are spent flushing before the process exits with code 1, as it would have anyway. If your app has its own `uncaughtException` listener, the crash is left to that listener and nothing is flushed early.

A failed export is retried for up to 10 seconds and then dropped. Metrics recover on the next export, since they're cumulative, but a dropped batch of spans or logs is gone.

# Authentication
Pass an `authenticate` function to the Server constructor to enable authentication. It runs as an `onRequest` hook on all standard HTTP methods (GET, POST, PUT, PATCH, DELETE), except `/health` and swagger endpoints. The return value is available at `req.auth` in your route handlers and is included in production logs (minus `token`, `accessToken`, and `issuerConfig`).
```javascript
import Server from 'fastify-txstate'
const server = new Server({
  authenticate: async (req) => {
    // extract and verify credentials from the request
    // return a FastifyTxStateAuthInfo object, or undefined if unauthenticated
    // throw to reject with 401
  }
})
```
The `authenticate` function should return a `FastifyTxStateAuthInfo` object with at least `username`, `sessionId`, and `token`. This gives us a predictable interface, since raw JWT claims may vary by provider. Returning `undefined` means the request is unauthenticated (but allowed). Throwing an error sends a 401 response.

We provide a built-in `jwtAuthenticate` that validates JWT tokens from any combination of issuer types — OAuth/OIDC providers (with auto-discovery), TxState Unified Auth, raw JWKS endpoints, symmetric secrets, and asymmetric public keys. You can also write your own `authenticate` for any authentication scheme — API keys, session lookups, custom token formats, etc.

# JWT Authentication
The `jwtAuthenticate` function validates JWTs from the `Authorization: Bearer` header or a session cookie. It supports any mix of these issuer types:

- **OAuth/OIDC** — auto-discovers the provider's JWKS via `.well-known/openid-configuration` or `.well-known/oauth-authorization-server` from the issuer's `iss` claim. If the provider advertises a token introspection endpoint ([RFC 7662](https://www.rfc-editor.org/rfc/rfc7662)), tokens more than 5 minutes old are also polled for revocation, so ended sessions and deactivated users stop working within minutes instead of at token expiration. See `OAUTH_INTROSPECT_TOKEN` below.
- **TxState Unified Auth** — JWKS + a `/validateToken` poll for centralized deauth.
- **JWKS endpoint** — a direct JWKS URL (no discovery).
- **Asymmetric public key** — a PEM-encoded RSA/EC public key.
- **Symmetric secret** — an HMAC shared secret.

For providers like Google that issue opaque access tokens, have the client send the ID token instead — it's a standard JWT that proves the user's identity without requiring a round-trip to the provider on every request.
```javascript
import Server, { jwtAuthenticate } from 'fastify-txstate'
const server = new Server({
  authenticate: jwtAuthenticate({ authenticateAll: true })
})
```
## Environment Variables
At least one issuer must be configured. Use any combination of the env-var shortcuts below, or the JSON-based `JWT_TRUSTED_ISSUERS` for full control. Configuration from both sources is merged.

| Variable | Description |
|----------|-------------|
| `UA_URL` | URL of a TxState Unified Auth service. Creates a unified-auth issuer with `iss: 'unified-auth'`. |
| `UA_URL_INTERNAL` | Internal URL of the UA service for server-to-server requests in split-horizon DNS scenarios. |
| `OAUTH_URLS` | Comma-separated OAuth/OIDC issuer URLs (e.g. `https://accounts.google.com,https://login.microsoftonline.com/{tenant}/v2.0`). Each becomes an issuer with `iss` equal to the URL. |
| `OAUTH_INTERNAL_URLS` | Map external OAuth issuer URLs to internal URLs for docker-compose / split-horizon DNS. Format: `external=internal,external=internal` (e.g. `https://auth.example.com=http://keycloak:8080`). Rewrites server-to-server requests (discovery, JWKS, token exchange) but not browser redirects. |
| `OAUTH_INTROSPECT_TOKEN` | Service token sent as a Bearer credential when polling an OAuth provider's token introspection endpoint. RFC 7662 requires providers to authorize introspection callers, so most will reject the poll without this. When a provider rejects our credentials, the revocation check is disabled for that endpoint (until restart) and we behave as though no introspection endpoint was advertised. |
| `JWT_SECRET` | Symmetric HMAC secret for verifying JWTs. Tokens must have `iss: 'jwt-secret'`. |
| `JWT_PUBLIC_KEY` | PEM-encoded asymmetric public key for verifying JWTs. Tokens must have `iss: 'jwt-public-key'` (use `JWT_TRUSTED_ISSUERS` instead for another name). Literal `\n` is converted to real newlines so PEMs survive env-var encoding. |
| `JWT_TRUSTED_AUDIENCES` | Comma-separated list of accepted `aud` values, unioned into every issuer's audience list. See [Audience Validation](#audience-validation). |
| `JWT_TRUSTED_CLIENTIDS` | Comma-separated list of accepted `client_id` values, unioned into every issuer's client-id list. |
| `JWT_TRUSTED_ISSUERS` | JSON array of issuer configs for advanced setups. See [Issuer JSON Config](#issuer-json-config). |

### Issuer JSON Config
`JWT_TRUSTED_ISSUERS` accepts a JSON array of objects. Each object describes one issuer:

| Field | Required | Description |
|-------|----------|-------------|
| `iss` | Yes | The `iss` claim that tokens from this issuer must carry. |
| `type` | No | One of `oauth`, `jwks`, `unified-auth`, `publicKey`, `secret`. Inferred from other fields if omitted: `iss === 'unified-auth'` → unified-auth; `secret` → secret; `publicKey` → publicKey; `url` → jwks. Set explicitly to `oauth` to enable `.well-known` discovery. |
| `url` | Conditional | Required for `oauth`, `jwks`, and `unified-auth`. For `oauth` it's the issuer URL (discovery is performed relative to it); for `jwks` it's the JWKS endpoint directly. |
| `publicKey` | Conditional | PEM-encoded public key (`publicKey` type). |
| `secret` | Conditional | Symmetric HMAC secret (`secret` type). |
| `internalUrl` | No | Server-to-server URL prefix override for split-horizon DNS. |
| `audiences` | No | Array of accepted `aud` values for this issuer. Unioned with `JWT_TRUSTED_AUDIENCES`. |
| `clientIds` | No | Array of accepted `client_id` values for this issuer. Unioned with `JWT_TRUSTED_CLIENTIDS`. |
| `validateUrl` | No | (unified-auth only) Override URL for the deauth poll. Resolved relative to `url`. Defaults to `<url>/validateToken`. |
| `logoutUrl` | No | End-session URL surfaced as `req.auth.issuerConfig.logoutUrl`. For OAuth issuers this is auto-discovered; set only to override. Resolved relative to `url`. |

## Options
| Option | Description |
|--------|-------------|
| `authenticateAll` | If true, all requests require authentication except routes in `exceptRoutes` or `optionalRoutes`. |
| `exceptRoutes` | `Set<string>` of route URLs that skip authentication entirely and do not receive an auth object. |
| `optionalRoutes` | `Set<string>` of route URLs that do not require authentication but populate `req.auth` if a session is available. |
| `extraClaims` | A function that receives the full JWT payload and returns extra properties to merge into the auth object (e.g. `payload => ({ roles: payload.roles })`). If you use this, you should also set `JWT_TRUSTED_AUDIENCES` or per-issuer `audiences`. See [Audience Validation](#audience-validation). |
| `protectedResourceMetadata` | Extra fields for the RFC 9728 discovery document, or `false` to disable it. See [Protected Resource Metadata](#protected-resource-metadata). |

Calling `registerOAuthCookieRoutes` or `registerUaCookieRoutes` automatically excludes their callback/redirect routes from authentication and marks their logout routes as optional, so you do not need to list them here.

## Cookie Endpoints
For server-rendered applications or SPAs that need cookie-based sessions, `registerOAuthCookieRoutes` implements the full OAuth authorization code flow with PKCE (S256), storing the ID token in an HttpOnly cookie. The access token and refresh token are stored in separate cookies (optionally encrypted via `OAUTH_COOKIE_SECRET`). Expired ID tokens are transparently refreshed using the refresh token cookie.
```javascript
import Server, { jwtAuthenticate, registerOAuthCookieRoutes } from 'fastify-txstate'
const server = new Server({
  authenticate: jwtAuthenticate({ authenticateAll: true })
})
registerOAuthCookieRoutes(server.app)
```
The access token is available at `req.auth.accessToken` for making requests to the provider's APIs on behalf of the user (e.g. Google Drive, Microsoft Graph).
`registerOAuthCookieRoutes` accepts an optional second argument with:
| Option | Description |
|--------|-------------|
| `scopes` | Array of scopes to always include in the authorization request, merged with any scopes the client passes via the `scope` query parameter. |
| `loginPage` | A function for rendering a login selection page when multiple issuers are configured. See [Multiple Issuers](#multiple-issuers). |

### Multiple Issuers
When multiple OAuth issuers are configured (via `OAUTH_URLS` or `JWT_TRUSTED_ISSUERS`), you can provide a `loginPage` function to let the user choose which provider to sign in with. The function receives an array of `{ issuerUrl, redirectHref }` and should return an HTML string.
```javascript
registerOAuthCookieRoutes(server.app, {
  loginPage: issuers => `<!DOCTYPE html>
    <html><body>
      <h1>Sign in with</h1>
      ${issuers.map(i => `<a href="${i.redirectHref}">${new URL(i.issuerUrl).hostname}</a>`).join('<br>')}
    </body></html>`
})
```
When a user hits `/.oauthRedirect` without specifying an `issuer` query parameter, they see this page. Each link redirects back to `/.oauthRedirect` with the chosen issuer pre-filled. If no `loginPage` is provided, the first trusted issuer is used. Clients can also bypass the selection by passing `issuer` directly: `/.oauthRedirect?requestedUrl=...&issuer=https://accounts.google.com`.

### Additional Environment Variables
| Variable | Required | Description |
|----------|----------|-------------|
| `OAUTH_COOKIE_CLIENT_ID` | Yes | OAuth client ID for the authorization code flow. |
| `OAUTH_COOKIE_CLIENT_SECRET` | No | OAuth client secret. PKCE secures the code exchange, but some providers require a secret even with PKCE. |
| `OAUTH_COOKIE_SECRET` | No | If set, the refresh token and access token cookies are encrypted with AES-256-GCM. If not, they are stored as plaintext (still HttpOnly and Secure). |
| `OAUTH_COOKIE_NAME` | No | Name for the session cookie. Defaults to a random hex string. |
| `PUBLIC_URL` | No | Base URL for the API, used to generate callback URIs (e.g. `https://myapp.example.com/api`). Derived from the request hostname if not set. |
| `UI_URL` | No | Base URL for the UI (e.g. `https://myapp.example.com`). Used as the default redirect destination after login/logout. If not set, guessed by removing the last path segment from `PUBLIC_URL` or the request URL. |

### Routes
- **`GET /.oauthRedirect?requestedUrl=...&scope=...&issuer=...`** — Redirects to the OAuth provider's login page. `requestedUrl` is required and specifies where to redirect after login. `scope` is optional and defaults to `openid offline_access`. `issuer` is optional and selects which trusted issuer to use; if omitted with multiple issuers and a `loginPage` configured, a selection page is shown.
- **`GET /.oauthCallback`** — Handles the provider's redirect. Exchanges the authorization code for tokens (using PKCE), sets the ID token, access token, and refresh token as cookies, and redirects to the original `requestedUrl`. If no ID token is returned, falls back to the access token if it is a JWT.
- **`GET /.oauthLogout`** — Clears all OAuth cookies and redirects to the provider's `end_session_endpoint` if available, with the ID token as a hint for single sign-out.

### Server-Rendered Login Redirects
For server-rendered routes where you want to redirect unauthenticated users straight into the login flow (rather than returning a 401 and letting client code react), call `requireCookieAuthOAuth(req, res)` at the top of your handler. If `req.auth` is empty it redirects the browser through `/.oauthRedirect` (preserving the current URL as `requestedUrl`) and returns `true`; otherwise it returns `false` and your handler proceeds.
```javascript
import { requireCookieAuthOAuth } from 'fastify-txstate'
server.app.get('/dashboard', async (req, res) => {
  if (await requireCookieAuthOAuth(req, res)) return
  // ...render the page using req.auth
})
```
If you are using `registerUaCookieRoutes` for TxState Unified Auth instead of OAuth, the equivalent helper is `requireCookieAuthUa(req, res)`. (The old name `requireCookieAuth` still works but is deprecated.)

## Client-Side Authentication (without cookie endpoints)
If you are implementing the OAuth flow in your client application instead of using the cookie endpoints above, send the token to the API as an `Authorization: Bearer <token>` header. Here is what you need to know:

### Which token to send
The API validates tokens locally by verifying the JWT signature against the provider's JWKS. This means **the token must be a JWT**. Choose accordingly:
- **Microsoft, Okta, Auth0, Keycloak**: Access tokens are JWTs. Send the access token.
- **Google**: Access tokens are opaque and cannot be verified locally. Send the **ID token** instead — it is a standard JWT containing the user's identity.
- **General rule**: If your provider's access token is a JWT (three base64url segments separated by dots), send it. If it's opaque, send the ID token.

### Scopes
Scopes control what the user sees on the consent screen and what permissions the token carries. Each provider has its own conventions:
- **Google**: `openid` for basic sign-in, add `email` or `profile` for more claims. Scopes like `https://www.googleapis.com/auth/drive.readonly` authorize access to Google APIs — only request these if the client needs them.
- **Microsoft**: `openid` for sign-in, `User.Read` for Microsoft Graph, `api://{resource-id}/.default` for custom APIs.
- **Okta / Auth0**: `openid` for sign-in, custom scopes as configured in your authorization server.
- For all providers, `openid` is the minimum needed to get an ID token.

### Refresh tokens
The client is responsible for refreshing tokens before they expire and sending a fresh token with each request. How to obtain a refresh token varies by provider:
- **Most OIDC providers** (Microsoft, Okta, Auth0, Keycloak): Request the `offline_access` scope.
- **Google**: Pass `access_type=offline&prompt=consent` as query parameters on the authorization request. The `offline_access` scope is ignored.
- **Apple, AWS Cognito**: Return refresh tokens automatically based on app configuration — no special scope needed.

### PKCE
Use PKCE (S256) for the authorization code exchange even if your provider doesn't require it. Generate a `code_verifier`, send the `code_challenge` in the authorization request, and include the `code_verifier` when exchanging the code for tokens. This protects against authorization code interception and is supported by all major providers.

## Protected Resource Metadata
A client that has never seen your API has a bootstrapping problem: before it can get a token, it has to figure out which authorization server your API trusts. [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728) solves this with a discovery document served at `/.well-known/oauth-protected-resource` — this is how MCP clients, among others, find their way to a login page.

We serve it automatically. When the server starts, if the `jwtAuthenticate` factory has been called and there is something to advertise — trusted OAuth issuers, cookie login routes, or both — the route answers with a document built from the same configuration that drives token verification:
```json
{
  "resource": "https://myapp.example.com/api",
  "authorization_servers": ["https://auth.example.com"],
  "bearer_methods_supported": ["header"],
  "cookie_login_uri": "https://myapp.example.com/api/.oauthRedirect",
  "cookie_logout_uri": "https://myapp.example.com/api/.oauthLogout"
}
```
`authorization_servers` lists your `OAUTH_URLS` and any `type: 'oauth'` entries in `JWT_TRUSTED_ISSUERS`. Issuers of other types (unified-auth, raw JWKS, secrets, public keys) are left out because they aren't authorization servers a client could discover and log in with. `cookie_login_uri` and `cookie_logout_uri` appear when `registerOAuthCookieRoutes` or `registerUaCookieRoutes` has been called — they are our own extension fields, not part of the RFC, so conformant OAuth clients simply ignore them (see the note about first-party SPAs below for why they exist). If there is nothing to advertise at all — no OAuth issuers, no cookie routes — or `jwtAuthenticate` was never set up, the route is not registered and the path returns 404, rather than advertise a login setup that doesn't exist.

While the route is being served, every 401 response also carries a `WWW-Authenticate: Bearer resource_metadata="..."` header pointing at the document, as the RFC prescribes, so a client can discover everything by making one unauthenticated request and following the pointer.

If you'd rather serve your own metadata document, just declare the route before calling `server.start()` — we only register ours if the path is still free, and the 401 header will point at yours. The one case that needs configuration is declaring the route inside an encapsulated fastify plugin, which we can't see at registration time: pass `protectedResourceMetadata: false` to `jwtAuthenticate` and we'll stay out of the way entirely (this also suppresses the `WWW-Authenticate` pointer).

The RFC recommends two fields we can't infer: `scopes_supported` (which scopes a client should request for your API) and `resource_name` (a human-readable name for consent screens). Pass them — or any other RFC 9728 field — in the `jwtAuthenticate` options, using the RFC's snake_case names:
```javascript
const server = new Server({
  authenticate: jwtAuthenticate({
    authenticateAll: true,
    protectedResourceMetadata: {
      resource_name: 'My Application API',
      scopes_supported: ['openid', 'profile']
    }
  })
})
```
Fields you pass win over the automatic ones, so this is also the escape hatch if the derived `resource` identifier is wrong for your deployment — or if you need to supply `authorization_servers` yourself, e.g. when you verify tokens against a `jwks` or `publicKey` issuer (which we can't advertise, since they aren't discoverable authorization servers) but clients still need to know where to log in.

### Note about first-party SPAs
A compiled SPA served as static files can't easily receive environment variables. The metadata document lets your SPA take all its cues from the API instead:

1. The page makes any API request and gets a 401 with the `WWW-Authenticate` header.
2. The client fetches the `resource_metadata` URL from that header.
3. If the document has `cookie_login_uri`, navigate the browser there with a `requestedUrl` query parameter naming the page to return to after login. Done — the API's cookie routes run the whole flow and the session lands in an HttpOnly cookie.
4. Only if there is no `cookie_login_uri` should a browser client consider `authorization_servers` and running the OAuth flow.

Logout is discoverable the same way: navigate the browser to `cookie_logout_uri` and the API clears its cookies and redirects through the provider's logout when it has one (logout accepts an optional `returnUrl` query parameter).

Prefer the cookie flow in shared browser code whenever it's offered: it needs zero client-side configuration and keeps tokens out of reach of injected scripts.

### Note about reverse proxies and base paths
If your API is proxied underneath a base path (say `https://myapp.example.com/api`), be aware that the RFC puts the canonical metadata URL at the *domain root* with the path appended — `https://myapp.example.com/.well-known/oauth-protected-resource/api` — not underneath your base path. Clients that construct the URL themselves (instead of reading the `WWW-Authenticate` header of a 401) will look there and never hit your app. To handle them, make sure your proxy forwards `/.well-known/oauth-protected-resource` and everything under it to the API unchanged. We accept the path-suffix form and serve the same document for it, so no rewriting is needed. Clients that follow the `WWW-Authenticate` pointer instead will find the copy underneath your base path without any proxy help.

# Streaming File Proxy with postFormData
When your API receives a file upload and needs to forward it to another service, you typically have to buffer the entire file in memory or write it to disk first. The `postFormData` helper avoids this by constructing a multipart/form-data request from streams, allowing you to pipe an incoming upload directly to a remote API with no intermediate storage.

For example, proxying an uploaded file to S3-compatible storage:
```javascript
import Server, { postFormData } from 'fastify-txstate'
const server = new Server()
server.app.post('/upload', async (req, res) => {
  const results = []
  for await (const part of req.parts()) {
    if (part.type === 'file') {
      // forward each file stream directly to S3 with no intermediate storage
      const resp = await postFormData(
        `https://s3.amazonaws.com/${BUCKET_NAME}`,
        [
          { name: 'key', value: `uploads/${part.filename}` },
          { name: 'Content-Type', value: part.mimetype },
          { name: 'file', value: part.file, filename: part.filename, filetype: part.mimetype }
        ],
        { Authorization: `AWS ${AWS_ACCESS_KEY}:${signature}` }
      )
      results.push({ filename: part.filename, status: resp.status })
    }
  }
  return results
})
```

Each field is either a text field (`{ name, value: string }`) or a file field (`{ name, value: ReadableStream | Readable, filename?, filetype?, filesize? }`). If all file fields include `filesize`, a `Content-Length` header is calculated automatically; otherwise the request is sent as chunked.

You can also pass custom headers as a third argument: `postFormData(url, fields, { Authorization: 'Bearer ...' })`.

# File Storage with FileSystemHandler
`FileSystemHandler` provides an opinionated way to stream uploaded files into the local filesystem, named by their SHA-256 checksum. Since identical files produce the same checksum, duplicates are automatically deduplicated — uploading the same file twice stores it only once.

Files are organized into a two-level directory structure based on the checksum (`ab/cd/ef01...`) to avoid overwhelming a single directory with too many entries.

```javascript
import Server, { FileSystemHandler } from 'fastify-txstate'
const storage = new FileSystemHandler({ tmpdir: '/files/tmp', permdir: '/files/storage' })
await storage.init() // ensures tmpdir and permdir exist

const server = new Server()
server.app.post('/upload', async (req, res) => {
  const results = []
  for await (const part of req.parts()) {
    if (part.type === 'file') {
      const { checksum, size } = await storage.put(part.file)
      // save the checksum in your database alongside whatever record it was uploaded against
    }
  }
})

server.app.get('/download/:checksum', async (req, res) => {
  const stream = storage.get(req.params.checksum)
  return res.send(stream)
})
```

The `put` method streams the file to a temporary location while computing its SHA-256 hash, then re-reads the file to verify it was written correctly before moving it to its permanent checksum-based path. It returns the `checksum` (base64url-encoded, to keep database columns short) and `size` in bytes. Files are named on disk by the hex form of the checksum, and every method accepts either form.

| Method | Description |
|--------|-------------|
| `init()` | Creates `tmpdir` and `permdir` if they don't exist and deletes tmp files left by a crash. Call this before using the handler. |
| `put(stream)` | Streams a `Readable` to storage. Returns `{ checksum, size }`. |
| `get(checksum, range?)` | Returns a `Readable` stream for the file. Pass `{ start, end }` to read only part of it, e.g. to answer an HTTP range request. Offsets are zero-based and inclusive like `fs.createReadStream`, so `{ start: 0, end: 9 }` is the first 10 bytes; leave out `end` to read to the end of the file. Clamp the range to the file's size before calling, since a local file returns an empty stream for an out-of-bounds range while S3 and Azure Blob return 416. |
| `remove(checksum)` | Deletes the file, and any folders that leaves empty. No-op if already gone. |
| `exists(checksum)` | Returns `true` if the file exists. |
| `fileSize(checksum)` | Returns the file size in bytes. |
| `cleanupTmp({ olderThanMs? })` | Deletes tmp files left behind by interrupted uploads that are older than `olderThanMs` (default 24 hours). `init()` already does this, but you can also call it periodically if your process runs for a long time. |
| `migrateLegacyFiles()` | Runs `migrateLegacyFile` on every legacy file in storage. Returns the number of files moved. |
| `checksums()` | Async iterator over the base64url checksum of every stored file, including legacy files that haven't been migrated. On a case-insensitive filesystem (e.g. Azure Files over SMB) the case of folder names can be lost, so legacy files are hashed to recover their checksum and skipped if their contents don't match their name. Hashing is skipped once the presence of both an `x/` and an `X/` folder proves the filesystem is case-sensitive. |
| `migrateLegacyFile(checksum)` | Moves a file stored by an older version under its base64url name to its hex location. Returns `false` if there was no legacy file. |

Both `tmpdir` and `permdir` default to `/files/tmp/` and `/files/storage/` respectively. A default instance is also exported as `fileHandler` if the defaults work for your setup.

The `FileHandler` interface is also exported, so you can write your own storage backend with the same API. The idea is that your application accepts a `FileHandler` as configuration rather than depending on a concrete implementation. In development or simple deployments you use `FileSystemHandler`; in production a different instance of the same service could provide an S3-backed implementation — the route handlers don't change. The `postFormData` helper is useful for building cloud implementations, since it can stream files to a remote API without buffering.

```javascript
import { FileSystemHandler, type FileHandler } from 'fastify-txstate'
import { S3FileHandler } from './s3filehandler.js'

const storage: FileHandler = process.env.FILE_STORAGE === 's3'
  ? new S3FileHandler({ bucket: process.env.S3_BUCKET })
  : new FileSystemHandler()
```

# Analytics
The `analyticsPlugin` registers a `POST /analytics` endpoint that accepts an array of interaction events from your frontend, enriches them with server-side context (user agent, IP, authentication, timestamp), and flushes them in batches to a storage backend every 5 seconds.

```javascript
import Server, { analyticsPlugin } from 'fastify-txstate'
const server = new Server()
server.app.register(analyticsPlugin, { appName: 'my-app' })
```

The client sends events shaped like:
```json
[{
  "eventType": "ActionPanel.svelte",
  "screen": "/pages/[id]",
  "action": "Edit Page",
  "target": "/sites/5/pages/12"
}]
```

`eventType`, `screen`, and `action` are required. `target` and `additionalProperties` are optional.

## Options
| Option | Description |
|--------|-------------|
| `appName` | **Required.** Identifies the application in stored events. |
| `analyticsClient` | An `AnalyticsClient` instance for storing events. See below for defaults. |
| `authorize` | Restricts access to the endpoint. Pass `true` to require any authenticated user, or a function `(req) => boolean` for custom logic. A failed check throws a 401. |

## Storage Clients
By default, the plugin picks a client automatically:

- If `ELASTICSEARCH_URL` is set, events are bulk-indexed into Elasticsearch using `ElasticAnalyticsClient`.
- Otherwise, in development (`NODE_ENV=development`), events are logged to the console.
- Otherwise, events are logged via the fastify logger (`LoggingAnalyticsClient`).

You can override this by passing your own `analyticsClient`. Extend the `AnalyticsClient` class and implement the `push` method:

```javascript
import { AnalyticsClient, type StoredInteractionEvent } from 'fastify-txstate'

class BigQueryAnalyticsClient extends AnalyticsClient {
  async push (events: StoredInteractionEvent[]) {
    // write events to BigQuery, ClickHouse, etc.
  }
}

server.app.register(analyticsPlugin, {
  appName: 'my-app',
  analyticsClient: new BigQueryAnalyticsClient()
})
```

### Elasticsearch Environment Variables
| Variable | Required | Description |
|----------|----------|-------------|
| `ELASTICSEARCH_URL` | Yes | Elasticsearch node URL. |
| `ELASTICSEARCH_USER` | No | Defaults to `elastic`. |
| `ELASTICSEARCH_PASS` | No | Elasticsearch password. |
| `ELASTICSEARCH_USEREVENTS_INDEX` | No | Index name. Defaults to `interaction-analytics`. |

## Audience Validation
Audience validation is a way to ensure that tokens you accept were generated with your API in mind. This helps when the token's claims include authorization like role memberships specific to your app. An attacker could register their own app with identical role names and use their token for your API, unless you specify your API as the only valid audience via `JWT_TRUSTED_AUDIENCES` (or per-issuer `audiences` in `JWT_TRUSTED_ISSUERS`).

fastify-txstate is somewhat opinionated about storing authorization information in your authentication tokens. It's generally not a good idea - you'll end up with people staying in roles until their token expires, and be vulnerable to attacks like this. Let the authentication layer identify the user, and let your API match the user's identity with any authorization roles. To this end, `FastifyTxStateAuthInfo` doesn't have any spec for authorization-related claims.

Audience validation only becomes necessary if you use the `extraClaims` option to pull authorization claims from the token into your `auth` object.

# AI Agent Skills
If you use AI coding agents (Claude Code, Cursor, Copilot, etc.) to help build your APIs, this repo includes skill files that teach them how to use fastify-txstate. Copy the ones relevant to your project into your agent configuration (e.g. `.claude/` or `.cursor/rules/`):

| Skill | Description |
|-------|-------------|
| [`server-basics.md`](skills/server-basics.md) | Teaches the agent how to set up the server's error handling, SSL, health checks, logging |
| [`validation.md`](skills/validation.md) | Teaches the agent how to create POST/PUT endpoints that cooperate with svelte-forms to show validation feedback to users. |
| [`authentication.md`](skills/authentication.md) | Teaches the agent how to configure authentication for the server. |
| [`file-handling.md`](skills/file-handling.md) | Teaches the agent how to use our tools for streaming files to disk or swappable backends |
| [`endpoint-schemas.md`](skills/endpoint-schemas.md) | Teaches the agent how to define route schemas for type inference, validation, and Swagger documentation |
| [`analytics.md`](skills/analytics.md) | Teaches the agent how to configure the server for interaction event tracking in Elasticsearch or a custom storage client |
