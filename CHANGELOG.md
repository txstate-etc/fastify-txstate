# Changelog

## 4.4.0 (in progress)

### New Features

- Built-in OpenTelemetry export of metrics, logs and traces, with no SDK to install. Set `OTEL_EXPORTER_OTLP_ENDPOINT` and `Server` starts sending to it. Leave it unset and everything below is a no-op, so instrumentation can stay in your code everywhere.
- What you get automatically:
  - **Traces**: a span for every request (except `/health` and `/analytics`), continuing the caller's `traceparent`, with child spans for outgoing `fetch`/`node:http` calls, mysql2, oracle-async, postgres.js (4.0+) and `node:sqlite` (Node 26+) queries, and mongoose (9.7+) operations. Outgoing requests carry a `traceparent` so the next service joins the same trace.
  - **Metrics**: `http.server.request.duration`, per the HTTP semantic conventions.
  - **Logs**: every error that ends in a 5xx, as an `http.server.request.exception` log record tied to its trace.
  - Every request's log lines get `trace_id` and `span_id`.
- New exports for reporting your own telemetry, with the same names and shapes as `@opentelemetry/api`, so the upstream docs apply:
  - `metrics.getMeter(name)` for every instrument the API has: counters, up-down counters, gauges, histograms, and the observable kinds.
  - `logs.getLogger(name)` for structured log records, stamped with the current trace.
  - `trace.getTracer(name)` for spans of your own, like one around an LLM call with its token counts.
  - `traceJob(name, task)` runs a background task, like a cron job, as its own trace. Without it, a job's outgoing calls and queries go untraced. A failure is reported and then rethrown.
  - `recordError(error)` for errors you catch yourself but want someone to see. It records telemetry only, so log the error as usual too. Errors that turn into a 5xx are already recorded.
- `analyticsPlugin` sends interaction events as OTLP log records when logs export is enabled, and now flushes its queue when the server closes instead of losing the last few seconds of events on every deploy.

### Notes

- Errors reaching the error handler are now logged at `error` level when the response is a 5xx and `warn` otherwise, instead of always `warn`.
- New dependency on `@opentelemetry/api` (the API package only, no SDK). We register as its global tracer, meter and logger providers, so apps and libraries can record through the API itself, and our `trace`, `metrics` and `logs` exports are just shortcuts to the same thing. If another SDK registered first, it wins and we warn.

### OpenTelemetry details

- We read the official SDK's environment variables: `OTEL_EXPORTER_OTLP_ENDPOINT` and its per-signal `_ENDPOINT` and `_HEADERS` variants, `OTEL_SERVICE_NAME`, `OTEL_RESOURCE_ATTRIBUTES`, `OTEL_SDK_DISABLED`, `OTEL_METRIC_EXPORT_INTERVAL` (default 60s), `OTEL_{TRACES,METRICS,LOGS}_EXPORTER` (`otlp` or `none`), and `OTEL_TRACES_SAMPLER`/`_ARG` (all but the remote samplers).
- `OTLP_PASSWORD` sends basic auth with the service name as the username. `NODE_ENV` becomes `deployment.environment.name` and `CI_GIT_VERSION` becomes `service.version`, unless `OTEL_RESOURCE_ATTRIBUTES` sets them.
- A failed export is retried for up to 10 seconds, then dropped, and only the first failure in a streak is logged. Metrics recover on the next export, but a dropped log or span batch is gone.
- Each metric keeps at most 2000 attribute sets; past that, new ones are lumped under `otel.metric.overflow` with a warning, which almost always means an id or full URL ended up in an attribute.
- `token` and `unifiedJwt` query parameters are redacted from recorded URLs, mysql2 `query()` and `node:sqlite` text has its literals replaced with `?`, and mongoose filters and documents are never recorded.
- `startTelemetry()`, `telemetryEnabled(signal)` and `flushTelemetry()` are exported for using any of this outside `Server`, e.g. in a standalone worker script. `OtlpAnalyticsClient` is exported too.

## 4.3.4

### Fixes

- `FileSystemHandler.remove()` and `migrateLegacyFile()` now also delete the folders they leave empty, so storage doesn't accumulate thousands of empty folders over time, and the old base64url folders disappear as their files are migrated.

## 4.3.3

### Fixes

- `FileSystemHandler.init()` now deletes tmp files more than a day old, left behind when the process died mid-upload. If you want to clean them up more often, call the new `cleanupTmp()` periodically.

## 4.3.2

### Notes

- `FileSystemHandler` now uses two hex characters per folder level (`ab/cd/ef01...`) instead of one (`a/b/cdef...`), so storage spreads across 65,536 folders instead of 256 and no folder gets crowded even with tens of millions of files. This also keeps the hex folders from ever sharing a name with the single-character folders of the old base64url layout. Nobody had installed 4.3.0 or 4.3.1 yet, so there's nothing to migrate. Files from before 4.3.0 are still found and migrated as described under 4.3.0.

## 4.3.1

### New Features

- `FileHandler.get()` takes an optional `{ start, end }` byte range, for serving HTTP range requests (video seeking, resumed downloads). The offsets are inclusive like `fs.createReadStream`, which is also what the S3 and Azure Blob `Range` headers expect, so a cloud implementation can pass them straight through as `bytes=start-end`. A custom `FileHandler` written before this will still type-check, because TypeScript lets a function ignore trailing parameters, but it will silently send the whole file when asked for a range, so update it to honor the new parameter.

## 4.3.0

### New Features

- `FileSystemHandler` now names files on disk by the hex form of their SHA-256 checksum instead of base64url. Base64url mixes upper and lower case, and a case-insensitive filesystem like Azure Files over SMB can't tell `a/` from `A/`. `put()` still returns the shorter base64url checksum for your database, and every method accepts either form.
- Files stored by older versions keep working without any action on your part: `get`, `exists`, `fileSize`, and `remove` fall back to the old base64url location when a file isn't at its hex location yet.
- New `migrateLegacyFiles()` moves every file still stored under its base64url name to its hex location and returns how many it moved. It's safe to re-run, safe to interrupt, and safe to run on more than one server at once. If you'd rather drive it from your database, `migrateLegacyFile(checksum)` does the same for one file.
- New `checksums()` is an async iterator over the base64url checksum of every stored file, migrated or not. On a case-insensitive filesystem the folder names don't reliably record the case of the checksum, so each unmigrated file has to be read and hashed to recover its true checksum, and any file whose contents don't match its name is skipped. Once it sees both an `x/` and an `X/` folder, it knows the filesystem is case-sensitive and trusts the names instead. That hashing is a one-time cost that goes away once everything is migrated.

## 4.2.1

### Fixes

- Our `onSend` hooks are now registered callback-style instead of as async functions. An async `onSend` hook adds a microtask to fastify's send pipeline, and fastify decides whether an async route handler needs an automatic send by checking `reply.sent` when the handler's promise resolves — but `reply.sent` only becomes true once the response has fully ended, so a handler that calls `res.send()` and resolves undefined could win the race against its own send and trigger a second one. For buffered payloads the second send was swallowed, with a `Reply was already sent` warning logged on every request; for streamed payloads it ended the raw response while the stream was still piping, destroying the socket so clients saw `TypeError: fetch failed`. The `WWW-Authenticate` hook added in 4.1.0 widened the window enough to hit every async handler that uses the `res.send()`-without-return pattern. Note that the underlying race is fastify's and still exists: if your app registers its own async `onSend` hook, protect any handler that sends a stream by ending it with `return res`.

## 4.2.0

### New Features

- OAuth issuers that advertise a token introspection endpoint ([RFC 7662](https://www.rfc-editor.org/rfc/rfc7662)) in their discovery document now get the same treatment unified-auth gets from its `/validateToken` poll: once a session token is more than 5 minutes old, we periodically ask the provider whether it is still active, so revoked tokens and deactivated users stop working within minutes instead of at token expiration. RFC 7662 requires providers to authorize introspection callers, so set the new `OAUTH_INTROSPECT_TOKEN` env var to a service token the provider will accept as a Bearer credential. If the provider rejects our credentials, the check is disabled for that endpoint until restart and we behave as though no introspection endpoint was advertised.

### Fixes

- Registering a route with a `schema.body` but no `schema.response` crashed the server at boot with a `TypeError` from deep inside fastify (`Cannot read properties of undefined (reading 'isFluentSchema')`). The hook that adds our default 400/422 response schemas was accidentally creating the response map as a 400-element array instead of an object.
- That same hook was overwriting an explicitly declared `response.400` with our ValidatedResponse schema, so a route that needs to control its own 400 body (e.g. an OAuth token endpoint returning RFC 6749's `{"error": ...}` object) would fail output serialization and send a 500 instead. Now we only fill in 400/422 when the route didn't declare its own.

## 4.1.0

### New Features

- The server now answers `/.well-known/oauth-protected-resource` with an OAuth 2.0 Protected Resource Metadata document ([RFC 9728](https://www.rfc-editor.org/rfc/rfc9728)), listing the trusted OAuth issuers as `authorization_servers` and any registered cookie login/logout routes as the extension fields `cookie_login_uri` and `cookie_logout_uri`, so first-party SPAs can discover the cookie session flow with zero client-side configuration. The route is registered at `start()`, only when `jwtAuthenticate` has been initialized and there is something to advertise, and only if the app hasn't declared the route itself. The RFC's path-suffix form (`/.well-known/oauth-protected-resource/api`) is accepted too, for APIs reverse-proxied under a base path. Extra metadata fields (e.g. `scopes_supported`, `resource_name`) can be passed via the new `protectedResourceMetadata` option on `jwtAuthenticate`, and `protectedResourceMetadata: false` disables the feature.
- While the metadata route is being served, 401 responses include a `WWW-Authenticate: Bearer resource_metadata="..."` header pointing at it, per RFC 9728 section 5.1, unless the response already set one.
- `postFormData` now accepts an async iterable of fields in addition to an array. This is for proxying an incoming multipart request through to another server: `@fastify/multipart` will not yield the next part until the current part's file stream has been consumed, so collecting the parts into an array before posting hangs the request forever. With an async iterable, `postFormData` pulls each field only after the previous one has been fully sent, which is exactly the order the parts iterator needs — files of any size flow through without being buffered. Note that this mode cannot set a `Content-Length` header; the request goes out with chunked transfer encoding. If you know all of your fields up front, keep using an array with `filesize` set on each file field — file contents are streamed either way.
- New `formDataFieldsFromParts` helper converts the parts iterator from `@fastify/multipart`'s `request.parts()` into the async iterable that `postFormData` accepts, so proxying an upload is one line: `await postFormData(url, formDataFieldsFromParts(req.parts()))`. It is typed structurally, so this library still has no dependency on `@fastify/multipart`.
- New `formDataFilesFromParts` helper does the same but forwards only the files, for when the request's text fields were meant for your server and the destination only needs the upload itself.

### Fixes

- `postFormData` computed a `Content-Length` that omitted the closing boundary whenever every field had a known size (an all-text form, or `filesize` provided on every file field). undici refuses to send a body that disagrees with its `Content-Length` header, so those requests failed with `UND_ERR_REQ_CONTENT_LENGTH_MISMATCH`.
- Fixed a race in `postFormData`'s body stream that could permanently stall the request partway through a larger upload. Small payloads usually won the race, which is why our tests never caught it.

### Notes

- `jwtAuthenticate()` now reads its trust configuration from the environment when the factory is called instead of on the first request, so a malformed `JWT_TRUSTED_ISSUERS` fails at startup instead of at first login.

## 4.0.0

### Breaking Changes

- Upgraded to [Fastify 5](https://fastify.dev/docs/latest/Guides/Migration-Guide-V5/).
- ESM only. CJS is no longer supported.
- Removed `req.token` from `FastifyRequest`. Use `req.auth.token` instead.
- Removed the deprecated `FailedValidationError` class. Use `ValidationError` or `ValidationErrors` instead.
- `devLogger` and `prodLogger` are now `pino` instances instead of plain objects. Fastify 5 no longer accepts a logger instance via `logger` — use `loggerInstance` instead.
- `FileSystemHandler.remove()` now throws on errors other than `ENOENT` instead of silently logging a warning.
- `IssuerConfigRaw` has been removed. Use `JwtIssuerConfigRaw` instead. Its shape is a superset of the old type (adds optional `type`, `internalUrl`, `audiences`, `clientIds`), so existing `JWT_TRUSTED_ISSUERS` env values continue to work at runtime — only the TypeScript import name has changed.
- `/.uaService` and `/.uaRedirect` now validate the `requestedUrl` query parameter against the configured origin checker (`validOrigins` / `validOriginHosts` / `validOriginSuffixes`). A `requestedUrl` whose origin is not allowed now returns 403 instead of being followed.
- Major dependency version bumps: `@elastic/elasticsearch` ^8 → ^9, `ua-parser-js` ^1 → ^2, `jose` ^5 dropped (^6 only), `@fastify/swagger` ^8 → ^9, `@fastify/swagger-ui` ^3 → ^5, `@fastify/type-provider-json-schema-to-ts` ^3 → ^5, `fastify-plugin` ^4 → ^5.

### Deprecations

- `unifiedAuthenticate` is deprecated in favor of `jwtAuthenticate`, which handles unified-auth, JWKS, OAuth/OIDC, public-key, and symmetric-secret issuers from a single entry point driven by `JWT_TRUSTED_ISSUERS`. Note the new (easier) shape: `jwtAuthenticate` is now a factory that takes options up front and returns the authenticator (`authenticate: jwtAuthenticate({ authenticateAll: true })`). The old `unifiedAuthenticate(req, options?)` signature is preserved for the deprecated function.
- `requireCookieAuth` has been renamed to `requireCookieAuthUa`. The old name is kept as a deprecated alias and will be removed in a future major version.
- environment variable `UA_CLIENTID` is deprecated in favor of new `UA_COOKIE_CLIENTID` which makes its purpose more clear and distinct from `JWT_TRUSTED_CLIENTIDS`.

### Notes

- `registerOAuthCookieRoutes` and `registerUaCookieRoutes` now automatically exclude their callback/redirect routes from authentication and mark their logout routes as optional, so you no longer have to tell `jwtAuthenticate` about them.
