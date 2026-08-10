# Changelog

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
