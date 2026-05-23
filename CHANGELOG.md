# Changelog

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
