# Changelog

## 4.0.0

### Breaking Changes

- Upgraded to [Fastify 5](https://fastify.dev/docs/latest/Guides/Migration-Guide-V5/).
- ESM only. CJS is no longer supported.
- Removed `req.token` from `FastifyRequest`. Use `req.auth.token` instead.
- Removed the deprecated `FailedValidationError` class. Use `ValidationError` or `ValidationErrors` instead.
- `devLogger` and `prodLogger` are now `pino` instances instead of plain objects. Fastify 5 no longer accepts a logger instance via `logger` — use `loggerInstance` instead.
- `FileSystemHandler.remove()` now throws on errors other than `ENOENT` instead of silently logging a warning.
- Major dependency version bumps: `@elastic/elasticsearch` ^8 → ^9, `ua-parser-js` ^1 → ^2, `jose` ^5 dropped (^6 only), `@fastify/swagger` ^8 → ^9, `@fastify/swagger-ui` ^3 → ^5, `@fastify/type-provider-json-schema-to-ts` ^3 → ^5, `fastify-plugin` ^4 → ^5.
