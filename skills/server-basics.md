# fastify-txstate: Server Setup & Configuration

Use this skill when creating or configuring an HTTP API server with fastify-txstate.

## Creating a Server

```javascript
import Server from 'fastify-txstate'
const server = new Server()
server.app.get('/yourpath', async (req, res) => {
  return { hello: 'world' }
})
server.start().then(() => console.log('started!'))
```

- Pass any valid fastify config to `new Server({ ... })`.
- `server.app` is the raw fastify instance — use it for routes, plugins, decorators, etc.

## Error Handling

Throw `HttpError` for simple HTTP errors:
```javascript
import { HttpError } from 'fastify-txstate'
throw new HttpError(400, 'Please provide an id.')
throw new HttpError(401) // uses default message: "Authentication is required."
```

For input validation errors, see the **validation** skill.

For custom error handling, use `server.addErrorHandler`. Call `res.send()` to signal the error is handled; otherwise default handling continues:
```javascript
server.addErrorHandler(async (err, req, res) => {
  if (err instanceof MyCustomErrorClass) {
    res.status(500).send('You done messed up.')
  }
})
```

## SSL

SSL/HTTP2 is automatic when `/securekeys/private.key` and `/securekeys/cert.pem` exist:
- No custom port + no SSL: port 80
- No custom port + SSL: port 443, with HTTP-to-HTTPS redirect on port 80
- Custom port via `server.start(8080)` or `PORT` env var: that port expects HTTPS if certs are present

## Health Checks

`/health` is registered automatically. Control it with:
- `server.setUnhealthy('message')` / `server.setHealthy()`
- `LOAD_BALANCE_TIMEOUT` env var (seconds): on SIGINT/SIGTERM, `/health` returns 503 for this duration while other requests continue, then the process exits.

## Origin Checking (XSRF Protection)

Requests with an `Origin` header that doesn't match the request hostname are rejected automatically (HTTP 403). When an origin passes, CORS headers are set automatically.

There are several ways to allow additional origins, each available as a constructor config option, an environment variable, and a runtime setter:

| Config | Env Var | Runtime | Match behavior |
|--------|---------|---------|----------------|
| `validOrigins` | `VALID_ORIGINS` | `server.setValidOrigins(origins)` | Exact origin match (scheme + host + port, e.g. `https://app.example.com`) |
| `validOriginHosts` | `VALID_ORIGIN_HOSTS` | `server.setValidOriginHosts(hosts)` | Hostname match, ignoring scheme/port (e.g. `app.example.com`) |
| `validOriginSuffixes` | `VALID_ORIGIN_SUFFIXES` | `server.setValidOriginSuffixes(suffixes)` | Domain suffix match — allows any subdomain (e.g. `example.com` allows `foo.example.com`, `bar.baz.example.com`) |
| `checkOrigin` | — | — | Custom function `(req) => boolean` for arbitrary logic. Runs after the other checks; return true to allow. |

Env vars accept comma-separated lists. Config options accept string arrays. All methods are additive — origins are allowed if they pass any check.

- Disable entirely: `skipOriginCheck` config or `SKIP_ORIGIN_CHECK` env var.
- In development (`NODE_ENV=development`), `Origin: null` is allowed (common with `file://` and redirects).

## Reverse Proxy

Behind a reverse proxy, set `trustProxy: true` in config or `TRUST_PROXY` env var (`true`/`1` = boolean true, anything else passed as string).

## Logging

- Development (`NODE_ENV=development`): brief, non-JSON output.
- Production: structured JSON with traceparent, URL in both request and response log entries.
- Custom logger: pass a pino instance via `loggerInstance` in the constructor.
- `devLogger` and `prodLogger` are exported if you want to extend them.
- Add data to `reply.extraLogInfo` in a route handler and it will appear in the production access log automatically.
