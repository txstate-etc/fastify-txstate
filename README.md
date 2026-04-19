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

We provide two built-in implementations: `unifiedAuthenticate` for TxState's Unified Auth service, and `oauthAuthenticate` for standard OAuth/OIDC providers. You can also write your own for any authentication scheme — API keys, session lookups, custom JWTs, etc.

# OAuth Authentication
The `oauthAuthenticate` function we provide validates JWT tokens (access tokens or ID tokens) from any OAuth/OIDC provider. It uses the token's `iss` claim to auto-discover the provider's JWKS endpoint via `.well-known/openid-configuration` or `.well-known/oauth-authorization-server`, then verifies the signature locally.

For providers like Google that issue opaque access tokens, have the client send the ID token instead — it's a standard JWT that proves the user's identity without requiring a round-trip to the provider on every request.
```javascript
import Server, { oauthAuthenticate } from 'fastify-txstate'
const server = new Server({
  authenticate: req => oauthAuthenticate(req, { authenticateAll: true })
})
```
## Environment Variables
| Variable | Required | Description |
|----------|----------|-------------|
| `OAUTH_TRUSTED_ISSUERS` | Yes | Comma-separated list of trusted issuer URLs (e.g. `https://accounts.google.com,https://login.microsoftonline.com/{tenant}/v2.0`) |
| `OAUTH_TRUSTED_AUDIENCES` | No | Comma-separated list of accepted `aud` values. See [Audience Validation](#audience-validation) for details. |
| `OAUTH_TRUSTED_CLIENTIDS` | No | Comma-separated list of accepted `client_id` values. |
| `OAUTH_ISSUER_INTERNAL_URLS` | No | Map external issuer URLs to internal URLs for docker-compose / split-horizon DNS scenarios where the browser reaches the provider on one hostname but the resource provider reaches it on another. Format: `external=internal` (e.g. `https://auth.example.com=http://keycloak:8080`). Rewrites server-to-server requests (discovery, JWKS, token exchange) but not browser redirects. |

## Options
| Option | Description |
|--------|-------------|
| `authenticateAll` | If true, all requests require authentication except routes in `exceptRoutes` or `optionalRoutes`. |
| `exceptRoutes` | `Set<string>` of route URLs that skip authentication entirely and do not receive an auth object. |
| `optionalRoutes` | `Set<string>` of route URLs that do not require authentication but populate `req.auth` if a session is available. |
| `usingOAuthCookieRoutes` | Set to true if you are using `registerOAuthCookieRoutes` with `authenticateAll`. Automatically excludes cookie endpoints from authentication requirements. |
| `extraClaims` | A function that receives the full JWT payload and returns extra properties to merge into the auth object (e.g. `payload => ({ roles: payload.roles })`). If you use this, you should also set `OAUTH_TRUSTED_AUDIENCES`. See [Audience Validation](#audience-validation). |

## Cookie Endpoints
For server-rendered applications or SPAs that need cookie-based sessions, `registerOAuthCookieRoutes` implements the full OAuth authorization code flow with PKCE (S256), storing the ID token in an HttpOnly cookie. The access token and refresh token are stored in separate cookies (optionally encrypted via `OAUTH_COOKIE_SECRET`). Expired ID tokens are transparently refreshed using the refresh token cookie.
```javascript
import Server, { oauthAuthenticate, registerOAuthCookieRoutes } from 'fastify-txstate'
const server = new Server({
  authenticate: req => oauthAuthenticate(req, {
    authenticateAll: true,
    usingOAuthCookieRoutes: true
  })
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
When `OAUTH_TRUSTED_ISSUERS` contains multiple issuers, you can provide a `loginPage` function to let the user choose which provider to sign in with. The function receives an array of `{ issuerUrl, redirectHref }` and should return an HTML string.
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
| `OAUTH_CLIENT_ID` | Yes | OAuth client ID for the authorization code flow. |
| `OAUTH_CLIENT_SECRET` | No | OAuth client secret. PKCE secures the code exchange, but some providers require a secret even with PKCE. |
| `OAUTH_COOKIE_SECRET` | No | If set, the refresh token and access token cookies are encrypted with AES-256-GCM. If not, they are stored as plaintext (still HttpOnly and Secure). |
| `OAUTH_COOKIE_NAME` | No | Name for the session cookie. Defaults to a random hex string. |
| `PUBLIC_URL` | No | Base URL for the API, used to generate callback URIs (e.g. `https://myapp.example.com/api`). Derived from the request hostname if not set. |
| `UI_URL` | No | Base URL for the UI (e.g. `https://myapp.example.com`). Used as the default redirect destination after login/logout. If not set, guessed by removing the last path segment from `PUBLIC_URL` or the request URL. |

### Routes
- **`GET /.oauthRedirect?requestedUrl=...&scope=...&issuer=...`** — Redirects to the OAuth provider's login page. `requestedUrl` is required and specifies where to redirect after login. `scope` is optional and defaults to `openid offline_access`. `issuer` is optional and selects which trusted issuer to use; if omitted with multiple issuers and a `loginPage` configured, a selection page is shown.
- **`GET /.oauthCallback`** — Handles the provider's redirect. Exchanges the authorization code for tokens (using PKCE), sets the ID token, access token, and refresh token as cookies, and redirects to the original `requestedUrl`. If no ID token is returned, falls back to the access token if it is a JWT.
- **`GET /.oauthLogout`** — Clears all OAuth cookies and redirects to the provider's `end_session_endpoint` if available, with the ID token as a hint for single sign-out.

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

Files are organized into a two-level directory structure based on the checksum (`a/b/cdef...`) to avoid overwhelming a single directory with too many entries.

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

The `put` method streams the file to a temporary location while computing its SHA-256 hash, then re-reads the file to verify it was written correctly before moving it to its permanent checksum-based path. It returns the `checksum` (base64url-encoded) and `size` in bytes.

| Method | Description |
|--------|-------------|
| `init()` | Creates `tmpdir` and `permdir` if they don't exist. Call this before using the handler. |
| `put(stream)` | Streams a `Readable` to storage. Returns `{ checksum, size }`. |
| `get(checksum)` | Returns a `Readable` stream for the file. |
| `remove(checksum)` | Deletes the file. No-op if already gone. |
| `exists(checksum)` | Returns `true` if the file exists. |
| `fileSize(checksum)` | Returns the file size in bytes. |

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
| `authorize` | A function `(req) => boolean` to restrict access to the endpoint. If it returns false, a 401 is thrown. |

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
Audience validation is a way to ensure that tokens you accept were generated with your API in mind. This helps when the token's claims include authorization like role memberships specific to your app. An attacker could register their own app with identical role names and use their token for your API, unless you specify your API as the only valid audience with OAUTH_TRUSTED_AUDIENCES.

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
| [`analytics.md`](skills/analytics.md) | Teaches the agent how to configure the server for interaction event tracking in Elasticsearch or a custom storage client |
