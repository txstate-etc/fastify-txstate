# fastify-txstate: Authentication

Use this skill when adding authentication to an API built with fastify-txstate.

## How Authentication Works

Pass an `authenticate` function to the Server constructor. It runs as an `onRequest` hook on GET, POST, PUT, PATCH, DELETE (except `/health` and swagger endpoints). The return value is available at `req.auth`.

```javascript
import Server from 'fastify-txstate'
const server = new Server({
  authenticate: async (req) => {
    // return a FastifyTxStateAuthInfo object, or undefined if unauthenticated
    // throw to reject with 401
  }
})
```

`FastifyTxStateAuthInfo` requires at least `username`, `sessionId`, and `token`.

## OAuth / OIDC Authentication

`oauthAuthenticate` validates JWT tokens from any OAuth/OIDC provider. It auto-discovers the JWKS endpoint from the token's `iss` claim.

```javascript
import Server, { oauthAuthenticate } from 'fastify-txstate'
const server = new Server({
  authenticate: req => oauthAuthenticate(req, { authenticateAll: true })
})
```

### Required Environment Variables
| Variable | Required | Description |
|----------|----------|-------------|
| `OAUTH_TRUSTED_ISSUERS` | Yes | Comma-separated list of trusted issuer URLs |
| `OAUTH_TRUSTED_AUDIENCES` | No | Comma-separated accepted `aud` values. Only needed if using `extraClaims`. |
| `OAUTH_TRUSTED_CLIENTIDS` | No | Comma-separated accepted `client_id` values |
| `OAUTH_ISSUER_INTERNAL_URLS` | No | Map external to internal issuer URLs for split-horizon DNS. Format: `external=internal` |

### Options
| Option | Description |
|--------|-------------|
| `authenticateAll` | All requests require auth except `exceptRoutes` and `optionalRoutes` |
| `exceptRoutes` | `Set<string>` of routes that skip auth entirely |
| `optionalRoutes` | `Set<string>` of routes that populate `req.auth` if available but don't require it |
| `usingOAuthCookieRoutes` | Set true when using `registerOAuthCookieRoutes` with `authenticateAll` |
| `extraClaims` | `(payload) => ({...})` to pull extra JWT claims into auth object |

## Cookie-Based Sessions (Server-Side OAuth Flow)

For server-rendered apps or SPAs needing cookie sessions, `registerOAuthCookieRoutes` implements the full authorization code flow with PKCE (S256).

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

This registers three routes:
- `GET /.oauthRedirect?requestedUrl=...&scope=...&issuer=...` — redirects to the OAuth provider
- `GET /.oauthCallback` — exchanges the code for tokens, sets cookies, redirects to `requestedUrl`
- `GET /.oauthLogout` — clears cookies, redirects to provider's `end_session_endpoint` if available

The access token is available at `req.auth.accessToken` for provider API calls (Google Drive, MS Graph, etc.).

### Additional Environment Variables
| Variable | Required | Description |
|----------|----------|-------------|
| `OAUTH_CLIENT_ID` | Yes | OAuth client ID |
| `OAUTH_CLIENT_SECRET` | No | Some providers require it even with PKCE |
| `OAUTH_COOKIE_SECRET` | No | Encrypts refresh/access token cookies with AES-256-GCM |
| `OAUTH_COOKIE_NAME` | No | Session cookie name. Defaults to a random hex string |
| `PUBLIC_URL` | No | Base URL for the API, used for callback URIs |
| `UI_URL` | No | Base URL for the UI, used as default redirect after login/logout |

### Multiple Issuers

When `OAUTH_TRUSTED_ISSUERS` has multiple entries, provide a `loginPage` function:
```javascript
registerOAuthCookieRoutes(server.app, {
  loginPage: issuers => `<!DOCTYPE html>
    <html><body>
      <h1>Sign in with</h1>
      ${issuers.map(i => `<a href="${i.redirectHref}">${new URL(i.issuerUrl).hostname}</a>`).join('<br>')}
    </body></html>`
})
```

Clients can bypass selection by passing `issuer` directly in the query string.

## Client-Side Authentication (No Cookie Endpoints)

When the client handles the OAuth flow itself, it sends tokens via `Authorization: Bearer <token>`.

### Which token to send
The token **must be a JWT** (verified locally against JWKS):
- **Microsoft, Okta, Auth0, Keycloak**: send the access token (it's a JWT).
- **Google**: send the **ID token** (access tokens are opaque).
- **General rule**: if it has three base64url segments separated by dots, it's a JWT.

### Scopes
- All providers: `openid` is the minimum for an ID token.
- **Google**: `openid`, add `email`/`profile` for more claims.
- **Microsoft**: `openid`, `User.Read` for Graph, `api://{id}/.default` for custom APIs.

### Refresh tokens
- **Most providers** (Microsoft, Okta, Auth0, Keycloak): request `offline_access` scope.
- **Google**: pass `access_type=offline&prompt=consent` as query params. `offline_access` is ignored.
- **Apple, Cognito**: automatic based on app config.

### PKCE
Always use PKCE (S256) for the authorization code exchange, even if not required. Generate a `code_verifier`, send the `code_challenge` in the auth request, include `code_verifier` when exchanging.

## Audience Validation

Only necessary when using `extraClaims` to pull authorization claims from tokens. Set `OAUTH_TRUSTED_AUDIENCES` to ensure tokens were issued for your API specifically. Without this, an attacker could register their own app with identical role names and use those tokens against your API.

The library's opinion: don't store authorization in tokens. Let the auth layer identify the user, and let your API match identity to roles. This avoids stale-role and cross-audience attacks.
