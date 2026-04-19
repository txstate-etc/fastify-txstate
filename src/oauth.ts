import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto'
import type { FastifyRequest } from 'fastify'
import { createRemoteJWKSet, decodeJwt, jwtVerify } from 'jose'
import { Cache, isBlank, isNotBlank, htmlEncode } from 'txstate-utils'
import { apiBaseUrl, uiBaseUrl, type FastifyTxStateAuthInfo, type FastifyInstanceTyped, type IssuerConfig } from './index.ts'

interface OAuthDiscovery {
  issuer: string
  jwks_uri: string
  authorization_endpoint?: string
  token_endpoint?: string
  userinfo_endpoint?: string
  end_session_endpoint?: string
}

interface TokenResponse {
  id_token?: string
  access_token?: string
  refresh_token?: string
  token_type?: string
  expires_in?: number
  scope?: string
}

declare module 'fastify' {
  interface FastifyRequest {
    pendingOAuthCookies?: string[]
  }
}

let hasInit = false
const trustedIssuers = new Set<string>()
const trustedAudiences = new Set<string>()
const trustedClients = new Set<string>()
const issuerInternalUrls = new Map<string, string>()

/** Rewrite a URL for server-to-server requests. Not for browser-facing URLs. */
function toInternalUrl (url: string): string {
  for (const [external, internal] of issuerInternalUrls) {
    if (url.startsWith(external)) return internal + url.slice(external.length)
  }
  return url
}

const oauthCookieName = process.env.OAUTH_COOKIE_NAME ?? randomBytes(16).toString('hex')
const oauthCookieNameRegex = new RegExp(`${oauthCookieName}=([^;]+)`, 'v')
const refreshCookieName = oauthCookieName + '_rt'
const refreshCookieRegex = new RegExp(`${refreshCookieName}=([^;]+)`, 'v')
const accessTokenCookieName = oauthCookieName + '_at'
const accessTokenCookieRegex = new RegExp(`${accessTokenCookieName}=([^;]+)`, 'v')

let cookieEncryptionKey: Buffer | undefined

function wrapRefreshToken (token: string): string {
  if (!cookieEncryptionKey) return token
  const iv = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', cookieEncryptionKey, iv)
  const encrypted = Buffer.concat([cipher.update(token, 'utf8'), cipher.final()])
  const tag = cipher.getAuthTag()
  return Buffer.concat([iv, tag, encrypted]).toString('base64url')
}

function unwrapRefreshToken (value: string): string | undefined {
  if (!cookieEncryptionKey) return value
  try {
    const data = Buffer.from(value, 'base64url')
    const iv = data.subarray(0, 12)
    const tag = data.subarray(12, 28)
    const encrypted = data.subarray(28)
    const decipher = createDecipheriv('aes-256-gcm', cookieEncryptionKey, iv)
    decipher.setAuthTag(tag)
    return decipher.update(encrypted, undefined, 'utf8') + decipher.final('utf8')
  } catch {
    return undefined
  }
}

const discoveryCache = new Cache(async (issuerUrl: string) => {
  const base = issuerUrl.endsWith('/') ? issuerUrl : issuerUrl + '/'
  // try OpenID Connect discovery first, then OAuth 2.0 Authorization Server Metadata
  for (const path of ['.well-known/openid-configuration', '.well-known/oauth-authorization-server']) {
    try {
      const resp = await fetch(new URL(path, toInternalUrl(base)))
      if (resp.ok) {
        const doc = await resp.json() as OAuthDiscovery
        if (isNotBlank(doc.jwks_uri)) return doc
      }
    } catch { /* try next */ }
  }
  return undefined
}, { freshseconds: 3600 })

const jwkSetCache = new Cache(
  async (jwksUri: string) => createRemoteJWKSet(new URL(toInternalUrl(jwksUri))),
  { freshseconds: 3600 }
)

function checkAudience (aud: string | string[] | undefined, req: FastifyRequest) {
  if (!trustedAudiences.size) return true
  const audiences = Array.isArray(aud) ? aud : [aud]
  if (!audiences.some(a => trustedAudiences.has(a!))) {
    req.log.warn(`Received token with untrusted audience: ${String(aud)}`)
    return false
  }
  return true
}

function checkClientId (clientId: string | undefined, req: FastifyRequest) {
  if (!trustedClients.size) return true
  if (!trustedClients.has(clientId!)) {
    req.log.warn(`Received token with untrusted client_id: ${String(clientId)}.`)
    return false
  }
  return true
}

const tokenCache = new Cache(async (token: string, req: FastifyRequest) => {
  const claims = decodeJwt(token)
  if (!claims.iss) {
    req.log.warn('Received OAuth token without an issuer claim.')
    return undefined
  }

  if (!trustedIssuers.has(claims.iss)) {
    req.log.warn(`Received token with untrusted issuer: ${claims.iss}`)
    return undefined
  }

  try {
    const discovery = await discoveryCache.get(claims.iss)
    if (!discovery?.jwks_uri) return undefined
    const jwkSet = await jwkSetCache.get(discovery.jwks_uri)
    const { payload } = await jwtVerify(token, jwkSet)

    if (!checkAudience(payload.aud, req)) return undefined
    if (!checkClientId(payload.client_id as string | undefined, req)) return undefined

    return { payload, discovery }
  } catch (e: unknown) {
    const code = (e as { code?: string }).code
    if (code !== 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED' && code !== 'ERR_JWT_EXPIRED') req.log.error(e)
    return undefined
  }
}, { freshseconds: 3600 })

function init () {
  hasInit = true
  const issuers = process.env.OAUTH_TRUSTED_ISSUERS?.split(',').filter(isNotBlank).map(s => s.trim()) ?? []
  if (!issuers.length) throw new Error('OAUTH_TRUSTED_ISSUERS environment variable must be set when using oauthAuthenticate. Provide a comma-separated list of trusted issuer URLs.')
  for (const issuer of issuers) {
    trustedIssuers.add(issuer)
  }
  // Note: some providers (e.g. Google) set `aud` on ID tokens to the OAuth client ID
  // rather than a resource server URL. If accepting ID tokens from such providers, set
  // OAUTH_TRUSTED_AUDIENCES to your OAuth client ID.
  for (const audience of (process.env.OAUTH_TRUSTED_AUDIENCES?.split(',').filter(isNotBlank).map(s => s.trim()) ?? [])) {
    trustedAudiences.add(audience)
  }
  for (const clientId of (process.env.OAUTH_TRUSTED_CLIENTIDS?.split(',').filter(isNotBlank).map(s => s.trim()) ?? [])) {
    trustedClients.add(clientId)
  }
  // Map external issuer URLs to internal URLs for split-horizon DNS (e.g. communication inside a docker network)
  for (const pair of (process.env.OAUTH_ISSUER_INTERNAL_URLS?.split(',').filter(isNotBlank).map(s => s.trim()) ?? [])) {
    const eq = pair.indexOf('=')
    if (eq > 0) issuerInternalUrls.set(pair.slice(0, eq), pair.slice(eq + 1))
  }
  if (isNotBlank(process.env.OAUTH_COOKIE_SECRET)) {
    cookieEncryptionKey = createHash('sha256').update(process.env.OAUTH_COOKIE_SECRET).digest()
  }
}

function tokenFromReq (req?: FastifyRequest): string | undefined {
  const m = req?.headers.authorization?.match(/^bearer (.*)$/iv)
  if (m != null) return m[1]

  const m2 = req?.headers.cookie?.match(oauthCookieNameRegex)
  if (m2 != null) return m2[1]
}

function refreshTokenFromReq (req: FastifyRequest): string | undefined {
  const m = req.headers.cookie?.match(refreshCookieRegex)
  if (!m) return undefined
  return unwrapRefreshToken(m[1])
}

function accessTokenFromReq (req: FastifyRequest): string | undefined {
  const m = req.headers.cookie?.match(accessTokenCookieRegex)
  if (!m) return undefined
  return unwrapRefreshToken(m[1])
}

interface TokenCacheResult {
  token: string
  payload: Record<string, unknown>
  discovery: OAuthDiscovery
}

async function tryRefresh (req: FastifyRequest, expiredIssuer?: string): Promise<TokenCacheResult | undefined> {
  const refreshToken = refreshTokenFromReq(req)
  if (!refreshToken) return undefined

  const clientId = process.env.OAUTH_CLIENT_ID
  if (!clientId) return undefined

  const issuerUrl = (expiredIssuer && trustedIssuers.has(expiredIssuer)) ? expiredIssuer : [...trustedIssuers][0]
  const discovery = await discoveryCache.get(issuerUrl)
  if (!discovery?.token_endpoint) return undefined

  const body: Record<string, string> = {
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
    client_id: clientId
  }
  const clientSecret = process.env.OAUTH_CLIENT_SECRET
  if (clientSecret) body.client_secret = clientSecret

  try {
    const tokenResp = await fetch(toInternalUrl(discovery.token_endpoint), {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(body)
    })
    if (!tokenResp.ok) return undefined

    const tokens = await tokenResp.json() as TokenResponse
    if (!tokens.id_token) return undefined

    // queue new cookies to be set on the response
    req.pendingOAuthCookies = [
      `${oauthCookieName}=${tokens.id_token}; Path=/; Secure; HttpOnly; SameSite=Lax`
    ]
    if (tokens.access_token) {
      req.pendingOAuthCookies.push(
        `${accessTokenCookieName}=${wrapRefreshToken(tokens.access_token)}; Path=/; Secure; HttpOnly; SameSite=Lax`
      )
    }
    // some providers rotate the refresh token on each use
    if (tokens.refresh_token) {
      req.pendingOAuthCookies.push(
        `${refreshCookieName}=${wrapRefreshToken(tokens.refresh_token)}; Path=/; Secure; HttpOnly; SameSite=Lax`
      )
    }

    const result = await tokenCache.get(tokens.id_token, req)
    if (!result) return undefined

    if (result.payload.exp && result.payload.exp * 1000 <= Date.now()) return undefined

    return { token: tokens.id_token, payload: result.payload, discovery }
  } catch (e: unknown) {
    req.log.error(e)
    return undefined
  }
}

function buildAuthInfo (token: string, payload: Record<string, unknown>, discovery: OAuthDiscovery, extraClaims?: (payload: Record<string, unknown>) => Record<string, unknown>): FastifyTxStateAuthInfo {
  const issuerConf: IssuerConfig = {
    iss: payload.iss as string,
    url: payload.iss as string,
    logoutUrl: isNotBlank(discovery.end_session_endpoint) ? new URL(discovery.end_session_endpoint) : undefined
  }

  return {
    ...extraClaims?.(payload),
    token,
    issuerConfig: issuerConf,
    username: payload.sub as string,
    sessionId: (payload.sub as string) + '-' + String(payload.iat),
    sessionCreatedAt: payload.iat ? new Date((payload.iat as number) * 1000) : undefined,
    clientId: payload.client_id as string | undefined,
    impersonatedBy: (payload.act as { sub?: string } | undefined)?.sub,
    scope: payload.scope as string | undefined
  }
}

async function oauthAuthenticateInternal (req: FastifyRequest, extraClaims?: (payload: Record<string, unknown>) => Record<string, unknown>): Promise<FastifyTxStateAuthInfo | undefined> {
  if (!hasInit) init()
  const token = tokenFromReq(req)
  if (!token) return undefined
  let result: TokenCacheResult | undefined
  const cacheResult = await tokenCache.get(token, req)
  if (!cacheResult) {
    // jwtVerify rejects expired tokens, so the cache returns undefined — try to refresh
    try {
      const { iss } = decodeJwt(token)
      result = await tryRefresh(req, iss ?? undefined)
    } catch { /* no result */ }
  } else if (cacheResult.payload.exp && cacheResult.payload.exp * 1000 <= Date.now()) {
    // belt-and-suspenders: catch tokens that expired after being cached
    result = await tryRefresh(req, cacheResult.payload.iss)
  } else {
    result = { token, payload: cacheResult.payload, discovery: cacheResult.discovery }
  }

  if (!result) return undefined
  const authInfo = buildAuthInfo(result.token, result.payload, result.discovery, extraClaims)
  authInfo.accessToken = accessTokenFromReq(req)
  return authInfo
}

/**
 * Authenticate requests using JWT tokens from any OAuth/OIDC provider. The token's
 * issuer claim is used to auto-discover the provider's JWKS endpoint for signature
 * verification.
 *
 * Expects JWT tokens (access tokens or ID tokens) in the Authorization Bearer header
 * or in a cookie set by registerOAuthCookieRoutes.
 *
 * For providers like Google that issue opaque access tokens, have the client send the
 * ID token instead — it's a standard JWT that proves the user's identity without
 * requiring a round-trip to the provider on every request.
 */
export async function oauthAuthenticate (req: FastifyRequest, options?: {
  /** If true, all requests require authentication, except routes listed in exceptRoutes or optionalRoutes. */
  authenticateAll?: boolean
  /** Routes that skip authentication entirely. They will not receive an auth object. */
  exceptRoutes?: Set<string>
  /** Routes that do not require authentication, but will fill req.auth if a session is available. */
  optionalRoutes?: Set<string>
  /** Set this true if you are using registerOAuthCookieRoutes and authenticateAll. */
  usingOAuthCookieRoutes?: boolean
  /** Receives the full JWT payload and returns extra properties to merge into the auth object.
   *  If you use this, you should also set OAUTH_TRUSTED_AUDIENCES to prevent tokens from
   *  other applications carrying unexpected authorization claims. */
  extraClaims?: (payload: Record<string, unknown>) => Record<string, unknown>
}): Promise<FastifyTxStateAuthInfo | undefined> {
  if (options?.usingOAuthCookieRoutes) {
    options.exceptRoutes ??= new Set<string>()
    options.exceptRoutes.add('/.oauthCallback')
    options.exceptRoutes.add('/.oauthRedirect')
    options.optionalRoutes ??= new Set<string>()
    options.optionalRoutes.add('/.oauthLogout')
  }
  if (options?.exceptRoutes?.has(req.routeOptions.url!)) return undefined
  const auth = await oauthAuthenticateInternal(req, options?.extraClaims)
  if (options?.authenticateAll && !options.optionalRoutes?.has(req.routeOptions.url!) && isBlank(auth?.username)) {
    throw new Error('Request requires authentication.')
  }
  return auth
}

/**
 * Register cookie-based OAuth login/logout endpoints. Uses the authorization code flow
 * with PKCE (S256) to exchange a code for tokens, then stores the ID token in an HttpOnly
 * cookie. The access token and refresh token are stored in separate cookies (optionally
 * encrypted via OAUTH_COOKIE_SECRET) so that the ID token can be transparently refreshed
 * when it expires and the access token is available at `req.auth.accessToken` for calling
 * provider APIs.
 *
 * Requires OAUTH_CLIENT_ID environment variable. OAUTH_CLIENT_SECRET is optional — PKCE
 * provides the security for the code exchange, but some providers require a client secret
 * even with PKCE. OAUTH_COOKIE_SECRET is optional — if set, the access token and refresh
 * token cookies are encrypted with AES-256-GCM; if not, they are stored as plaintext
 * (still HttpOnly and Secure).
 *
 * Registers three routes:
 * - `/.oauthRedirect` - Redirects to the OAuth provider's login page. The client passes
 *    `requestedUrl` (required) which is sent to the provider as the `state` parameter,
 *    round-tripped back, and used as the redirect destination after login.
 * - `/.oauthCallback` - Handles the provider's redirect, exchanges the code for tokens
 *    using the PKCE code verifier. Sets the ID token (or JWT access token as fallback),
 *    access token, and refresh token as cookies.
 * - `/.oauthLogout` - Clears all OAuth cookies and redirects to the provider's logout
 *    endpoint if available.
 */
export interface IssuerChoice {
  issuerUrl: string
  redirectHref: string
}

export function registerOAuthCookieRoutes (app: FastifyInstanceTyped, options?: {
  /** Scopes to always include in the authorization request, merged with any scopes
   *  the client passes via the `scope` query parameter. */
  scopes?: string[]
  /** When multiple issuers are configured and the client doesn't specify one,
   *  this function is called to render a login selection page. It receives an array
   *  of issuer URLs with their corresponding redirect hrefs and should return an HTML
   *  string. If not provided, the first trusted issuer is used. */
  loginPage?: (issuers: IssuerChoice[]) => string
}): void {
  const clientId = process.env.OAUTH_CLIENT_ID
  if (!clientId) throw new Error('OAUTH_CLIENT_ID environment variable must be set when using registerOAuthCookieRoutes.')
  if (!hasInit) init()
  const clientSecret = process.env.OAUTH_CLIENT_SECRET

  const callbackPath = '/.oauthCallback'

  const pkceVerifierCookieName = oauthCookieName + '_pkce'
  const pkceVerifierCookieRegex = new RegExp(`${pkceVerifierCookieName}=([A-Za-z0-9_-]+)`, 'v')
  const issuerCookieName = oauthCookieName + '_iss'
  const issuerCookieRegex = new RegExp(`${issuerCookieName}=([^;]+)`, 'v')

  // flush any pending cookies set during token refresh
  app.addHook('onSend', async (req, res) => {
    if (req.pendingOAuthCookies?.length) {
      for (const cookie of req.pendingOAuthCookies) void res.header('Set-Cookie', cookie)
    }
  })

  app.get('/.oauthRedirect', {
    schema: {
      querystring: {
        type: 'object',
        properties: {
          requestedUrl: { type: 'string', format: 'uri' },
          scope: { type: 'string' },
          issuer: { type: 'string', format: 'uri' }
        },
        required: ['requestedUrl'],
        additionalProperties: false
      }
    }
  }, async (req, res) => {
    if (req.originChecker && !req.originChecker.check(req.query.requestedUrl, req.hostname)) {
      void res.status(403)
      return 'Requested URL failed origin check.'
    }

    // if multiple issuers and no issuer specified, show a login selection page
    if (!req.query.issuer && trustedIssuers.size > 1 && options?.loginPage) {
      const issuers: IssuerChoice[] = [...trustedIssuers].map(iss => {
        const redirectUrl = new URL(apiBaseUrl(req) + '/.oauthRedirect')
        redirectUrl.searchParams.set('requestedUrl', req.query.requestedUrl)
        if (req.query.scope) redirectUrl.searchParams.set('scope', req.query.scope)
        redirectUrl.searchParams.set('issuer', iss)
        return { issuerUrl: iss, redirectHref: redirectUrl.toString() }
      })
      void res.type('text/html')
      return options.loginPage(issuers)
    }

    const issuerUrl = req.query.issuer && trustedIssuers.has(req.query.issuer)
      ? req.query.issuer
      : [...trustedIssuers][0]

    const discovery = await discoveryCache.get(issuerUrl)
    if (!discovery?.authorization_endpoint) throw new Error(`OAuth issuer ${issuerUrl} does not have an authorization endpoint.`)

    const codeVerifier = randomBytes(32).toString('base64url')
    const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url')

    const redirectUri = apiBaseUrl(req) + callbackPath
    const authUrl = new URL(discovery.authorization_endpoint)
    authUrl.searchParams.set('response_type', 'code')
    authUrl.searchParams.set('client_id', clientId)
    authUrl.searchParams.set('redirect_uri', redirectUri)
    const isGoogle = discovery.authorization_endpoint.includes('accounts.google.com')
    const scopeParts = new Set((req.query.scope ?? 'openid').split(' '))
    for (const s of options?.scopes ?? []) scopeParts.add(s)
    if (!isGoogle && !req.query.scope) scopeParts.add('offline_access')
    authUrl.searchParams.set('scope', [...scopeParts].join(' '))
    authUrl.searchParams.set('state', req.query.requestedUrl)
    authUrl.searchParams.set('code_challenge', codeChallenge)
    authUrl.searchParams.set('code_challenge_method', 'S256')
    if (isGoogle) {
      authUrl.searchParams.set('access_type', 'offline')
      authUrl.searchParams.set('prompt', 'consent')
    }

    // store the code verifier and chosen issuer in short-lived HttpOnly cookies
    void res.header('Set-Cookie', `${pkceVerifierCookieName}=${codeVerifier}; Path=${callbackPath}; Secure; HttpOnly; SameSite=Lax; Max-Age=600`)
    void res.header('Set-Cookie', `${issuerCookieName}=${encodeURIComponent(issuerUrl)}; Path=${callbackPath}; Secure; HttpOnly; SameSite=Lax; Max-Age=600`)

    return await res.redirect(authUrl.toString())
  })

  app.get(callbackPath, {
    schema: {
      querystring: {
        type: 'object',
        properties: {
          code: { type: 'string' },
          state: { type: 'string' }
        },
        required: ['code', 'state'],
        additionalProperties: false
      }
    }
  }, async (req, res) => {
    const verifierMatch = req.headers.cookie?.match(pkceVerifierCookieRegex)
    if (!verifierMatch) {
      void res.status(403)
      return 'Missing PKCE code verifier. The login flow may have expired.'
    }
    const codeVerifier = verifierMatch[1]

    const issuerMatch = req.headers.cookie?.match(issuerCookieRegex)
    const issuerUrl = issuerMatch ? decodeURIComponent(issuerMatch[1]) : [...trustedIssuers][0]

    const discovery = await discoveryCache.get(issuerUrl)
    if (!discovery?.token_endpoint) throw new Error(`OAuth issuer ${issuerUrl} does not have a token endpoint.`)

    const redirectUri = apiBaseUrl(req) + callbackPath
    const body: Record<string, string> = {
      grant_type: 'authorization_code',
      code: req.query.code,
      redirect_uri: redirectUri,
      client_id: clientId,
      code_verifier: codeVerifier
    }
    if (clientSecret) body.client_secret = clientSecret

    const tokenResp = await fetch(toInternalUrl(discovery.token_endpoint), {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(body)
    })

    if (!tokenResp.ok) {
      req.log.error(`OAuth token exchange failed: ${tokenResp.status} ${await tokenResp.text()}`)
      void res.status(502)
      return 'OAuth token exchange failed.'
    }

    const tokens = await tokenResp.json() as TokenResponse
    // prefer id_token, fall back to access_token if it's a JWT (some providers
    // like Okta and Microsoft issue JWT access tokens)
    let sessionToken = tokens.id_token
    if (!sessionToken && tokens.access_token) {
      try {
        decodeJwt(tokens.access_token)
        sessionToken = tokens.access_token
      } catch { /* not a JWT, can't use it */ }
    }
    if (!sessionToken) {
      req.log.error('OAuth token response did not include a usable JWT (no id_token and access_token is not a JWT).')
      void res.status(502)
      return 'OAuth provider did not return a usable JWT.'
    }

    const destination = isNotBlank(req.query.state) ? req.query.state : uiBaseUrl(req)
    const cookies = [
      `${oauthCookieName}=${sessionToken}; Path=/; Secure; HttpOnly; SameSite=Lax`,
      `${pkceVerifierCookieName}=; Path=${callbackPath}; Secure; HttpOnly; SameSite=Lax; Expires=Thu, 01 Jan 1970 00:00:00 GMT`,
      `${issuerCookieName}=; Path=${callbackPath}; Secure; HttpOnly; SameSite=Lax; Expires=Thu, 01 Jan 1970 00:00:00 GMT`
    ]
    if (tokens.access_token) {
      cookies.push(`${accessTokenCookieName}=${wrapRefreshToken(tokens.access_token)}; Path=/; Secure; HttpOnly; SameSite=Lax`)
    }
    if (tokens.refresh_token) {
      cookies.push(`${refreshCookieName}=${wrapRefreshToken(tokens.refresh_token)}; Path=/; Secure; HttpOnly; SameSite=Lax`)
    }
    for (const cookie of cookies) void res.header('Set-Cookie', cookie)
    void res.type('text/html')
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="refresh" content="0; url=${htmlEncode(destination)}">
  <title>Logging in...</title>
</head>
<body>
</body>
</html>`
  })

  app.get(
    '/.oauthLogout',
    {
      schema: {
        querystring: {
          type: 'object',
          properties: {
            returnUrl: { type: 'string', format: 'uri' }
          },
          additionalProperties: false
        },
        headers: {
          type: 'object',
          properties: {
            cookie: { type: 'string', pattern: `${oauthCookieName}=[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+` }
          },
          required: ['cookie']
        }
      }
    },
    async (req, res) => {
      if (req.query.returnUrl && req.originChecker && !req.originChecker.check(req.query.returnUrl, req.hostname)) {
        void res.status(403)
        return 'Return URL failed origin check.'
      }
      const postLogoutDestination = req.query.returnUrl ?? uiBaseUrl(req)
      let redirectUrl = postLogoutDestination
      if (req.auth?.issuerConfig?.logoutUrl) {
        const logoutUrl = new URL(req.auth.issuerConfig.logoutUrl)
        if (isNotBlank(req.auth.token)) logoutUrl.searchParams.set('id_token_hint', req.auth.token)
        logoutUrl.searchParams.set('post_logout_redirect_uri', postLogoutDestination)
        redirectUrl = logoutUrl.toString()
      }
      const cookies = [
        `${oauthCookieName}=; Path=/; Secure; HttpOnly; SameSite=Lax; Expires=Thu, 01 Jan 1970 00:00:00 GMT`,
        `${accessTokenCookieName}=; Path=/; Secure; HttpOnly; SameSite=Lax; Expires=Thu, 01 Jan 1970 00:00:00 GMT`,
        `${refreshCookieName}=; Path=/; Secure; HttpOnly; SameSite=Lax; Expires=Thu, 01 Jan 1970 00:00:00 GMT`
      ]
      for (const cookie of cookies) void res.header('Set-Cookie', cookie)
      return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="refresh" content="0; url=${htmlEncode(redirectUrl)}">
  <title>Logging out...</title>
</head>
<body>
</body>
</html>`
    }
  )
}
