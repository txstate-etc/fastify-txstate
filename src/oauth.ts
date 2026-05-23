import { createHash, randomBytes } from 'node:crypto'
import type { FastifyReply, FastifyRequest } from 'fastify'
import { decodeJwt } from 'jose'
import { htmlEncode, isBlank, isNotBlank } from 'txstate-utils'
import { apiBaseUrl, uiBaseUrl, type FastifyInstanceTyped } from './server.ts'
import {
  accessTokenCookieName,
  getOAuthDiscovery,
  getOAuthIssuerUrls,
  init,
  oauthCookieName,
  refreshCookieName,
  toInternalUrl,
  wrapRefreshToken
} from './jwt-auth.ts'

interface TokenResponse {
  id_token?: string
  access_token?: string
  refresh_token?: string
  token_type?: string
  expires_in?: number
  scope?: string
}

export interface IssuerChoice {
  issuerUrl: string
  redirectHref: string
}

/**
 * Register cookie-based OAuth login/logout endpoints. Uses the authorization code flow
 * with PKCE (S256) to exchange a code for tokens, then stores the ID token in an HttpOnly
 * cookie. The access token and refresh token are stored in separate cookies (optionally
 * encrypted via OAUTH_COOKIE_SECRET) so that the ID token can be transparently refreshed
 * by jwtAuthenticate when it expires, and the access token is available at
 * `req.auth.accessToken` for calling provider APIs.
 *
 * Requires OAUTH_COOKIE_CLIENT_ID environment variable. OAUTH_COOKIE_CLIENT_SECRET is
 * optional — PKCE provides the security for the code exchange, but some providers require
 * a client secret even with PKCE. OAUTH_COOKIE_SECRET is optional — if set, the access
 * token and refresh token cookies are encrypted with AES-256-GCM; if not, they are stored
 * as plaintext (still HttpOnly and Secure).
 *
 * Trusted issuers are configured via OAUTH_URLS or JWT_TRUSTED_ISSUERS (see jwt-auth.ts).
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
  const clientId = process.env.OAUTH_COOKIE_CLIENT_ID
  if (!clientId) throw new Error('OAUTH_COOKIE_CLIENT_ID environment variable must be set when using registerOAuthCookieRoutes.')
  init()
  const clientSecret = process.env.OAUTH_COOKIE_CLIENT_SECRET

  const callbackPath = '/.oauthCallback'

  const pkceVerifierCookieName = oauthCookieName + '_pkce'
  const pkceVerifierCookieRegex = new RegExp(`${pkceVerifierCookieName}=([A-Za-z0-9_-]+)`, 'v')
  const issuerCookieName = oauthCookieName + '_iss'
  const issuerCookieRegex = new RegExp(`${issuerCookieName}=([^;]+)`, 'v')

  // flush any pending cookies queued during token refresh by jwtAuthenticate
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

    const issuerUrls = getOAuthIssuerUrls()
    if (!issuerUrls.length) throw new Error('No OAuth issuers are configured. Set OAUTH_URLS or include oauth issuers in JWT_TRUSTED_ISSUERS.')

    // if multiple issuers and no issuer specified, show a login selection page
    if (!req.query.issuer && issuerUrls.length > 1 && options?.loginPage) {
      const issuers: IssuerChoice[] = issuerUrls.map(iss => {
        const redirectUrl = new URL(apiBaseUrl(req) + '/.oauthRedirect')
        redirectUrl.searchParams.set('requestedUrl', req.query.requestedUrl)
        if (req.query.scope) redirectUrl.searchParams.set('scope', req.query.scope)
        redirectUrl.searchParams.set('issuer', iss)
        return { issuerUrl: iss, redirectHref: redirectUrl.toString() }
      })
      void res.type('text/html')
      return options.loginPage(issuers)
    }

    const issuerUrl = req.query.issuer && issuerUrls.includes(req.query.issuer)
      ? req.query.issuer
      : issuerUrls[0]

    const discovery = await getOAuthDiscovery(issuerUrl)
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

    const issuerUrls = getOAuthIssuerUrls()
    const issuerMatch = req.headers.cookie?.match(issuerCookieRegex)
    const issuerUrl = issuerMatch ? decodeURIComponent(issuerMatch[1]) : issuerUrls[0]

    const discovery = await getOAuthDiscovery(issuerUrl)
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

/**
 * This function is available for server-side view code instead of a client-side application
 * using a framework. It will automatically redirect the user through the OAuth login flow
 * (via /.oauthRedirect, which must be registered by registerOAuthCookieRoutes) and return
 * true if they are not authenticated. Otherwise it simply returns false.
 */
export async function requireCookieAuthOAuth (req: FastifyRequest, res: FastifyReply): Promise<boolean> {
  if (isBlank(req.auth?.username)) {
    const redirectUrl = new URL(apiBaseUrl(req) + '/.oauthRedirect')
    redirectUrl.searchParams.set('requestedUrl', apiBaseUrl(req) + req.originalUrl)
    void res.redirect(redirectUrl.toString())
    return true
  } else {
    return false
  }
}
