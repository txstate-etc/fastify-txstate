import { createCipheriv, createDecipheriv, createHash, createPublicKey, createSecretKey, randomBytes, type KeyObject } from 'node:crypto'
import type { FastifyRequest } from 'fastify'
import { createRemoteJWKSet, decodeJwt, importJWK, jwtVerify, type JWK, type JWTHeaderParameters, type JWTPayload, type JWTVerifyGetKey } from 'jose'
import { Cache, isBlank, isNotBlank, toArray } from 'txstate-utils'
import type { FastifyTxStateAuthInfo, IssuerConfig } from './server.ts'

export interface OAuthDiscovery {
  issuer: string
  jwks_uri: string
  authorization_endpoint?: string
  token_endpoint?: string
  end_session_endpoint?: string
}

interface TokenResponse {
  id_token?: string
  access_token?: string
  refresh_token?: string
}

declare module 'fastify' {
  interface FastifyRequest {
    pendingOAuthCookies?: string[]
  }
}

// Cookie names are owned here; oauth.ts and unified-auth.ts import them so the random
// fallbacks don't drift between modules in deployments that don't set the env vars.
export const oauthCookieName = process.env.OAUTH_COOKIE_NAME ?? randomBytes(16).toString('hex')
export const refreshCookieName = oauthCookieName + '_rt'
export const accessTokenCookieName = oauthCookieName + '_at'
export const uaCookieName = process.env.UA_COOKIE_NAME ?? randomBytes(16).toString('hex')

const oauthCookieRegex = new RegExp(`${oauthCookieName}=([^;]+)`, 'v')
const refreshCookieRegex = new RegExp(`${refreshCookieName}=([^;]+)`, 'v')
const accessTokenCookieRegex = new RegExp(`${accessTokenCookieName}=([^;]+)`, 'v')
const uaCookieRegex = new RegExp(`${uaCookieName}=([^;]+)`, 'v')

let cookieEncryptionKey: Buffer | undefined
if (isNotBlank(process.env.OAUTH_COOKIE_SECRET)) {
  cookieEncryptionKey = createHash('sha256').update(process.env.OAUTH_COOKIE_SECRET).digest()
}

export function wrapRefreshToken (token: string): string {
  if (!cookieEncryptionKey) return token
  const iv = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', cookieEncryptionKey, iv)
  const encrypted = Buffer.concat([cipher.update(token, 'utf8'), cipher.final()])
  const tag = cipher.getAuthTag()
  return Buffer.concat([iv, tag, encrypted]).toString('base64url')
}

export function unwrapRefreshToken (value: string): string | undefined {
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

type JwtIssuerType = 'oauth' | 'jwks' | 'unified-auth' | 'publicKey' | 'secret'

export interface JwtIssuerConfigRaw {
  iss: string
  /** Explicitly set the issuer type. Optional — when omitted, the type is inferred:
   *  iss === 'unified-auth' → 'unified-auth'; secret → 'secret'; publicKey → 'publicKey';
   *  url → 'jwks'. Set type: 'oauth' to enable OAuth/OIDC auto-discovery via
   *  .well-known/openid-configuration on the issuer URL. */
  type?: JwtIssuerType
  /** Issuer URL. For 'oauth' this is the issuer (.well-known/openid-configuration is
   *  fetched relative to it). For 'jwks' this is the JWKS endpoint directly. For
   *  'unified-auth' this is the UA service URL. */
  url?: string
  /** PEM-encoded public key (publicKey type). */
  publicKey?: string
  /** Symmetric HMAC secret (secret type). */
  secret?: string
  /** Override URL for the unified-auth /validateToken poll. Resolved relative to `url`. */
  validateUrl?: string
  /** End-session URL surfaced as `req.auth.issuerConfig.logoutUrl`. For 'oauth' issuers
   *  this is auto-discovered; set this only to override. Resolved relative to `url`. */
  logoutUrl?: string
  /** Server-to-server URL prefix override for split-horizon DNS (e.g. talking to the
   *  issuer over a docker-internal hostname while the browser uses the public URL). */
  internalUrl?: string
  /** If set, only accept tokens whose `aud` claim contains one of these values. */
  audiences?: string[]
  /** If set, only accept tokens whose `client_id` claim matches one of these values. */
  clientIds?: string[]
}

interface ResolvedIssuerConfig {
  type: JwtIssuerType
  iss: string
  url?: string
  validateUrl?: URL
  logoutUrl?: URL
  audiences?: Set<string>
  clientIds?: Set<string>
}

let hasInit = false
const issuerConfigByIss = new Map<string, ResolvedIssuerConfig>()
const verifyKeyByIss = new Map<string, KeyObject | JWTVerifyGetKey>()
const issuerInternalUrls = new Map<string, string>()

function inferType (config: JwtIssuerConfigRaw): JwtIssuerType {
  if (config.type) return config.type
  if (config.iss === 'unified-auth') return 'unified-auth'
  if (isNotBlank(config.secret)) return 'secret'
  if (isNotBlank(config.publicKey)) return 'publicKey'
  if (isNotBlank(config.url)) return 'jwks'
  throw new Error(`Could not infer type for JWT issuer ${config.iss}. Set "type" explicitly or provide one of url/publicKey/secret.`)
}

export function toInternalUrl (url: string): string {
  for (const [external, internal] of issuerInternalUrls) {
    if (url.startsWith(external)) return internal + url.slice(external.length)
  }
  return url
}

export function getOAuthIssuerUrls (): string[] {
  init()
  const urls: string[] = []
  for (const config of issuerConfigByIss.values()) {
    if (config.type === 'oauth' && config.url) urls.push(config.url)
  }
  return urls
}

export function getIssuerConfig (iss: string): IssuerConfig | undefined {
  init()
  const config = issuerConfigByIss.get(iss)
  if (!config) return undefined
  return {
    iss: config.iss,
    url: config.url,
    validateUrl: config.validateUrl,
    logoutUrl: config.logoutUrl
  }
}

export async function getOAuthDiscovery (issuerUrl: string): Promise<OAuthDiscovery | undefined> {
  init()
  return await discoveryCache.get(issuerUrl)
}

const jwksRemoteCache = new Cache(
  async (jwksUri: string) => createRemoteJWKSet(new URL(toInternalUrl(jwksUri))),
  { freshseconds: 3600 }
)

const uaJwkCache = new Cache(async (url: string) => {
  const { keys } = await (await fetch(toInternalUrl(url))).json() as { keys: JWK[] }
  const map: Record<string, CryptoKey | Uint8Array> = {}
  for (const jwk of keys) {
    if (jwk.kid) map[jwk.kid] = await importJWK(jwk)
  }
  return map
})

function uaRemoteJWKSet (url: string): JWTVerifyGetKey {
  return async (header: JWTHeaderParameters) => {
    const map = await uaJwkCache.get(url)
    return map[header.kid!]
  }
}

const discoveryCache = new Cache(async (issuerUrl: string) => {
  const base = issuerUrl.endsWith('/') ? issuerUrl : issuerUrl + '/'
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

function buildLogoutUrl (config: JwtIssuerConfigRaw, type: JwtIssuerType): URL | undefined {
  if (isNotBlank(config.logoutUrl)) {
    return config.url ? new URL(config.logoutUrl, config.url) : new URL(config.logoutUrl)
  }
  if (type === 'unified-auth') {
    if (isNotBlank(process.env.UA_URL)) return new URL(process.env.UA_URL + '/logout')
    if (config.url) return new URL('logout', config.url)
  }
  return undefined
}

function csvEnv (value: string | undefined): string[] {
  return value?.split(',').map(s => s.trim()).filter(isNotBlank) ?? []
}

function issuersFromEnv (): JwtIssuerConfigRaw[] {
  const result: JwtIssuerConfigRaw[] = []
  if (isNotBlank(process.env.UA_URL)) {
    result.push({
      iss: 'unified-auth',
      type: 'unified-auth',
      url: process.env.UA_URL,
      internalUrl: isNotBlank(process.env.UA_URL_INTERNAL) ? process.env.UA_URL_INTERNAL : undefined
    })
  }
  if (isNotBlank(process.env.OAUTH_URLS)) {
    const internalByExternal = new Map<string, string>()
    for (const pair of csvEnv(process.env.OAUTH_INTERNAL_URLS)) {
      const eq = pair.indexOf('=')
      if (eq > 0) internalByExternal.set(pair.slice(0, eq).trim(), pair.slice(eq + 1).trim())
    }
    for (const url of csvEnv(process.env.OAUTH_URLS)) {
      result.push({
        iss: url,
        type: 'oauth',
        url,
        internalUrl: internalByExternal.get(url)
      })
    }
  }
  if (isNotBlank(process.env.JWT_SECRET)) {
    result.push({
      iss: 'jwt-secret',
      type: 'secret',
      secret: process.env.JWT_SECRET
    })
  }
  if (isNotBlank(process.env.JWT_PUBLIC_KEY)) {
    // accept PEM with literal \n escapes for env-var friendliness
    result.push({
      iss: 'jwt-public-key',
      type: 'publicKey',
      publicKey: process.env.JWT_PUBLIC_KEY.replace(/\\n/gv, '\n')
    })
  }
  return result
}

export function init () {
  if (hasInit) return
  hasInit = true
  const globalAudiences = csvEnv(process.env.JWT_TRUSTED_AUDIENCES)
  const globalClientIds = csvEnv(process.env.JWT_TRUSTED_CLIENTIDS)
  const jsonIssuers = process.env.JWT_TRUSTED_ISSUERS
    ? toArray(JSON.parse(process.env.JWT_TRUSTED_ISSUERS)) as JwtIssuerConfigRaw[]
    : []
  // env-derived issuers first, then JSON-derived — JSON entries with the same iss override.
  for (const issuer of [...issuersFromEnv(), ...jsonIssuers]) {
    const type = inferType(issuer)
    if (isNotBlank(issuer.url) && isNotBlank(issuer.internalUrl)) {
      issuerInternalUrls.set(issuer.url, issuer.internalUrl)
    }
    switch (type) {
      case 'unified-auth':
        if (!issuer.url) throw new Error(`unified-auth issuer ${issuer.iss} requires url`)
        verifyKeyByIss.set(issuer.iss, uaRemoteJWKSet(issuer.url))
        break
      case 'oauth':
        if (!issuer.url) throw new Error(`oauth issuer ${issuer.iss} requires url`)
        // verify key resolved per request via discovery
        break
      case 'jwks':
        if (!issuer.url) throw new Error(`jwks issuer ${issuer.iss} requires url`)
        verifyKeyByIss.set(issuer.iss, createRemoteJWKSet(new URL(toInternalUrl(issuer.url))))
        break
      case 'publicKey':
        if (!issuer.publicKey) throw new Error(`publicKey issuer ${issuer.iss} requires publicKey`)
        verifyKeyByIss.set(issuer.iss, createPublicKey(issuer.publicKey))
        break
      case 'secret':
        if (!issuer.secret) throw new Error(`secret issuer ${issuer.iss} requires secret`)
        verifyKeyByIss.set(issuer.iss, createSecretKey(Buffer.from(issuer.secret, 'ascii')))
        break
    }
    const validateUrl = type === 'unified-auth'
      ? (isNotBlank(issuer.validateUrl) ? new URL(issuer.validateUrl, issuer.url) : new URL('validateToken', issuer.url))
      : undefined
    const audiences = new Set([...(issuer.audiences ?? []), ...globalAudiences])
    const clientIds = new Set([...(issuer.clientIds ?? []), ...globalClientIds])
    issuerConfigByIss.set(issuer.iss, {
      type,
      iss: issuer.iss,
      url: issuer.url,
      validateUrl,
      logoutUrl: buildLogoutUrl(issuer, type),
      audiences: audiences.size ? audiences : undefined,
      clientIds: clientIds.size ? clientIds : undefined
    })
  }
}

function checkAudience (aud: JWTPayload['aud'], audiences: Set<string> | undefined, req: FastifyRequest): boolean {
  if (!audiences?.size) return true
  // RFC 7519: a consumer accepts a token if it identifies itself in the aud claim, so
  // any single trusted audience appearing in the token is sufficient — additional
  // untrusted audiences alongside it do not cause rejection.
  if (!toArray(aud).some(a => audiences.has(a))) {
    req.log.warn(`Received token with untrusted audience: ${String(aud)}`)
    return false
  }
  return true
}

function checkClientId (clientId: string | undefined, clientIds: Set<string> | undefined, req: FastifyRequest): boolean {
  if (!clientIds?.size) return true
  if (!clientIds.has(clientId!)) {
    req.log.warn(`Received token with untrusted client_id: ${String(clientId)}`)
    return false
  }
  return true
}

interface CachedToken {
  payload: JWTPayload
  config: ResolvedIssuerConfig
  discovery?: OAuthDiscovery
}

async function resolveVerifyKey (config: ResolvedIssuerConfig): Promise<{ key: KeyObject | JWTVerifyGetKey, discovery?: OAuthDiscovery } | undefined> {
  if (config.type === 'oauth') {
    if (!config.url) return undefined
    const discovery = await discoveryCache.get(config.url)
    if (!discovery?.jwks_uri) return undefined
    return { key: await jwksRemoteCache.get(discovery.jwks_uri), discovery }
  }
  const key = verifyKeyByIss.get(config.iss)
  return key ? { key } : undefined
}

const tokenCache = new Cache(async (token: string, req: FastifyRequest): Promise<CachedToken | undefined> => {
  const claims = decodeJwt(token)
  if (!claims.iss) {
    req.log.warn('Received token without an issuer claim.')
    return undefined
  }
  const config = issuerConfigByIss.get(claims.iss)
  if (!config) {
    req.log.warn(`Received token with untrusted issuer: ${claims.iss}`)
    return undefined
  }
  try {
    const resolved = await resolveVerifyKey(config)
    if (!resolved) {
      req.log.warn(`Could not resolve verification key for issuer ${claims.iss}`)
      return undefined
    }
    const { payload } = await jwtVerify(token, resolved.key as unknown as CryptoKey)
    if (!checkAudience(payload.aud, config.audiences, req)) return undefined
    if (!checkClientId(payload.client_id as string | undefined, config.clientIds, req)) return undefined
    return { payload, config, discovery: resolved.discovery }
  } catch (e: unknown) {
    const code = (e as { code?: string }).code
    if (code !== 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED' && code !== 'ERR_JWT_EXPIRED') req.log.error(e)
    return undefined
  }
}, { freshseconds: 3600 })

const validateCache = new Cache(async (token: string, payload: JWTPayload) => {
  const config = payload.iss ? issuerConfigByIss.get(payload.iss) : undefined
  if (!config?.validateUrl) return
  // avoid checking for deauth until the token is more than 5 minutes old
  if (new Date(payload.iat! * 1000) > new Date(Date.now() - 1000 * 60 * 5)) return
  const validateUrl = new URL(config.validateUrl)
  validateUrl.searchParams.set('unifiedJwt', token)
  const resp = await fetch(validateUrl)
  const validate = await resp.json() as { valid: boolean, reason?: string }
  if (!validate.valid) throw new Error(validate.reason ?? 'Your session has been ended on another device or in another browser tab/window. It\'s also possible your NetID is no longer active.')
})

interface RefreshResult {
  token: string
  payload: JWTPayload
  config: ResolvedIssuerConfig
  discovery?: OAuthDiscovery
}

async function tryRefresh (req: FastifyRequest, expiredIss?: string): Promise<RefreshResult | undefined> {
  const m = req.headers.cookie?.match(refreshCookieRegex)
  if (!m) return undefined
  const refreshToken = unwrapRefreshToken(m[1])
  if (!refreshToken) return undefined

  const clientId = process.env.OAUTH_COOKIE_CLIENT_ID
  if (!clientId) return undefined

  const candidate = (expiredIss && issuerConfigByIss.get(expiredIss)?.type === 'oauth')
    ? issuerConfigByIss.get(expiredIss)!
    : [...issuerConfigByIss.values()].find(c => c.type === 'oauth')
  if (!candidate?.url) return undefined

  const discovery = await discoveryCache.get(candidate.url)
  if (!discovery?.token_endpoint) return undefined

  const body: Record<string, string> = {
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
    client_id: clientId
  }
  const clientSecret = process.env.OAUTH_COOKIE_CLIENT_SECRET
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

    req.pendingOAuthCookies = [
      `${oauthCookieName}=${tokens.id_token}; Path=/; Secure; HttpOnly; SameSite=Lax`
    ]
    if (tokens.access_token) {
      req.pendingOAuthCookies.push(
        `${accessTokenCookieName}=${wrapRefreshToken(tokens.access_token)}; Path=/; Secure; HttpOnly; SameSite=Lax`
      )
    }
    if (tokens.refresh_token) {
      req.pendingOAuthCookies.push(
        `${refreshCookieName}=${wrapRefreshToken(tokens.refresh_token)}; Path=/; Secure; HttpOnly; SameSite=Lax`
      )
    }

    const cached = await tokenCache.get(tokens.id_token, req)
    if (!cached) return undefined
    if (cached.payload.exp && cached.payload.exp * 1000 <= Date.now()) return undefined
    return { token: tokens.id_token, payload: cached.payload, config: cached.config, discovery: cached.discovery }
  } catch (e: unknown) {
    req.log.error(e)
    return undefined
  }
}

function tokenFromReq (req: FastifyRequest): string | undefined {
  const m = req.headers.authorization?.match(/^bearer (.*)$/iv)
  if (m) return m[1]
  const oauthM = req.headers.cookie?.match(oauthCookieRegex)
  if (oauthM) return oauthM[1]
  const uaM = req.headers.cookie?.match(uaCookieRegex)
  if (uaM) return uaM[1]
}

function accessTokenFromReq (req: FastifyRequest): string | undefined {
  const m = req.headers.cookie?.match(accessTokenCookieRegex)
  if (!m) return undefined
  return unwrapRefreshToken(m[1])
}

function authIssuerConfig (config: ResolvedIssuerConfig, discovery?: OAuthDiscovery): IssuerConfig {
  const logoutUrl = config.type === 'oauth' && isNotBlank(discovery?.end_session_endpoint)
    ? new URL(discovery.end_session_endpoint)
    : config.logoutUrl
  return {
    iss: config.iss,
    url: config.url,
    validateUrl: config.validateUrl,
    logoutUrl
  }
}

function buildAuthInfo (result: RefreshResult, extraClaims?: (payload: JWTPayload) => Record<string, unknown>): FastifyTxStateAuthInfo {
  const { token, payload, config, discovery } = result
  return {
    ...extraClaims?.(payload),
    token,
    issuerConfig: authIssuerConfig(config, discovery),
    username: payload.sub!,
    sessionId: payload.sub! + '-' + String(payload.iat),
    sessionCreatedAt: payload.iat ? new Date(payload.iat * 1000) : undefined,
    clientId: payload.client_id as string | undefined,
    impersonatedBy: (payload.act as { sub?: string } | undefined)?.sub,
    scope: payload.scope as string | undefined
  }
}

async function jwtAuthenticateInternal (req: FastifyRequest, extraClaims?: (payload: JWTPayload) => Record<string, unknown>): Promise<FastifyTxStateAuthInfo | undefined> {
  init()
  const token = tokenFromReq(req)
  if (!token) return undefined

  let result: RefreshResult | undefined

  const cached = await tokenCache.get(token, req)
  if (!cached) {
    // jwtVerify rejects expired tokens — try a refresh if we have a refresh-token cookie
    try {
      const { iss } = decodeJwt(token)
      result = await tryRefresh(req, iss ?? undefined)
    } catch { /* not a JWT */ }
  } else if (cached.payload.exp && cached.payload.exp * 1000 <= Date.now()) {
    // belt-and-suspenders: catch tokens that expired between cache and now
    result = await tryRefresh(req, cached.payload.iss)
  } else {
    result = { token, payload: cached.payload, config: cached.config, discovery: cached.discovery }
  }

  if (!result) return undefined

  await validateCache.get(result.token, result.payload)

  const authInfo = buildAuthInfo(result, extraClaims)
  authInfo.accessToken = accessTokenFromReq(req)
  return authInfo
}

export interface JwtAuthenticateOptions {
  /** If true, all requests require authentication, except routes listed in exceptRoutes or optionalRoutes. */
  authenticateAll?: boolean
  /** Routes that skip authentication entirely. They will not receive an auth object. */
  exceptRoutes?: Set<string>
  /** Routes that do not require authentication, but will fill req.auth if a session is available. */
  optionalRoutes?: Set<string>
  /** Receives the full JWT payload and returns extra properties to merge into the auth object.
   *  If you use this, set per-issuer `audiences` to prevent tokens from other applications
   *  carrying unexpected authorization claims. */
  extraClaims?: (payload: JWTPayload) => Record<string, unknown>
}

// Routes contributed by registerOAuthCookieRoutes / registerUaCookieRoutes. The
// authenticator returned by jwtAuthenticate consults these at request time so that
// registration order (factory vs. route registration) doesn't matter.
export const registeredExceptRoutes = new Set<string>()
export const registeredOptionalRoutes = new Set<string>()

/**
 * Build an `authenticate` function that validates JWTs from the Authorization Bearer
 * header or a session cookie. Supports any mix of issuer types via the
 * JWT_TRUSTED_ISSUERS env var:
 *
 *   - 'oauth'         — OAuth/OIDC provider with .well-known auto-discovery
 *   - 'jwks'          — JWKS endpoint URL (no discovery)
 *   - 'unified-auth'  — TxState Unified Auth (JWKS + /validateToken poll for deauth)
 *   - 'publicKey'     — PEM-encoded asymmetric public key
 *   - 'secret'        — symmetric HMAC secret
 *
 * Usage:
 *   new Server({ authenticate: jwtAuthenticate({ authenticateAll: true }) })
 *
 * Or with no options:
 *   new Server({ authenticate: jwtAuthenticate() })
 *
 * Calling `registerOAuthCookieRoutes` or `registerUaCookieRoutes` automatically excludes
 * their callback/redirect routes from authentication requirements and marks their logout
 * routes as optional, so you do not need to configure that here.
 *
 * If a refresh-token cookie is present (set by registerOAuthCookieRoutes) and the access
 * token has expired, the returned authenticator transparently exchanges the refresh
 * token for a new access token and queues the replacement cookies on
 * `req.pendingOAuthCookies`. The onSend hook installed by registerOAuthCookieRoutes
 * flushes those cookies onto the response.
 */
export function jwtAuthenticate (options?: JwtAuthenticateOptions): (req: FastifyRequest) => Promise<FastifyTxStateAuthInfo | undefined> {
  const exceptRoutes = new Set(options?.exceptRoutes)
  const optionalRoutes = new Set(options?.optionalRoutes)
  return async (req: FastifyRequest) => {
    const url = req.routeOptions.url!
    if (exceptRoutes.has(url) || registeredExceptRoutes.has(url)) return undefined
    const auth = await jwtAuthenticateInternal(req, options?.extraClaims)
    if (options?.authenticateAll && !optionalRoutes.has(url) && !registeredOptionalRoutes.has(url) && isBlank(auth?.username)) {
      throw new Error('Request requires authentication.')
    }
    return auth
  }
}
