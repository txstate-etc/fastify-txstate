import { createPublicKey, createSecretKey, type KeyObject, randomBytes } from 'node:crypto'
import type { FastifyReply, FastifyRequest } from 'fastify'
import { createRemoteJWKSet, decodeJwt, type JWTPayload, jwtVerify, type JWTVerifyGetKey, type JWTHeaderParameters, type JWK, importJWK } from 'jose'
import { Cache, htmlEncode, isBlank, isNotBlank, toArray } from 'txstate-utils'
import { apiBaseUrl, uiBaseUrl, type IssuerConfig, type FastifyInstanceTyped, type FastifyTxStateAuthInfo } from './server.ts'

export interface IssuerConfigRaw extends Omit<IssuerConfig, 'validateUrl' | 'logoutUrl'> {
  validateUrl?: string
  logoutUrl?: string
}

type KeyLike = CryptoKey | JWTVerifyGetKey | KeyObject

let hasInit = false
const issuerKeys = new Map<string, KeyLike>()
const issuerConfig = new Map<string, IssuerConfig>()
const trustedClients = new Set<string>()
const uaCookieName = process.env.UA_COOKIE_NAME ?? randomBytes(16).toString('hex')
const uaCookieNameRegex = new RegExp(`${uaCookieName}=([^;]+)`, 'v')
function uaServiceUrl (req: FastifyRequest) {
  return apiBaseUrl(req) + '/.uaService'
}

const tokenCache = new Cache(async (token: string, req: FastifyRequest) => {
  const claims = decodeJwt(token)
  let verifyKey: KeyLike | undefined
  if (claims.iss && issuerKeys.has(claims.iss)) verifyKey = issuerKeys.get(claims.iss)
  if (!verifyKey) {
    req.log.warn(`Received token with issuer: ${claims.iss} but JWT secret could not be found. The server may be misconfigured or the user may have presented a JWT from an untrusted issuer.`)
    return undefined
  }
  try {
    const { payload } = await jwtVerify(token, verifyKey as CryptoKey)
    if (trustedClients.size && !trustedClients.has(payload.client_id as string)) {
      req.log.warn(`Received token with untrusted client_id: ${payload.client_id as string}.`)
      return undefined
    }
    return payload
  } catch (e: unknown) {
    // squelch expected token errors — bad signatures and expirations show as 401 in the access log
    const code = (e as { code?: string }).code
    if (code !== 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED' && code !== 'ERR_JWT_EXPIRED') req.log.error(e)
    return undefined
  }
}, { freshseconds: 3600 })

const validateCache = new Cache(async (token: string, payload: JWTPayload) => {
  const config = issuerConfig.get(payload.iss!)
  if (!config?.validateUrl) return
  // avoid checking for deauth until the token is more than 5 minutes old
  if (new Date(payload.iat! * 1000) > new Date(new Date().getTime() - 1000 * 60 * 5)) return
  const validateUrl = new URL(config.validateUrl)
  validateUrl.searchParams.set('unifiedJwt', token)
  const resp = await fetch(validateUrl)
  const validate = await resp.json() as { valid: boolean, reason?: string }
  if (!validate.valid) throw new Error(validate.reason ?? 'Your session has been ended on another device or in another browser tab/window. It\'s also possible your NetID is no longer active.')
})

const jwkCache = new Cache(async (url: string) => {
  const { keys } = await (await fetch(url)).json() as { keys: JWK[] }
  const publicKeyByKid: Record<string, CryptoKey | Uint8Array> = {}
  for (const jwk of keys) {
    if (jwk.kid) publicKeyByKid[jwk.kid] = await importJWK(jwk)
  }
  return publicKeyByKid
})

function remoteJWKSet (jwkUrl: string) {
  return async (protectedHeader: JWTHeaderParameters) => {
    const publicKeyByKid = await jwkCache.get(jwkUrl)
    return publicKeyByKid[protectedHeader.kid!]
  }
}

function processIssuerConfig (config: IssuerConfigRaw) {
  if (config.iss === 'unified-auth') {
    const validateUrl = isNotBlank(config.validateUrl)
      ? new URL(config.validateUrl, config.url)
      : new URL('validateToken', config.url)

    const logoutUrl = isNotBlank(config.logoutUrl)
      ? new URL(config.logoutUrl, config.url)
      : isNotBlank(process.env.UA_URL)
        ? new URL(process.env.UA_URL + '/logout')
        : new URL('logout', config.url)

    return {
      ...config,
      validateUrl,
      logoutUrl
    }
  }
  return {
    ...config,
    validateUrl: undefined,
    logoutUrl: config.logoutUrl ? new URL(config.logoutUrl, config.url) : undefined
  }
}

function init () {
  hasInit = true
  if (process.env.JWT_TRUSTED_ISSUERS) {
    const issuers = toArray(JSON.parse(process.env.JWT_TRUSTED_ISSUERS)) as IssuerConfigRaw[]
    for (const issuer of issuers) {
      issuerConfig.set(issuer.iss, processIssuerConfig(issuer))
      if (issuer.iss === 'unified-auth') issuerKeys.set(issuer.iss, remoteJWKSet(issuer.url!))
      else if (issuer.url) issuerKeys.set(issuer.iss, createRemoteJWKSet(new URL(issuer.url)))
      else if (issuer.publicKey) issuerKeys.set(issuer.iss, createPublicKey(issuer.publicKey))
      else if (issuer.secret) issuerKeys.set(issuer.iss, createSecretKey(Buffer.from(issuer.secret, 'ascii')))
    }
  }
  for (const clientId of (process.env.JWT_TRUSTED_CLIENTIDS?.split(',').filter(isNotBlank).map(clientId => clientId.trim()) ?? [])) {
    trustedClients.add(clientId)
  }
}

function tokenFromReq (req?: FastifyRequest): string | undefined {
  const m = req?.headers.authorization?.match(/^bearer (.*)$/iv)
  if (m != null) return m[1]

  const m2 = req?.headers.cookie?.match(uaCookieNameRegex)
  if (m2 != null) return m2[1]
}

async function unifiedAuthenticateInternal (req: FastifyRequest): Promise<FastifyTxStateAuthInfo | undefined> {
  if (!hasInit) init()
  const token = tokenFromReq(req)
  if (!token) return undefined
  const payload = await tokenCache.get(token, req)
  if (!payload) return undefined
  if (payload.exp && payload.exp * 1000 <= Date.now()) return undefined
  await validateCache.get(token, payload)
  return {
    token,
    issuerConfig: payload.iss ? issuerConfig.get(payload.iss) : undefined,
    username: payload.sub!,
    sessionId: payload.sub! + '-' + payload.iat,
    sessionCreatedAt: payload.iat ? new Date(payload.iat * 1000) : undefined,
    clientId: payload.client_id as string | undefined,
    impersonatedBy: (payload.act as { sub?: string } | undefined)?.sub,
    scope: payload.scope as string | undefined
  }
}

export async function unifiedAuthenticate (req: FastifyRequest, options?: {
  // If true, all requests require authentication, except a few routes created by fastify-txstate,
  // like /docs and /.uaService.
  authenticateAll?: boolean
  // You can set this option to exclude certain routes from authentication. They will
  // not receive an auth object, even if a cookie or bearer token is present.
  exceptRoutes?: Set<string>
  // If authenticateAll is true, you can set this to a set of routes that do not require
  // authentication, but will fill req.auth if a session is available.
  optionalRoutes?: Set<string>
  // Set this true if you are using the registerUaCookieRoutes function and set
  // authenticateAll to true. They will break if you don't.
  usingUaCookieRoutes?: boolean
}): Promise<FastifyTxStateAuthInfo | undefined> {
  const auth = await unifiedAuthenticateInternal(req)
  if (options?.usingUaCookieRoutes) {
    options.exceptRoutes ??= new Set<string>()
    options.exceptRoutes.add('/.uaService')
    options.exceptRoutes.add('/.uaRedirect')
    options.optionalRoutes ??= new Set<string>()
    options.optionalRoutes.add('/.uaLogout')
  }
  const isNoAuthenticationRoute = options?.exceptRoutes?.has(req.routeOptions.url!)
  const requiresAuthenticationRoute = options?.authenticateAll
    && !options.exceptRoutes?.has(req.routeOptions.url!)
    && !options.optionalRoutes?.has(req.routeOptions.url!)

  if (requiresAuthenticationRoute && isBlank(auth?.username)) {
    throw new Error('Request requires authentication.')
  }
  return isNoAuthenticationRoute ? undefined : auth
}

/**
 * @deprecated Use unifiedAuthenticateWithOptions with { authenticateAll: true } instead.
 */
export async function unifiedAuthenticateAll (req: FastifyRequest): Promise<FastifyTxStateAuthInfo> {
  return (await unifiedAuthenticate(req, { authenticateAll: true }))!
}

/**
 * This function is available for server-side view code instead of a client-side application
 * using a framework. It will automatically redirect the user to the Unified Auth login page
 * and return true if they are not authenticated. Otherwise it simply returns false.
 */
export async function requireCookieAuth (req: FastifyRequest, res: FastifyReply): Promise<boolean> {
  if (isBlank(req.auth?.username)) {
    const loginUrl = new URL(process.env.UA_URL! + '/login')
    loginUrl.searchParams.set('clientId', process.env.UA_CLIENTID!)
    loginUrl.searchParams.set('returnUrl', uaServiceUrl(req))
    loginUrl.searchParams.set('requestedUrl', req.originalUrl)
    void res.redirect(loginUrl.toString())
    return true
  } else {
    return false
  }
}

export function registerUaCookieRoutes (app: FastifyInstanceTyped): void {
  app.get(
    '/.uaLogout',
    {
      schema: {
        headers: {
          type: 'object',
          properties: {
            cookie: { type: 'string', pattern: `${uaCookieName}=[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+` }
          },
          required: ['cookie']
        }
      }
    },
    async (req, res) => {
      const redirectUrl = req.auth?.issuerConfig?.logoutUrl && isNotBlank(req.auth.token)
        ? `${req.auth.issuerConfig.logoutUrl.toString()}?unifiedJwt=${encodeURIComponent(req.auth.token)}`
        : uiBaseUrl(req)
      void res.header('Set-Cookie', `${uaCookieName}=; Path=/; Secure; HttpOnly; SameSite=Lax; Expires=Thu, 01 Jan 1970 00:00:00 GMT`)
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

  app.get(
    '/.uaService',
    {
      schema: {
        querystring: {
          type: 'object',
          properties: {
            unifiedJwt: { type: 'string', pattern: '^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+$' },
            requestedUrl: { type: 'string', format: 'uri' }
          },
          required: ['unifiedJwt'],
          additionalProperties: false
        }
      }
    },
    async (req, res) => {
      const destination = req.query.requestedUrl ?? uiBaseUrl(req)
      if (req.query.requestedUrl && req.originChecker && !req.originChecker.check(req.query.requestedUrl, req.hostname)) {
        void res.status(403)
        return 'Requested URL failed origin check.'
      }
      void res.header('Set-Cookie', `${uaCookieName}=${req.query.unifiedJwt}; Path=/; Secure; HttpOnly; SameSite=Lax`)
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
    }
  )

  /**
   * In the case of a client-side application that uses the UA cookie to authenticate,
   * the client code can detect a 401 from the API and redirect the user to this endpoint.
   *
   * This endpoint will redirect the browser to Unified Auth so that the client code does
   * not need to have any configuration for Unified Auth.
   */
  app.get('/.uaRedirect', {
    schema: {
      querystring: {
        type: 'object',
        properties: {
          requestedUrl: { type: 'string', format: 'uri' }
        },
        additionalProperties: false
      }
    }
  }, async (req, res) => {
    if (req.query.requestedUrl && req.originChecker && !req.originChecker.check(req.query.requestedUrl, req.hostname)) {
      void res.status(403)
      return 'Requested URL failed origin check.'
    }
    const loginUrl = isNotBlank(process.env.UA_URL)
      ? new URL(process.env.UA_URL + '/login')
      : new URL('login', issuerConfig.get('unified-auth')?.url)
    loginUrl.searchParams.set('clientId', process.env.UA_CLIENTID ?? process.env.JWT_TRUSTED_CLIENTIDS!.split(',')[0])
    const returnUrl = uaServiceUrl(req)
    loginUrl.searchParams.set('returnUrl', returnUrl)
    if (req.query.requestedUrl) loginUrl.searchParams.set('requestedUrl', req.query.requestedUrl)
    return await res.redirect(loginUrl.toString())
  })
}
