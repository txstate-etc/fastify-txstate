import { createPublicKey, createSecretKey, randomBytes } from 'crypto'
import { type FastifyReply, type FastifyRequest } from 'fastify'
import { createRemoteJWKSet, decodeJwt, type JWTPayload, jwtVerify, type JWTVerifyGetKey, type KeyLike, type JWTHeaderParameters, type JWK, importJWK } from 'jose'
import { Cache, isNotBlank, toArray } from 'txstate-utils'
import { type FastifyInstanceTyped, type FastifyTxStateAuthInfo } from '.'

interface IssuerConfig {
  iss: string
  url?: string
  publicKey?: string
  secret?: string
  validateUrl: URL
}

let hasInit = false
const issuerKeys = new Map<string, KeyLike | JWTVerifyGetKey>()
const issuerConfig = new Map<string, IssuerConfig>()
const trustedClients = new Set<string>()
export const uaCookieName = process.env.UA_COOKIE_NAME ?? randomBytes(16).toString('hex')

const tokenCache = new Cache(async (token: string, req: FastifyRequest) => {
  const claims = decodeJwt(token)
  let verifyKey: KeyLike | JWTVerifyGetKey | undefined
  if (claims.iss && issuerKeys.has(claims.iss)) verifyKey = issuerKeys.get(claims.iss)
  if (!verifyKey) {
    req.log.warn(`Received token with issuer: ${claims.iss} but JWT secret could not be found. The server may be misconfigured or the user may have presented a JWT from an untrusted issuer.`)
    return undefined
  }
  try {
    const { payload } = await jwtVerify(token, verifyKey as KeyLike)
    if (trustedClients.size && !trustedClients.has(payload.client_id as string)) {
      req.log.warn(`Received token with untrusted client_id: ${payload.client_id as string}.`)
      return undefined
    }
    return payload
  } catch (e: any) {
    // squelch errors about bad tokens, we can already see the 401 in the log
    if (e.code !== 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED') req.log.error(e)
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
  const publicKeyByKid: Record<string, KeyLike | Uint8Array> = {}
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

function processIssuerConfig (config: IssuerConfig) {
  if (config.iss === 'unified-auth') {
    config.validateUrl = new URL(config.url ?? '')
    config.validateUrl.pathname = '/validateToken'
  }
  return config
}

function init () {
  hasInit = true
  if (process.env.JWT_TRUSTED_ISSUERS) {
    const issuers = toArray(JSON.parse(process.env.JWT_TRUSTED_ISSUERS)) as IssuerConfig[]
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
  const m = req?.headers.authorization?.match(/^bearer (.*)$/i)
  if (m != null) return m[1]

  const m2 = req?.headers.cookie?.match(new RegExp(`${uaCookieName}=([^;]+)`))
  if (m2 != null) return m2[1]
}

export async function unifiedAuthenticate (req: FastifyRequest): Promise<FastifyTxStateAuthInfo | undefined> {
  if (!hasInit) init()
  const token = tokenFromReq(req)
  if (!token) return undefined
  const payload = await tokenCache.get(token, req)
  if (!payload) return undefined
  await validateCache.get(token, payload)
  req.token = token
  return {
    username: payload.sub!,
    sessionId: payload.sub! + '-' + payload.iat,
    clientId: payload.client_id as string | undefined,
    impersonatedBy: (payload.act as any)?.sub as string | undefined
  }
}

export async function unifiedAuthenticateAll (req: FastifyRequest): Promise<FastifyTxStateAuthInfo> {
  const auth = await unifiedAuthenticate(req)
  if (!auth?.username.length) throw new Error('All requests require authentication.')
  return auth
}

export async function requireCookieAuth (req: FastifyRequest, res: FastifyReply): Promise<boolean> {
  if (req.auth === undefined || req.auth.username.length === 0) {
    await res
      .header('Set-Cookie', `${uaCookieName}_return=${encodeURIComponent(`${process.env.PUBLIC_URL ?? ''}${req.originalUrl}`)}; Path=/; Secure; HttpOnly; SameSite=Lax`)
      .redirect(`${process.env.UA_URL ?? ''}/login?clientId=${process.env.UA_CLIENTID ?? ''}&returnUrl=${encodeURIComponent(`${process.env.PUBLIC_URL ?? ''}/.uaService`)}`)
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
      const m = req.headers.cookie.match(new RegExp(`${uaCookieName}=([^;]+)`))
      if (m == null) return res.code(400).send('Missing UA JWT')

      return res
        .header('Set-Cookie', `${uaCookieName}=; Path=/; Secure; HttpOnly; SameSite=Lax; Expires=Thu, 01 Jan 1970 00:00:00 GMT`)
        .redirect(`${process.env.UA_URL ?? ''}/logout?unifiedJwt=${encodeURIComponent(m[1])}`)
    }
  )

  app.get(
    '/.uaService',
    {
      schema: {
        querystring: {
          type: 'object',
          properties: {
            unifiedJwt: { type: 'string', pattern: '^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+$' }
          },
          required: ['unifiedJwt'],
          additionalProperties: false
        },
        headers: {
          type: 'object',
          properties: {
            cookie: { type: 'string', pattern: `${uaCookieName}_return=${encodeURIComponent(`${process.env.PUBLIC_URL ?? ''}`)}` }
          },
          required: ['cookie']
        }
      }
    },
    async (req, res) => {
      const m = req.headers.cookie.match(new RegExp(`${uaCookieName}_return=([^;]+)`))
      if (m == null) return res.code(400).send('Return URL cookie not found')
      return res
        .header('Set-Cookie', `${uaCookieName}=${req.query.unifiedJwt}; Path=/; Secure; HttpOnly; SameSite=Lax`)
        .header('Set-Cookie', `${uaCookieName}_return=; Path=/; Secure; HttpOnly; SameSite=Lax; Expires=Thu, 01 Jan 1970 00:00:00 GMT`)
        .redirect(decodeURIComponent(m[1]))
    }
  )
}
