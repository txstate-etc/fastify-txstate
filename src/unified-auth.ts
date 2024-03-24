import { createPublicKey, createSecretKey, type KeyObject } from 'crypto'
import { type FastifyRequest } from 'fastify'
import { createRemoteJWKSet, decodeJwt, type JWTPayload, jwtVerify, type JWTVerifyGetKey, type KeyLike } from 'jose'
import { Cache, omit, toArray } from 'txstate-utils'
import { type FastifyTxStateAuthInfo } from '.'

function cleanPem (secretOrPem: string | undefined) {
  return secretOrPem?.replace(/(-+BEGIN [\w\s]+ KEY-+)\s*(.*?)\s*(-+END [\w\s]+ KEY-+)/, '$1\n$2\n$3')
}

class MockContext<AuthType = any> {
  public auth?: AuthType

  constructor (auth: any) {
    this.auth = auth
  }

  async waitForAuth () {
    return this.auth
  }

  static init () {}
}

interface IssuerConfig {
  iss: string
  url?: string
  publicKey?: string
  secret?: string
  validateUrl: URL
}

class Context<AuthType extends FastifyTxStateAuthInfo = FastifyTxStateAuthInfo> extends MockContext<AuthType> {
  private readonly authPromise: Promise<AuthType | undefined> | AuthType | undefined
  protected static jwtVerifyKey: KeyObject | undefined
  protected static issuerKeys = new Map<string, KeyLike | JWTVerifyGetKey>()
  protected static issuerConfig = new Map<string, any>()

  protected static tokenCache = new Cache(async (token: string, { req, ctx }: { req?: FastifyRequest, ctx: Context }) => {
    // `this` is always the Context class, even if we are making instances of a subclass of Context
    // we need to get the instance's constructor instead in case it has overridden one of our
    // static methods/variables
    const ctxStatic = ctx.constructor as typeof Context

    const logger = req?.log ?? console
    let verifyKey: KeyLike | JWTVerifyGetKey | undefined = Context.jwtVerifyKey
    try {
      const claims = decodeJwt(token)
      if (claims.iss && ctxStatic.issuerKeys.has(claims.iss)) verifyKey = ctxStatic.issuerKeys.get(claims.iss)
      if (!verifyKey) {
        logger.info(`Received token with issuer: ${claims.iss} but JWT secret could not be found. The server may be misconfigured or the user may have presented a JWT from an untrusted issuer.`)
        return undefined
      }
      await ctxStatic.validateToken?.(token, ctxStatic.issuerConfig.get(claims.iss!), claims)
      const { payload } = await jwtVerify(token, verifyKey as KeyLike)
      return await ctx.authFromPayload(payload) as any
    } catch (e: any) {
      // squelch errors about bad tokens, we can already see the 401 in the log
      if (e.code !== 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED') logger.error(e)
      return undefined
    }
  }, { freshseconds: 10 })

  constructor (req?: FastifyRequest) {
    super(undefined)
    this.authPromise = this.authFromReq(req)
  }

  async waitForAuth () {
    this.auth = await this.authPromise
    return this.auth
  }

  static init () {
    let secret = cleanPem(process.env.JWT_SECRET_VERIFY)
    if (secret != null) {
      Context.jwtVerifyKey = createPublicKey(secret)
    } else {
      secret = cleanPem(process.env.JWT_SECRET)
      if (secret != null) {
        try {
          Context.jwtVerifyKey = createPublicKey(secret)
        } catch (e: any) {
          console.info('JWT_SECRET was not a private key, treating it as symmetric.')
          Context.jwtVerifyKey = createSecretKey(Buffer.from(secret, 'ascii'))
        }
      }
    }
    if (process.env.JWT_TRUSTED_ISSUERS) {
      const issuers = toArray(JSON.parse(process.env.JWT_TRUSTED_ISSUERS)) as IssuerConfig[]
      for (const issuer of issuers) {
        this.issuerConfig.set(issuer.iss, this.processIssuerConfig?.(omit(issuer, 'publicKey', 'secret')))
        if (issuer.url) this.issuerKeys.set(issuer.iss, createRemoteJWKSet(new URL(issuer.url)))
        else if (issuer.publicKey) this.issuerKeys.set(issuer.iss, createPublicKey(issuer.publicKey))
        else if (issuer.secret) this.issuerKeys.set(issuer.iss, createSecretKey(Buffer.from(issuer.secret, 'ascii')))
      }
    }
  }

  /**
   * If implemented, this method will be called on startup, once per configured issuer. It receives
   * the issuer configuration from the JWT_TRUSTED_ISSUERS environment variable and allows you to manipulate
   * the configuration before storing it.
   *
   * Once stored, whatever you create may be used in your custom validateToken method. For example,
   * you might want to create an in-memory URL object with an issuer's URL so that it can be manipulated
   * easily to send validation checks to the issuer.
   */
  static processIssuerConfig: undefined | ((config: any) => any)

  /**
   * If implemented, this method is called after a token's signature is checked and passes. You would
   * typically implement this method to check whether the user has manually signed out, or the token has
   * been otherwise deauthorized before its expiration date.
   *
   * If the token is not valid, this method should throw an error with an appropriate message.
   */
  static validateToken: undefined | ((token: string, issuerConfig: any, claims: JWTPayload) => void | Promise<void>)

  tokenFromReq (req?: FastifyRequest) {
    const m = req?.headers.authorization?.match(/^bearer (.*)$/i)
    return m?.[1]
  }

  async authFromReq (req?: FastifyRequest): Promise<AuthType | undefined> {
    const token = this.tokenFromReq(req)
    if (!token) return undefined
    return (this.constructor as typeof Context).tokenCache.get(token, { req, ctx: this })
  }

  async authFromPayload (payload: JWTPayload) {
    return payload as unknown as AuthType
  }
}

class TxStateUAuthContext extends Context {
  static processIssuerConfig (config: IssuerConfig) {
    if (config.iss === 'unified-auth') {
      config.validateUrl = new URL(config.url ?? '')
      config.validateUrl.pathname = '/validateToken'
    }
    return config
  }

  static async validateToken (token: string, issuerConfig: IssuerConfig, claims: any) {
    if (claims.iss === 'unified-auth') {
      const validateUrl = new URL(issuerConfig.validateUrl)
      validateUrl.searchParams.set('unifiedJwt', token)
      const resp = await fetch(validateUrl)
      const validate = await resp.json() as { valid: boolean, reason?: string }
      if (!validate.valid) throw new Error(validate.reason ?? 'Your session has been ended on another device or in another browser tab/window. It\'s also possible your NetID is no longer active.')
    }
  }

  async authFromPayload (payload: JWTPayload): Promise<FastifyTxStateAuthInfo> {
    return {
      username: payload.sub!,
      sessionId: payload.sub! + '-' + payload.iat,
      clientId: payload.client_id as string | undefined,
      impersonatedBy: payload.impersonatedBy as string | undefined
    }
  }
}

export async function unifiedAuthenticate (req: FastifyRequest, ContextClass = TxStateUAuthContext) {
  const ctx = new ContextClass(req)
  return ctx.waitForAuth()
}
