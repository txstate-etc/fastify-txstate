import type { FastifyReply, FastifyRequest } from 'fastify'
import { htmlEncode, isBlank, isNotBlank } from 'txstate-utils'
import { getIssuerConfig, jwtAuthenticate, registeredExceptRoutes, registeredOptionalRoutes, uaCookieName } from './jwt-auth.ts'
import { apiBaseUrl, uiBaseUrl, type FastifyInstanceTyped, type FastifyTxStateAuthInfo } from './server.ts'

function uaServiceUrl (req: FastifyRequest) {
  return apiBaseUrl(req) + '/.uaService'
}

/**
 * @deprecated Use `jwtAuthenticate(options)` instead. Note the new shape: `jwtAuthenticate`
 * is now a factory that takes options up front and returns the authenticator function
 * (`authenticate: jwtAuthenticate({ authenticateAll: true })`), so the options actually
 * take effect when wired into `new Server({ authenticate })`.
 */
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
  // No longer needed — calling registerUaCookieRoutes automatically excludes its
  // callback/redirect routes from authentication. Accepted for backward compatibility
  // but has no effect.
  usingUaCookieRoutes?: boolean
}): Promise<FastifyTxStateAuthInfo | undefined> {
  return await jwtAuthenticate(options)(req)
}

/**
 * @deprecated Use `jwtAuthenticate({ authenticateAll: true })` instead.
 */
export async function unifiedAuthenticateAll (req: FastifyRequest): Promise<FastifyTxStateAuthInfo> {
  return (await jwtAuthenticate({ authenticateAll: true })(req))!
}

/**
 * This function is available for server-side view code instead of a client-side application
 * using a framework. It will automatically redirect the user to the Unified Auth login page
 * and return true if they are not authenticated. Otherwise it simply returns false.
 */
export async function requireCookieAuthUa (req: FastifyRequest, res: FastifyReply): Promise<boolean> {
  if (isBlank(req.auth?.username)) {
    const loginUrl = new URL(process.env.UA_URL! + '/login')
    loginUrl.searchParams.set('clientId', (process.env.UA_COOKIE_CLIENTID ?? process.env.UA_CLIENTID)!)
    loginUrl.searchParams.set('returnUrl', uaServiceUrl(req))
    loginUrl.searchParams.set('requestedUrl', req.originalUrl)
    void res.redirect(loginUrl.toString())
    return true
  } else {
    return false
  }
}

/**
 * @deprecated Use requireCookieAuthUa instead.
 */
export async function requireCookieAuth (req: FastifyRequest, res: FastifyReply): Promise<boolean> {
  return await requireCookieAuthUa(req, res)
}

export function registerUaCookieRoutes (app: FastifyInstanceTyped): void {
  registeredExceptRoutes.add('/.uaService')
  registeredExceptRoutes.add('/.uaRedirect')
  registeredOptionalRoutes.add('/.uaLogout')

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
      : new URL('login', getIssuerConfig('unified-auth')?.url)
    loginUrl.searchParams.set('clientId', process.env.UA_COOKIE_CLIENTID ?? process.env.UA_CLIENTID ?? process.env.JWT_TRUSTED_CLIENTIDS!.split(',')[0])
    const returnUrl = uaServiceUrl(req)
    loginUrl.searchParams.set('returnUrl', returnUrl)
    if (req.query.requestedUrl) loginUrl.searchParams.set('requestedUrl', req.query.requestedUrl)
    return await res.redirect(loginUrl.toString())
  })
}
