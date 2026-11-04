import type { InteractionEvent } from '@txstate-mws/fastify-shared'
import axios, { type AxiosInstance } from 'axios'
import { expect } from 'chai'
import { after, before, describe, it } from 'node:test'
import { createServer } from 'node:http'
import https from 'node:https'

const client = axios.create({
  baseURL: 'http://fastify-http'
})

const httpsClient = axios.create({
  baseURL: 'https://fastify-https',
  httpsAgent: new https.Agent({ rejectUnauthorized: false })
})

const redirClient = axios.create({
  baseURL: 'http://fastify-https',
  httpsAgent: new https.Agent({ rejectUnauthorized: false })
})

const authClient = axios.create({
  baseURL: 'http://fakeauth'
})

interface OtlpJsonScope {
  name: string
  version?: string
}
interface OtlpJsonLogRecord {
  timeUnixNano: string
  eventName?: string
  severityNumber?: number
  severityText?: string
  body?: { stringValue?: string }
  traceId?: string
  spanId?: string
  flags?: number
  attributes?: { key: string, value: { stringValue?: string, intValue?: string, boolValue?: boolean, arrayValue?: { values: { stringValue?: string }[] } } }[]
}
interface OtlpJsonLogs {
  resourceLogs: { resource: { attributes: OtlpJsonLogRecord['attributes'] }, scopeLogs: { scope: OtlpJsonScope, logRecords: OtlpJsonLogRecord[] }[] }[]
}
interface OtlpJsonDataPoint {
  asDouble?: number
  attributes?: OtlpJsonLogRecord['attributes']
}
interface OtlpJsonHistogramPoint {
  count: string
  sum?: number
  min?: number
  max?: number
  bucketCounts: string[]
  explicitBounds: number[]
  attributes?: OtlpJsonLogRecord['attributes']
}
interface OtlpJsonMetric {
  name: string
  description?: string
  unit?: string
  sum?: { dataPoints: OtlpJsonDataPoint[], isMonotonic?: boolean }
  gauge?: { dataPoints: OtlpJsonDataPoint[] }
  histogram?: { dataPoints: OtlpJsonHistogramPoint[], aggregationTemporality?: number }
}
interface OtlpJsonMetrics {
  resourceMetrics: { resource: { attributes: OtlpJsonLogRecord['attributes'] }, scopeMetrics: { scope: OtlpJsonScope, metrics: OtlpJsonMetric[] }[] }[]
}
interface OtlpJsonSpan {
  traceId: string
  spanId: string
  parentSpanId?: string
  name: string
  kind: number
  attributes?: OtlpJsonLogRecord['attributes']
  status?: { code?: number, message?: string }
  events?: { name: string, attributes?: OtlpJsonLogRecord['attributes'] }[]
}
interface OtlpJsonTraces {
  resourceSpans: { resource: { attributes: OtlpJsonLogRecord['attributes'] }, scopeSpans: { scope: OtlpJsonScope, spans: OtlpJsonSpan[] }[] }[]
}

// otel-collector forwards metrics, logs and traces here as OTLP JSON, see test/otel-collector.yaml
const otlpSpans: { resource: Record<string, string | undefined>, scope: OtlpJsonScope, span: OtlpJsonSpan, attributes: Record<string, string | undefined> }[] = []
const otlpLogs: { resource: Record<string, string | undefined>, scope: OtlpJsonScope, record: OtlpJsonLogRecord, attributes: Record<string, string | undefined> }[] = []
const otlpMetrics: { resource: Record<string, string | undefined>, scope: OtlpJsonScope, metric: OtlpJsonMetric }[] = []
function otlpAttributes (attributes: OtlpJsonLogRecord['attributes']) {
  return Object.fromEntries((attributes ?? []).map(a => [a.key, a.value.stringValue ?? a.value.intValue]))
}
const otlpSink = createServer((req, res) => {
  // fastify-https's /tracing route calls this to see what headers it propagated
  if (req.url?.startsWith('/echo')) {
    res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify(req.headers))
    return
  }
  const chunks: Buffer[] = []
  req.on('data', (chunk: Buffer) => { chunks.push(chunk) })
  req.on('end', () => {
    if (req.url === '/v1/traces') {
      const traces: OtlpJsonTraces = JSON.parse(Buffer.concat(chunks).toString())
      for (const rs of traces.resourceSpans) {
        for (const ss of rs.scopeSpans) {
          for (const span of ss.spans) otlpSpans.push({ resource: otlpAttributes(rs.resource.attributes), scope: ss.scope, span, attributes: otlpAttributes(span.attributes) })
        }
      }
      res.writeHead(200, { 'Content-Type': 'application/json' }).end('{}')
      return
    }
    if (req.url === '/v1/metrics') {
      const body: OtlpJsonMetrics = JSON.parse(Buffer.concat(chunks).toString())
      for (const rm of body.resourceMetrics) {
        for (const sm of rm.scopeMetrics) {
          for (const metric of sm.metrics) otlpMetrics.push({ resource: otlpAttributes(rm.resource.attributes), scope: sm.scope, metric })
        }
      }
      res.writeHead(200, { 'Content-Type': 'application/json' }).end('{}')
      return
    }
    const body: OtlpJsonLogs = JSON.parse(Buffer.concat(chunks).toString())
    for (const rl of body.resourceLogs) {
      for (const sl of rl.scopeLogs) {
        for (const record of sl.logRecords) otlpLogs.push({ resource: otlpAttributes(rl.resource.attributes), scope: sl.scope, record, attributes: otlpAttributes(record.attributes) })
      }
    }
    res.writeHead(200, { 'Content-Type': 'application/json' }).end('{}')
  })
})

async function expectErrorCode (client: AxiosInstance, path: string, code: number) {
  try {
    await client.get(path)
    expect(true).to.be.false
  } catch (e: any) {
    expect(e.response.status).to.equal(code)
    return e.response.data
  }
}

describe('fastify-txstate', () => {
  after(() => { otlpSink.close() })
  before(async () => {
    otlpSink.listen(4318)
    for (let i = 0; i < 30; i++) {
      try {
        const resp = await client.get('/health')
        if (resp.status === 200) {
          const resp2 = await httpsClient.get('/health')
          if (resp2.status === 200) {
            const resp3 = await authClient.get('/health')
            if (resp3.status === 200) break
          }
        }
      } catch (e: any) {
        await new Promise<void>(resolve => { setTimeout(resolve, 200) })
      }
    }
  })

  describe('basic tests', () => {
    it('should be online and respond to request with { hello: "world" }', async () => {
      const resp = await client.get('/test')
      expect(resp.data.hello).to.equal('world')
    })
    it('should deliver a whole streamed reply from an async handler that does not return the reply', async () => {
      const resp = await client.get('/streamlate')
      expect(resp.data).to.equal('row 0\nrow 1\nrow 2\nrow 3\nrow 4\n')
    })
    it('should return a 403 by throwing an error', async () => {
      await expectErrorCode(client, '/403', 403)
    })
    it('should return a plain non-JSON 404 for any uncaught route', async () => {
      const message = await expectErrorCode(client, '/doesntexist', 404)
      expect(message).to.be.a.string
      expect(message).to.not.include('{')
    })
    it('should return 500 for any uncaught exception', async () => {
      await expectErrorCode(client, '/500', 500)
    })
    it('should be able to set a custom error handler', async () => {
      await expectErrorCode(client, '/422', 422)
    })
    it('should fill in reasonable error text for unhandled http status codes', async () => {
      const message = await expectErrorCode(client, '/409', 409)
      expect(message).to.equal('Conflict')
    })
    it('should return 503 on health checks and 200 on normal requests for 5 seconds after shutdown is requested', async () => {
      let resp = await client.get('/health')
      expect(resp.status).to.equal(200)
      await client.get('/shutdown')
      await expectErrorCode(client, '/health', 503)
      resp = await client.get('/test')
      expect(resp.data.hello).to.equal('world')
    })
    it('should return the correct protocol', async () => {
      const resp = await client.get('/proxy')
      expect(resp.data.protocol).to.equal('http')
    })
    it('should return the correct protocol when proxying', async () => {
      const resp = await client.get('/proxy', { headers: { 'X-Forwarded-Proto': 'https' } })
      expect(resp.data.protocol).to.equal('https')
    })
    it('should return the correct hostname when proxying', async () => {
      const resp = await client.get('/proxy', { headers: { Host: 'www.proxiedhost.com:3000' } })
      expect(resp.data.host).to.equal('www.proxiedhost.com:3000')
      expect(resp.data.hostname).to.equal('www.proxiedhost.com')
    })
    it('should not set the strict transport security header', async () => {
      const resp = await client.get('/test')
      expect(resp.headers['strict-transport-security']).to.be.undefined
    })
  })

  describe('https tests', () => {
    it('should respond to https requests', async () => {
      const resp = await httpsClient.get('/test')
      expect(resp.data.hello).to.equal('world')
    })
    it('should redirect from http to https', async () => {
      const resp = await redirClient('/test')
      expect(resp.request._redirectable._redirectCount).to.be.greaterThan(0)
      expect(resp.data.hello).to.equal('world')
    })
    it('should return the correct protocol', async () => {
      const resp = await httpsClient.get('/proxy')
      expect(resp.data.protocol).to.equal('https')
    })
    it('should set the strict transport security header', async () => {
      const resp = await httpsClient.get('/test')
      expect(resp.headers['strict-transport-security']).not.to.be.undefined
    })
  })

  describe('origin filtering', () => {
    it('should allow requests from the same origin subdomain', async () => {
      const resp = await client.get('/test', { headers: { origin: 'http://fastify-http' } })
      expect(resp.data.hello).to.equal('world')
      expect(resp.headers['access-control-allow-origin']).to.equal('http://fastify-http')
    })
    it('should allow requests when port is redundantly specified', async () => {
      const resp = await client.get('/test', { headers: { origin: 'http://fastify-http:80' } })
      expect(resp.data.hello).to.equal('world')
      expect(resp.headers['access-control-allow-origin']).to.equal('http://fastify-http:80')
    })
    it('should allow requests with a different origin port', async () => {
      const resp = await client.get('/test', { headers: { origin: 'http://fastify-http:3000' } })
      expect(resp.data.hello).to.equal('world')
      expect(resp.headers['access-control-allow-origin']).to.equal('http://fastify-http:3000')
    })
    it('should allow alternate origins when server sets them in validOriginSuffixes', async () => {
      const resp = await client.get('/test', { headers: { origin: 'http://www.proxiedhost.com' } })
      expect(resp.data.hello).to.equal('world')
      expect(resp.headers['access-control-allow-origin']).to.equal('http://www.proxiedhost.com')
    })
    it('should allow smaller alternate origins when server sets them in validOriginSuffixes', async () => {
      const resp = await client.get('/test', { headers: { origin: 'http://proxiedhost.com' } })
      expect(resp.data.hello).to.equal('world')
      expect(resp.headers['access-control-allow-origin']).to.equal('http://proxiedhost.com')
    })
    it('should allow alternate origins when server sets them in validOrigins', async () => {
      const resp = await client.get('/test', { headers: { origin: 'http://www.proxiedhost.com' } })
      expect(resp.data.hello).to.equal('world')
      expect(resp.headers['access-control-allow-origin']).to.equal('http://www.proxiedhost.com')
    })
    it('should allow alternate origins when server sets them in validOriginHosts', async () => {
      const resp = await client.get('/test', { headers: { origin: 'http://subd.validhost.com' } })
      expect(resp.data.hello).to.equal('world')
      expect(resp.headers['access-control-allow-origin']).to.equal('http://subd.validhost.com')
    })
    it('should allow alternate origins when server provides a checkOrigin function', async () => {
      const resp = await client.get('/test', { headers: { origin: 'http://www.someothervalidhost.com', 'x-auto-cors-pass': 1 } })
      expect(resp.data.hello).to.equal('world')
      expect(resp.headers['access-control-allow-origin']).to.equal('http://www.someothervalidhost.com')
    })
    it('should disallow requests from a different origin subdomain', async () => {
      try {
        await client.get('/test', { headers: { origin: 'http://fastify-fake' } })
        expect.fail('Should have gotten a 403.')
      } catch (e: any) {
        expect(e.response.status).to.equal(403)
      }
    })
    it('should disallow requests from an origin with a different subdomain than declared in validOriginHosts', async () => {
      try {
        await client.get('/test', { headers: { origin: 'http://validhost.com' } })
        expect.fail('Should have gotten a 403.')
      } catch (e: any) {
        expect(e.response.status).to.equal(403)
      }
    })
    it('should respond to preflight requests', async () => {
      const resp = await client.options('/test', { headers: { origin: 'http://fastify-http:3000', 'access-control-request-headers': 'authorization' } })
      expect(resp.status).to.equal(200)
      expect(resp.headers['access-control-allow-origin']).to.equal('http://fastify-http:3000')
      expect(resp.headers['access-control-allow-headers']).to.equal('authorization')
    })
  })

  describe('logging test', () => {
    it('should not log health checks', async () => {
      const resp = await httpsClient.get('/health')
      expect(resp.status).to.equal(200)
    })
    it('should log extra info when given', async () => {
      const resp = await httpsClient.get('/logging')
      expect(resp.data.success).to.be.true
    })
  })

  describe('validation tests', () => {
    it('should accept a payload that validates', async () => {
      const resp = await client.post('/typed', {
        str: 'hello',
        num: 4.3,
        int: 5
      })
      expect(resp.data).to.equal('hello')
    })
    it('should accept a payload that validates and sends null for an optional property', async () => {
      const resp = await client.post('/typed', {
        str: 'hello',
        num: 4.3,
        int: null
      })
      expect(resp.data).to.equal('hello')
    })
    it('should not error when the endpoint sends back null for an optional property', async () => {
      const resp = await client.post('/numtyped', {
        str: 'hello'
      })
      expect(resp.data.num == null).to.be.true
    })
    it('should not convert a null to a zero on input or output', async () => {
      const resp = await client.post('/numtyped', {
        str: 'hello',
        num: null
      })
      expect(resp.data.num === 0).to.be.false
    })
    it('should coerce querystring values to the declared schema type', async () => {
      const resp = await client.get('/coerce?id=123')
      expect(resp.data.id).to.equal(123)
    })
    it('should not coerce JSON body values to the declared schema type', async () => {
      try {
        await client.post('/typed', {
          str: 'hello',
          num: '4.3'
        })
        expect.fail('should have thrown')
      } catch (e: any) {
        if (e.response == null) throw e
        expect(e.response.status).to.equal(400)
      }
    })
    it('should reject a mis-typed payload with a 400 status', async () => {
      try {
        await client.post('/typed', {
          str: 'hello',
          num: 4.3,
          int: 5.5
        })
        expect.fail('should have thrown')
      } catch (e: any) {
        if (e.response == null) throw e
        expect(e.response.status).to.equal(400)
        expect(e.response.data[0].message).to.equal('The "int" property must be an integer.')
      }
    })
    it('should have a good dot-separated path when an array element fails to validate', async () => {
      try {
        await client.post('/typed', {
          str: 3,
          num: 4.3,
          int: 5,
          array: [3, 4, 5.6, 7]
        })
        expect.fail('should have thrown')
      } catch (e: any) {
        if (e.response == null) throw e
        expect(e.response.status).to.equal(400)
        expect(e.response.data.some((err: any) => err.path === 'array.2')).to.be.true
      }
    })
    it('should reject a payload with 422 status when it is a user error like missing a required field.', async () => {
      try {
        await client.post('/typed', {
          num: 4.3,
          int: 5,
          array: [3, 4, 5.6, 7]
        })
        expect.fail('should have thrown')
      } catch (e: any) {
        if (e.response == null) throw e
        expect(e.response.status).to.equal(422)
      }
    })
    it('should reject a payload with an invalid recursive object', async () => {
      try {
        await client.post('/typed', {
          str: 'str',
          num: 4.3,
          int: 5,
          array: [3, 4, 5, 7],
          more: [{ array: [2, 3, 4] }]
        })
        expect.fail('should have thrown')
      } catch (e: any) {
        if (e.response == null) throw e
        expect(e.response.status).to.equal(422)
      }
    })
    it('should error out when the route has a bug and returns something invalid', async () => {
      try {
        await client.post('/badtyped', {
          str: 'str',
          num: 4.3,
          int: 5,
          array: [3, 4, 5, 7]
        })
        expect.fail('should have thrown')
      } catch (e: any) {
        if (e.response == null) throw e
        console.log(e.response.data)
        expect(e.response.status).to.equal(500)
      }
    })
    it('should accept a route with a body schema and no response schema without crashing at boot', async () => {
      const resp = await client.post('/bodyonly', { str: 'hello' })
      expect(resp.data.str).to.equal('hello')
    })
    it('should still reject invalid payloads on a route with a body schema and no response schema', async () => {
      try {
        await client.post('/bodyonly', { num: 4.3 })
        expect.fail('should have thrown')
      } catch (e: any) {
        if (e.response == null) throw e
        expect(e.response.status).to.equal(422)
      }
    })
    it('should not overwrite an explicitly declared response.400 schema', async () => {
      try {
        await client.post('/custom400', { grant_type: 'authorization_code' })
        expect.fail('should have thrown')
      } catch (e: any) {
        if (e.response == null) throw e
        expect(e.response.status).to.equal(400)
        expect(e.response.data.error).to.equal('invalid_grant')
        expect(e.response.data.error_description).to.equal('The provided grant is invalid.')
      }
    })
    it('should accept a date-time formatted string', async () => {
      const resp = await client.post('/datetime', { mydate: '2023-10-01T12:00:00Z' })
      expect(new Date(resp.data.yourdate).getTime()).to.equal(new Date('2023-10-01T12:00:00Z').getTime())
    })
    it('should accept a date-time formatted string with a non-UTC timezone', async () => {
      const resp = await client.post('/datetime', { mydate: '2023-10-01T12:00:00-05:00' })
      expect(new Date(resp.data.yourdate).getTime()).to.equal(new Date('2023-10-01T12:00:00-05:00').getTime())
    })
    it('should reject a date-time formatted string with an invalid date', async () => {
      try {
        await client.post('/datetime', { mydate: 'invalid-date' })
        expect.fail('should have thrown')
      } catch (e: any) {
        if (e.response == null) throw e
        expect(e.response.status).to.equal(422)
      }
    })
    it('should accept a date-time formatted string with an impossible date as long as new Date() doesn\'t throw an error', async () => {
      // I don't like this behavior, but it's how ajv date-time format works, maybe can fix later
      const resp = await client.post('/datetime', { mydate: '2023-02-30T12:00:00Z' })
      // February 30th is invalid, but JS Date rolls it over to March 2nd
      expect(new Date(resp.data.yourdate).getTime()).to.equal(new Date('2023-02-30T12:00:00Z').getTime())
    })
    it('should reject a date-time formatted string with an invalid format', async () => {
      try {
        await client.post('/datetime', { mydate: '2023-10-01 12:00:00' })
        expect.fail('should have thrown')
      } catch (e: any) {
        if (e.response == null) throw e
        expect(e.response.status).to.equal(422)
      }
    })
    it('should reject a date-time with no timezone', async () => {
      try {
        await client.post('/datetime', { mydate: '2023-10-01T12:00:00' })
        expect.fail('should have thrown')
      } catch (e: any) {
        if (e.response == null) throw e
        expect(e.response.status).to.equal(422)
      }
    })
  })

  describe('analytics tests', () => {
    it('should accept an analytics event', async () => {
      const resp = await client.post('/analytics', [{ eventType: 'TestEvent', screen: 'N/A', action: 'Test' } satisfies InteractionEvent])
      expect(resp.data).to.equal('OK')
      expect(resp.status).to.equal(202)
    })
  })

  describe('verifying authentication', () => {
    it('should not allow access to a protected route without authentication', async () => {
      try {
        await client.post('/protected', { test: true })
        expect.fail('should have thrown')
      } catch (e: any) {
        if (e.response == null) throw e
        expect(e.response.status).to.equal(401)
      }
    })

    it('should allow access to a protected route with authentication', async () => {
      const tokenResp = await authClient.get('/generateToken', { params: { username: 'testuser', clientId: 'fastify-test' } })
      const token = tokenResp.data
      const resp = await client.post('/protected', { test: true }, { headers: { Authorization: `Bearer ${token}` } })
      expect(resp.data.authenticated).to.equal('testuser')
      expect(new Date().getTime() - new Date(resp.data.sessionCreatedAt).getTime()).to.be.lessThan(10000)
    })

    it('should not allow access to a protected route with the wrong clientId', async () => {
      try {
        const tokenResp = await authClient.get('/generateToken', { params: { username: 'testuser', clientId: 'wrong-client' } })
        const token = tokenResp.data
        await client.post('/protected', { test: true }, { headers: { Authorization: `Bearer ${token}` } })
        expect.fail('should have thrown')
      } catch (e: any) {
        if (e.response == null) throw e
        expect(e.response.status).to.equal(401)
      }
    })
    it('should redirect requests to the auth server for authentication', async () => {
      try {
        await client.get('/.uaRedirect', { params: { requestedUrl: 'http://fastify-http/protected' }, maxRedirects: 0 })
      } catch (e: any) {
        expect(e.response.status).to.equal(302)
        expect(e.response.headers.location).to.equal('http://fakeauth/login?clientId=fastify-test&returnUrl=http%3A%2F%2Ffastify-http%2F.uaService&requestedUrl=http%3A%2F%2Ffastify-http%2Fprotected')
      }
    })
    let token: string
    it('should redirect to the requestedUrl after authentication', async () => {
      try {
        const tokenResp = await authClient.get('/generateToken', { params: { username: 'testuser', clientId: 'fastify-test' } })
        token = tokenResp.data
        await client.get('/.uaService', { params: { unifiedJwt: token, requestedUrl: 'http://fastify-http/protected' }, maxRedirects: 0 })
      } catch (e: any) {
        expect(e.response.status).to.equal(200)
        expect(e.response.headers['set-cookie'][0]).to.include(`fastify_token=${encodeURIComponent(token!)}`)
        expect(e.response.data).to.include('http://fastify-http/protected')
      }
    })
    it('should delete the cookie and redirect to unified auth logout upon logout', async () => {
      try {
        await client.get('/.uaLogout', { headers: { Cookie: `fastify_token=${encodeURIComponent(token!)}` }, maxRedirects: 0 })
      } catch (e: any) {
        expect(e.response.status).to.equal(200)
        expect(e.response.headers['set-cookie'][0]).to.include('fastify_token=;')
        expect(e.response.data).to.include(`http://fakeauth/logout?unifiedJwt=${encodeURIComponent(token!)}`)
      }
    })
  })

  describe('protected resource metadata (RFC 9728)', () => {
    it('should serve metadata listing the trusted oauth issuers as authorization_servers', async () => {
      const resp = await client.get('/.well-known/oauth-protected-resource')
      expect(resp.status).to.equal(200)
      expect(resp.headers['content-type']).to.include('application/json')
      expect(resp.data.resource).to.equal('http://fastify-http')
      expect(resp.data.authorization_servers).to.deep.equal(['http://fakeauth'])
      expect(resp.data.bearer_methods_supported).to.deep.equal(['header'])
    })
    it('should advertise registered cookie login/logout routes as cookie_login_uri and cookie_logout_uri', async () => {
      const resp = await client.get('/.well-known/oauth-protected-resource')
      expect(resp.data.cookie_login_uri).to.equal('http://fastify-http/.uaRedirect')
      expect(resp.data.cookie_logout_uri).to.equal('http://fastify-http/.uaLogout')
    })
    it('should serve metadata without authorization_servers when cookie login routes exist but no oauth-type issuers are configured', async () => {
      const resp = await httpsClient.get('/.well-known/oauth-protected-resource')
      expect(resp.status).to.equal(200)
      expect(resp.data.resource).to.equal('https://fastify-https')
      expect(resp.data.authorization_servers).to.be.undefined
      expect(resp.data.cookie_login_uri).to.equal('https://fastify-https/.uaRedirect')
      expect(resp.data.cookie_logout_uri).to.equal('https://fastify-https/.uaLogout')
    })
    it('should serve the same metadata for the RFC path-suffix form used behind reverse proxies', async () => {
      const resp = await client.get('/.well-known/oauth-protected-resource/api')
      expect(resp.status).to.equal(200)
      expect(resp.data.authorization_servers).to.deep.equal(['http://fakeauth'])
    })
    it('should point 401 responses at the metadata document via WWW-Authenticate', async () => {
      try {
        await client.post('/protected', { test: true })
        expect.fail('should have thrown')
      } catch (e: any) {
        if (e.response == null) throw e
        expect(e.response.status).to.equal(401)
        expect(e.response.headers['www-authenticate']).to.equal('Bearer resource_metadata="http://fastify-http/.well-known/oauth-protected-resource"')
      }
    })
    it('should point 401 responses at the metadata document when only cookie login routes are being advertised', async () => {
      try {
        await httpsClient.post('/protected', { test: true })
        expect.fail('should have thrown')
      } catch (e: any) {
        if (e.response == null) throw e
        expect(e.response.status).to.equal(401)
        expect(e.response.headers['www-authenticate']).to.equal('Bearer resource_metadata="https://fastify-https/.well-known/oauth-protected-resource"')
      }
    })
  })

  describe('file storage', () => {
    it('should upload a file and return its checksum and size', async () => {
      const fileContent = Buffer.from('hello world file storage test')
      const formData = new FormData()
      formData.append('file', new Blob([fileContent], { type: 'text/plain' }), 'test.txt')
      const resp = await client.post('/filestorage/upload', formData)
      expect(resp.data).to.be.an('array').with.lengthOf(1)
      expect(resp.data[0].checksum).to.match(/^[\w\-]{43}$/v)
      expect(resp.data[0].size).to.equal(fileContent.length)
      expect(resp.data[0].filename).to.equal('test.txt')
    })
    it('should download a previously uploaded file', async () => {
      const fileContent = Buffer.from('download test content')
      const formData = new FormData()
      formData.append('file', new Blob([fileContent], { type: 'text/plain' }), 'download.txt')
      const uploadResp = await client.post('/filestorage/upload', formData)
      const checksum = uploadResp.data[0].checksum
      const downloadResp = await client.get(`/filestorage/download/${checksum}`, { responseType: 'arraybuffer' })
      expect(Buffer.from(downloadResp.data).toString()).to.equal('download test content')
    })
    it('should download a file by the hex form of its checksum', async () => {
      const formData = new FormData()
      formData.append('file', new Blob([Buffer.from('hex lookup content')], { type: 'text/plain' }), 'hex.txt')
      const uploadResp = await client.post('/filestorage/upload', formData)
      const hex = Buffer.from(uploadResp.data[0].checksum, 'base64url').toString('hex')
      const downloadResp = await client.get(`/filestorage/download/${hex}`, { responseType: 'arraybuffer' })
      expect(Buffer.from(downloadResp.data).toString()).to.equal('hex lookup content')
    })
    it('should migrate a file stored under its base64url checksum to its hex location', async () => {
      const { data: { checksum } } = await client.post('/filestorage/legacyupload', { content: 'legacy file content' })
      expect((await client.post(`/filestorage/migrate/${checksum}`, {})).data.migrated).to.equal(true)
      const downloadResp = await client.get(`/filestorage/download/${checksum}`, { responseType: 'arraybuffer' })
      expect(Buffer.from(downloadResp.data).toString()).to.equal('legacy file content')
      expect((await client.post(`/filestorage/migrate/${checksum}`, {})).data.migrated).to.equal(false)
    })
    it('should serve and remove a legacy file that has not been migrated', async () => {
      const { data: { checksum } } = await client.post('/filestorage/legacyupload', { content: 'unmigrated download content' })
      const downloadResp = await client.get(`/filestorage/download/${checksum}`, { responseType: 'arraybuffer' })
      expect(Buffer.from(downloadResp.data).toString()).to.equal('unmigrated download content')
      await client.post(`/filestorage/remove/${checksum}`, {})
      try {
        await client.get(`/filestorage/download/${checksum}`)
        expect.fail('should have thrown')
      } catch (e: any) {
        expect(e.response.status).to.equal(404)
      }
      expect((await client.post(`/filestorage/migrate/${checksum}`, {})).data.migrated).to.equal(false)
    })
    it('should survive two bulk migrations running at once', async () => {
      const legacy: string[] = []
      for (let i = 0; i < 20; i++) legacy.push((await client.post('/filestorage/legacyupload', { content: `concurrent legacy ${i}` })).data.checksum)
      const results = await Promise.all([client.post('/filestorage/migrateall', {}), client.post('/filestorage/migrateall', {})])
      expect(results[0].data.migrated + results[1].data.migrated).to.be.at.least(20)
      const { data: checksums } = await client.get('/filestorage/checksums')
      expect(checksums).to.include.members(legacy)
      expect((await client.post('/filestorage/migrateall', {})).data.migrated).to.equal(0)
    })
    it('should list the checksums of stored files, including legacy files', async () => {
      const formData = new FormData()
      formData.append('file', new Blob([Buffer.from('checksum listing content')], { type: 'text/plain' }), 'list.txt')
      const { data: [{ checksum }] } = await client.post('/filestorage/upload', formData)
      const { data: { checksum: legacy } } = await client.post('/filestorage/legacyupload', { content: 'unmigrated legacy content' })
      const { data: checksums } = await client.get('/filestorage/checksums')
      expect(checksums).to.include.members([checksum, legacy])
    })
    it('should migrate all legacy files at once', async () => {
      const { data: { checksum: legacy1 } } = await client.post('/filestorage/legacyupload', { content: 'bulk legacy one' })
      const { data: { checksum: legacy2 } } = await client.post('/filestorage/legacyupload', { content: 'bulk legacy two' })
      expect((await client.post('/filestorage/migrateall', {})).data.migrated).to.be.at.least(2)
      const { data: checksums } = await client.get('/filestorage/checksums')
      expect(checksums).to.include.members([legacy1, legacy2])
      const downloadResp = await client.get(`/filestorage/download/${legacy2}`, { responseType: 'arraybuffer' })
      expect(Buffer.from(downloadResp.data).toString()).to.equal('bulk legacy two')
      expect((await client.post('/filestorage/migrateall', {})).data.migrated).to.equal(0)
    })
    it('should trust legacy names without rehashing on a case-sensitive filesystem', async () => {
      await client.post('/filestorage/legacyupload', { content: 'q', checksum: 'q'.repeat(43) })
      await client.post('/filestorage/legacyupload', { content: 'Q', checksum: 'Q'.repeat(43) })
      const { data: checksums } = await client.get('/filestorage/checksums')
      // contents don't match the names, so these would be skipped if they had been rehashed
      expect(checksums).to.include.members(['q'.repeat(43), 'Q'.repeat(43)])
      await client.post(`/filestorage/remove/${'q'.repeat(43)}`, {})
      await client.post(`/filestorage/remove/${'Q'.repeat(43)}`, {})
    })
    it('should remove empty folders after removing a file, but not folders that still hold files', async () => {
      const { data } = await client.post('/filestorage/removeprune', {})
      expect(data.afterFirst).to.deep.equal({ leaf: false, top: true })
      expect(data.afterSecond).to.deep.equal({ top: false, permdir: true })
    })
    it('should remove empty legacy folders after migrating a file', async () => {
      const { data } = await client.post('/filestorage/migrateprune', {})
      expect(data).to.deep.equal({ migrated: true, legacyTop: false, stored: true })
    })
    it('should clean up tmp files older than the threshold', async () => {
      const { data } = await client.post('/filestorage/cleanuptmp', { ageMs: [2 * 60 * 60 * 1000, 5 * 60 * 1000, 0], olderThanMs: 60 * 60 * 1000 })
      expect(data.deleted).to.equal(1)
      expect(data.remaining).to.deep.equal([false, true, true, true])
    })
    it('should clean up day-old tmp files during init', async () => {
      const { data } = await client.post('/filestorage/cleanuptmp', { ageMs: [25 * 60 * 60 * 1000, 23 * 60 * 60 * 1000], viaInit: true })
      expect(data.remaining).to.deep.equal([false, true, true])
    })
    it('should download a byte range of a file', async () => {
      const formData = new FormData()
      formData.append('file', new Blob([Buffer.from('0123456789')], { type: 'text/plain' }), 'range.txt')
      const { data: [{ checksum }] } = await client.post('/filestorage/upload', formData)
      const middle = await client.get(`/filestorage/download/${checksum}?start=2&end=5`, { responseType: 'arraybuffer' })
      expect(Buffer.from(middle.data).toString()).to.equal('2345')
      const tail = await client.get(`/filestorage/download/${checksum}?start=7`, { responseType: 'arraybuffer' })
      expect(Buffer.from(tail.data).toString()).to.equal('789')
    })
    it('should download a byte range of a legacy file that has not been migrated', async () => {
      const { data: { checksum } } = await client.post('/filestorage/legacyupload', { content: 'abcdefghij' })
      const middle = await client.get(`/filestorage/download/${checksum}?start=2&end=5`, { responseType: 'arraybuffer' })
      expect(Buffer.from(middle.data).toString()).to.equal('cdef')
    })
    it('should return 404 for a non-existent checksum', async () => {
      try {
        await client.get('/filestorage/download/nonexistentchecksum')
        expect.fail('should have thrown')
      } catch (e: any) {
        expect(e.response.status).to.equal(404)
      }
    })
    it('should deduplicate identical files by checksum', async () => {
      const fileContent = Buffer.from('identical content for dedup test')
      const formData1 = new FormData()
      formData1.append('file', new Blob([fileContent], { type: 'text/plain' }), 'file1.txt')
      const resp1 = await client.post('/filestorage/upload', formData1)
      const formData2 = new FormData()
      formData2.append('file', new Blob([fileContent], { type: 'text/plain' }), 'file2.txt')
      const resp2 = await client.post('/filestorage/upload', formData2)
      expect(resp1.data[0].checksum).to.equal(resp2.data[0].checksum)
      expect(resp1.data[0].filename).to.equal('file1.txt')
      expect(resp2.data[0].filename).to.equal('file2.txt')
    })
    it('should handle uploading multiple files at once', async () => {
      const formData = new FormData()
      formData.append('file1', new Blob([Buffer.from('first file')], { type: 'text/plain' }), 'first.txt')
      formData.append('file2', new Blob([Buffer.from('second file')], { type: 'text/plain' }), 'second.txt')
      const resp = await client.post('/filestorage/upload', formData)
      expect(resp.data).to.be.an('array').with.lengthOf(2)
      expect(resp.data[0].checksum).to.not.equal(resp.data[1].checksum)
    })
  })

  describe('postFormData', () => {
    it('should post file data', async () => {
      const fileData = Buffer.from('JVBERi0xLjQKMSAwIG9iago8PC9UeXBlIC9DYXRhbG9nCi9QYWdlcyAyIDAgUgo+PgplbmRvYmoK MiAwIG9iago8PC9UeXBlIC9QYWdlcwovS2lkcyBbMyAwIFJdCi9Db3VudCAxCj4+CmVuZG9iagoz IDAgb2JqCjw8L1R5cGUgL1BhZ2UKL1BhcmVudCAyIDAgUgovTWVkaWFCb3ggWzAgMCA1OTUgODQy XQovQ29udGVudHMgNSAwIFIKL1Jlc291cmNlcyA8PC9Qcm9jU2V0IFsvUERGIC9UZXh0XQovRm9u dCA8PC9GMSA0IDAgUj4+Cj4+Cj4+CmVuZG9iago0IDAgb2JqCjw8L1R5cGUgL0ZvbnQKL1N1YnR5 cGUgL1R5cGUxCi9OYW1lIC9GMQovQmFzZUZvbnQgL0hlbHZldGljYQovRW5jb2RpbmcgL01hY1Jv bWFuRW5jb2RpbmcKPj4KZW5kb2JqCjUgMCBvYmoKPDwvTGVuZ3RoIDUzCj4+CnN0cmVhbQpCVAov RjEgMjAgVGYKMjIwIDQwMCBUZAooRHVtbXkgUERGKSBUagpFVAplbmRzdHJlYW0KZW5kb2JqCnhy ZWYKMCA2CjAwMDAwMDAwMDAgNjU1MzUgZgowMDAwMDAwMDA5IDAwMDAwIG4KMDAwMDAwMDA2MyAw MDAwMCBuCjAwMDAwMDAxMjQgMDAwMDAgbgowMDAwMDAwMjc3IDAwMDAwIG4KMDAwMDAwMDM5MiAw MDAwMCBuCnRyYWlsZXIKPDwvU2l6ZSA2Ci9Sb290IDEgMCBSCj4+CnN0YXJ0eHJlZgo0OTUKJSVF T0YK', 'base64')
      const formData = new FormData()
      formData.append('file', new Blob([fileData], { type: 'application/pdf' }), 'dummy.pdf')
      const resp = await client.post('/proxymultipart', formData)
      expect(resp.data).to.deep.equal({ received: fileData.length, files: 1, textFields: 0 })
    })
    it('should stream a file much larger than busboy\'s 64KB buffer without stalling', async () => {
      const fileData = Buffer.alloc(512 * 1024, 'x')
      const formData = new FormData()
      formData.append('note', 'this text field exercises the non-file path')
      formData.append('file', new Blob([fileData], { type: 'application/octet-stream' }), 'big.bin')
      const resp = await client.post('/proxymultipart', formData)
      expect(resp.data).to.deep.equal({ received: fileData.length, files: 1, textFields: 1 })
    })
    it('should forward only the files when using formDataFilesFromParts', async () => {
      const fileData = Buffer.from('files-only forwarding test')
      const formData = new FormData()
      formData.append('note', 'this text field should be dropped')
      formData.append('file', new Blob([fileData], { type: 'text/plain' }), 'keep.txt')
      const resp = await client.post('/proxymultipartfiles', formData)
      expect(resp.data).to.deep.equal({ received: fileData.length, files: 1, textFields: 0 })
    })
  })

  // last, because waiting on the 5s flush lets fastify-http's keep-alive connection go idle,
  // and after the /shutdown test that lets it exit; fastify-https never shuts down
  describe('OpenTelemetry tests', () => {
    const spansFor = (traceId: string) => otlpSpans.filter(s => s.span.traceId === traceId)
    const durationPoint = (route: string) => otlpMetrics.findLast(m => m.metric.name === 'http.server.request.duration')?.metric.histogram?.dataPoints.find(p => otlpAttributes(p.attributes)['http.route'] === route)
    let analyticsStart: number
    let tracingResp: { fetch: string, http: string }
    let apiResp: { injected: string }
    let jobResp: { rethrown: boolean }
    // make every request up front so the tests below share one wait on the exporters' flush intervals
    before(async () => {
      // the unsampled requests go first, so once the sampled ones arrive we know these would have too
      await httpsClient.get('/test', { headers: { traceparent: '00-6bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00' } })
      await httpsClient.post('/analytics', [{ eventType: 'UntracedEvent', screen: '/', action: 'View' } satisfies InteractionEvent], { headers: { traceparent: '00-8bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01' } })
      analyticsStart = Date.now()
      await httpsClient.post('/analytics', [{ eventType: 'OtlpTestEvent', screen: '/pages/[id]', action: 'Edit', target: '/pages/12', additionalProperties: { path: 'areas.main' } } satisfies InteractionEvent], { headers: { Cookie: '_ga=GA1.2.123.456' } })
      await httpsClient.get('/telemetry')
      await httpsClient.get('/telemetry')
      await httpsClient.get('/telemetry/api')
      await httpsClient.get('/telemetry', { headers: { traceparent: '00-9bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01' } })
      tracingResp = (await httpsClient.get<{ fetch: string, http: string }>('/tracing', { headers: { traceparent: '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01', tracestate: 'vendor=abc' } })).data
      await httpsClient.get('/tracing/app', { headers: { traceparent: '00-abf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01' } })
      apiResp = (await httpsClient.get<{ injected: string }>('/tracing/api', { headers: { traceparent: '00-3bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01' } })).data
      await httpsClient.get('/telemetry/histogram')
      await httpsClient.get('/test')
      await httpsClient.get('/health')
      await httpsClient.get('/telemetry/cardinality')
      await httpsClient.get('/tracing/db', { headers: { traceparent: '00-7bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01' } })
      await httpsClient.get('/tracing/mongo', { headers: { traceparent: '00-fbf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01' } })
      await httpsClient.get('/500', { headers: { traceparent: '00-5bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01' }, validateStatus: () => true })
      await httpsClient.get('/422', { headers: { traceparent: '00-cbf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01' }, validateStatus: () => true })
      await httpsClient.get('/telemetry/report', { headers: { traceparent: '00-dbf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01' } })
      jobResp = (await httpsClient.get<{ rethrown: boolean }>('/telemetry/job', { headers: { traceparent: '00-ebf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01' } })).data
      // analytics flush every 5s, spans every 5s, metrics every 1s (OTEL_METRIC_EXPORT_INTERVAL in docker-compose.yml)
      const arrived = () => otlpLogs.some(l => l.attributes.eventType === 'OtlpTestEvent')
        && otlpLogs.some(l => l.attributes.eventType === 'UntracedEvent')
        && otlpLogs.some(l => l.record.traceId === '9bf92f3577b34da6a3ce929d0e0e4736')
        && otlpMetrics.findLast(m => m.metric.name === 'testserver.telemetry.hits')?.metric.sum?.dataPoints[0].asDouble === 3
        && otlpMetrics.some(m => m.metric.name === 'testserver.queue.depth')
        && ['testlib.queued', 'testlib.temperature', 'testlib.cpu.time', 'testlib.connections'].every(name => otlpMetrics.some(m => m.metric.name === name))
        && otlpLogs.some(l => l.record.eventName === 'testlib.failed')
        && otlpMetrics.some(m => m.metric.name === 'testserver.duration')
        && otlpMetrics.some(m => m.metric.name === 'testserver.cardinality')
        && !!durationPoint('/test')
        && spansFor('9bf92f3577b34da6a3ce929d0e0e4736').length >= 1
        && spansFor('4bf92f3577b34da6a3ce929d0e0e4736').length >= 3
        && spansFor('3bf92f3577b34da6a3ce929d0e0e4736').length >= 3
        && spansFor('abf92f3577b34da6a3ce929d0e0e4736').length >= 3
        && spansFor('7bf92f3577b34da6a3ce929d0e0e4736').length >= 2
        && spansFor('fbf92f3577b34da6a3ce929d0e0e4736').length >= 3
        && spansFor('5bf92f3577b34da6a3ce929d0e0e4736').length >= 1
        && spansFor('cbf92f3577b34da6a3ce929d0e0e4736').length >= 1
        && spansFor('dbf92f3577b34da6a3ce929d0e0e4736').length >= 1
        && otlpSpans.some(s => s.span.name === 'testserver.cleanup')
        && otlpLogs.some(l => l.record.eventName === 'http.server.request.exception')
        && otlpLogs.some(l => l.attributes['exception.message'] === 'could not reach the mail server')
        && otlpLogs.some(l => l.attributes['exception.message'] === 'cleanup failed')
      for (let i = 0; i < 80 && !arrived(); i++) await new Promise<void>(resolve => { setTimeout(resolve, 250) })
    })

    it('should export analytics events to the OpenTelemetry collector', () => {
      const log = otlpLogs.find(l => l.attributes.eventType === 'OtlpTestEvent')
      expect(log, 'event never reached the collector').to.exist
      expect(log!.record.eventName).to.equal('analytics.interaction')
      expect(log!.scope.name).to.equal('fastify-txstate')
      expect(log!.resource['service.name']).to.equal('fastify-https')
      expect(log!.attributes).to.include({
        screen: '/pages/[id]',
        action: 'Edit',
        target: '/pages/12',
        'additionalProperties.path': 'areas.main',
        appName: 'testserver',
        environment: 'production',
        'user.username': 'unauthenticated',
        'user.ga': 'GA1.2.123.456'
      })
      const eventTime = Number(BigInt(log!.record.timeUnixNano) / 1_000_000n)
      expect(eventTime).to.be.within(analyticsStart - 1000, Date.now())
    })

    it('should export metrics and logs recorded through @opentelemetry/api', () => {
      const metric = (name: string) => otlpMetrics.findLast(m => m.metric.name === name)
      const queued = metric('testlib.queued')
      expect(queued, 'up-down counter never reached the collector').to.exist
      expect(queued!.scope).to.deep.equal({ name: 'testlib', version: '0.1.0' })
      expect(queued!.metric.sum?.isMonotonic).to.not.be.ok
      expect(queued!.metric.sum?.dataPoints[0].asDouble).to.equal(3)
      expect(metric('testlib.temperature')?.metric.gauge?.dataPoints[0].asDouble).to.equal(21.5)
      const cpu = metric('testlib.cpu.time')
      expect(cpu?.metric.sum?.isMonotonic).to.be.true
      expect(cpu?.metric.sum?.dataPoints.map(p => p.asDouble)).to.deep.equal([12.5])
      const connections = metric('testlib.connections')
      expect(connections?.metric.sum?.isMonotonic).to.not.be.ok
      expect(connections?.metric.sum?.dataPoints[0].asDouble).to.equal(4)
      expect(otlpAttributes(connections?.metric.sum?.dataPoints[0].attributes)).to.deep.equal({ 'testlib.pool': 'main' })

      const log = otlpLogs.find(l => l.record.eventName === 'testlib.failed')
      expect(log, 'log never reached the collector').to.exist
      expect(log!.scope).to.deep.equal({ name: 'testlib', version: '0.1.0' })
      expect(log!.record).to.include({ severityNumber: 17 })
      expect(log!.attributes).to.include({ 'testlib.step': 'parse', 'exception.type': 'TypeError', 'exception.message': 'bad input' })
    })

    it('should export an app\'s own metrics and logs under its own scope', () => {
      const counter = otlpMetrics.findLast(m => m.metric.name === 'testserver.telemetry.hits')
      const gauge = otlpMetrics.find(m => m.metric.name === 'testserver.queue.depth')
      const log = otlpLogs.find(l => l.record.eventName === 'testserver.hit')
      expect(counter, 'counter never reached the collector').to.exist
      expect(counter!.scope).to.deep.equal({ name: 'testserver', version: '1.2.3' })
      expect(counter!.resource['service.name']).to.equal('fastify-https')
      expect(counter!.metric).to.include({ description: 'Requests to /telemetry', unit: '{request}' })
      expect(counter!.metric.sum?.isMonotonic).to.be.true
      expect(counter!.metric.sum?.dataPoints[0].asDouble).to.equal(3)
      expect(otlpAttributes(counter!.metric.sum?.dataPoints[0].attributes)).to.deep.equal({ 'testserver.kind': 'test' })

      expect(gauge, 'gauge never reached the collector').to.exist
      expect(gauge!.scope.name).to.equal('testserver')
      expect(gauge!.metric.gauge?.dataPoints[0].asDouble).to.equal(7)
      expect(otlpAttributes(gauge!.metric.gauge?.dataPoints[0].attributes)).to.deep.equal({ 'testserver.queue': 'email' })

      expect(log, 'log never reached the collector').to.exist
      expect(log!.scope).to.deep.equal({ name: 'testserver', version: '1.2.3' })
      expect(log!.record).to.include({ severityNumber: 13, severityText: 'WARN' })
      expect(log!.record.body?.stringValue).to.equal('hit the telemetry route')
      expect(log!.attributes).to.deep.equal({ 'testserver.kind': 'test' })
    })

    it('should stamp a log emitted during a request with the request\'s trace and span', () => {
      const traceId = '9bf92f3577b34da6a3ce929d0e0e4736'
      const log = otlpLogs.find(l => l.record.traceId === traceId)
      const server = spansFor(traceId).find(s => s.span.kind === 2)
      expect(log, 'log never reached the collector').to.exist
      expect(server, 'span never reached the collector').to.exist
      expect(log!.record.eventName).to.equal('testserver.hit')
      expect(log!.record.spanId).to.equal(server!.span.spanId)
      expect(log!.record.flags).to.equal(1)
    })

    it('should trace a request and its outgoing calls, continuing the caller\'s trace', () => {
      const traceId = '4bf92f3577b34da6a3ce929d0e0e4736'
      const callerSpanId = '00f067aa0ba902b7'
      const spans = spansFor(traceId)
      const server = spans.find(s => s.span.kind === 2)
      expect(server, 'server span never reached the collector').to.exist
      expect(server!.span.name).to.equal('GET /tracing')
      expect(server!.span.parentSpanId).to.equal(callerSpanId)
      expect(server!.resource['service.name']).to.equal('fastify-https')
      expect(server!.resource['deployment.environment.name']).to.equal('production')
      expect(server!.resource['service.version']).to.equal('v1.2.3')
      expect(server!.attributes).to.include({ 'http.request.method': 'GET', 'http.route': '/tracing', 'url.path': '/tracing', 'http.response.status_code': '200' })

      const clients = spans.filter(s => s.span.kind === 3)
      expect(clients).to.have.lengthOf(2)
      for (const client of clients) {
        expect(client.span.parentSpanId).to.equal(server!.span.spanId)
        expect(client.span.name).to.equal('GET')
        expect(client.attributes).to.include({ 'http.request.method': 'GET', 'server.address': 'fastify-test', 'server.port': '4318', 'http.response.status_code': '200' })
      }
      expect(clients.map(c => c.attributes['url.full'])).to.have.members(['http://fastify-test:4318/echo', 'http://fastify-test:4318/echo?token=REDACTED'])
      // each outgoing request carries its own client span as the parent
      expect(clients.map(c => `00-${traceId}-${c.span.spanId}-01`)).to.have.members([tracingResp.fetch, tracingResp.http])
    })

    it('should put spans made through @opentelemetry/api into the request\'s trace', () => {
      const traceId = '3bf92f3577b34da6a3ce929d0e0e4736'
      const spans = spansFor(traceId)
      const server = spans.find(s => s.span.kind === 2)
      const work = spans.find(s => s.span.kind === 1)
      const fetchSpan = spans.find(s => s.span.kind === 3)
      expect(work, 'API span never reached the collector').to.exist
      expect(work!.scope).to.deep.equal({ name: 'testserver', version: '1.2.3' })
      expect(work!.span.name).to.equal('testserver.work')
      expect(work!.span.parentSpanId).to.equal(server?.span.spanId)
      expect(work!.span.status).to.deep.equal({ code: 2, message: 'partly failed' })
      const tags = work!.span.attributes?.find(a => a.key === 'testserver.tags')
      expect(tags?.value.arrayValue?.values.map(v => v.stringValue)).to.deep.equal(['a', 'b'])
      // our own instrumentation nests under the API span, and propagation.inject uses it too
      expect(fetchSpan!.span.parentSpanId).to.equal(work!.span.spanId)
      expect(apiResp.injected).to.equal(`00-${traceId}-${work!.span.spanId}-01`)
    })

    it('should put spans from fastify-txstate\'s own trace export into the request\'s trace', () => {
      const spans = spansFor('abf92f3577b34da6a3ce929d0e0e4736')
      const server = spans.find(s => s.span.kind === 2)
      const chat = spans.find(s => s.span.name === 'chat test-model')
      const fetchSpan = spans.find(s => s.span.name === 'GET')
      expect(chat, 'app span never reached the collector').to.exist
      expect(chat!.scope).to.deep.equal({ name: 'testserver', version: '1.2.3' })
      expect(chat!.span.kind).to.equal(3)
      expect(chat!.span.parentSpanId).to.equal(server?.span.spanId)
      expect(chat!.attributes).to.include({ 'gen_ai.operation.name': 'chat', 'gen_ai.request.model': 'test-model', 'gen_ai.usage.input_tokens': '1200', 'gen_ai.usage.output_tokens': '300' })
      // the provider call nests under the model call span
      expect(fetchSpan!.span.parentSpanId).to.equal(chat!.span.spanId)
    })

    it('should export a histogram with explicit buckets', () => {
      const metric = otlpMetrics.findLast(m => m.metric.name === 'testserver.duration')
      expect(metric, 'histogram never reached the collector').to.exist
      expect(metric!.metric).to.include({ description: 'How long the job took', unit: 's' })
      expect(metric!.metric.histogram?.aggregationTemporality).to.equal(2)
      const point = metric!.metric.histogram!.dataPoints[0]
      expect(otlpAttributes(point.attributes)).to.deep.equal({ 'testserver.kind': 'test' })
      expect(point.explicitBounds).to.deep.equal([0.1, 1, 10])
      // bounds are inclusive, so 1 lands in the (0.1, 1] bucket
      expect(point.bucketCounts).to.deep.equal(['1', '2', '0', '1'])
      expect(point).to.include({ count: '4', sum: 21.55, min: 0.05, max: 20 })
    })

    it('should record each request\'s duration in http.server.request.duration', () => {
      const point = durationPoint('/test')
      expect(point, 'request duration never reached the collector').to.exist
      const metric = otlpMetrics.findLast(m => m.metric.name === 'http.server.request.duration')!
      expect(metric.scope.name).to.equal('fastify-txstate')
      expect(metric.metric.unit).to.equal('s')
      expect(otlpAttributes(point!.attributes)).to.deep.equal({ 'http.request.method': 'GET', 'http.route': '/test', 'http.response.status_code': '200' })
      expect(Number(point!.count)).to.be.at.least(1)
      expect(point!.explicitBounds).to.have.lengthOf(14)
      // like tracing, health checks are left out
      expect(metric.metric.histogram!.dataPoints.find(p => otlpAttributes(p.attributes)['http.route'] === '/health')).to.not.exist
    })

    it('should count attribute sets past the cardinality limit in one overflow series', () => {
      const metric = otlpMetrics.findLast(m => m.metric.name === 'testserver.cardinality')
      expect(metric, 'metric never reached the collector').to.exist
      const points = metric!.metric.sum!.dataPoints
      expect(points).to.have.lengthOf(2001)
      const overflow = points.filter(p => p.attributes?.some(a => a.key === 'otel.metric.overflow' && a.value.boolValue === true))
      expect(overflow).to.have.lengthOf(1)
      expect(overflow[0].asDouble).to.equal(5)
      expect(overflow[0].attributes).to.have.lengthOf(1)
      // a set seen before the limit keeps its own series
      expect(points.find(p => p.attributes?.[0].value.intValue === '0')?.asDouble).to.equal(2)
    })

    it('should trace a database query from its diagnostics channel, without literals', () => {
      const spans = spansFor('7bf92f3577b34da6a3ce929d0e0e4736')
      const server = spans.find(s => s.span.kind === 2)
      const db = spans.find(s => s.span.kind === 3)
      expect(db, 'database span never reached the collector').to.exist
      expect(db!.span.parentSpanId).to.equal(server?.span.spanId)
      expect(db!.span.name).to.equal('SELECT users roles')
      expect(db!.attributes).to.include({
        'db.system.name': 'mysql',
        'db.namespace': 'app',
        'db.query.summary': 'SELECT users roles',
        'db.query.text': 'SELECT * FROM `users` u JOIN roles r ON r.userId = u.id WHERE u.name = ? AND u.age > ?',
        'server.address': 'db',
        'server.port': '3306'
      })
    })

    it('should trace mongoose operations from their diagnostics channels, without filters', () => {
      const spans = spansFor('fbf92f3577b34da6a3ce929d0e0e4736')
      const server = spans.find(s => s.span.kind === 2)
      const find = spans.find(s => s.span.name === 'find users')
      const save = spans.find(s => s.span.name === 'save users')
      expect(find, 'find span never reached the collector').to.exist
      expect(save, 'save span never reached the collector').to.exist
      expect(find!.span.parentSpanId).to.equal(server?.span.spanId)
      expect(find!.span.kind).to.equal(3)
      expect(find!.attributes).to.include({
        'db.system.name': 'mongodb',
        'db.namespace': 'app',
        'db.collection.name': 'users',
        'db.operation.name': 'find',
        'server.address': 'mongo',
        'server.port': '27017'
      })
      expect(JSON.stringify(find!.attributes)).not.to.include('secret')
      expect(find!.span.status?.code).not.to.equal(2)
      expect(save!.span.status?.code).to.equal(2)
      expect(save!.attributes).to.include({ 'error.type': 'DuplicateKey', 'db.response.status_code': '11000' })
      expect(save!.span.events?.some(e => e.name === 'exception')).to.equal(true)
    })

    it('should record an exception on a failed request\'s span', () => {
      const server = spansFor('5bf92f3577b34da6a3ce929d0e0e4736').find(s => s.span.kind === 2)
      expect(server, 'span never reached the collector').to.exist
      expect(server!.span.status?.code).to.equal(2)
      expect(server!.attributes['error.type']).to.equal('500')
      const exception = server!.span.events?.find(e => e.name === 'exception')
      expect(exception, 'no exception event').to.exist
      expect(otlpAttributes(exception!.attributes)).to.include({ 'exception.type': 'Error', 'exception.message': 'Random Error' })
    })

    it('should export a failed request\'s exception as a log record in its trace', () => {
      const traceId = '5bf92f3577b34da6a3ce929d0e0e4736'
      const server = spansFor(traceId).find(s => s.span.kind === 2)
      const log = otlpLogs.find(l => l.record.eventName === 'http.server.request.exception' && l.record.traceId === traceId)
      expect(log, 'exception log never reached the collector').to.exist
      expect(log!.scope.name).to.equal('fastify-txstate')
      expect(log!.record).to.include({ severityNumber: 17, severityText: 'ERROR', spanId: server?.span.spanId })
      expect(log!.attributes).to.include({ 'exception.type': 'Error', 'exception.message': 'Random Error', 'http.request.method': 'GET', 'http.route': '/500' })
      expect(log!.attributes['exception.stacktrace']).to.include('Random Error')
    })

    it('should not record an error that an error handler turned into a 4xx', () => {
      const traceId = 'cbf92f3577b34da6a3ce929d0e0e4736'
      const server = spansFor(traceId).find(s => s.span.kind === 2)
      expect(server, 'span never reached the collector').to.exist
      expect(server!.span.status?.code).to.not.equal(2)
      expect(server!.span.events ?? []).to.be.empty
      expect(otlpLogs.filter(l => l.record.traceId === traceId)).to.be.empty
    })

    it('should export an error the app reported itself, and fail the active span', () => {
      const traceId = 'dbf92f3577b34da6a3ce929d0e0e4736'
      const server = spansFor(traceId).find(s => s.span.kind === 2)
      const log = otlpLogs.find(l => l.attributes['exception.message'] === 'could not reach the mail server')
      expect(log, 'exception log never reached the collector').to.exist
      expect(log!.record).to.include({ eventName: 'exception', severityNumber: 17, traceId, spanId: server?.span.spanId })
      expect(log!.attributes).to.include({ 'exception.type': 'CustomError', 'testserver.kind': 'test' })
      expect(server!.span.status?.code).to.equal(2)
      expect(server!.attributes['error.type']).to.equal('CustomError')
    })

    it('should trace a background job in its own trace, report its failure and rethrow', () => {
      expect(jobResp.rethrown).to.be.true
      const job = otlpSpans.find(s => s.span.name === 'testserver.cleanup')
      expect(job, 'job span never reached the collector').to.exist
      expect(job!.span.traceId).to.not.equal('ebf92f3577b34da6a3ce929d0e0e4736')
      expect(job!.span.parentSpanId).to.not.be.ok
      expect(job!.span.kind).to.equal(1)
      expect(job!.span.status?.code).to.equal(2)
      expect(job!.attributes).to.include({ 'testserver.job': 'cleanup', 'error.type': 'Error' })
      // the job's own outgoing call nests under it
      expect(spansFor(job!.span.traceId).find(s => s.span.kind === 3)?.span.parentSpanId).to.equal(job!.span.spanId)
      const log = otlpLogs.find(l => l.attributes['exception.message'] === 'cleanup failed')
      expect(log, 'exception log never reached the collector').to.exist
      expect(log!.record).to.include({ eventName: 'exception', traceId: job!.span.traceId, spanId: job!.span.spanId })
      expect(log!.attributes).to.include({ 'testserver.job': 'cleanup' })
    })

    it('should not trace an unsampled request, or the analytics route', () => {
      expect(spansFor('6bf92f3577b34da6a3ce929d0e0e4736')).to.be.empty
      expect(spansFor('8bf92f3577b34da6a3ce929d0e0e4736')).to.be.empty
    })
  })
})
