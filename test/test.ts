/* eslint-disable @typescript-eslint/unbound-method */
/* eslint-disable @typescript-eslint/no-unused-expressions */
/* global before, describe, it */
import type { InteractionEvent } from '@txstate-mws/fastify-shared'
import axios, { type AxiosInstance } from 'axios'
import { expect } from 'chai'
import https from 'https'

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
  baseURL: 'http://fakeauth',
})

before(async function () {
  this.timeout(5000)
  for (let i = 0; i < 30; i++) {
    try {
      const resp = await client.get('/health')
      if (resp.status === 200) {
        const resp2 = await httpsClient.get('/health')
        if (resp2.status === 200) break
      }
    } catch (e: any) {
      await new Promise(resolve => setTimeout(resolve, 200))
    }
  }
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

describe('basic tests', () => {
  it('should be online and respond to request with { hello: "world" }', async () => {
    const resp = await client.get('/test')
    expect(resp.data.hello).to.equal('world')
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
    expect(resp.data.hostname).to.equal('www.proxiedhost.com:3000')
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
  it('should reject a mis-typed payload with a 400 status', async () => {
    try {
      await client.post('/typed', {
        str: 3,
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
      console.log(e.response.data)
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
      console.log(e.response.data)
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
      await client.post('/protected', { test: true})
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
    expect(resp.data).to.deep.equal({ authenticated: 'testuser' })
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
      const resp = await client.get('/.uaRedirect', { params: { requestedUrl: 'http://fastify-http/protected' }, maxRedirects: 0 })
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
      expect(e.response.status).to.equal(302)
      expect(e.response.headers['set-cookie'][0]).to.include(`fastify_token=${encodeURIComponent(token!)}`)
      expect(e.response.headers.location).to.equal('http://fastify-http/protected')
    }
  })
  it('should delete the cookie and redirect to unified auth logout upon logout', async () => {
    try {
      await client.get('/.uaLogout', { headers: { Cookie: `fastify_token=${encodeURIComponent(token!)}` }, maxRedirects: 0 })
    } catch (e: any) {
      expect(e.response.status).to.equal(302)
      expect(e.response.headers['set-cookie'][0]).to.include('fastify_token=;')
      expect(e.response.headers.location).to.equal(`http://fakeauth/logout?unifiedJwt=${encodeURIComponent(token!)}`)
    }
  })
})
