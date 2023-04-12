/* eslint-disable @typescript-eslint/no-unused-expressions */
/* global before, describe, it */
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

before(async function () {
  this.timeout(5000)
  for (let i = 0; i < 30; i++) {
    try {
      const resp = await client.get('/health')
      if (resp.status === 200) break
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
