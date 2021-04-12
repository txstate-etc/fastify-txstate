/* eslint-disable @typescript-eslint/no-unused-expressions */
/* global before, describe, it */
import axios, { AxiosInstance } from 'axios'
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

before(async () => {
  await new Promise(resolve => setTimeout(resolve, 1000))
})

async function expectErrorCode (client: AxiosInstance, path: string, code: number) {
  try {
    await client.get(path)
    expect(true).to.be.false
  } catch (e) {
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
    const resp = await client.get('/protocol')
    expect(resp.data.protocol).to.equal('http')
  })
  it('should return the correct protocol when proxying', async () => {
    const resp = await client.get('/protocol', { headers: { 'X-Forwarded-Proto': 'https' } })
    expect(resp.data.protocol).to.equal('https')
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
    const resp = await httpsClient.get('/protocol')
    expect(resp.data.protocol).to.equal('https')
  })
})

describe('origin filtering', () => {
  it('should allow requests from the same origin subdomain', async () => {
    const resp = await client.get('/test', { headers: { origin: 'http://fastify-http' } })
    expect(resp.data.hello).to.equal('world')
  })
  it('should allow requests when port is redundantly specified', async () => {
    const resp = await client.get('/test', { headers: { origin: 'http://fastify-http:80' } })
    expect(resp.data.hello).to.equal('world')
  })
  it('should allow requests with a different origin port', async () => {
    const resp = await client.get('/test', { headers: { origin: 'http://fastify-http:3000' } })
    expect(resp.data.hello).to.equal('world')
  })
  it('should disallow requests from a different origin subdomain', async () => {
    try {
      await client.get('/test', { headers: { origin: 'http://fastify-fake' } })
      expect.fail('Should have gotten a 403.')
    } catch (e) {
      expect(e.response.statusCode === 403)
    }
  })
})
