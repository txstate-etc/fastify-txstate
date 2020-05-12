/* global before, describe, it */
import axios from 'axios'
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

describe('basic tests', () => {
  it('should be online and respond to request with { hello: "world" }', async () => {
    const resp = await client.get('/test')
    expect(resp.data.hello).to.equal('world')
  })
  it('should return a 403 by throwing an error', async () => {
    try {
      await client.get('/403')
      expect(false).to.be.true
    } catch (e) {
      expect(e.response.status).to.equal(403)
    }
  })
  it('should return 500 for any uncaught exception', async () => {
    try {
      await client.get('/500')
      expect(false).to.be.true
    } catch (e) {
      expect(e.response.status).to.equal(500)
    }
  })
  it('should be able to set a custom error handler', async () => {
    try {
      await client.get('/422')
      expect(false).to.be.true
    } catch (e) {
      expect(e.response.status).to.equal(422)
    }
  })
  it('should fill in reasonable error text for unhandled http status codes', async () => {
    try {
      await client.get('/409')
      expect(false).to.be.true
    } catch (e) {
      expect(e.response.status).to.equal(409)
      expect(e.response.data).to.equal('Conflict')
    }
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
})
