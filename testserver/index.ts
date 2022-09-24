import Server, { HttpError } from '../src'

class CustomError extends Error {}

const server = new Server({
  trustProxy: true,
  validOrigins: ['http://validorgin.com'],
  validOriginHosts: ['subd.validhost.com'],
  validOriginSuffixes: ['proxiedhost.com'],
  checkOrigin: req => req.headers['x-auto-cors-pass'] === '1'
})
server.app.get('/test', async (req, res) => {
  return { hello: 'world' }
})
server.app.get('/403', async (req, res) => {
  throw new HttpError(403, 'Not Authorized')
})
server.app.get('/409', async (req, res) => {
  throw new HttpError(409)
})
server.app.get('/422', async (req, res) => {
  throw new CustomError('My Custom Error')
})
server.app.get('/500', async (req, res) => {
  throw new Error('Random Error')
})
server.app.get('/shutdown', async (req, res) => {
  await res.send('OK')
  await server.close(5000)
})
server.app.get('/proxy', async (req, res) => {
  return { protocol: req.protocol, hostname: req.hostname }
})
server.addErrorHandler(async (err, req, res) => {
  if (err instanceof CustomError) await res.status(422).send('My Custom Error')
})
server.start().catch(e => console.error(e))
