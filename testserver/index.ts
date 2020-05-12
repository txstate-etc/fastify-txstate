import Server, { RequestError } from '../src'

class CustomError extends Error {

}

const server = new Server()
server.app.get('/test', async (req, res) => {
  return { hello: 'world' }
})
server.app.get('/403', async (req, res) => {
  throw new RequestError(403, 'Not Authorized')
})
server.app.get('/409', async (req, res) => {
  throw new RequestError(409)
})
server.app.get('/422', async (req, res) => {
  throw new CustomError('My Custom Error')
})
server.app.get('/500', async (req, res) => {
  throw new Error('Random Error')
})
server.addErrorHandler(async (err, req, res) => {
  if (err instanceof CustomError) res.status(422).send('My Custom Error')
})
server.start()
