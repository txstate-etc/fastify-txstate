/* eslint-disable @typescript-eslint/no-redeclare */
import { type FromSchema } from 'json-schema-to-ts'
import Server, { HttpError, analyticsPlugin } from '../src'

class CustomError extends Error {}

const server = new Server({
  trustProxy: true,
  validOrigins: ['http://validorgin.com'],
  validOriginHosts: ['subd.validhost.com'],
  validOriginSuffixes: ['proxiedhost.com'],
  checkOrigin: req => req.headers['x-auto-cors-pass'] === '1',
  authenticate: async req => ({ username: 'testuser', sessionId: 'zzzzzzzzzzz' })
})
server.addErrorHandler(async (err, req, res) => {
  if (err instanceof CustomError) await res.status(422).send('My Custom Error')
})

const typedInput = {
  type: 'object',
  properties: {
    str: {
      type: 'string',
      description: 'This is a string. There are many like it. This one is yours.'
    },
    num: { type: 'number' },
    int: { type: 'integer', errorMessage: 'The "int" property must be an integer.' },
    array: { type: 'array', items: { type: 'integer' } }
  },
  examples: [{ num: 12 }],
  required: ['str'],
  additionalProperties: false
} as const
const typedInputRecursive = {
  ...typedInput,
  $id: '#typedInput',
  properties: {
    ...typedInput.properties,
    more: { type: 'array', items: { $ref: '#' } }
  }
} as const
export type TypedInput = FromSchema<typeof typedInput>
export type TypedInputRecursive = TypedInput & { more?: TypedInputRecursive[] }
server.swagger().then(async () => {
  await server.app.register(analyticsPlugin, { appName: 'testserver' })
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
  server.app.get('/logging', async (req, res) => {
    res.extraLogInfo = { hello: 'world' }
    return { success: true }
  })
  server.app.post<{ Body: TypedInputRecursive }>('/typed', { schema: { body: typedInputRecursive, response: { 200: { type: 'string' } } } }, (req, res) => {
    return req.body.str
  })
  server.app.post<{ Body: TypedInputRecursive }>('/numtyped', { schema: { body: typedInputRecursive, response: { 200: { type: 'object', properties: { num: { type: 'number' } } } } } }, (req, res) => {
    return { num: req.body.num }
  })
  server.app.post<{ Body: TypedInputRecursive }>('/badtyped', { schema: { body: typedInputRecursive, response: { 200: { type: 'integer' } } } }, (req, res) => {
    return 5.5
  })
})
  .then(async () => server.start())
  .catch(e => { console.error(e) })
