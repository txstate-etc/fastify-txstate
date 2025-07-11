/* eslint-disable @typescript-eslint/no-redeclare */
import fastifyMultipart from '@fastify/multipart'
import { type FromSchema } from 'json-schema-to-ts'
import { isBlank } from 'txstate-utils'
import Server, { FormDataField, HttpError, analyticsPlugin, postFormData, registerUaCookieRoutes, requireCookieAuth, unifiedAuthenticate } from '../src'

class CustomError extends Error {}

const server = new Server({
  trustProxy: true,
  validOrigins: ['http://validorigin.com'],
  validOriginHosts: ['subd.validhost.com'],
  validOriginSuffixes: ['proxiedhost.com'],
  checkOrigin: req => req.headers['x-auto-cors-pass'] === '1',
  authenticate: unifiedAuthenticate
})
server.addErrorHandler(async (err, req, res) => {
  if (err instanceof CustomError) await res.status(422).send('My Custom Error')
})
registerUaCookieRoutes(server.app)

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
  await server.app.register(fastifyMultipart)

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
  server.app.post('/datetime', { schema: { body: { type: 'object', properties: { mydate: { type: 'string', format: 'date-time' } }, required: ['mydate'], additionalProperties: false }, response: { 200: { type: 'object', properties: { yourdate: { type: 'string', format: 'date-time' } } } } } }, (req, res) => {
    const date = new Date(req.body.mydate)
    return { yourdate: date.toISOString() }
  })
  server.app.post('/protected', async (req, res) => {
    if (isBlank(req.auth?.username)) throw new HttpError(401, 'Authentication is required.')
    return { authenticated: req.auth!.username, sessionCreatedAt: req.auth!.sessionCreatedAt }
  })
  server.app.post('/protectedCookie', async (req, res) => {
    if (await requireCookieAuth(req, res)) return
    return { authenticated: req.auth?.username }
  })
  server.app.post('/acceptupload', async (req, res) => {
    let contentLength = 0
    for await (const part of req.parts()) {
      if (part.type === 'file') {
        for await (const chunk of part.file) {
          contentLength += chunk.length
        }
      }
    }
    return { received: contentLength }
  })
  server.app.post('/proxymultipart', async (req, res) => {
    if (req.isMultipart()) {
      const fields: FormDataField[] = []
      for await (const part of req.parts()) {
        if (part.type === 'file') {
          fields.push({ name: part.fieldname, value: part.file, filename: part.filename, filetype: part.mimetype })
        }
      }
      const resp = await postFormData('http://fastify-http/acceptupload', fields)
      return await resp.json()
    } else {
      throw new HttpError(400, 'Expected multipart/form-data')
    }
  })
})
  .then(async () => server.start())
  .catch(e => { console.error(e) })
