# fastify-txstate
A small wrapper for fastify providing a set of common conventions &amp; utility functions we use.

# Basic Usage
```javascript
const Server = require('fastify-txstate').default
const server = new Server()
server.app.get('/yourpath', async (req, res) => {
  return { hello: 'world' }
})
server.start().then(() => {
  console.log('started!')
}).catch(e => console.error(e))
```
* If you need special configuration for fastify, pass it to `new Server({ /* any valid fastify config */ })`.
* `server.app` is the fastify instance.
# Error Handling
Some resources are available to make error handling easy.
## HttpError
This class is available to throw simple errors while processing a request:
```javascript
const { HttpError } = require('fastify-txstate')
server.app.get('/yourpath', async (req, res) => {
  if (!req.params.id) throw new HttpError(400, 'Please provide an id.')
  /* ... */
})
```
This will result in a 400 error being returned to the client, with a plain text body: `Please provide an id.`

You may skip the message string and a default will be used, e.g. `throw new HttpError(401)` sends a plain text body: `Authentication failed.`
## FailedValidationError
This class helps an API communicate with its client about errors that occured during a validation or writing operation. An `errors` object should be passed during construction whose keys correspond to the dot-separated paths of the input object that had problems, and each value is an array of error messages related to that path.
```javascript
const { FailedValidationError } = require('fastify-txstate')
server.app.post('/saveathing', async (req, res) => {
  const thing = req.body
  const errors = {}
  if (!thing.title) errors.title = ['Title is required.']
  if (!thing?.address?.zip) errors['address.zip'] = ['Zip code is required.']
  if (Object.keys(errors).length) throw new FailedValidationError(errors)
  /* continue processing request */
})
```
## Custom Error Handling
If you would like special treatment for certain errors, `addErrorHandler` provides an easy way:
```javascript
server.addErrorHandler(async (err, req, res) => {
  if (err instanceof MyCustomErrorClass) {
    res.status(500).send('You done messed up.')
  }
})
```
In this case we only need custom error handling for a specific class of Error. Calling `res.send()` in your handler is how you signal that the error has been intercepted. If you do not call `res.send()`, the default error handling will kick in, so you can still throw `HttpError` or `FailedValidationError` and have them handled properly.

You may call `addErrorHandler` multiple times; they will be executed in order and bail out when one calls `res.send()`.
## Opt-Out of Error Handling
If you want all the error handling to yourself, you may use fastify's `setErrorHandler` method to override all of `fastify-txstate`'s behavior:
```javascript
server.app.setErrorHandler((err, req, res) => {
  /* whatever you want */
})
```
# SSL
SSL and HTTP2 support is enabled automatically if you provide a key and cert at `/securekeys/private.key` and `/securekeys/cert.pem`, respectively.

* If you do not provide a custom port, and SSL key and cert are not present, port 80 will be used.
* If you do not provide a custom port, and SSL key and cert are present, port 443 will be used and http traffic on port 80 will be redirected to https.
* You can set a custom port with e.g. `server.start(8080)`, or you can set the `PORT` environment variable. If the SSL key and cert are present, your custom port will expect https.

# Health checks / load-balanced restart
A health check is automatically available at `/health`. You may use `server.setUnhealthy('your message')` and `server.setHealthy()` to alter the response. When a SIGINT or SIGTERM is issued (e.g. during an intentional restart), you have the option of delaying for a few seconds to allow the load-balancer to see that you are down. Do this by setting the `LOAD_BALANCE_TIMEOUT` environment variable in seconds.

During this period, `/health` will return HTTP 503, but all other requests will process normally. After the period, the service shuts down as requested. This gives load balancers time to switch all incoming traffic to another service, ensuring no clients see an error during the restart.
