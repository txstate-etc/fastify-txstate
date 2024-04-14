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

You may skip the message string and a default will be used, e.g. `throw new HttpError(401)` sends a plain text body: `Authentication is required.`
## ValidationErrors
This class helps an API communicate with its client about errors that occured during a validation or writing operation. The constructor takes three arguments: a message to be displayed to the user, a dot-separated path to the property of the input object that the message is related to, and a message type, which could be 'error', 'info', 'warning', 'success', or 'system' (system is for errors that the user is not responsible for like a database being offline).
```javascript
import { ValidationErrors } from 'fastify-txstate'
import { hasFatalErrors } from '@txstate-mws/fastify-shared'
server.app.post('/saveathing', async (req, res) => {
  const thing = req.body
  const messages = []
  if (!thing.title) messages.push({ message: 'Title is required.', path: 'title', type: 'error' })
  if (!thing?.address?.zip) messages.push({ message: 'Zip code is required.', path: 'address.zip', type: 'error' })
  if (hasFatalErrors(messages)) throw new ValidationErrors(messages)
  /* continue processing request */
})
```
The client will receive HTTP status 422 and a JSON body that looks like this:
```json
{
  "success": false,
  "messages": [
    { "type": "error", "message": "Zip code is required.", "path": "address.zip" }
  ]
}
```
This format is well supported by our @txstate-mws/svelte-forms library, so it should be easy to pass the errors into your form.

### ValidationError
`ValidationErrors` is preferred since it will show multiple errors at once, instead of making the user fix errors one at a time and not know how far they are from being done. If you just need to throw a quick single error, `throw new ValidationError('Wrong!', 'answer')` is also available.

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

# Origin Checking
To help prevent XSRF attacks, we automatically reject requests that send an origin header that doesn't match the host (sub)domain. Only domain is compared, not protocol or port. This is especially helpful in large organizations where untrusted web sites run under different subdomains. SameSite cookies can help with attacks from other domains, but attacks on the same subdomain can still succeed.

You can authorize more subdomains with the `validOriginHosts` configuration option, or by setting the `VALID_ORIGIN_HOSTS` environment variable. You can authorize subdomains at runtime with `server.setValidOriginHosts(hosts: string[])`.

You can disable these origin checks entirely with the `skipOriginCheck` configuration or `SKIP_ORIGIN_CHECK` environment variable.

# Reverse Proxy
If your application is behind a reverse proxy, you'll want to set the `trustProxy` configuration to true so that variables like `request.protocol` get set correctly. You can also set the `TRUST_PROXY` environment variable. `true` or `1` will translate to `{ trustProxy: true }`; anything else will be passed unchanged as a string.

# Logging
We try to set up logging well by default, including things like the HTTP traceparent header, and putting the url in both the incoming and outgoing access log entries so that it's easy to grep for certain routes/params.

Development and production logs are different, based on the `NODE_ENV` environment variable. The development logger is designed to be extremely brief and not in JSON format, so that you can see errors clearly.

If you want to manipulate the logging you can import the `devLogger` and `prodLogger` into your project, manipulate them, and pass them into the server constructor configuration.

You can also simply add information to the `reply.extraLogInfo` object and it will automatically appear in the outgoing access log in production.
