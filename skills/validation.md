# fastify-txstate: Validation & Error Messages

Use this skill when building RESTful API endpoints that validate input and return structured error messages to the client.

## Response Format

All endpoints that require validation should follow this shape:
```json
{
  "success": false,
  "messages": [
    { "type": "error", "message": "Title is required.", "path": "title" },
    { "type": "error", "message": "Zip code is required.", "path": "address.zip" }
  ]
}
```

This format is supported by the `@txstate-mws/svelte-forms` library, so messages can be passed directly into forms for display.

## Message Structure

Each message has:
| Field | Required | Description |
|-------|----------|-------------|
| `type` | Yes | `'error'` \| `'warning'` \| `'success'` \| `'system'` \| `'info'` |
| `message` | Yes | Human-readable text to display to the user |
| `path` | No | Dot-separated path to the input field (e.g. `'address.zip'`, `'cart.item.0.quantity'`) |

### Message types
- `error` — the user did something wrong and must fix it before resubmitting.
- `warning` — something may be wrong but the operation can still proceed.
- `info` — informational feedback (e.g. "This name is already taken but you can still use it").
- `success` — positive confirmation (e.g. "Username is available").
- `system` — something the user is not responsible for (e.g. database offline, upstream service unavailable).

`hasFatalErrors(messages)` from `@txstate-mws/fastify-shared` returns true if any message has type `error` or `system`.

## Throwing Validation Errors

Collect all messages first, then throw them together so the user sees every problem at once:
```javascript
import { ValidationErrors } from 'fastify-txstate'
import { hasFatalErrors, validatedResponse } from '@txstate-mws/fastify-shared'

server.app.post('/saveathing', { schema: { response: { 200: validatedResponse, 422: validatedResponse } } }, async (req, res) => {
  const thing = req.body
  const messages = []
  if (!thing.title) messages.push({ message: 'Title is required.', path: 'title', type: 'error' })
  if (!thing?.address?.zip) messages.push({ message: 'Zip code is required.', path: 'address.zip', type: 'error' })
  if (thing.title && thing.title.length > 200) messages.push({ message: 'Title must be under 200 characters.', path: 'title', type: 'error' })
  if (hasFatalErrors(messages)) throw new ValidationErrors(messages)
  // continue processing — save to database, etc.
})
```

The client receives HTTP 422 with the `{ success, messages }` JSON body.

### Important
- Always prefer `ValidationErrors` (plural) over `ValidationError`. Throwing one error at a time forces users to fix and resubmit repeatedly without knowing how many problems remain.
- `ValidationError` (singular) exists for quick one-offs: `throw new ValidationError('Wrong!', 'answer')` — but reach for `ValidationErrors` by default.

## Validate-Only Requests

The shared library exports a `queryWithValidateFlag` schema for endpoints that support a `?validate=1` query parameter. This lets the client check validity without committing the operation.
```javascript
import { queryWithValidateFlag, validatedResponse } from '@txstate-mws/fastify-shared'

server.app.post('/saveathing', { schema: { querystring: queryWithValidateFlag, response: { 200: validatedResponse, 422: validatedResponse } } }, async (req, res) => {
  const thing = req.body
  const messages = []
  // ... collect validation messages ...
  if (hasFatalErrors(messages)) throw new ValidationErrors(messages)
  if (req.query.validate) return { success: true, messages }
  // only proceed with the actual save if not a validate-only request
  await db.save(thing)
  return { success: true, messages }
})
```