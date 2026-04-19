# fastify-txstate: Endpoint Schemas

Use this skill when defining RESTful route schemas for request validation, response serialization, and OpenAPI/Swagger documentation.

## Built-in Type Inference

fastify-txstate configures the `@fastify/type-provider-json-schema-to-ts` type provider automatically. When you define a schema with `as const`, TypeScript infers the request types — no need for separate interfaces or generics:

```javascript
const createUserBody = {
  type: 'object',
  properties: {
    name: { type: 'string' },
    email: { type: 'string' },
    age: { type: 'integer', minimum: 0 }
  },
  additionalProperties: false
} as const

server.app.post('/users', {
  schema: {
    body: createUserBody,
    response: {
      200: {
        type: 'object',
        properties: {
          id: { type: 'string' },
          name: { type: 'string' },
          email: { type: 'string' }
        },
        required: ['id', 'name', 'email'],
        additionalProperties: false
      }
    }
  }
}, async (req, res) => {
  // req.body is typed as { name?: string, email?: string, age?: number }
  const user = await db.createUser(req.body)
  return user
})
```

The `as const` assertion is critical — without it, TypeScript widens the types and inference won't work.

### Do not use `required` on user-validated input schemas

When a schema marks a property as `required`, fastify rejects the request with a **400** before your route handler runs. The user sees a generic schema error instead of a friendly inline message on the form field.

Instead, make all user-input properties optional in the schema and check for them in your route handler, returning a `ValidationMessage` with a path so the UI can display it inline:

```javascript
// WRONG — user gets a 400 with no inline feedback
const body = { type: 'object', properties: { name: { type: 'string' } }, required: ['name'] } as const

// RIGHT — user gets a 422 with an inline message on the name field
const body = { type: 'object', properties: { name: { type: 'string' } } } as const
// then in the handler:
if (!req.body.name) messages.push({ message: 'Name is required.', path: 'name', type: 'error' })
```

Reserve `required` for response schemas and non-user-facing inputs where a missing field is a client bug, not a user mistake. This extends to other schema validations. Avoid using the schema to check regex patterns or formats that are under the user's control, only use it to check that the client is operating correctly/non-maliciously. ISO date format is acceptable if we can assume the client is preprocessing user input into ISO.

## SchemaObject Type

When defining schemas as standalone objects, use `as const satisfies SchemaObject` from `@txstate-mws/fastify-shared`. SchemaObject extends JSON Schema with OpenAPI properties (`example`, `description`) and `ajv-errors` support (`errorMessage`). Adding `as const satisfies SchemaObject` ensures schema is compliant without sacrificing json-schema-to-ts compatibility:

```typescript
import type { SchemaObject } from '@txstate-mws/fastify-shared'

const addressSchema = {
  type: 'object',
  properties: {
    street: { type: 'string', example: '123 Main St' },
    city: { type: 'string', example: 'San Marcos' },
    zip: { type: 'string', description: '5-digit US zip code' }
  },
  additionalProperties: false
} as const satisfies SchemaObject
```

## Pre-built Schemas from @txstate-mws/fastify-shared

The shared library provides reusable schemas for common patterns:

| Export | Description |
|--------|-------------|
| `validatedResponse` | Schema for `{ success: boolean, messages: ValidationMessage[] }`. Use for response schemas on mutation endpoints. |
| `validationMessage` | Schema for a single `{ type, message, path?, extra? }` message. |
| `queryWithValidateFlag` | Schema for `{ validate?: 0 \| 1 }` query string. Lets clients validate without committing. |

The library also exports TypeScript interfaces (`ValidatedResponse`, `ValidationMessage`, `QueryWithValidateFlag`) matching each schema.

## Automatic Response Schemas

When a route has a `body` schema, fastify-txstate automatically adds response schemas for:
- **400** — basic validation failure (request didn't match the schema). Indicates a client bug.
- **422** — validation failure (the user provided invalid data that passed schema validation but failed business rules).

If you don't specify a 200 response schema, a permissive `{ type: 'object' }` default is added.

## Validation Behavior

fastify-txstate configures Ajv with:
- **`coerceTypes: true`** — strings are coerced to numbers/booleans where the schema expects them.
- **`allErrors: true`** — all validation errors are reported, not just the first.
- **`ajv-formats`** — supports `format` keywords like `date-time`, `email`, `uri`, etc.
- **`ajv-errors`** — supports `errorMessage` for custom error text.
- **`strictSchema: false`** — allows OpenAPI properties (`example`, `description`) without errors.

Null values in request bodies and responses are converted to `undefined` before validation, since Ajv treats optional properties as non-nullable.

## Response Serialization

Responses are validated through Ajv (not fast-json-stringify), which means input and output validation behave identically. If a response doesn't match its schema, the server throws an error rather than sending malformed data. Date objects are automatically stringified to ISO format before validation.

## Swagger / OpenAPI

Call `server.swagger()` before registering routes to enable Swagger documentation:

```javascript
const server = new Server()
await server.swagger({ path: '/docs' })
// register routes after this
```

Route schemas are automatically exposed in the OpenAPI spec. The `example` and `description` properties from `SchemaObject` appear in the Swagger UI. If authentication is configured, security schemes are added automatically.
