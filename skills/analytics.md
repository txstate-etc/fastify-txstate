# fastify-txstate: Analytics

Use this skill to add support for user interaction analytics to an API built with fastify-txstate.

## Setting Up Analytics

`analyticsPlugin` registers a `POST /analytics` endpoint that accepts interaction events from the frontend, enriches them with server-side context (user agent, IP, authentication, timestamp), and flushes them in batches every 5 seconds.

```javascript
import Server, { analyticsPlugin } from 'fastify-txstate'
const server = new Server()
server.app.register(analyticsPlugin, { appName: 'my-app' })
```

`NODE_ENV` must be set when using analytics.

## Event Shape

The client sends an array of events:
```json
[{
  "eventType": "ActionPanel.svelte",
  "screen": "/pages/[id]",
  "action": "Edit Page",
  "target": "/sites/5/pages/12"
}]
```

| Field | Required | Description |
|-------|----------|-------------|
| `eventType` | Yes | Identifies the code that generated the event (e.g. component name) |
| `screen` | Yes | The page/screen/dialog the user is on. Use router patterns, not literal URLs (e.g. `/pages/[id]` not `/pages/12`) |
| `action` | Yes | The action taken (e.g. button label: "Edit Page", "Download") |
| `target` | No | The object of the action. Use full paths/GUIDs (e.g. `/sites/5/pages/12`) for grouping |
| `additionalProperties` | No | Extra key-value pairs. Use sparingly — each key expands the Elasticsearch index |

The server enriches each event with: `@timestamp`, `appName`, `environment`, parsed user agent (browser, device, OS), user info (IP, Google Analytics cookie, auth details).

## Plugin Options

| Option | Description |
|--------|-------------|
| `appName` | **Required.** Identifies the application in stored events |
| `analyticsClient` | An `AnalyticsClient` instance. See below for defaults |
| `authorize` | `(req) => boolean` to restrict access. Returns 401 if false |

## Storage Clients

The plugin picks a client automatically:
1. If `ELASTICSEARCH_URL` is set: `ElasticAnalyticsClient` (bulk-indexes to Elasticsearch)
2. If `NODE_ENV=development`: `AnalyticsClient` (logs to console)
3. Otherwise: `LoggingAnalyticsClient` (logs via fastify logger)

### Elasticsearch Environment Variables
| Variable | Required | Description |
|----------|----------|-------------|
| `ELASTICSEARCH_URL` | Yes | Elasticsearch node URL |
| `ELASTICSEARCH_USER` | No | Defaults to `elastic` |
| `ELASTICSEARCH_PASS` | No | Elasticsearch password |
| `ELASTICSEARCH_USEREVENTS_INDEX` | No | Index name. Defaults to `interaction-analytics` |

### Custom Storage Client

Extend `AnalyticsClient` and implement the `push` method:

```javascript
import { AnalyticsClient, type StoredInteractionEvent } from 'fastify-txstate'

class BigQueryAnalyticsClient extends AnalyticsClient {
  async push (events: StoredInteractionEvent[]) {
    // write events to BigQuery, ClickHouse, etc.
  }
}

server.app.register(analyticsPlugin, {
  appName: 'my-app',
  analyticsClient: new BigQueryAnalyticsClient()
})
```

## Failure Handling

If `push` throws, the events are re-queued and retried on the next 5-second flush cycle. Errors are logged to stderr.
