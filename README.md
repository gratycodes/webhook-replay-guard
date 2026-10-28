# webhook-replay-guard

Verify signed webhooks in Node.js: HMAC-SHA256 over timestamp and raw body, constant-time
comparison, a timestamp tolerance window, replay protection by delivery ID and several secrets
at once for rotation. No runtime dependencies. ESM and CommonJS. Node.js 18+.

> Status: pre-release (0.0.0). The API below is the target; the implementation is in progress.

## Install

```sh
npm install webhook-replay-guard
```

## Wire format

```
X-Webhook-Signature: t=1730000000,v1=5257a869e7ecebeda32affa62cdca3fa51cad7e77a0e56ff536d0ce8e108d8bd
X-Webhook-Id:        evt_01J9Z3...        (optional, enables replay protection)
```

- `t`: Unix time in seconds when the sender signed the request.
- `v1`: hex HMAC-SHA256 of the bytes `` `${t}.` `` followed by the raw request body.
  Several `v1` values are allowed, so a sender can sign with old and new secrets during rotation.
- Unknown schemes (`v0=...`) are ignored.

## Usage

### Framework-agnostic

```ts
import { verifyWebhook, isWebhookVerificationError } from 'webhook-replay-guard';

try {
  const { timestamp, id, secretIndex } = await verifyWebhook(
    { rawBody, signatureHeader: headers['x-webhook-signature'], id: headers['x-webhook-id'] },
    { secrets: process.env.WEBHOOK_SECRET! },
  );
  // handle the event
} catch (err) {
  if (isWebhookVerificationError(err)) return respond(400, { error: err.code });
  throw err;
}
```

### Express

Use `express.raw()` on the webhook route only. `express.json()` would replace the bytes with an
object and the signature could no longer be checked.

```ts
import express from 'express';
import { expressWebhookMiddleware } from 'webhook-replay-guard';

const app = express();
app.post(
  '/webhooks',
  express.raw({ type: 'application/json' }),
  expressWebhookMiddleware({ secrets: [process.env.WEBHOOK_SECRET!] }),
  (req, res) => {
    const event = JSON.parse(req.body.toString('utf8'));
    res.sendStatus(204);
  },
);
```

On failure the middleware responds `400 { "error": "<CODE>" }`; on success it sets `req.webhook`.

### Fastify

```ts
import Fastify from 'fastify';
import { fastifyRawBody, verifyWebhook } from 'webhook-replay-guard';

const app = Fastify();
app.register(async (scope) => {
  fastifyRawBody(scope); // keeps request.rawBody, still parses JSON into request.body
  scope.post('/webhooks', async (request, reply) => {
    await verifyWebhook(
      {
        rawBody: request.rawBody!,
        signatureHeader: request.headers['x-webhook-signature'] as string,
        id: request.headers['x-webhook-id'] as string,
      },
      { secrets: process.env.WEBHOOK_SECRET! },
    );
    return reply.code(204).send();
  });
});
```

### Secret rotation

1. Add the new secret first: `secrets: [NEW, OLD]`.
2. Switch the sender to `NEW` (or have it send both `v1` values).
3. Once no deliveries use `OLD`, remove it: `secrets: [NEW]`.

`secretIndex` in the result tells you which secret matched, so you can see when `OLD` stops being used.

### Replay protection across instances

The default `MemoryReplayStore` only protects a single process. With several instances, provide a
shared store:

```ts
import type { ReplayStore } from 'webhook-replay-guard';

const redisStore: ReplayStore = {
  async markIfNew(id, ttlSeconds) {
    return (await redis.set(`webhook:${id}`, '1', { NX: true, EX: ttlSeconds })) === 'OK';
  },
};
```

## API

| Export                                                    | Description                                                                            |
| --------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| `verifyWebhook(input, options)`                           | Resolves `{ timestamp, id?, secretIndex }` or rejects with `WebhookVerificationError`. |
| `computeSignature(secret, timestamp, rawBody)`            | Hex HMAC-SHA256 of `` `${timestamp}.` `` + body.                                       |
| `signWebhook(rawBody, secret, timestamp?)`                | Builds a `t=...,v1=...` header (sender side and tests).                                |
| `parseSignatureHeader(header)`                            | `{ timestamp, signatures[] }`; throws `MALFORMED_HEADER`.                              |
| `safeCompareHex(a, b)`                                    | Constant-time hex comparison; `false` on length mismatch or bad hex.                   |
| `MemoryReplayStore`                                       | In-memory LRU with TTL (`maxEntries` default 10,000).                                  |
| `getDefaultReplayStore()`                                 | Process-wide store used when `replayStore` is not given.                               |
| `expressWebhookMiddleware(options)`                       | Express middleware (after `express.raw()`).                                            |
| `fastifyRawBody(fastify, contentTypes?)`                  | Fastify JSON parser that keeps `request.rawBody`.                                      |
| `WebhookVerificationError` / `isWebhookVerificationError` | Error with a `code`.                                                                   |

### Options

| Option             | Default                          | Meaning                                                                 |
| ------------------ | -------------------------------- | ----------------------------------------------------------------------- |
| `secrets`          | required                         | One secret or an array (rotation). Strings are UTF-8.                   |
| `toleranceSeconds` | `300`                            | Accepted clock difference in both directions.                           |
| `replayStore`      | process-wide `MemoryReplayStore` | `ReplayStore`, or `false` to disable. Used only when an `id` is passed. |
| `now`              | `Date.now`                       | Clock in milliseconds (tests).                                          |

### Error codes

`NO_SECRETS`, `MISSING_HEADER`, `MALFORMED_HEADER`, `INVALID_BODY`, `INVALID_SIGNATURE`,
`TIMESTAMP_TOO_OLD`, `TIMESTAMP_IN_FUTURE`, `REPLAYED`.

## Security notes

- **Verify the raw bytes.** Parsing and re-serialising JSON changes whitespace and key order, and
  the signature no longer matches. Capture the body before any JSON parser runs.
- **Constant-time comparison.** Signatures are compared with `crypto.timingSafeEqual`, so response
  time does not leak how much of a forged signature was correct.
- **Timestamp window.** The timestamp is inside the signed payload, so it cannot be changed without
  breaking the signature; old captured requests are rejected after `toleranceSeconds`. Keep server
  clocks in sync (NTP).
- **Replay inside the window.** Pass the delivery ID to reject duplicates. The ID is recorded only
  after the signature and timestamp pass, so forged requests cannot burn real IDs. IDs are kept for
  twice the tolerance.
- **Return generic errors to callers.** Log the error code, but do not echo expected signatures.
- **Secrets.** Use at least 32 random bytes, keep them out of source control and rotate them with
  the multi-secret option.
- This library authenticates the sender; it does not make handlers idempotent. Senders may
  legitimately retry with the same ID, so handle duplicates in your business logic as well.

## Development

```sh
npm install
npm run lint && npm run typecheck && npm test && npm run build
```

See [GUIDE.md](./GUIDE.md) for the implementation walkthrough.

## License

MIT © Gratus Antin George
