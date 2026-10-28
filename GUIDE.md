# Implementation guide

This guide walks through the functions you need to write in `src/index.ts`, in an order where each
step makes more tests pass. Every stub currently throws `TODO: implement ...`; the test suite in
`test/` defines the behaviour.

```sh
npm install
npx vitest            # watch mode; save a file and the suite re-runs
npx vitest -t computeSignature   # run one group
```

Starting point: 70 tests, 2 passing (error class only), 68 failing with `TODO: implement`.

---

## Step 1: `computeSignature(secret, timestamp, rawBody)`

**What:** `hex(HMAC-SHA256(secret, `${timestamp}.` + rawBody))`.

**How:**

1. Check `Number.isInteger(timestamp) && timestamp >= 0`, else `throw new TypeError(...)`.
2. `const h = createHmac('sha256', secret);`
3. `h.update(`${timestamp}.`)` then `h.update(body)`, where a string body is `Buffer.from(body, 'utf8')`
   and a Buffer/Uint8Array is used as-is.
4. `return h.digest('hex');`
5. Delete the `void createHmac; void timingSafeEqual;` lines once both are used.

**Why:**

- **HMAC, not plain SHA-256.** `sha256(secret + body)` is open to length-extension attacks; HMAC
  is the standard keyed construction.
- **Timestamp inside the signed bytes.** If `t` were only a header field, an attacker could replay
  an old request with a fresh `t`. Binding it into the MAC means changing `t` breaks the signature
  (test: "rejects when the timestamp in the header was changed after signing").
- **The `.` separator** stops ambiguity between where the timestamp ends and the body starts.
- **Bytes, not objects.** The sender signed exact bytes. Never `JSON.stringify` a parsed body to
  rebuild it (test: "rejects a re-serialised body").

Tests: `signature.test.ts > computeSignature`, `signWebhook`.

---

## Step 2: `safeCompareHex(a, b)`

**What:** compare two hex strings without leaking timing information.

**How:**

1. Both must match `/^(?:[0-9a-f]{2})*$/i` (even-length hex); otherwise return `false`.
2. If `a.length !== b.length` return `false`.
3. `return timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));`

**Why:**

- **Timing attacks.** `a === b` stops at the first differing character. By measuring response time
  over many requests, an attacker can find the correct signature one byte at a time.
  `timingSafeEqual` always compares every byte.
- **Length check first.** `timingSafeEqual` throws `RangeError` when buffers differ in length. An
  uncaught throw becomes a 500 and a crash path an attacker can trigger with a short signature.
  Returning `false` early is safe because the length is not secret (always 64 hex chars).
- **Hex validation.** `Buffer.from('zz', 'hex')` silently returns an empty or short buffer, which
  can confuse the length check. Reject bad hex explicitly.
- Comparing decoded bytes also makes upper and lower-case hex compare equal.

Tests: `signature.test.ts > safeCompareHex`, and "length-mismatched signatures" in `verify.test.ts`.

---

## Step 3: `parseSignatureHeader(header)`

**What:** turn `t=123,v1=abc,v1=def` into `{ timestamp: 123, signatures: ['abc', 'def'] }`.

**How:**

1. `header.split(',')`; for each part, split on the **first** `=` (`indexOf`), trim key and value.
2. `t`: count occurrences; accept only `/^\d+$/`, convert with `Number`.
3. `v1`: push `value.toLowerCase()` if non-empty.
4. Ignore other keys.
5. Throw `new WebhookVerificationError('MALFORMED_HEADER')` unless there is exactly one valid `t`
   and at least one `v1`.

**Why:**

- **Strict digits** rejects `12.5`, `-5`, `1e9` and `0x10`, which `Number()` or `parseInt()` would
  quietly accept.
- **Duplicate `t` rejected** so an attacker cannot add a second timestamp and hope a different one
  is checked in the window than the one that was signed.
- **Several `v1` values** let a sender sign with old and new secrets during rotation.
- **Unknown schemes ignored** so a future `v2` does not break old receivers.
- Do not validate hex here: a bad signature should end as `INVALID_SIGNATURE`, which is what callers
  expect, and `safeCompareHex` already handles it.

Tests: `signature.test.ts > parseSignatureHeader`.

---

## Step 4: `MemoryReplayStore`

**What:** an in-memory LRU of delivery IDs with expiry.

**How:**

1. Constructor: after setting `maxEntries`, throw `TypeError` unless it is a positive integer.
2. `markIfNew(id, ttlSeconds)`:
   - `const now = this.now(); const exp = this.entries.get(id);`
   - If `exp !== undefined && exp > now`: `delete` then `set(id, exp)` (moves it to most recent),
     return `false`.
   - Otherwise `delete(id)` (clears an expired entry), `set(id, now + ttlSeconds * 1000)`.
   - `while (this.entries.size > this.maxEntries)` delete `this.entries.keys().next().value`.
   - return `true`.
3. `get size()` returns `this.entries.size`.
4. Remove the `void this.now; void this.entries;` line.

**Why:**

- **Map insertion order = LRU.** JavaScript `Map` iterates in insertion order, so delete plus
  re-insert moves a key to the end, and the first key is always the least recently used. You get an
  O(1) LRU without a linked list.
- **Bounded size.** Without `maxEntries`, an attacker with valid traffic (or a buggy sender) could
  grow memory without limit.
- **TTL.** IDs only need remembering while the timestamp could still pass the window; after that the
  timestamp check rejects the replay anyway.
- **Single process only.** With several instances, each has its own memory: use a shared store
  (Redis `SET NX EX`), as shown in the README.

Tests: `replay-store.test.ts`.

---

## Step 5: `verifyWebhook(input, options)`

**What:** the full check. The order of the steps matters.

**How:**

1. `secrets = Array.isArray(options.secrets) ? options.secrets : [options.secrets]`; empty ->
   `NO_SECRETS`.
2. `rawBody` must be a `string` or `Uint8Array` (Buffer is a Uint8Array) -> else `INVALID_BODY`.
3. No or empty `signatureHeader` -> `MISSING_HEADER`.
4. `const { timestamp, signatures } = parseSignatureHeader(header)`.
5. `now = Math.floor((options.now ?? Date.now)() / 1000)`, `tol = options.toleranceSeconds ?? 300`.
   `timestamp < now - tol` -> `TIMESTAMP_TOO_OLD`; `timestamp > now + tol` -> `TIMESTAMP_IN_FUTURE`.
6. For each secret `i`: `expected = computeSignature(secret, timestamp, rawBody)`; if
   `signatures.some(s => safeCompareHex(expected, s))` then `secretIndex = i` and stop.
   None -> `INVALID_SIGNATURE`.
7. If `input.id` is a non-empty string and `options.replayStore !== false`:
   `store = options.replayStore ?? getDefaultReplayStore()`;
   `if (!(await store.markIfNew(id, 2 * tol))) throw REPLAYED`.
8. Return `{ timestamp, secretIndex }`, adding `id` only when one was given.

**Why the order:**

- **Cheap checks first** (secrets, body, header, timestamp) reject junk before spending HMAC work.
- **Replay check last, after the signature.** If you recorded the ID before verifying, an attacker
  could send forged requests carrying IDs they expect (or saw) and the real delivery would later be
  rejected as `REPLAYED`. Test: "does not record the id when the signature is invalid".
- **Clock skew.** Sender and receiver clocks differ by seconds or more. The tolerance applies in
  both directions; a timestamp too far in the future is as suspicious as an old one (someone
  pre-signing requests to replay later). Boundary values are accepted (`<` and `>`, not `<=`).
- **TTL = 2 x tolerance.** A request is valid from `t - tol` to `t + tol` in receiver time, a span
  of `2 * tol`, so the ID must be remembered at least that long.
- **Rotation.** Trying every secret against every provided signature supports both receiver-side
  rotation (`secrets: [new, old]`) and sender-side rotation (two `v1` values). `secretIndex` lets
  operators see when the old secret is no longer used.
- `markIfNew` can return a Promise (Redis), so always `await` it.

Tests: `verify.test.ts`.

---

## Step 6: `expressWebhookMiddleware(options)`

**How:** return `async (req, res, next) => { ... }`:

1. `sh = options.signatureHeader ?? DEFAULT_SIGNATURE_HEADER` (same for the ID header).
2. Header values may be `string[]`; take the first element.
3. `req.webhook = await verifyWebhook({ rawBody: req.body, signatureHeader, id }, options); next();`
4. `catch (err)`: if `isWebhookVerificationError(err)` -> `res.status(400).json({ error: err.code })`
   and return without calling `next`; otherwise `next(err)`.

**Why:** Express only gives you the raw bytes if `express.raw()` runs on that route. If someone
mounts `express.json()` globally, `req.body` is an object and step 2 of `verifyWebhook` reports
`INVALID_BODY` instead of a confusing signature mismatch. Unknown errors go to `next(err)` so the
app's error handler sees real bugs.

Tests: `adapters.test.ts > expressWebhookMiddleware`.

---

## Step 7: `fastifyRawBody(fastify, contentTypes?)`

**How:**

```ts
fastify.addContentTypeParser(
  contentTypes ?? 'application/json',
  { parseAs: 'buffer' },
  (req, body, done) => {
    req.rawBody = body;
    if (body.length === 0) return done(null, undefined);
    try {
      done(null, JSON.parse(body.toString('utf8')));
    } catch (e) {
      (e as Error & { statusCode?: number }).statusCode = 400;
      done(e as Error);
    }
  },
);
```

**Why:** Fastify parses JSON before your handler runs and throws the bytes away. Registering a
buffer parser keeps them on `request.rawBody` while handlers still get parsed JSON. Register it
inside the plugin scope that holds the webhook route so the rest of the app keeps the default
parser. Setting `statusCode = 400` makes Fastify answer bad JSON with 400, not 500.

Tests: `adapters.test.ts > fastifyRawBody`.

---

## Finish

```sh
npm run lint && npm run format:check && npm run typecheck && npm test && npm run build
```

All 70 tests should pass. Then:

1. Add a few tests of your own (e.g. a Redis-backed store, a very large body).
2. Update `CHANGELOG.md` (0.1.0) and remove the "pre-release" note in the README.
3. Create the GitHub repo, push, and let CI run on Node 18/20/22.
4. Publishing: `npm login`, then `npm publish --access public` (scoped packages are private by
   default). The `@gratycodes` scope must exist first: create the npm user or org `gratycodes`.
   If you prefer an unscoped name, `webhook-replay-guard` was available on 2026-10-29.
   Consider `npm publish --provenance` from GitHub Actions later.
