/**
 * webhook-replay-guard
 *
 * Verify HMAC-SHA256 webhook signatures with:
 *   - a signed timestamp and a tolerance window (stops old captured requests being replayed later)
 *   - an optional replay store keyed by delivery ID (stops replays inside the window)
 *   - constant-time comparison (stops timing attacks)
 *   - several secrets at once (zero-downtime secret rotation)
 *
 * Wire format (Stripe-style, documented in README.md):
 *
 *   X-Webhook-Signature: t=1730000000,v1=<hex hmac>[,v1=<hex hmac>...]
 *   X-Webhook-Id:        <unique delivery id>          (optional, enables replay protection)
 *
 *   signed payload = `${t}.` + raw body bytes
 *   v1             = hex( HMAC-SHA256(secret, signed payload) )
 *
 * SCAFFOLD: every function marked `TODO: implement` is for you to write.
 * GUIDE.md walks through each one; the tests in test/ define the expected behaviour.
 */
import { createHmac, timingSafeEqual } from 'node:crypto';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Default allowed clock difference between sender and receiver, in seconds (5 minutes). */
export const DEFAULT_TOLERANCE_SECONDS = 300;

/** Signature scheme name used in the header. Unknown schemes (e.g. `v0`) are ignored. */
export const SIGNATURE_SCHEME = 'v1';

/** Default header names used by the framework helpers (lower-case, as Node exposes them). */
export const DEFAULT_SIGNATURE_HEADER = 'x-webhook-signature';
export const DEFAULT_ID_HEADER = 'x-webhook-id';

/** Default maximum number of IDs held by MemoryReplayStore. */
export const DEFAULT_REPLAY_STORE_MAX_ENTRIES = 10_000;

// Keep the crypto imports referenced so the stubs typecheck and lint cleanly.
// Delete this line once computeSignature and safeCompareHex use them.
void createHmac;
void timingSafeEqual;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** A shared secret. Strings are encoded as UTF-8. */
export type SecretInput = string | Uint8Array;

/** The raw request body exactly as received. Never a re-serialised JSON object. */
export type RawBody = string | Uint8Array;

export type WebhookErrorCode =
  | 'NO_SECRETS' // options.secrets is empty
  | 'MISSING_HEADER' // signature header absent or empty
  | 'MALFORMED_HEADER' // header present but cannot be parsed
  | 'INVALID_BODY' // raw body missing or not a string/Buffer (e.g. a body parser already ran)
  | 'INVALID_SIGNATURE' // no provided signature matches any secret
  | 'TIMESTAMP_TOO_OLD' // timestamp older than now - tolerance
  | 'TIMESTAMP_IN_FUTURE' // timestamp newer than now + tolerance
  | 'REPLAYED'; // delivery ID already seen

export interface ParsedSignatureHeader {
  /** Unix time in seconds, as sent in `t=`. */
  timestamp: number;
  /** All `v1=` values, lower-cased hex, in header order. */
  signatures: string[];
}

/**
 * Pluggable store for replay protection. Implement it on Redis, a database, etc.
 * for multi-instance deployments; the default MemoryReplayStore only protects one process.
 */
export interface ReplayStore {
  /**
   * Atomically record `id`.
   * Return `true` if the id had NOT been seen (first delivery: accept),
   * `false` if it was already present (replay: reject).
   * `ttlSeconds` is how long the id must be remembered.
   * Redis example: `SET key 1 NX EX ttlSeconds` and return whether it was set.
   */
  markIfNew(id: string, ttlSeconds: number): boolean | Promise<boolean>;
}

export interface VerifyOptions {
  /**
   * One secret, or several during rotation. The first secret that matches wins;
   * its position is returned as `secretIndex`.
   */
  secrets: SecretInput | readonly SecretInput[];
  /** Allowed clock skew in seconds, both directions. Default 300. */
  toleranceSeconds?: number;
  /**
   * Replay store used when an `id` is supplied.
   * `undefined` uses a lazily created process-wide MemoryReplayStore.
   * `false` disables replay protection.
   */
  replayStore?: ReplayStore | false;
  /** Clock in epoch milliseconds. Injected by tests; defaults to Date.now. */
  now?: () => number;
}

export interface VerifyInput {
  rawBody: RawBody;
  /** Value of the signature header. */
  signatureHeader: string | null | undefined;
  /** Value of the delivery ID header, if the sender provides one. */
  id?: string | null;
}

export interface VerifiedWebhook {
  /** The verified `t=` timestamp in seconds. */
  timestamp: number;
  /** The delivery ID, if one was supplied. */
  id?: string;
  /** Index in `options.secrets` of the secret that matched. */
  secretIndex: number;
}

// ---------------------------------------------------------------------------
// Errors (implemented: not part of the exercise)
// ---------------------------------------------------------------------------

export class WebhookVerificationError extends Error {
  readonly code: WebhookErrorCode;

  constructor(code: WebhookErrorCode, message?: string) {
    super(message ?? code);
    this.name = 'WebhookVerificationError';
    this.code = code;
  }
}

export function isWebhookVerificationError(err: unknown): err is WebhookVerificationError {
  return err instanceof WebhookVerificationError;
}

function todo(name: string): never {
  throw new Error(`TODO: implement ${name}`);
}

// ---------------------------------------------------------------------------
// Core: signature
// ---------------------------------------------------------------------------

/**
 * Compute the hex HMAC-SHA256 signature for a payload.
 *
 * TODO: implement
 *  1. Build the signed payload as BYTES: the ASCII string `${timestamp}.` followed by the raw body bytes.
 *     - If rawBody is a string, encode it as UTF-8. If it is a Uint8Array/Buffer, use it as-is.
 *     - Do NOT JSON.parse / JSON.stringify anything: one changed space breaks the signature.
 *     - Tip: `hmac.update(prefix); hmac.update(body)` avoids copying with Buffer.concat.
 *  2. `createHmac('sha256', secret)` accepts a string or Uint8Array secret directly.
 *  3. Return `digest('hex')` (64 lower-case hex characters).
 *  4. Validate `timestamp` is a finite, non-negative integer; otherwise throw a TypeError.
 */
export function computeSignature(
  _secret: SecretInput,
  _timestamp: number,
  _rawBody: RawBody,
): string {
  return todo('computeSignature');
}

/**
 * Parse `t=1730000000,v1=abc...,v1=def...`.
 *
 * TODO: implement
 *  1. Split on ',' then each part on the FIRST '=' only; trim whitespace around keys and values.
 *  2. `t`: must appear exactly once and be all digits (/^\d+$/). Convert with Number().
 *  3. `v1`: may appear several times (sender-side rotation). Lower-case each value and keep it
 *     only if it is non-empty. Do not reject odd-length or non-hex values here: safeCompareHex
 *     handles them, and a bad value must still end as INVALID_SIGNATURE, not a crash.
 *  4. Ignore other keys (e.g. `v0`) so the format can evolve.
 *  5. Throw WebhookVerificationError('MALFORMED_HEADER') when: there is no valid `t`, `t` repeats,
 *     or there are no `v1` values.
 */
export function parseSignatureHeader(_header: string): ParsedSignatureHeader {
  return todo('parseSignatureHeader');
}

/**
 * Constant-time comparison of two hex strings.
 *
 * TODO: implement
 *  1. If either string is not even-length hex (/^[0-9a-f]*$/i), return false.
 *  2. Decode both with Buffer.from(x, 'hex').
 *  3. crypto.timingSafeEqual THROWS a RangeError when lengths differ, so check
 *     `a.length !== b.length` first and return false. (Length is not secret: every
 *     valid SHA-256 hex signature is 64 characters long.)
 *  4. Return timingSafeEqual(bufA, bufB).
 *  Never use `===` on signatures: it returns as soon as a character differs, so
 *  response time reveals how many leading characters were right.
 */
export function safeCompareHex(_a: string, _b: string): boolean {
  return todo('safeCompareHex');
}

// ---------------------------------------------------------------------------
// Core: verification
// ---------------------------------------------------------------------------

/**
 * Verify a webhook. Resolves with details on success; rejects with WebhookVerificationError.
 *
 * TODO: implement, in THIS order (the order matters; see GUIDE.md):
 *  1. Normalise `options.secrets` to an array. Empty array: throw NO_SECRETS.
 *  2. rawBody must be a string or Uint8Array: else throw INVALID_BODY
 *     (a plain object means a JSON body parser ran first).
 *  3. Missing or empty signatureHeader: throw MISSING_HEADER.
 *  4. parseSignatureHeader (throws MALFORMED_HEADER).
 *  5. Timestamp window, with now = Math.floor((options.now ?? Date.now)() / 1000)
 *     and tolerance = options.toleranceSeconds ?? DEFAULT_TOLERANCE_SECONDS:
 *       timestamp < now - tolerance: TIMESTAMP_TOO_OLD
 *       timestamp > now + tolerance: TIMESTAMP_IN_FUTURE
 *     (Exactly on the boundary is accepted.)
 *  6. For each secret (index i), compute the expected signature once, then compare it with
 *     EVERY provided signature using safeCompareHex. The first match sets secretIndex = i.
 *     No match: throw INVALID_SIGNATURE.
 *  7. Only AFTER the signature is valid, replay check if `input.id` is a non-empty string and
 *     options.replayStore !== false:
 *       store = options.replayStore ?? getDefaultReplayStore()
 *       ttl   = 2 * tolerance (the id must be remembered for as long as the timestamp could still pass)
 *       if (!(await store.markIfNew(id, ttl))) throw REPLAYED
 *     Checking replay before the signature would let an attacker burn real IDs with forged requests.
 *  8. Return { timestamp, id, secretIndex } (omit `id` when none was given).
 */
export async function verifyWebhook(
  _input: VerifyInput,
  _options: VerifyOptions,
): Promise<VerifiedWebhook> {
  return todo('verifyWebhook');
}

/**
 * Build a signature header for a payload (sender side, and handy in tests).
 * Implemented on top of computeSignature, so it works once that does.
 */
export function signWebhook(
  rawBody: RawBody,
  secret: SecretInput,
  timestamp: number = Math.floor(Date.now() / 1000),
): { header: string; timestamp: number } {
  return {
    header: `t=${timestamp},${SIGNATURE_SCHEME}=${computeSignature(secret, timestamp, rawBody)}`,
    timestamp,
  };
}

// ---------------------------------------------------------------------------
// Replay store: in-memory LRU with TTL
// ---------------------------------------------------------------------------

export interface MemoryReplayStoreOptions {
  /** Maximum IDs held; the least recently used is evicted beyond this. Default 10,000. */
  maxEntries?: number;
  /** Clock in epoch milliseconds (for tests). Default Date.now. */
  now?: () => number;
}

/**
 * Single-process replay store. Use a shared store (Redis etc.) when you run several instances.
 *
 * TODO: implement
 *  - Keep a `Map<string, number>` of id -> expiresAtMs. A JS Map iterates in insertion order,
 *    so the first key is the oldest: that gives an LRU cheaply.
 *  - markIfNew(id, ttlSeconds):
 *      1. now = this.now(); look up id.
 *      2. Present and not expired: delete and re-insert it (marks it most recently used), return false.
 *      3. Present but expired: delete it and treat as new.
 *      4. New: set(id, now + ttlSeconds * 1000). While size > maxEntries, delete the first key.
 *         Return true.
 *  - size: number of entries currently held (expired entries may still count until touched).
 *  - Validate maxEntries is a positive integer in the constructor (TypeError otherwise).
 */
export class MemoryReplayStore implements ReplayStore {
  readonly maxEntries: number;
  private readonly now: () => number;
  private readonly entries = new Map<string, number>();

  constructor(options: MemoryReplayStoreOptions = {}) {
    this.maxEntries = options.maxEntries ?? DEFAULT_REPLAY_STORE_MAX_ENTRIES;
    this.now = options.now ?? Date.now;
  }

  markIfNew(_id: string, _ttlSeconds: number): boolean {
    void this.now;
    void this.entries;
    return todo('MemoryReplayStore.markIfNew');
  }

  get size(): number {
    return todo('MemoryReplayStore.size');
  }
}

let defaultStore: MemoryReplayStore | undefined;

/** Process-wide default store used when VerifyOptions.replayStore is undefined. */
export function getDefaultReplayStore(): MemoryReplayStore {
  defaultStore ??= new MemoryReplayStore();
  return defaultStore;
}

// ---------------------------------------------------------------------------
// Framework helpers (no runtime dependency on Express or Fastify)
// ---------------------------------------------------------------------------

/** Minimal shapes so the package does not depend on @types/express. */
export interface ExpressLikeRequest {
  headers: Record<string, string | string[] | undefined>;
  body?: unknown;
  webhook?: VerifiedWebhook;
}
export interface ExpressLikeResponse {
  status(code: number): ExpressLikeResponse;
  json(body: unknown): unknown;
}
export type ExpressLikeNext = (err?: unknown) => void;

export interface MiddlewareOptions extends VerifyOptions {
  /** Default 'x-webhook-signature'. */
  signatureHeader?: string;
  /** Default 'x-webhook-id'. */
  idHeader?: string;
}

/**
 * Express middleware. Mount it AFTER `express.raw({ type: 'application/json' })` on the webhook
 * route only, so `req.body` is the raw Buffer.
 *
 * TODO: implement. Return `async (req, res, next) => { ... }` that:
 *  1. Reads the headers (lower-case names; if a header value is an array, use the first item).
 *  2. Calls verifyWebhook({ rawBody: req.body, signatureHeader, id }, options).
 *  3. Success: sets req.webhook = result and calls next() with no arguments.
 *  4. WebhookVerificationError: res.status(400).json({ error: err.code }) and does NOT call next.
 *  5. Any other error: next(err).
 */
export function expressWebhookMiddleware(
  _options: MiddlewareOptions,
): (req: ExpressLikeRequest, res: ExpressLikeResponse, next: ExpressLikeNext) => Promise<void> {
  return todo('expressWebhookMiddleware');
}

/** Minimal Fastify shapes. */
export interface FastifyLikeRequest {
  rawBody?: Buffer;
}
export type FastifyContentParser = (
  req: FastifyLikeRequest,
  body: Buffer,
  done: (err: Error | null, value?: unknown) => void,
) => void;
export interface FastifyLike {
  addContentTypeParser(
    contentType: string | string[],
    opts: { parseAs: 'buffer' },
    parser: FastifyContentParser,
  ): void;
}

/**
 * Register a JSON parser on a Fastify instance (or encapsulated plugin scope) that keeps the
 * raw bytes on `request.rawBody` and still gives handlers the parsed JSON as `request.body`.
 *
 * TODO: implement
 *  1. Call fastify.addContentTypeParser(contentTypes ?? 'application/json', { parseAs: 'buffer' }, parser).
 *  2. parser(req, body, done): set req.rawBody = body; then try JSON.parse(body.toString('utf8')).
 *       success: done(null, parsed)
 *       failure: done(error) with the error's statusCode set to 400
 *     An empty body should parse to `undefined` rather than failing.
 *  Register it inside the plugin that holds the webhook route so other routes keep Fastify's
 *  default parser. In the route, call verifyWebhook({ rawBody: request.rawBody, ... }).
 */
export function fastifyRawBody(_fastify: FastifyLike, _contentTypes?: string | string[]): void {
  todo('fastifyRawBody');
}
