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

/** Even-length hex (case-insensitive). Empty string matches; length is checked separately. */
const HEX_RE = /^(?:[0-9a-f]{2})*$/i;

/** A Unix timestamp in the header: digits only (rejects `1.5`, `-1`, `1e9`, `0x10`). */
const DIGITS_RE = /^\d+$/;

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
// Errors
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

// ---------------------------------------------------------------------------
// Core: signature
// ---------------------------------------------------------------------------

/**
 * Compute the hex HMAC-SHA256 signature for a payload.
 *
 * The signed bytes are the ASCII string `${timestamp}.` followed by the raw body. Binding the
 * timestamp into the MAC means it cannot be changed without invalidating the signature.
 *
 * @throws TypeError if `timestamp` is not a non-negative integer.
 */
export function computeSignature(secret: SecretInput, timestamp: number, rawBody: RawBody): string {
  if (!Number.isInteger(timestamp) || timestamp < 0) {
    throw new TypeError(`timestamp must be a non-negative integer, got ${String(timestamp)}`);
  }
  // HMAC (not a plain hash of secret + body) avoids length-extension attacks.
  const hmac = createHmac('sha256', secret);
  // Two update() calls avoid copying the body into a new concatenated buffer.
  hmac.update(`${timestamp}.`);
  hmac.update(typeof rawBody === 'string' ? Buffer.from(rawBody, 'utf8') : rawBody);
  return hmac.digest('hex');
}

/**
 * Parse `t=1730000000,v1=abc...,v1=def...`.
 *
 * - `t` must appear exactly once and be all digits.
 * - `v1` may appear several times (sender-side rotation); values are lower-cased.
 *   Hex is not validated here: a bad value must end as INVALID_SIGNATURE, not a parse error.
 * - Other keys (e.g. `v0`) are ignored so the format can evolve.
 *
 * @throws WebhookVerificationError('MALFORMED_HEADER')
 */
export function parseSignatureHeader(header: string): ParsedSignatureHeader {
  let timestamp: number | undefined;
  let timestampCount = 0;
  const signatures: string[] = [];

  for (const part of header.split(',')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    // Split on the FIRST '=' only; trim so `t = 1 , v1 = x` is accepted.
    const key = part.slice(0, eq).trim();
    const value = part.slice(eq + 1).trim();

    if (key === 't') {
      timestampCount += 1;
      if (DIGITS_RE.test(value)) timestamp = Number(value);
    } else if (key === SIGNATURE_SCHEME && value !== '') {
      signatures.push(value.toLowerCase());
    }
  }

  // A repeated `t` is rejected so an attacker cannot smuggle a second timestamp in.
  if (timestampCount !== 1 || timestamp === undefined || !Number.isSafeInteger(timestamp)) {
    throw new WebhookVerificationError('MALFORMED_HEADER', 'missing or invalid timestamp (t=)');
  }
  if (signatures.length === 0) {
    throw new WebhookVerificationError('MALFORMED_HEADER', `no ${SIGNATURE_SCHEME}= signature`);
  }
  return { timestamp, signatures };
}

/**
 * Constant-time comparison of two hex strings.
 *
 * Returns `false` (never throws) on invalid hex or a length mismatch. Length is not secret:
 * every valid SHA-256 hex signature is 64 characters long.
 */
export function safeCompareHex(a: string, b: string): boolean {
  if (!HEX_RE.test(a) || !HEX_RE.test(b)) return false;
  // timingSafeEqual throws a RangeError on different lengths, so check first.
  if (a.length !== b.length) return false;
  // Comparing decoded bytes makes upper- and lower-case hex equal.
  return timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
}

// ---------------------------------------------------------------------------
// Core: verification
// ---------------------------------------------------------------------------

/**
 * Verify a webhook. Resolves with details on success; rejects with WebhookVerificationError.
 *
 * Order of checks (it matters):
 *  1. configuration and input shape (cheap)
 *  2. header parse
 *  3. timestamp window
 *  4. signature against every secret (rotation)
 *  5. replay check, only once the request is proven authentic, so forged requests cannot
 *     "burn" real delivery IDs
 */
export async function verifyWebhook(
  input: VerifyInput,
  options: VerifyOptions,
): Promise<VerifiedWebhook> {
  const secrets: readonly SecretInput[] = isSecretList(options.secrets)
    ? options.secrets
    : [options.secrets];
  if (secrets.length === 0) {
    throw new WebhookVerificationError('NO_SECRETS', 'at least one secret is required');
  }

  // A plain object here means a JSON body parser already replaced the bytes.
  const { rawBody, signatureHeader } = input;
  if (typeof rawBody !== 'string' && !(rawBody instanceof Uint8Array)) {
    throw new WebhookVerificationError('INVALID_BODY', 'rawBody must be a string or Buffer');
  }

  if (!signatureHeader) {
    throw new WebhookVerificationError('MISSING_HEADER', 'signature header is missing');
  }
  const { timestamp, signatures } = parseSignatureHeader(signatureHeader);

  // Clock skew is allowed in both directions; exactly on the boundary is accepted.
  const tolerance = options.toleranceSeconds ?? DEFAULT_TOLERANCE_SECONDS;
  const nowSeconds = Math.floor((options.now ?? Date.now)() / 1000);
  if (timestamp < nowSeconds - tolerance) {
    throw new WebhookVerificationError('TIMESTAMP_TOO_OLD', 'timestamp outside tolerance');
  }
  if (timestamp > nowSeconds + tolerance) {
    throw new WebhookVerificationError('TIMESTAMP_IN_FUTURE', 'timestamp outside tolerance');
  }

  // Each secret's expected signature is computed once and compared with every provided one.
  const secretIndex = secrets.findIndex((secret) => {
    const expected = computeSignature(secret, timestamp, rawBody);
    return signatures.some((candidate) => safeCompareHex(expected, candidate));
  });
  if (secretIndex === -1) {
    throw new WebhookVerificationError('INVALID_SIGNATURE', 'no matching signature');
  }

  const id = input.id;
  if (typeof id !== 'string' || id === '') {
    return { timestamp, secretIndex };
  }

  if (options.replayStore !== false) {
    const store = options.replayStore ?? getDefaultReplayStore();
    // A request is acceptable for 2 x tolerance of receiver time, so remember the id that long.
    const isNew = await store.markIfNew(id, 2 * tolerance);
    if (!isNew) {
      throw new WebhookVerificationError('REPLAYED', 'delivery id already processed');
    }
  }
  return { timestamp, id, secretIndex };
}

/** Narrow `SecretInput | readonly SecretInput[]` (Array.isArray does not narrow readonly arrays). */
function isSecretList(
  value: SecretInput | readonly SecretInput[],
): value is readonly SecretInput[] {
  return Array.isArray(value);
}

/**
 * Build a signature header for a payload (sender side, and handy in tests).
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
 * A JS Map iterates in insertion order, so deleting and re-inserting a key moves it to the end,
 * and the first key is always the least recently used: an O(1) LRU without a linked list.
 * Expired entries are dropped lazily when touched or evicted.
 */
export class MemoryReplayStore implements ReplayStore {
  readonly maxEntries: number;
  private readonly now: () => number;
  /** id -> expiry time in epoch milliseconds. */
  private readonly entries = new Map<string, number>();

  constructor(options: MemoryReplayStoreOptions = {}) {
    const maxEntries = options.maxEntries ?? DEFAULT_REPLAY_STORE_MAX_ENTRIES;
    if (!Number.isInteger(maxEntries) || maxEntries < 1) {
      throw new TypeError(`maxEntries must be a positive integer, got ${String(maxEntries)}`);
    }
    this.maxEntries = maxEntries;
    this.now = options.now ?? Date.now;
  }

  markIfNew(id: string, ttlSeconds: number): boolean {
    const now = this.now();
    const expiresAt = this.entries.get(id);

    if (expiresAt !== undefined && expiresAt > now) {
      // Seen and still live: a replay. Refresh recency (keep the original expiry).
      this.entries.delete(id);
      this.entries.set(id, expiresAt);
      return false;
    }

    // New, or seen but expired: (re)record it as the most recently used entry.
    this.entries.delete(id);
    this.entries.set(id, now + ttlSeconds * 1000);

    // Bound memory: evict least recently used entries (the oldest keys in the Map).
    while (this.entries.size > this.maxEntries) {
      const oldest = this.entries.keys().next();
      if (oldest.done) break;
      this.entries.delete(oldest.value);
    }
    return true;
  }

  /** Entries currently held (expired entries count until they are touched or evicted). */
  get size(): number {
    return this.entries.size;
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

/** Node exposes repeated headers as arrays; use the first value. */
function firstHeader(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

/**
 * Express middleware. Mount it AFTER `express.raw({ type: 'application/json' })` on the webhook
 * route only, so `req.body` is the raw Buffer.
 *
 * On success sets `req.webhook` and calls `next()`. On a verification failure responds
 * `400 { error: <code> }`. Any other error is passed to `next(err)`.
 */
export function expressWebhookMiddleware(
  options: MiddlewareOptions,
): (req: ExpressLikeRequest, res: ExpressLikeResponse, next: ExpressLikeNext) => Promise<void> {
  const signatureHeaderName = (options.signatureHeader ?? DEFAULT_SIGNATURE_HEADER).toLowerCase();
  const idHeaderName = (options.idHeader ?? DEFAULT_ID_HEADER).toLowerCase();

  return async (req, res, next) => {
    try {
      req.webhook = await verifyWebhook(
        {
          // Validated inside verifyWebhook (INVALID_BODY if a JSON parser already ran).
          rawBody: req.body as RawBody,
          signatureHeader: firstHeader(req.headers[signatureHeaderName]),
          id: firstHeader(req.headers[idHeaderName]) ?? null,
        },
        options,
      );
    } catch (err) {
      if (isWebhookVerificationError(err)) {
        res.status(400).json({ error: err.code });
        return;
      }
      next(err);
      return;
    }
    // Called outside the try so errors thrown by later handlers are not reported as 400s.
    next();
  };
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
 * Register it inside the plugin that holds the webhook route so other routes keep the default.
 */
export function fastifyRawBody(fastify: FastifyLike, contentTypes?: string | string[]): void {
  fastify.addContentTypeParser(
    contentTypes ?? 'application/json',
    { parseAs: 'buffer' },
    (req, body, done) => {
      req.rawBody = body;
      if (body.length === 0) {
        done(null, undefined);
        return;
      }
      try {
        done(null, JSON.parse(body.toString('utf8')));
      } catch (err) {
        // Answer malformed JSON with 400, not 500.
        const error = (err instanceof Error ? err : new Error(String(err))) as Error & {
          statusCode?: number;
        };
        error.statusCode = 400;
        done(error);
      }
    },
  );
}
