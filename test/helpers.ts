import { createHmac } from 'node:crypto';

/**
 * Independent reference signer. It does NOT use the library, so the tests pin the wire format
 * rather than whatever the implementation happens to do.
 */
export function refSign(
  secret: string | Uint8Array,
  timestamp: number,
  body: string | Uint8Array,
): string {
  const h = createHmac('sha256', secret);
  h.update(`${timestamp}.`);
  h.update(typeof body === 'string' ? Buffer.from(body, 'utf8') : body);
  return h.digest('hex');
}

export function refHeader(
  secret: string | Uint8Array,
  timestamp: number,
  body: string | Uint8Array,
): string {
  return `t=${timestamp},v1=${refSign(secret, timestamp, body)}`;
}

/** Fixed clock: 2026-10-29T00:00:00Z. */
export const NOW_S = 1_793_232_000;
export const NOW_MS = NOW_S * 1000;
export const clock = () => NOW_MS;

export const SECRET = 'whsec_test_primary_secret';
export const OLD_SECRET = 'whsec_test_previous_secret';
export const BODY = '{"id":"evt_1","type":"payment.succeeded","amount":1200}';

let counter = 0;
export const uniqueId = () => `delivery_${Date.now()}_${++counter}`;
