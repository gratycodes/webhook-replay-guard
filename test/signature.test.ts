import { describe, expect, it } from 'vitest';
import {
  computeSignature,
  parseSignatureHeader,
  safeCompareHex,
  signWebhook,
  WebhookVerificationError,
} from '../src/index.js';
import { BODY, NOW_S, SECRET, refSign } from './helpers.js';

describe('computeSignature', () => {
  it('matches the reference HMAC-SHA256 over `${t}.` + body (string body)', () => {
    expect(computeSignature(SECRET, NOW_S, BODY)).toBe(refSign(SECRET, NOW_S, BODY));
  });

  it('treats a Buffer body and its UTF-8 string identically', () => {
    const utf8 = '{"name":"Grâce ☕"}';
    expect(computeSignature(SECRET, NOW_S, Buffer.from(utf8, 'utf8'))).toBe(
      computeSignature(SECRET, NOW_S, utf8),
    );
  });

  it('accepts a binary (Uint8Array) secret', () => {
    const key = new Uint8Array([1, 2, 3, 4, 5, 250, 251, 252]);
    expect(computeSignature(key, NOW_S, BODY)).toBe(refSign(key, NOW_S, BODY));
  });

  it('returns 64 lower-case hex characters', () => {
    expect(computeSignature(SECRET, NOW_S, BODY)).toMatch(/^[0-9a-f]{64}$/);
  });

  it('changes when the timestamp changes (timestamp is part of the signed payload)', () => {
    expect(computeSignature(SECRET, NOW_S, BODY)).not.toBe(
      computeSignature(SECRET, NOW_S + 1, BODY),
    );
  });

  it('rejects a non-integer or negative timestamp', () => {
    expect(computeSignature(SECRET, 0, BODY)).toBe(refSign(SECRET, 0, BODY));
    expect(() => computeSignature(SECRET, 1.5, BODY)).toThrow(TypeError);
    expect(() => computeSignature(SECRET, -1, BODY)).toThrow(TypeError);
    expect(() => computeSignature(SECRET, Number.NaN, BODY)).toThrow(TypeError);
  });
});

describe('signWebhook', () => {
  it('produces a header in the documented format', () => {
    const { header, timestamp } = signWebhook(BODY, SECRET, NOW_S);
    expect(timestamp).toBe(NOW_S);
    expect(header).toBe(`t=${NOW_S},v1=${refSign(SECRET, NOW_S, BODY)}`);
  });
});

describe('parseSignatureHeader', () => {
  const a = 'a'.repeat(64);
  const b = 'B'.repeat(64);

  it('parses timestamp and a single v1 signature', () => {
    expect(parseSignatureHeader(`t=${NOW_S},v1=${a}`)).toEqual({
      timestamp: NOW_S,
      signatures: [a],
    });
  });

  it('collects several v1 values in order, lower-cased', () => {
    expect(parseSignatureHeader(`t=${NOW_S},v1=${a},v1=${b}`).signatures).toEqual([
      a,
      b.toLowerCase(),
    ]);
  });

  it('tolerates whitespace and ignores unknown schemes', () => {
    expect(parseSignatureHeader(` t = ${NOW_S} , v0=deadbeef , v1 = ${a} `)).toEqual({
      timestamp: NOW_S,
      signatures: [a],
    });
  });

  it.each([
    ['empty string', ''],
    ['no timestamp', `v1=${a}`],
    ['non-numeric timestamp', `t=abc,v1=${a}`],
    ['decimal timestamp', `t=12.5,v1=${a}`],
    ['negative timestamp', `t=-5,v1=${a}`],
    ['duplicate timestamp', `t=1,t=2,v1=${a}`],
    ['no v1 signature', `t=${NOW_S}`],
    ['only unknown schemes', `t=${NOW_S},v0=${a}`],
    ['empty v1 value', `t=${NOW_S},v1=`],
    ['garbage', 'not a header'],
  ])('throws MALFORMED_HEADER for %s', (_label, header) => {
    try {
      parseSignatureHeader(header);
      expect.fail('expected parseSignatureHeader to throw');
    } catch (err) {
      expect(err).toBeInstanceOf(WebhookVerificationError);
      expect((err as WebhookVerificationError).code).toBe('MALFORMED_HEADER');
    }
  });
});

describe('safeCompareHex', () => {
  const sig = refSign(SECRET, NOW_S, BODY);

  it('returns true for identical signatures', () => {
    expect(safeCompareHex(sig, sig)).toBe(true);
  });

  it('is case-insensitive for hex digits', () => {
    expect(safeCompareHex(sig, sig.toUpperCase())).toBe(true);
  });

  it('returns false for a different signature of the same length', () => {
    const other = refSign(SECRET, NOW_S + 1, BODY);
    expect(safeCompareHex(sig, other)).toBe(false);
  });

  it('returns false (does not throw) on length mismatch', () => {
    expect(() => safeCompareHex(sig, sig.slice(0, 32))).not.toThrow();
    expect(safeCompareHex(sig, sig.slice(0, 32))).toBe(false);
    expect(safeCompareHex(sig, `${sig}00`)).toBe(false);
    expect(safeCompareHex(sig, '')).toBe(false);
  });

  it('returns false for odd-length or non-hex input', () => {
    expect(safeCompareHex(sig, `${sig.slice(0, 63)}`)).toBe(false);
    expect(safeCompareHex(sig, `${sig.slice(0, 62)}zz`)).toBe(false);
  });
});
