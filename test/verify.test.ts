import { describe, expect, it } from 'vitest';
import {
  DEFAULT_TOLERANCE_SECONDS,
  MemoryReplayStore,
  verifyWebhook,
  WebhookVerificationError,
  type ReplayStore,
  type VerifyInput,
  type VerifyOptions,
  type WebhookErrorCode,
} from '../src/index.js';
import { BODY, NOW_S, OLD_SECRET, SECRET, clock, refHeader, refSign, uniqueId } from './helpers.js';

async function expectCode(p: Promise<unknown>, code: WebhookErrorCode) {
  await expect(p).rejects.toBeInstanceOf(WebhookVerificationError);
  await expect(p).rejects.toMatchObject({ code });
}

const opts = (extra: Partial<VerifyOptions> = {}): VerifyOptions => ({
  secrets: SECRET,
  now: clock,
  replayStore: false,
  ...extra,
});

const input = (extra: Partial<VerifyInput> = {}): VerifyInput => ({
  rawBody: BODY,
  signatureHeader: refHeader(SECRET, NOW_S, BODY),
  ...extra,
});

describe('verifyWebhook: signatures', () => {
  it('accepts a valid signature (string body)', async () => {
    await expect(verifyWebhook(input(), opts())).resolves.toEqual({
      timestamp: NOW_S,
      secretIndex: 0,
    });
  });

  it('accepts a valid signature (Buffer body)', async () => {
    await expect(
      verifyWebhook(input({ rawBody: Buffer.from(BODY, 'utf8') }), opts()),
    ).resolves.toMatchObject({ timestamp: NOW_S, secretIndex: 0 });
  });

  it('rejects a tampered body', async () => {
    const tampered = BODY.replace('1200', '120000');
    await expectCode(verifyWebhook(input({ rawBody: tampered }), opts()), 'INVALID_SIGNATURE');
  });

  it('rejects a re-serialised body (why the raw body matters)', async () => {
    const reserialised = JSON.stringify(JSON.parse(BODY), null, 2);
    await expectCode(verifyWebhook(input({ rawBody: reserialised }), opts()), 'INVALID_SIGNATURE');
  });

  it('rejects a signature made with the wrong secret', async () => {
    const header = refHeader('whsec_attacker_guess', NOW_S, BODY);
    await expectCode(
      verifyWebhook(input({ signatureHeader: header }), opts()),
      'INVALID_SIGNATURE',
    );
  });

  it('rejects when the timestamp in the header was changed after signing', async () => {
    const sig = refSign(SECRET, NOW_S - 10, BODY);
    const header = `t=${NOW_S},v1=${sig}`;
    await expectCode(
      verifyWebhook(input({ signatureHeader: header }), opts()),
      'INVALID_SIGNATURE',
    );
  });

  it('rejects length-mismatched signatures without throwing a RangeError', async () => {
    const sig = refSign(SECRET, NOW_S, BODY);
    for (const bad of [sig.slice(0, 63), sig.slice(0, 32), `${sig}ab`, 'ab']) {
      await expectCode(
        verifyWebhook(input({ signatureHeader: `t=${NOW_S},v1=${bad}` }), opts()),
        'INVALID_SIGNATURE',
      );
    }
  });

  it('rejects non-hex signatures as INVALID_SIGNATURE', async () => {
    const header = `t=${NOW_S},v1=${'z'.repeat(64)}`;
    await expectCode(
      verifyWebhook(input({ signatureHeader: header }), opts()),
      'INVALID_SIGNATURE',
    );
  });
});

describe('verifyWebhook: input validation', () => {
  it.each([undefined, null, ''])('throws MISSING_HEADER for header %j', async (h) => {
    await expectCode(verifyWebhook(input({ signatureHeader: h }), opts()), 'MISSING_HEADER');
  });

  it('throws MALFORMED_HEADER for an unparseable header', async () => {
    await expectCode(
      verifyWebhook(input({ signatureHeader: 'v1=abc' }), opts()),
      'MALFORMED_HEADER',
    );
  });

  it('throws NO_SECRETS for an empty secrets array', async () => {
    await expectCode(verifyWebhook(input(), opts({ secrets: [] })), 'NO_SECRETS');
  });

  it('throws INVALID_BODY when a body parser already turned the body into an object', async () => {
    const parsed = JSON.parse(BODY) as unknown as string;
    await expectCode(verifyWebhook(input({ rawBody: parsed }), opts()), 'INVALID_BODY');
  });
});

describe('verifyWebhook: timestamp window', () => {
  const at = (t: number) => input({ signatureHeader: refHeader(SECRET, t, BODY) });

  it('uses a 300 second default tolerance', () => {
    expect(DEFAULT_TOLERANCE_SECONDS).toBe(300);
  });

  it('rejects an expired timestamp', async () => {
    await expectCode(verifyWebhook(at(NOW_S - 301), opts()), 'TIMESTAMP_TOO_OLD');
  });

  it('rejects a timestamp too far in the future', async () => {
    await expectCode(verifyWebhook(at(NOW_S + 301), opts()), 'TIMESTAMP_IN_FUTURE');
  });

  it('accepts timestamps exactly on both boundaries', async () => {
    await expect(verifyWebhook(at(NOW_S - 300), opts())).resolves.toMatchObject({ secretIndex: 0 });
    await expect(verifyWebhook(at(NOW_S + 300), opts())).resolves.toMatchObject({ secretIndex: 0 });
  });

  it('honours a custom tolerance', async () => {
    await expectCode(
      verifyWebhook(at(NOW_S - 31), opts({ toleranceSeconds: 30 })),
      'TIMESTAMP_TOO_OLD',
    );
    await expect(
      verifyWebhook(at(NOW_S - 30), opts({ toleranceSeconds: 30 })),
    ).resolves.toBeDefined();
  });

  it('checks the window even when the signature is valid (old captured request)', async () => {
    await expectCode(verifyWebhook(at(NOW_S - 86_400), opts()), 'TIMESTAMP_TOO_OLD');
  });
});

describe('verifyWebhook: secret rotation', () => {
  it('accepts a payload signed with the previous secret and reports its index', async () => {
    const header = refHeader(OLD_SECRET, NOW_S, BODY);
    await expect(
      verifyWebhook(input({ signatureHeader: header }), opts({ secrets: [SECRET, OLD_SECRET] })),
    ).resolves.toMatchObject({ secretIndex: 1 });
  });

  it('prefers the first matching secret', async () => {
    await expect(
      verifyWebhook(input(), opts({ secrets: [SECRET, OLD_SECRET] })),
    ).resolves.toMatchObject({ secretIndex: 0 });
  });

  it('accepts a header carrying signatures for both old and new secrets', async () => {
    const header = `t=${NOW_S},v1=${refSign(OLD_SECRET, NOW_S, BODY)},v1=${refSign(SECRET, NOW_S, BODY)}`;
    await expect(
      verifyWebhook(input({ signatureHeader: header }), opts({ secrets: [SECRET] })),
    ).resolves.toMatchObject({ secretIndex: 0 });
  });

  it('rejects once the old secret has been removed', async () => {
    const header = refHeader(OLD_SECRET, NOW_S, BODY);
    await expectCode(
      verifyWebhook(input({ signatureHeader: header }), opts({ secrets: [SECRET] })),
      'INVALID_SIGNATURE',
    );
  });
});

describe('verifyWebhook: replay protection', () => {
  it('accepts the first delivery and rejects a replayed id', async () => {
    const store = new MemoryReplayStore({ now: clock });
    const id = uniqueId();
    await expect(verifyWebhook(input({ id }), opts({ replayStore: store }))).resolves.toEqual({
      timestamp: NOW_S,
      id,
      secretIndex: 0,
    });
    await expectCode(verifyWebhook(input({ id }), opts({ replayStore: store })), 'REPLAYED');
  });

  it('does not record the id when the signature is invalid', async () => {
    const store = new MemoryReplayStore({ now: clock });
    const id = uniqueId();
    await expectCode(
      verifyWebhook(input({ id, rawBody: `${BODY} ` }), opts({ replayStore: store })),
      'INVALID_SIGNATURE',
    );
    await expect(verifyWebhook(input({ id }), opts({ replayStore: store }))).resolves.toMatchObject(
      { id },
    );
  });

  it('does not record the id when the timestamp is outside the window', async () => {
    const calls: string[] = [];
    const spy: ReplayStore = { markIfNew: (id) => (calls.push(id), true) };
    const old = refHeader(SECRET, NOW_S - 1000, BODY);
    await expectCode(
      verifyWebhook(input({ id: uniqueId(), signatureHeader: old }), opts({ replayStore: spy })),
      'TIMESTAMP_TOO_OLD',
    );
    expect(calls).toEqual([]);
  });

  it('remembers ids for twice the tolerance', async () => {
    const ttls: number[] = [];
    const spy: ReplayStore = { markIfNew: (_id, ttl) => (ttls.push(ttl), true) };
    await verifyWebhook(
      input({ id: uniqueId() }),
      opts({ replayStore: spy, toleranceSeconds: 120 }),
    );
    expect(ttls).toEqual([240]);
  });

  it('supports async stores', async () => {
    const seen = new Set<string>();
    const asyncStore: ReplayStore = {
      markIfNew: async (id) => {
        await new Promise((r) => setTimeout(r, 1));
        if (seen.has(id)) return false;
        seen.add(id);
        return true;
      },
    };
    const id = uniqueId();
    await verifyWebhook(input({ id }), opts({ replayStore: asyncStore }));
    await expectCode(verifyWebhook(input({ id }), opts({ replayStore: asyncStore })), 'REPLAYED');
  });

  it('uses the default in-memory store when replayStore is undefined', async () => {
    const id = uniqueId();
    const o = opts({ replayStore: undefined });
    await verifyWebhook(input({ id }), o);
    await expectCode(verifyWebhook(input({ id }), o), 'REPLAYED');
  });

  it('skips replay checks when replayStore is false', async () => {
    const id = uniqueId();
    await verifyWebhook(input({ id }), opts({ replayStore: false }));
    await expect(verifyWebhook(input({ id }), opts({ replayStore: false }))).resolves.toBeDefined();
  });

  it('omits id from the result and skips the store when no id is given', async () => {
    const spy: ReplayStore = { markIfNew: () => expect.fail('store must not be called') };
    const res = await verifyWebhook(input(), opts({ replayStore: spy }));
    expect(res).not.toHaveProperty('id');
  });
});
