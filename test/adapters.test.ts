import { describe, expect, it, vi } from 'vitest';
import {
  expressWebhookMiddleware,
  fastifyRawBody,
  type ExpressLikeRequest,
  type ExpressLikeResponse,
  type FastifyContentParser,
  type FastifyLike,
} from '../src/index.js';
import { BODY, NOW_S, SECRET, clock, refHeader, uniqueId } from './helpers.js';

function fakeRes() {
  const res = {
    statusCode: 200,
    payload: undefined as unknown,
    status(code: number) {
      res.statusCode = code;
      return res as unknown as ExpressLikeResponse;
    },
    json(body: unknown) {
      res.payload = body;
      return body;
    },
  };
  return res;
}

describe('expressWebhookMiddleware', () => {
  const mw = () => expressWebhookMiddleware({ secrets: SECRET, now: clock, replayStore: false });

  it('calls next() and attaches req.webhook for a valid request', async () => {
    const req: ExpressLikeRequest = {
      headers: { 'x-webhook-signature': refHeader(SECRET, NOW_S, BODY), 'x-webhook-id': 'evt_1' },
      body: Buffer.from(BODY),
    };
    const res = fakeRes();
    const next = vi.fn();
    await mw()(req, res as unknown as ExpressLikeResponse, next);
    expect(next).toHaveBeenCalledWith();
    expect(req.webhook).toEqual({ timestamp: NOW_S, id: 'evt_1', secretIndex: 0 });
  });

  it('responds 400 with the error code and does not call next on failure', async () => {
    const req: ExpressLikeRequest = {
      headers: { 'x-webhook-signature': refHeader('wrong', NOW_S, BODY) },
      body: Buffer.from(BODY),
    };
    const res = fakeRes();
    const next = vi.fn();
    await mw()(req, res as unknown as ExpressLikeResponse, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(400);
    expect(res.payload).toEqual({ error: 'INVALID_SIGNATURE' });
  });

  it('reports INVALID_BODY when express.json() ran instead of express.raw()', async () => {
    const req: ExpressLikeRequest = {
      headers: { 'x-webhook-signature': refHeader(SECRET, NOW_S, BODY) },
      body: JSON.parse(BODY),
    };
    const res = fakeRes();
    await mw()(req, res as unknown as ExpressLikeResponse, vi.fn());
    expect(res.payload).toEqual({ error: 'INVALID_BODY' });
  });

  it('supports custom header names and array header values', async () => {
    const m = expressWebhookMiddleware({
      secrets: SECRET,
      now: clock,
      replayStore: false,
      signatureHeader: 'x-acme-signature',
      idHeader: 'x-acme-delivery',
    });
    const id = uniqueId();
    const req: ExpressLikeRequest = {
      headers: { 'x-acme-signature': [refHeader(SECRET, NOW_S, BODY)], 'x-acme-delivery': id },
      body: Buffer.from(BODY),
    };
    const next = vi.fn();
    await m(req, fakeRes() as unknown as ExpressLikeResponse, next);
    expect(next).toHaveBeenCalledWith();
    expect(req.webhook?.id).toBe(id);
  });
});

describe('fastifyRawBody', () => {
  function capture() {
    const calls: {
      type: string | string[];
      opts: { parseAs: string };
      parser: FastifyContentParser;
    }[] = [];
    const fastify: FastifyLike = {
      addContentTypeParser: (type, opts, parser) => calls.push({ type, opts, parser }),
    };
    return { fastify, calls };
  }

  it('registers a buffer parser for application/json by default', () => {
    const { fastify, calls } = capture();
    fastifyRawBody(fastify);
    expect(calls).toHaveLength(1);
    expect(calls[0]?.type).toBe('application/json');
    expect(calls[0]?.opts).toEqual({ parseAs: 'buffer' });
  });

  it('keeps the raw body and returns parsed JSON', () => {
    const { fastify, calls } = capture();
    fastifyRawBody(fastify, ['application/json', 'application/vnd.acme+json']);
    expect(calls[0]?.type).toEqual(['application/json', 'application/vnd.acme+json']);
    const req: { rawBody?: Buffer } = {};
    const done = vi.fn();
    const raw = Buffer.from(BODY);
    calls[0]?.parser(req, raw, done);
    expect(req.rawBody).toBe(raw);
    expect(done).toHaveBeenCalledWith(null, JSON.parse(BODY));
  });

  it('passes a 400 error to done for invalid JSON', () => {
    const { fastify, calls } = capture();
    fastifyRawBody(fastify);
    const done = vi.fn();
    calls[0]?.parser({}, Buffer.from('{not json'), done);
    const err = done.mock.calls[0]?.[0] as Error & { statusCode?: number };
    expect(err).toBeInstanceOf(Error);
    expect(err.statusCode).toBe(400);
  });

  it('parses an empty body to undefined', () => {
    const { fastify, calls } = capture();
    fastifyRawBody(fastify);
    const done = vi.fn();
    calls[0]?.parser({}, Buffer.alloc(0), done);
    expect(done).toHaveBeenCalledWith(null, undefined);
  });
});
