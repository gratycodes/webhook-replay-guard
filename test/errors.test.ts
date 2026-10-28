import { describe, expect, it } from 'vitest';
import { WebhookVerificationError, isWebhookVerificationError } from '../src/index.js';

describe('WebhookVerificationError', () => {
  it('carries a code and a name', () => {
    const err = new WebhookVerificationError('REPLAYED');
    expect(err).toBeInstanceOf(Error);
    expect(err.code).toBe('REPLAYED');
    expect(err.name).toBe('WebhookVerificationError');
    expect(isWebhookVerificationError(err)).toBe(true);
    expect(isWebhookVerificationError(new Error('x'))).toBe(false);
  });
});
