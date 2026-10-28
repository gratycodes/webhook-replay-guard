import { describe, expect, it } from 'vitest';
import { MemoryReplayStore } from '../src/index.js';

describe('MemoryReplayStore', () => {
  it('returns true for a new id and false for a repeat', () => {
    const store = new MemoryReplayStore();
    expect(store.markIfNew('a', 60)).toBe(true);
    expect(store.markIfNew('a', 60)).toBe(false);
    expect(store.markIfNew('b', 60)).toBe(true);
    expect(store.size).toBe(2);
  });

  it('forgets ids after their TTL', () => {
    let now = 1_000_000;
    const store = new MemoryReplayStore({ now: () => now });
    expect(store.markIfNew('a', 10)).toBe(true);
    now += 9_999;
    expect(store.markIfNew('a', 10)).toBe(false);
    now += 2;
    expect(store.markIfNew('a', 10)).toBe(true);
  });

  it('evicts the least recently used id beyond maxEntries', () => {
    const store = new MemoryReplayStore({ maxEntries: 2 });
    store.markIfNew('a', 60);
    store.markIfNew('b', 60);
    store.markIfNew('a', 60); // touch a: b is now least recently used
    store.markIfNew('c', 60); // evicts b
    expect(store.size).toBe(2);
    expect(store.markIfNew('a', 60)).toBe(false);
    expect(store.markIfNew('c', 60)).toBe(false);
    expect(store.markIfNew('b', 60)).toBe(true);
  });

  it('rejects an invalid maxEntries', () => {
    expect(new MemoryReplayStore({ maxEntries: 1 }).markIfNew('x', 1)).toBe(true);
    expect(() => new MemoryReplayStore({ maxEntries: 0 })).toThrow(TypeError);
    expect(() => new MemoryReplayStore({ maxEntries: 1.5 })).toThrow(TypeError);
  });
});
