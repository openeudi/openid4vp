import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { InMemoryCache, type Cache } from '../../src/trust/Cache.js';

describe('InMemoryCache', () => {
    let cache: Cache;

    beforeEach(() => {
        vi.useFakeTimers();
        cache = new InMemoryCache({ maxEntries: 3 });
    });

    afterEach(() => {
        vi.useRealTimers();
    });

    it('returns null for missing keys', async () => {
        expect(await cache.get('missing')).toBeNull();
    });

    it('round-trips values', async () => {
        const value = new Uint8Array([1, 2, 3]);
        await cache.set('k', value, 60);
        expect(await cache.get('k')).toEqual(value);
    });

    it('expires values after TTL', async () => {
        vi.setSystemTime(new Date('2026-01-01T00:00:00Z'));
        await cache.set('k', new Uint8Array([9]), 10);
        vi.setSystemTime(new Date('2026-01-01T00:00:09Z'));
        expect(await cache.get('k')).not.toBeNull();
        vi.setSystemTime(new Date('2026-01-01T00:00:11Z'));
        expect(await cache.get('k')).toBeNull();
    });

    it('evicts least-recently-used when maxEntries exceeded', async () => {
        await cache.set('a', new Uint8Array([1]), 60);
        await cache.set('b', new Uint8Array([2]), 60);
        await cache.set('c', new Uint8Array([3]), 60);
        await cache.get('a'); // touch 'a' — 'b' is now LRU
        await cache.set('d', new Uint8Array([4]), 60); // should evict 'b'
        expect(await cache.get('b')).toBeNull();
        expect(await cache.get('a')).not.toBeNull();
        expect(await cache.get('c')).not.toBeNull();
        expect(await cache.get('d')).not.toBeNull();
    });

    it('overwriting a key refreshes TTL and LRU position', async () => {
        vi.setSystemTime(new Date('2026-01-01T00:00:00Z'));
        await cache.set('k', new Uint8Array([1]), 10);
        vi.setSystemTime(new Date('2026-01-01T00:00:08Z'));
        await cache.set('k', new Uint8Array([2]), 10);
        vi.setSystemTime(new Date('2026-01-01T00:00:17Z'));
        const result = await cache.get('k');
        expect(result).toEqual(new Uint8Array([2]));
    });
});
