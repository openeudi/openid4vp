import { describe, expect, it } from 'vitest';
import {
    CompositeTrustStore,
    StaticTrustStore,
} from '../../src/trust/TrustStore.js';
import { createCa } from './helpers/synthetic-ca.js';

describe('CompositeTrustStore', () => {
    it('concatenates results from each child store in order', async () => {
        const a = await createCa({ name: 'CN=A' });
        const b = await createCa({ name: 'CN=B' });
        const storeA = new StaticTrustStore([a.certificate]);
        const storeB = new StaticTrustStore([b.certificate]);
        const composite = new CompositeTrustStore([storeA, storeB]);

        const allA = await composite.getAnchors({ issuer: 'CN=A' });
        const allB = await composite.getAnchors({ issuer: 'CN=B' });
        expect(allA).toHaveLength(1);
        expect(allB).toHaveLength(1);
    });

    it('dedupes anchors by Subject Key Identifier', async () => {
        const ca = await createCa({ name: 'CN=Shared' });
        const store1 = new StaticTrustStore([ca.certificate]);
        const store2 = new StaticTrustStore([ca.certificate]);
        const composite = new CompositeTrustStore([store1, store2]);

        const result = await composite.getAnchors({ issuer: 'CN=Shared' });
        expect(result).toHaveLength(1);
    });

    it('returns [] when every child returns []', async () => {
        const a = await createCa({ name: 'CN=A' });
        const storeA = new StaticTrustStore([a.certificate]);
        const composite = new CompositeTrustStore([storeA]);
        const result = await composite.getAnchors({ issuer: 'CN=Nope' });
        expect(result).toEqual([]);
    });

    it('calls children concurrently (parallelism)', async () => {
        const order: number[] = [];
        const slow = {
            async getAnchors() {
                await new Promise((r) => setTimeout(r, 20));
                order.push(1);
                return [];
            },
        };
        const fast = {
            async getAnchors() {
                order.push(2);
                return [];
            },
        };
        const composite = new CompositeTrustStore([slow, fast]);
        await composite.getAnchors({ issuer: 'x' });
        // fast finished first despite being listed second
        expect(order).toEqual([2, 1]);
    });
});
