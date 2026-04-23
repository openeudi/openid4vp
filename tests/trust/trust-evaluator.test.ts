import { describe, expect, it } from 'vitest';
import { TrustEvaluator } from '../../src/trust/TrustEvaluator.js';
import { StaticTrustStore } from '../../src/trust/TrustStore.js';
import {
    TrustAnchorNotFoundError,
    CertificateChainError,
} from '../../src/errors.js';
import {
    createCa,
    createIntermediate,
    createLeaf,
} from './helpers/synthetic-ca.js';

describe('TrustEvaluator', () => {
    it('returns a trust verdict for a valid chain', async () => {
        const root = await createCa({ name: 'CN=Root' });
        const leaf = await createLeaf(root);
        const store = new StaticTrustStore([root.certificate]);
        const evaluator = new TrustEvaluator({ trustStore: store });
        const result = await evaluator.evaluate(leaf.certificate);
        expect(result.anchor.certificate.subject).toBe('CN=Root');
        expect(result.anchor.source).toBe('static');
        expect(result.chain).toHaveLength(2);
        expect(result.revocationStatus).toBe('skipped');
    });

    it('uses extra intermediates extracted from leaf x5c when provided', async () => {
        const root = await createCa();
        const intermediate = await createIntermediate(root);
        const leaf = await createLeaf(intermediate);
        const store = new StaticTrustStore([root.certificate]);
        const evaluator = new TrustEvaluator({ trustStore: store });
        const result = await evaluator.evaluate(leaf.certificate, {
            intermediates: [intermediate.certificate],
        });
        expect(result.chain).toHaveLength(3);
    });

    it('throws TrustAnchorNotFoundError when no store returns anchors', async () => {
        const root = await createCa();
        const leaf = await createLeaf(root);
        const store = new StaticTrustStore([]);
        const evaluator = new TrustEvaluator({ trustStore: store });
        await expect(
            evaluator.evaluate(leaf.certificate)
        ).rejects.toBeInstanceOf(TrustAnchorNotFoundError);
    });

    it('propagates CertificateChainError when chain fails', async () => {
        const realRoot = await createCa();
        const attackerRoot = await createCa();
        const leaf = await createLeaf(attackerRoot);
        const store = new StaticTrustStore([realRoot.certificate]);
        const evaluator = new TrustEvaluator({ trustStore: store });
        await expect(
            evaluator.evaluate(leaf.certificate)
        ).rejects.toBeInstanceOf(CertificateChainError);
    });

    it('only permits revocationPolicy=skip in A.1', async () => {
        const root = await createCa();
        const store = new StaticTrustStore([root.certificate]);
        expect(
            () =>
                new TrustEvaluator({
                    trustStore: store,
                    revocationPolicy: 'prefer',
                })
        ).toThrow(/revocationPolicy='prefer' is not implemented yet/);
    });
});
