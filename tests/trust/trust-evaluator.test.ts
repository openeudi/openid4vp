import { describe, expect, it } from 'vitest';
import { TrustEvaluator } from '../../src/trust/TrustEvaluator.js';
import { StaticTrustStore } from '../../src/trust/TrustStore.js';
import {
    TrustAnchorNotFoundError,
    CertificateChainError,
    RevokedCertificateError,
    RevocationCheckFailedError,
} from '../../src/errors.js';
import {
    createCa,
    createIntermediate,
    createLeaf,
    signOcspResponse,
} from './helpers/synthetic-ca.js';
import type { Fetcher } from '../../src/trust/Fetcher.js';

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

    it('accepts revocationPolicy=prefer (A.2 unlocked)', async () => {
        const root = await createCa();
        const store = new StaticTrustStore([root.certificate]);
        expect(
            () =>
                new TrustEvaluator({
                    trustStore: store,
                    revocationPolicy: 'prefer',
                })
        ).not.toThrow();
    });
});

describe('TrustEvaluator — revocation', () => {
    it('returns revocationStatus=good under policy=prefer when OCSP says good', async () => {
        const root = await createCa({ name: 'CN=Root' });
        const leaf = await createLeaf(root, {
            ocspUrl: 'http://ocsp.example.com',
        });
        const client = new (
            await import('../../src/trust/OcspClient.js')
        ).OcspClient();
        const reqDer = await client.buildRequest(
            leaf.certificate,
            root.certificate
        );
        const ocspDer = await signOcspResponse(root, reqDer, {
            status: 'good',
            thisUpdate: new Date('2026-04-23'),
            nextUpdate: new Date('2026-04-30'),
        });
        const fetcher: Fetcher = async () =>
            new Response(ocspDer, { status: 200 });

        const store = new StaticTrustStore([root.certificate]);
        const evaluator = new TrustEvaluator({
            trustStore: store,
            revocationPolicy: 'prefer',
            fetcher,
        });
        const result = await evaluator.evaluate(leaf.certificate);
        expect(result.revocationStatus).toBe('good');
        expect(result.revocationCheckedAt).toBeInstanceOf(Date);
    });

    it('throws RevokedCertificateError when OCSP says revoked', async () => {
        const root = await createCa();
        const leaf = await createLeaf(root, {
            ocspUrl: 'http://ocsp.example.com',
        });
        const client = new (
            await import('../../src/trust/OcspClient.js')
        ).OcspClient();
        const reqDer = await client.buildRequest(
            leaf.certificate,
            root.certificate
        );
        const ocspDer = await signOcspResponse(root, reqDer, {
            status: 'revoked',
            revokedAt: new Date('2026-01-01T00:00:00Z'),
            thisUpdate: new Date('2026-04-23'),
            nextUpdate: new Date('2026-04-30'),
        });
        const fetcher: Fetcher = async () =>
            new Response(ocspDer, { status: 200 });

        const store = new StaticTrustStore([root.certificate]);
        const evaluator = new TrustEvaluator({
            trustStore: store,
            revocationPolicy: 'prefer',
            fetcher,
        });
        await expect(
            evaluator.evaluate(leaf.certificate)
        ).rejects.toBeInstanceOf(RevokedCertificateError);
    });

    it('throws RevocationCheckFailedError under policy=require when no URL is available', async () => {
        const root = await createCa();
        const leaf = await createLeaf(root);
        const store = new StaticTrustStore([root.certificate]);
        const evaluator = new TrustEvaluator({
            trustStore: store,
            revocationPolicy: 'require',
        });
        await expect(
            evaluator.evaluate(leaf.certificate)
        ).rejects.toBeInstanceOf(RevocationCheckFailedError);
    });
});
