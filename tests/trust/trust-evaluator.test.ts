import { describe, expect, it } from 'vitest';
import { TrustEvaluator } from '../../src/trust/TrustEvaluator.js';
import { getAkiKeyIdBase64Url, getSkiBase64Url, getSkiHex } from '../../src/trust/x509-utils.js';
import { CompositeTrustStore, StaticTrustStore } from '../../src/trust/TrustStore.js';
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
    createSelfSigned,
    signOcspResponse,
} from './helpers/synthetic-ca.js';
import type { Fetcher } from '../../src/trust/Fetcher.js';
import { LotlTrustStore } from '../../src/trust/LotlTrustStore.js';
import {
    buildSignedLotlXml,
    buildSignedNationalTlXml,
    createLotlSigner,
} from './helpers/lotl-fixtures.js';

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

    it('rejects a self-signed leaf that reuses a trusted anchor\'s Subject DN', async () => {
        // End-to-end guard for the DN-string trust bypass: an attacker mints a
        // self-signed certificate copying a trusted anchor's Subject DN string.
        // evaluate() must reject it instead of returning a trusted verdict
        // attributed to the real anchor.
        const anchorDn = 'CN=EU Trusted Root CA,O=Member State,C=EU';
        const realRoot = await createCa({ name: anchorDn });
        const impostor = await createSelfSigned({ name: anchorDn });
        const store = new StaticTrustStore([realRoot.certificate]);
        const evaluator = new TrustEvaluator({ trustStore: store });
        await expect(
            evaluator.evaluate(impostor.certificate)
        ).rejects.toBeInstanceOf(CertificateChainError);
    });

    it('reports the anchor the chain actually terminates at (byte-identity)', async () => {
        const root = await createCa({ name: 'CN=Root' });
        const leaf = await createLeaf(root);
        const store = new StaticTrustStore([root.certificate]);
        const evaluator = new TrustEvaluator({ trustStore: store });
        const result = await evaluator.evaluate(leaf.certificate);
        const terminus = result.chain[result.chain.length - 1];
        expect(
            new Uint8Array(result.anchor.certificate.rawData)
        ).toEqual(new Uint8Array(terminus.rawData));
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
            // Dynamic window relative to the real clock — `evaluate()` uses the
            // real `now` for OCSP staleness, so fixed past dates would go stale
            // (>7d) and the response would be silently dropped to source='none'.
            thisUpdate: new Date(Date.now() - 60_000),
            nextUpdate: new Date(Date.now() + 7 * 24 * 3600 * 1000),
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
            // Dynamic window relative to the real clock — `evaluate()` uses the
            // real `now` for OCSP staleness, so fixed past dates would go stale
            // (>7d) and the response would be silently dropped to source='none'.
            thisUpdate: new Date(Date.now() - 60_000),
            nextUpdate: new Date(Date.now() + 7 * 24 * 3600 * 1000),
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

describe('TrustEvaluator — LOTL provenance', () => {
    it('populates provenance when anchor source is lotl', async () => {
        const lotlSigner = await createLotlSigner();
        const frSigner = await createLotlSigner({ name: 'CN=FR TL Signer' });
        const tspRoot = await createCa({ name: 'CN=ANTS Root' });
        const tspLeaf = await createLeaf(tspRoot, { name: 'CN=Issuer 01' });
        const frXml = await buildSignedNationalTlXml(frSigner, {
            country: 'FR',
            issueDate: new Date('2026-04-01'),
            nextUpdate: null,
            services: [
                {
                    providerName: 'ANTS',
                    serviceTypeIdentifier:
                        'http://uri.etsi.org/TrstSvc/Svctype/CA/QC',
                    serviceStatus:
                        'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted',
                    serviceName: 'ANTS Qualified CA',
                    certificates: [tspRoot.certificate],
                    additionalServiceInformationUris: [
                        'http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/eIDASnotified-high',
                    ],
                },
            ],
        });
        const lotlXml = await buildSignedLotlXml(lotlSigner, {
            issueDate: new Date('2026-04-01'),
            nextUpdate: null,
            pointers: [
                {
                    country: 'FR',
                    tslLocation: 'http://fr.test/tl.xml',
                    signingCertificates: [frSigner.certificate],
                },
            ],
        });
        const fetcher: Fetcher = async (url) => {
            if (url.includes('eu-lotl')) return new Response(lotlXml, { status: 200 });
            if (url.includes('fr.test')) return new Response(frXml, { status: 200 });
            return new Response('', { status: 404 });
        };
        const store = new LotlTrustStore({
            fetcher,
            signingAnchors: [lotlSigner.certificate],
            lotlUrl: 'http://ec.test/eu-lotl.xml',
        });
        const evaluator = new TrustEvaluator({ trustStore: store });
        const result = await evaluator.evaluate(tspLeaf.certificate);
        expect(result.anchor.source).toBe('lotl');
        expect(result.provenance?.qualified).toBe(true);
        expect(result.provenance?.country).toBe('FR');
        expect(result.provenance?.loa).toBe('high');
        // aki: the leaf's AKI (= the TSP root's key id); etsi_tl: national TL + LOTL.
        expect(result.trustedAuthorities).toEqual([
            { type: 'aki', value: getSkiBase64Url(tspRoot.certificate) },
            { type: 'etsi_tl', value: 'http://fr.test/tl.xml' },
            { type: 'etsi_tl', value: 'http://ec.test/eu-lotl.xml' },
        ]);
    });

    it('populates provenance when LotlTrustStore is wrapped in CompositeTrustStore', async () => {
        const lotlSigner = await createLotlSigner();
        const frSigner = await createLotlSigner({ name: 'CN=FR TL Signer' });
        const tspRoot = await createCa({ name: 'CN=ANTS Root 2' });
        const tspLeaf = await createLeaf(tspRoot, { name: 'CN=Issuer 02' });
        const frXml = await buildSignedNationalTlXml(frSigner, {
            country: 'FR',
            issueDate: new Date('2026-04-01'),
            nextUpdate: null,
            services: [
                {
                    providerName: 'ANTS',
                    serviceTypeIdentifier:
                        'http://uri.etsi.org/TrstSvc/Svctype/CA/QC',
                    serviceStatus:
                        'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted',
                    serviceName: 'ANTS Qualified CA',
                    certificates: [tspRoot.certificate],
                    additionalServiceInformationUris: [],
                },
            ],
        });
        const lotlXml = await buildSignedLotlXml(lotlSigner, {
            issueDate: new Date('2026-04-01'),
            nextUpdate: null,
            pointers: [
                {
                    country: 'FR',
                    tslLocation: 'http://fr.test/tl.xml',
                    signingCertificates: [frSigner.certificate],
                },
            ],
        });
        const fetcher: Fetcher = async (url) => {
            if (url.includes('eu-lotl')) return new Response(lotlXml, { status: 200 });
            if (url.includes('fr.test')) return new Response(frXml, { status: 200 });
            return new Response('', { status: 404 });
        };
        const lotlStore = new LotlTrustStore({
            fetcher,
            signingAnchors: [lotlSigner.certificate],
            lotlUrl: 'http://ec.test/eu-lotl.xml',
        });
        const composite = new CompositeTrustStore([lotlStore]);
        const evaluator = new TrustEvaluator({ trustStore: composite });
        const result = await evaluator.evaluate(tspLeaf.certificate);
        expect(result.anchor.source).toBe('lotl');
        expect(result.provenance?.country).toBe('FR');
        expect(result.provenance?.qualified).toBe(true);
    });

    it('derives base64url aki ids from the chain for static-store anchors', async () => {
        const root = await createCa();
        const leaf = await createLeaf(root);
        const evaluator = new TrustEvaluator({
            trustStore: new StaticTrustStore([root.certificate]),
        });
        const result = await evaluator.evaluate(leaf.certificate);
        expect(result.anchor.source).toBe('static');
        expect(result.provenance).toBeUndefined();
        const rootAki = getSkiBase64Url(root.certificate)!;
        expect(rootAki).toMatch(/^[A-Za-z0-9_-]+$/);
        // OpenID4VP 1.0 §6.1.1.1: the leaf's AKI keyIdentifier, base64url.
        expect(getAkiKeyIdBase64Url(leaf.certificate)).toBe(rootAki);
        expect(result.trustedAuthorities).toEqual([{ type: 'aki', value: rootAki }]);
        // Deprecated untyped list keeps the hex SKI for one release.
        expect(result.trustedAuthorityIds).toEqual([rootAki, getSkiHex(root.certificate)]);
    });

    it('includes every AuthorityKeyIdentifier in a three-certificate chain', async () => {
        const root = await createCa({ name: `CN=Root ${crypto.randomUUID()}` });
        const inter = await createIntermediate(root, { name: `CN=Intermediate ${crypto.randomUUID()}` });
        const leaf = await createLeaf(inter);
        const evaluator = new TrustEvaluator({ trustStore: new StaticTrustStore([root.certificate]) });
        const result = await evaluator.evaluate(leaf.certificate, { intermediates: [inter.certificate] });
        expect(result.chain).toHaveLength(3);
        expect(result.trustedAuthorities).toEqual([
            { type: 'aki', value: getSkiBase64Url(inter.certificate) },
            { type: 'aki', value: getSkiBase64Url(root.certificate) },
        ]);
    });

    it('lets untyped ids from a custom store match every trusted_authorities type', async () => {
        const root = await createCa();
        const leaf = await createLeaf(root);
        const customId = `custom-${crypto.randomUUID()}`;
        const evaluator = new TrustEvaluator({
            trustStore: {
                getAnchors: async () => [
                    { certificate: root.certificate, source: 'static', trustedAuthorityIds: [customId] },
                ],
            },
        });
        const result = await evaluator.evaluate(leaf.certificate);
        expect(result.trustedAuthorities).toEqual(
            expect.arrayContaining([
                { type: 'aki', value: customId },
                { type: 'etsi_tl', value: customId },
                { type: 'openid_federation', value: customId },
            ])
        );
    });
});
