import { describe, expect, it } from 'vitest';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { LotlTrustStore } from '../../src/trust/LotlTrustStore.js';
import {
    buildSignedLotlXml,
    buildSignedNationalTlXml,
    createLotlSigner,
} from './helpers/lotl-fixtures.js';
import { createCa, createLeaf } from './helpers/synthetic-ca.js';
import { TrustEvaluator } from '../../src/trust/TrustEvaluator.js';

async function startServer(
    routes: Map<string, string>
): Promise<{ url: string; close: () => Promise<void> }> {
    const server = http.createServer((req, res) => {
        const body = routes.get(req.url ?? '');
        if (!body) {
            res.statusCode = 404;
            res.end();
            return;
        }
        res.setHeader('content-type', 'application/xml');
        res.end(body);
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    const addr = server.address() as AddressInfo;
    return {
        url: `http://127.0.0.1:${addr.port}`,
        close: () =>
            new Promise<void>((r) => server.close(() => r())),
    };
}

describe('end-to-end — SD-JWT with LotlTrustStore', () => {
    it('populates trust.provenance + trustedAuthorityIds on a valid chain', async () => {
        const lotlSigner = await createLotlSigner();
        const frSigner = await createLotlSigner({ name: 'CN=FR TL Signer' });
        const tspRoot = await createCa({ name: 'CN=ANTS Root, C=FR' });
        const issuerLeaf = await createLeaf(tspRoot, {
            name: 'CN=Issuer, C=FR',
        });

        // Start the server first with placeholder content so we can discover
        // the dynamic port, then patch in the real URL by rebuilding the
        // signed LOTL XML (signatures cover the TSLLocation content — patching
        // the pre-signed string would break verification).
        const routes = new Map<string, string>();
        routes.set('/fr-tl.xml', ''); // placeholder; filled after server starts

        const frXml = await buildSignedNationalTlXml(frSigner, {
            country: 'FR',
            issueDate: new Date('2026-04-01'),
            nextUpdate: new Date('2026-10-01'),
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
        routes.set('/fr-tl.xml', frXml);

        const server = await startServer(routes);
        const lotlUrl = `${server.url}/eu-lotl.xml`;
        const frUrl = `${server.url}/fr-tl.xml`;

        // Build the LOTL XML now that we know the real FR TL URL.
        // This MUST happen after server.listen() because the URL is part of
        // the signed payload — building before would produce an unusable
        // placeholder signature.
        const lotlXml = await buildSignedLotlXml(lotlSigner, {
            issueDate: new Date('2026-04-01'),
            nextUpdate: new Date('2026-10-01'),
            pointers: [
                {
                    country: 'FR',
                    tslLocation: frUrl,
                    signingCertificates: [frSigner.certificate],
                },
            ],
        });
        routes.set('/eu-lotl.xml', lotlXml);

        try {
            // No custom `fetcher` — exercises globalThis.fetch (Node v22 built-in)
            // hitting the real node:http server. This is the end-to-end contract.
            const store = new LotlTrustStore({
                signingAnchors: [lotlSigner.certificate],
                lotlUrl,
            });
            const evaluator = new TrustEvaluator({ trustStore: store });
            const result = await evaluator.evaluate(issuerLeaf.certificate);

            expect(result.anchor.source).toBe('lotl');
            expect(result.provenance?.qualified).toBe(true);
            expect(result.provenance?.country).toBe('FR');
            expect(result.provenance?.loa).toBe('high');
            expect(result.trustedAuthorityIds?.length).toBeGreaterThanOrEqual(1);
        } finally {
            await server.close();
        }
    });

    it('propagates LotlSignatureError when the server serves an unsigned LOTL', async () => {
        const lotlSigner = await createLotlSigner();
        const routes = new Map<string, string>();
        routes.set(
            '/eu-lotl.xml',
            `<?xml version="1.0"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#" Id="tsl-root">
  <SchemeInformation><ListIssueDateTime>2026-04-01T00:00:00Z</ListIssueDateTime></SchemeInformation>
</TrustServiceStatusList>`
        );
        const server = await startServer(routes);
        try {
            const store = new LotlTrustStore({
                signingAnchors: [lotlSigner.certificate],
                lotlUrl: `${server.url}/eu-lotl.xml`,
            });
            await expect(store.getAnchors({ issuer: 'CN=anyone' })).rejects.toThrow();
        } finally {
            await server.close();
        }
    });
});
