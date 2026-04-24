import { describe, expect, it } from 'vitest';
import { LotlFetcher } from '../../src/trust/LotlFetcher.js';
import { LotlFetchError, LotlSignatureError } from '../../src/errors.js';
import type { Fetcher } from '../../src/trust/Fetcher.js';
import {
    buildSignedLotlXml,
    createLotlSigner,
} from './helpers/lotl-fixtures.js';

function respond(xml: string, init: ResponseInit = {}): Response {
    return new Response(xml, {
        status: 200,
        headers: { 'content-type': 'application/xml' },
        ...init,
    });
}

describe('LotlFetcher — success', () => {
    it('fetches + verifies a signed LOTL against its signing anchor', async () => {
        const signer = await createLotlSigner();
        const xml = await buildSignedLotlXml(signer, {
            issueDate: new Date('2026-04-01'),
            nextUpdate: new Date('2026-10-01'),
            pointers: [],
        });
        const fetcher: Fetcher = async () => respond(xml);
        const lotlFetcher = new LotlFetcher({ fetcher });
        const doc = await lotlFetcher.fetchSigned(
            'http://ec.test/eu-lotl.xml',
            [signer.certificate]
        );
        expect(doc).toBeDefined();
        expect(doc.documentElement?.localName).toBe('TrustServiceStatusList');
    });
});

describe('LotlFetcher — fetch failures', () => {
    it('throws LotlFetchError on HTTP 500', async () => {
        const fetcher: Fetcher = async () => respond('', { status: 500 });
        const signer = await createLotlSigner();
        const lotlFetcher = new LotlFetcher({ fetcher });
        await expect(
            lotlFetcher.fetchSigned('http://ec.test/eu-lotl.xml', [signer.certificate])
        ).rejects.toBeInstanceOf(LotlFetchError);
    });

    it('throws LotlFetchError on network error', async () => {
        const fetcher: Fetcher = async () => {
            throw new Error('connection reset');
        };
        const signer = await createLotlSigner();
        const lotlFetcher = new LotlFetcher({ fetcher });
        await expect(
            lotlFetcher.fetchSigned('http://ec.test/eu-lotl.xml', [signer.certificate])
        ).rejects.toBeInstanceOf(LotlFetchError);
    });

    it('throws LotlFetchError when body is not valid XML', async () => {
        const fetcher: Fetcher = async () => respond('not xml');
        const signer = await createLotlSigner();
        const lotlFetcher = new LotlFetcher({ fetcher });
        await expect(
            lotlFetcher.fetchSigned('http://ec.test/eu-lotl.xml', [signer.certificate])
        ).rejects.toBeInstanceOf(LotlFetchError);
    });
});

describe('LotlFetcher — signature failures', () => {
    it('throws LotlSignatureError when Signature element is absent', async () => {
        const signer = await createLotlSigner();
        const xml = `<?xml version="1.0"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#" Id="tsl-root">
  <SchemeInformation/>
</TrustServiceStatusList>`;
        const fetcher: Fetcher = async () => respond(xml);
        const lotlFetcher = new LotlFetcher({ fetcher });
        await expect(
            lotlFetcher.fetchSigned('http://ec.test/eu-lotl.xml', [signer.certificate])
        ).rejects.toBeInstanceOf(LotlSignatureError);
    });

    it('throws LotlSignatureError when signed by a different key', async () => {
        const authenticSigner = await createLotlSigner({ name: 'CN=Genuine' });
        const wrongSigner = await createLotlSigner({ name: 'CN=Impersonator' });
        const xml = await buildSignedLotlXml(wrongSigner, {
            issueDate: new Date('2026-04-01'),
            nextUpdate: null,
            pointers: [],
        });
        const fetcher: Fetcher = async () => respond(xml);
        const lotlFetcher = new LotlFetcher({ fetcher });
        await expect(
            lotlFetcher.fetchSigned(
                'http://ec.test/eu-lotl.xml',
                [authenticSigner.certificate]
            )
        ).rejects.toBeInstanceOf(LotlSignatureError);
    });

    it('verifies against any anchor in the provided list (first match wins)', async () => {
        const anchorA = await createLotlSigner({ name: 'CN=Anchor A' });
        const anchorB = await createLotlSigner({ name: 'CN=Anchor B' });
        const xml = await buildSignedLotlXml(anchorB, {
            issueDate: new Date('2026-04-01'),
            nextUpdate: null,
            pointers: [],
        });
        const fetcher: Fetcher = async () => respond(xml);
        const lotlFetcher = new LotlFetcher({ fetcher });
        const doc = await lotlFetcher.fetchSigned(
            'http://ec.test/eu-lotl.xml',
            [anchorA.certificate, anchorB.certificate]
        );
        expect(doc).toBeDefined();
    });
});
