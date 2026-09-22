import { describe, expect, it, vi, afterEach } from 'vitest';
import * as xmldsig from 'xmldsigjs';

import { LotlFetcher } from '../../src/trust/LotlFetcher.js';
import { NationalTlResolver } from '../../src/trust/NationalTlResolver.js';
import { LotlConfigurationError, LotlSignatureError } from '../../src/errors.js';
import type { Fetcher } from '../../src/trust/Fetcher.js';
import {
    buildSignedLotlXml,
    createLotlSigner,
} from './helpers/lotl-fixtures.js';

/**
 * Simulate a process where the consumer never called
 * `xmldsig.Application.setEngine(...)`.
 *
 * `Application.crypto` is a static GETTER that THROWS `XmlError`
 * ("XMLJS0014: WebCrypto module is not found") when no engine is registered —
 * it does not return undefined. Verified against xmldsigjs 2.8.7:
 * `build/cjs/application.js` throws `XE.CRYPTOGRAPHIC_NO_MODULE` from the
 * getter body. Any guard written as `if (!Application.crypto)` would therefore
 * throw that raw error instead of evaluating falsy, which is precisely the
 * failure mode this suite pins.
 *
 * The test fixtures register an engine process-wide on import, so the
 * unregistered state has to be restored rather than assumed.
 */
function withoutCryptoEngine(): void {
    vi.spyOn(xmldsig.Application, 'crypto', 'get').mockImplementation(() => {
        throw new Error('XMLJS0014: WebCrypto module is not found');
    });
}

afterEach(() => {
    vi.restoreAllMocks();
});

describe('LotlFetcher — missing xmldsigjs crypto engine', () => {
    it('throws LotlConfigurationError instead of reporting a signature failure', async () => {
        const signer = await createLotlSigner();
        const xml = await buildSignedLotlXml(signer, {
            issueDate: new Date('2026-04-01'),
            nextUpdate: new Date('2026-10-01'),
            pointers: [],
        });
        const fetcher: Fetcher = async () =>
            new Response(xml, {
                status: 200,
                headers: { 'content-type': 'application/xml' },
            });

        withoutCryptoEngine();

        const lotlFetcher = new LotlFetcher({ fetcher });

        await expect(
            lotlFetcher.fetchSigned('http://ec.test/eu-lotl.xml', [signer.certificate]),
        ).rejects.toThrow(LotlConfigurationError);
    });

    it('does not report it as "no signing anchor verified the signature"', async () => {
        // The whole point of the issue: an environment error read as a trust
        // failure sent a consumer bisecting the trusted list's XML.
        const signer = await createLotlSigner();
        const xml = await buildSignedLotlXml(signer, {
            issueDate: new Date('2026-04-01'),
            nextUpdate: new Date('2026-10-01'),
            pointers: [],
        });
        const fetcher: Fetcher = async () =>
            new Response(xml, {
                status: 200,
                headers: { 'content-type': 'application/xml' },
            });

        withoutCryptoEngine();

        const lotlFetcher = new LotlFetcher({ fetcher });
        const err = await lotlFetcher
            .fetchSigned('http://ec.test/eu-lotl.xml', [signer.certificate])
            .catch((e: unknown) => e);

        expect(err).not.toBeInstanceOf(LotlSignatureError);
        expect((err as Error).message).not.toMatch(/no signing anchor verified/);
        // Names the remedy, not just the symptom.
        expect((err as Error).message).toMatch(/setEngine/);
    });

    it('fails before performing any network request', async () => {
        // A missing engine means no list can ever verify, so there is nothing
        // to gain from fetching first.
        const fetcher = vi.fn<Fetcher>();

        withoutCryptoEngine();

        const lotlFetcher = new LotlFetcher({ fetcher });

        await expect(
            lotlFetcher.fetchSigned('http://ec.test/eu-lotl.xml', []),
        ).rejects.toThrow(LotlConfigurationError);
        expect(fetcher).not.toHaveBeenCalled();
    });
});

describe('NationalTlResolver — configuration errors are not per-country failures', () => {
    const lotlSnapshot = {
        pointers: [
            {
                country: 'SE',
                tslLocation: 'http://se.test/tl.xml',
                signingCertificates: [],
            },
        ],
    };

    it('propagates LotlConfigurationError rather than degrading to a warning', async () => {
        // §8.4 graceful degradation is right for a country whose list is down.
        // It is wrong for a missing crypto engine: EVERY country will fail the
        // same way, so skipping them yields an empty anchor set and a pile of
        // misleading warnings.
        const resolver = new NationalTlResolver({
            fetcher: {
                fetchSigned: async () => {
                    throw new LotlConfigurationError('no xmldsigjs crypto engine registered');
                },
            } as unknown as LotlFetcher,
        });

        await expect(
            resolver.resolve(lotlSnapshot as never),
        ).rejects.toThrow(LotlConfigurationError);
    });

    it('still degrades gracefully on an ordinary per-country signature failure', async () => {
        // Regression guard against over-correcting the above into "throw on
        // everything", which would take down the whole store for one bad list.
        const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});

        const resolver = new NationalTlResolver({
            fetcher: {
                fetchSigned: async () => {
                    throw new LotlSignatureError('no signing anchor verified the signature on x');
                },
            } as unknown as LotlFetcher,
        });

        await expect(resolver.resolve(lotlSnapshot as never)).resolves.toEqual([]);
        expect(warn).toHaveBeenCalled();
    });
});
