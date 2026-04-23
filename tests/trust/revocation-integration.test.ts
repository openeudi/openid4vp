import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import * as http from 'node:http';
import type { AddressInfo } from 'node:net';
import * as jose from 'jose';
import * as x509 from '@peculiar/x509';
import { Crypto as PeculiarCrypto } from '@peculiar/webcrypto';

import { SdJwtParser } from '../../src/parsers/sd-jwt.parser.js';
import { StaticTrustStore } from '../../src/trust/TrustStore.js';
import { RevokedCertificateError, RevocationCheckFailedError } from '../../src/errors.js';
import { OcspClient } from '../../src/trust/OcspClient.js';
import { createCa, createCrl, createLeaf, signOcspResponse } from './helpers/synthetic-ca.js';

// ---------------------------------------------------------------------------
// SD-JWT signing helper (inline port).
//
// The synthetic-ca generates CryptoKey instances via `@peculiar/webcrypto`.
// Those keys are not directly consumable by `jose` under Node, so we round-trip
// the private key through JWK to obtain a native-webcrypto `CryptoKey` that
// `jose.SignJWT.sign()` accepts. The public side of the x5c chain is imported
// by `SdJwtParser` via `importX509(…)`, so no cross-provider coupling occurs.
// ---------------------------------------------------------------------------
const peculiarProvider = new PeculiarCrypto();

async function makeSdJwtSignedByLeaf(leaf: {
    certificate: x509.X509Certificate;
    keys: CryptoKeyPair;
}): Promise<string> {
    const leafDerBase64 = Buffer.from(new Uint8Array(leaf.certificate.rawData)).toString('base64');

    // Export via the peculiar provider that created the key, then re-import
    // via jose so the signing side runs on Node's native WebCrypto.
    const jwk = await peculiarProvider.subtle.exportKey('jwk', leaf.keys.privateKey);
    const signingKey = await jose.importJWK(jwk as jose.JWK, 'ES256');

    const now = Math.floor(Date.now() / 1000);
    const payload: jose.JWTPayload = {
        iss: 'https://issuer.example.com/eudi',
        vct: 'urn:eu.europa.ec.eudi:pid:1',
        iat: now,
        exp: now + 3600,
    };

    // Build a bare SD-JWT (no selective disclosures, no key binding). The
    // parser validates x5c + signature + `iss`/`vct` — nothing more is needed.
    const jwt = await new jose.SignJWT(payload)
        .setProtectedHeader({ alg: 'ES256', typ: 'vc+sd-jwt', x5c: [leafDerBase64] })
        .sign(signingKey);

    return jwt + '~';
}

// ---------------------------------------------------------------------------
// Local HTTP server (CRL/OCSP responder stand-in).
// ---------------------------------------------------------------------------
let server: http.Server;
let baseUrl: string;

beforeEach(async () => {
    server = http.createServer();
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
    const addr = server.address() as AddressInfo;
    baseUrl = `http://127.0.0.1:${addr.port}`;
});

afterEach(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
});

// ---------------------------------------------------------------------------
// Integration tests.
// ---------------------------------------------------------------------------
describe('A.2 integration — revocation end-to-end via SdJwtParser', () => {
    it('succeeds with policy=prefer + OCSP good', async () => {
        const root = await createCa();
        const leaf = await createLeaf(root, { ocspUrl: `${baseUrl}/ocsp` });

        const ocspClient = new OcspClient();
        const reqDer = await ocspClient.buildRequest(leaf.certificate, root.certificate);
        const ocspDer = await signOcspResponse(root, reqDer, {
            status: 'good',
            thisUpdate: new Date(),
            nextUpdate: new Date(Date.now() + 24 * 3600 * 1000),
        });

        server.on('request', (_req, res) => {
            res.writeHead(200, { 'content-type': 'application/ocsp-response' });
            res.end(Buffer.from(ocspDer));
        });

        const sdJwt = await makeSdJwtSignedByLeaf(leaf);
        const parser = new SdJwtParser();
        const result = await parser.parse(sdJwt, {
            nonce: 'abc',
            trustedCertificates: [],
            trustStore: new StaticTrustStore([root.certificate]),
            revocationPolicy: 'prefer',
        });

        expect(result.valid).toBe(true);
        expect(result.trust?.revocationStatus).toBe('good');
    });

    it('throws RevokedCertificateError with policy=require + CRL revoked', async () => {
        const root = await createCa();
        const leaf = await createLeaf(root, { crlUrls: [`${baseUrl}/a.crl`] });
        const { der: crlDer } = await createCrl(root, {
            revokedSerials: [
                {
                    serialHex: leaf.certificate.serialNumber,
                    revokedAt: new Date(Date.now() - 3600 * 1000),
                },
            ],
            thisUpdate: new Date(),
            nextUpdate: new Date(Date.now() + 24 * 3600 * 1000),
        });

        server.on('request', (_req, res) => {
            res.writeHead(200, { 'content-type': 'application/pkix-crl' });
            res.end(Buffer.from(crlDer));
        });

        const sdJwt = await makeSdJwtSignedByLeaf(leaf);
        const parser = new SdJwtParser();
        await expect(
            parser.parse(sdJwt, {
                nonce: 'abc',
                trustedCertificates: [],
                trustStore: new StaticTrustStore([root.certificate]),
                revocationPolicy: 'require',
            })
        ).rejects.toBeInstanceOf(RevokedCertificateError);
    });

    it('throws RevocationCheckFailedError with policy=require + 500 from OCSP', async () => {
        const root = await createCa();
        const leaf = await createLeaf(root, { ocspUrl: `${baseUrl}/ocsp` });

        server.on('request', (_req, res) => {
            res.writeHead(500);
            res.end();
        });

        const sdJwt = await makeSdJwtSignedByLeaf(leaf);
        const parser = new SdJwtParser();
        await expect(
            parser.parse(sdJwt, {
                nonce: 'abc',
                trustedCertificates: [],
                trustStore: new StaticTrustStore([root.certificate]),
                revocationPolicy: 'require',
            })
        ).rejects.toBeInstanceOf(RevocationCheckFailedError);
    });
});
