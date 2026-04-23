import { describe, expect, it } from 'vitest';
import { AsnConvert } from '@peculiar/asn1-schema';
import { OCSPRequest, OCSPResponse } from '@peculiar/asn1-ocsp';
import { OcspClient } from '../../src/trust/OcspClient.js';
import type { Fetcher } from '../../src/trust/Fetcher.js';
import {
    createCa,
    createLeaf,
    createOcspResponder,
    signOcspResponse,
} from './helpers/synthetic-ca.js';

describe('OcspClient — buildRequest', () => {
    it('produces a valid DER-encoded OCSPRequest', async () => {
        const root = await createCa();
        const leaf = await createLeaf(root);
        const client = new OcspClient();
        const requestDer = await client.buildRequest(leaf.certificate, root.certificate);
        const parsed = AsnConvert.parse(requestDer, OCSPRequest);
        expect(parsed.tbsRequest.requestList).toHaveLength(1);
        const certId = parsed.tbsRequest.requestList[0].reqCert;
        expect(certId.issuerNameHash).toBeDefined();
        expect(certId.issuerKeyHash).toBeDefined();
    });

    it('omits optionalSignature', async () => {
        const root = await createCa();
        const leaf = await createLeaf(root);
        const client = new OcspClient();
        const requestDer = await client.buildRequest(leaf.certificate, root.certificate);
        const parsed = AsnConvert.parse(requestDer, OCSPRequest);
        expect(parsed.optionalSignature).toBeUndefined();
    });
});

describe('OcspClient — sendRequest', () => {
    it('posts the request and parses a successful BasicOCSPResponse', async () => {
        const root = await createCa();
        const leaf = await createLeaf(root);
        const responder = await createOcspResponder(root);
        const client = new OcspClient();
        const requestDer = await client.buildRequest(leaf.certificate, root.certificate);
        const responseDer = await signOcspResponse(responder, requestDer, {
            status: 'good',
            thisUpdate: new Date('2026-04-23'),
            nextUpdate: new Date('2026-04-30'),
        });

        const fetcher = async (_url: string, init?: RequestInit): Promise<Response> => {
            expect(init?.method).toBe('POST');
            expect((init?.headers as Record<string, string>)?.['content-type']).toBe(
                'application/ocsp-request'
            );
            return new Response(responseDer, {
                status: 200,
                headers: { 'content-type': 'application/ocsp-response' },
            });
        };
        const c = new OcspClient({ fetcher: fetcher as Fetcher });
        const parsed = await c.sendRequest('http://ocsp.example.com', requestDer);
        expect(parsed.basic.tbsResponseData.responses).toHaveLength(1);
    });

    it('throws on non-successful responseStatus', async () => {
        const malformedResponse = AsnConvert.serialize(
            new OCSPResponse({ responseStatus: 1 /* malformedRequest */ })
        );
        const fetcher = async () =>
            new Response(new Uint8Array(malformedResponse), { status: 200 });
        const c = new OcspClient({ fetcher: fetcher as Fetcher });
        await expect(
            c.sendRequest('http://ocsp.example.com', new Uint8Array([0x30, 0x00]))
        ).rejects.toThrow(/responseStatus/);
    });
});

describe('OcspClient — verifyResponse', () => {
    it('accepts a response signed directly by the issuer', async () => {
        const root = await createCa();
        const leaf = await createLeaf(root);
        const client = new OcspClient();
        const requestDer = await client.buildRequest(leaf.certificate, root.certificate);
        // Sign using the root cert itself as "responder" (same key as issuer).
        const responseDer = await signOcspResponse(root, requestDer, {
            status: 'good',
            thisUpdate: new Date('2026-04-23'),
            nextUpdate: new Date('2026-04-30'),
        });
        const fetcher = async () => new Response(responseDer, { status: 200 });
        const c = new OcspClient({ fetcher: fetcher as Fetcher });
        const envelope = await c.sendRequest('http://ocsp.example.com', requestDer);
        await expect(c.verifyResponse(envelope, root.certificate)).resolves.toBeUndefined();
    });

    it('accepts a response signed by a responder sub-cert with id-kp-OCSPSigning EKU', async () => {
        const root = await createCa();
        const leaf = await createLeaf(root);
        const responder = await createOcspResponder(root);
        const client = new OcspClient();
        const requestDer = await client.buildRequest(leaf.certificate, root.certificate);
        const responseDer = await signOcspResponse(responder, requestDer, {
            status: 'good',
            thisUpdate: new Date('2026-04-23'),
            nextUpdate: new Date('2026-04-30'),
        });
        const fetcher = async () => new Response(responseDer, { status: 200 });
        const c = new OcspClient({ fetcher: fetcher as Fetcher });
        const envelope = await c.sendRequest('http://ocsp.example.com', requestDer);
        await expect(c.verifyResponse(envelope, root.certificate)).resolves.toBeUndefined();
    });

    it('rejects a response signed by a cert lacking id-kp-OCSPSigning', async () => {
        const root = await createCa();
        const leaf = await createLeaf(root);
        const notAResponder = await createLeaf(root, { name: 'CN=Fake Responder' });
        // Abuse signOcspResponse by passing a non-responder sub-cert as signer.
        const client = new OcspClient();
        const requestDer = await client.buildRequest(leaf.certificate, root.certificate);
        const responseDer = await signOcspResponse(notAResponder, requestDer, {
            status: 'good',
            thisUpdate: new Date('2026-04-23'),
            nextUpdate: new Date('2026-04-30'),
        });
        const fetcher = async () => new Response(responseDer, { status: 200 });
        const c = new OcspClient({ fetcher: fetcher as Fetcher });
        const envelope = await c.sendRequest('http://ocsp.example.com', requestDer);
        await expect(c.verifyResponse(envelope, root.certificate)).rejects.toThrow(
            /OCSPSigning/i
        );
    });

    it('rejects a response signed by an unknown key (attacker root)', async () => {
        const root = await createCa();
        const attackerRoot = await createCa();
        const leaf = await createLeaf(root);
        const client = new OcspClient();
        const requestDer = await client.buildRequest(leaf.certificate, root.certificate);
        // Sign with attacker root. The embedded attacker cert won't chain to
        // the real issuer, so ChainBuilder rejects it.
        const responseDer = await signOcspResponse(attackerRoot, requestDer, {
            status: 'good',
            thisUpdate: new Date('2026-04-23'),
            nextUpdate: new Date('2026-04-30'),
        });
        const fetcher = async () => new Response(responseDer, { status: 200 });
        const c = new OcspClient({ fetcher: fetcher as Fetcher });
        const envelope = await c.sendRequest('http://ocsp.example.com', requestDer);
        await expect(c.verifyResponse(envelope, root.certificate)).rejects.toThrow();
    });
});
