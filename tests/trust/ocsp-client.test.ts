import { describe, expect, it } from 'vitest';
import { AsnConvert } from '@peculiar/asn1-schema';
import { OCSPRequest } from '@peculiar/asn1-ocsp';
import { OcspClient } from '../../src/trust/OcspClient.js';
import { createCa, createLeaf } from './helpers/synthetic-ca.js';

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
