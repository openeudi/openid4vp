import { describe, expect, it } from 'vitest';
import { createLotlSigner } from './lotl-fixtures.js';

describe('lotl-fixtures — createLotlSigner', () => {
    it('produces a self-signed CA + keypair suitable for signing LOTL XML', async () => {
        const signer = await createLotlSigner({ name: 'CN=EU LOTL Test Signer' });
        expect(signer.certificate.subject).toBe('CN=EU LOTL Test Signer');
        expect(signer.keys.privateKey).toBeDefined();
        expect(signer.keys.publicKey).toBeDefined();
        // Signing certs don't need cA=true — they sign XML, not issue certs.
        // They must assert `digitalSignature`, which is the default we set.
    });
});
