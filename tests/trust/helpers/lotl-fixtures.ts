import * as x509 from '@peculiar/x509';
import { Crypto as PeculiarCrypto } from '@peculiar/webcrypto';

// Reuse the provider already set by synthetic-ca.ts — calling setSync again
// is a no-op. Import ordering in tests ensures this runs after synthetic-ca.
const provider = new PeculiarCrypto();
x509.cryptoProvider.set(provider as unknown as Crypto);

export interface LotlSigner {
    readonly certificate: x509.X509Certificate;
    readonly keys: CryptoKeyPair;
}

export interface CreateLotlSignerOpts {
    readonly name?: string;
    readonly notBefore?: Date;
    readonly notAfter?: Date;
}

/**
 * Build a self-signed cert suitable for signing LOTL / national-TL XML in
 * tests. Distinct from `createCa` in `synthetic-ca.ts` because LOTL signers
 * are NOT CAs — they do not issue subordinate certs.
 */
export async function createLotlSigner(
    opts: CreateLotlSignerOpts = {}
): Promise<LotlSigner> {
    const keys = await provider.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['sign', 'verify']
    );
    const now = opts.notBefore ?? new Date();
    const end = opts.notAfter ?? new Date(now.getTime() + 365 * 24 * 3600_000);
    const certificate = await x509.X509CertificateGenerator.createSelfSigned({
        name: opts.name ?? 'CN=LOTL Test Signer',
        serialNumber: '01',
        notBefore: now,
        notAfter: end,
        keys,
        signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
        extensions: [
            new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
        ],
    });
    return { certificate, keys };
}
