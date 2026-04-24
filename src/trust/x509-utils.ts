import {
    SubjectKeyIdentifierExtension,
    X509Certificate,
} from '@peculiar/x509';

/**
 * Return the hex-encoded Subject Key Identifier of the given cert, or
 * null if the cert has no SKI extension. Always lowercase.
 */
export function getSkiHex(cert: X509Certificate): string | null {
    const ext = cert.getExtension(SubjectKeyIdentifierExtension);
    return ext ? ext.keyId.toLowerCase() : null;
}

/**
 * Return the raw bytes of the Subject Key Identifier, or null.
 */
export function getSkiBytes(cert: X509Certificate): Uint8Array | null {
    const ext = cert.getExtension(SubjectKeyIdentifierExtension);
    if (!ext) return null;
    const hex = ext.keyId;
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) {
        out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
}
