/**
 * Internal ECDSA encoding helpers. `@peculiar/x509` + WebCrypto use
 * different wire formats for ECDSA signatures; these helpers bridge
 * DER (ASN.1 SEQUENCE { r, s }) and IEEE P1363 (r||s fixed-width).
 *
 * NOT exported from the package root.
 */

export function ecdsaDerToIeee(der: Uint8Array, coordBytes: number): Uint8Array {
    let pos = 0;
    if (der[pos++] !== 0x30)
        throw new Error('invalid DER signature: expected SEQUENCE');
    pos++; // skip seq-length
    if (der[pos++] !== 0x02)
        throw new Error('invalid DER signature: expected INTEGER r');
    const rLen = der[pos++];
    let r = der.slice(pos, pos + rLen);
    pos += rLen;
    if (der[pos++] !== 0x02)
        throw new Error('invalid DER signature: expected INTEGER s');
    const sLen = der[pos++];
    let s = der.slice(pos, pos + sLen);
    if (r.length > coordBytes) r = r.slice(r.length - coordBytes);
    if (s.length > coordBytes) s = s.slice(s.length - coordBytes);
    const out = new Uint8Array(coordBytes * 2);
    out.set(r, coordBytes - r.length);
    out.set(s, coordBytes * 2 - s.length);
    return out;
}
