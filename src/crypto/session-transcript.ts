import { Encoder as CborEncoder } from 'cbor-x';

// Plain-bstr encoder (tagUint8Array:false → byte strings are major-type-2, not
// the typed-array tag 64), matching how conformant issuers/holders encode COSE.
const enc = new CborEncoder({ mapsAsObjects: false, useRecords: false, tagUint8Array: false });

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
    return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes as Uint8Array<ArrayBuffer>));
}

/**
 * Build the legacy `OID4VPHandover` SessionTranscript of ISO 18013-7 Annex B,
 * as used by OpenID4VP draft-era (ID2/ID3) wallets. OpenID4VP 1.0 Final
 * wallets use {@link buildOpenID4VPHandoverSessionTranscript} instead; this
 * layout is selected by `sessionTranscriptProfile: 'oid4vp-draft-annex-b'`:
 *
 *   SessionTranscript = [ null, null, OID4VPHandover ]
 *   OID4VPHandover = [ clientIdHash, responseUriHash, nonce ]
 *   clientIdHash = SHA-256(cbor([clientId, mdocGeneratedNonce]))
 *   responseUriHash = SHA-256(cbor([responseUri, mdocGeneratedNonce]))
 *
 * Used to bind an mdoc DeviceAuthentication to the OpenID4VP authorization
 * request/response exchange it was presented in.
 */
export async function buildOid4vpSessionTranscript(params: {
    clientId: string;
    responseUri: string;
    nonce: string;
    mdocGeneratedNonce: string;
}): Promise<Uint8Array> {
    const { clientId, responseUri, nonce, mdocGeneratedNonce } = params;
    const clientIdHash = await sha256(new Uint8Array(enc.encode([clientId, mdocGeneratedNonce])));
    const responseUriHash = await sha256(new Uint8Array(enc.encode([responseUri, mdocGeneratedNonce])));
    return new Uint8Array(enc.encode([null, null, [clientIdHash, responseUriHash, nonce]]));
}

/**
 * RFC 7638 JWK SHA-256 thumbprint as RAW digest bytes (not base64url).
 *
 * The thumbprint is SHA-256 over the canonical JWK JSON containing ONLY the
 * required members in lexicographic key order, with no whitespace. For EC keys
 * (RFC 7638 §3.2) that is exactly `{"crv":..,"kty":"EC","x":..,"y":..}`.
 *
 * Returns the 32 raw hash bytes because the OpenID4VPHandover embeds the raw
 * thumbprint bytes in CBOR — mirroring the OIDF suite, which calls
 * `jwk.computeThumbprint().decode()` (base64url → raw bytes). See
 * AbstractCreateVP1FinalIsoMdocRedirectSessionTranscript in the conformance
 * suite (openid-certification/conformance-suite@release-v5.1.42).
 */
async function jwkSha256Thumbprint(jwk: JsonWebKey): Promise<Uint8Array> {
    if (jwk.kty !== 'EC') {
        throw new Error(`Unsupported JWK kty for thumbprint: ${jwk.kty}`);
    }
    if (!jwk.crv || !jwk.x || !jwk.y) {
        throw new Error('EC JWK for thumbprint is missing a required member (crv, x, or y)');
    }
    const canonical = `{"crv":"${jwk.crv}","kty":"EC","x":"${jwk.x}","y":"${jwk.y}"}`;
    return sha256(new TextEncoder().encode(canonical));
}

/**
 * Build the OpenID for Verifiable Presentations 1.0 (Final) `OpenID4VPHandover`
 * SessionTranscript (OID4VP 1.0 §B.2.6, `response_uri` flavour):
 *
 *   SessionTranscript = [ null, null, OpenID4VPHandover ]
 *   OpenID4VPHandover = [ "OpenID4VPHandover", SHA-256(cbor(OpenID4VPHandoverInfo)) ]
 *   OpenID4VPHandoverInfo = [ clientId, nonce, jwkThumbprint | null, responseUri ]
 *
 * `jwkThumbprint` is the RFC 7638 SHA-256 thumbprint of the verifier's response
 * ENCRYPTION public JWK as RAW 32 bytes, or CBOR `null` for an unencrypted
 * response. `clientId` is passed verbatim and is expected to already carry its
 * client-id-prefix (e.g. `x509_san_dns:v.example`) — the suite hashes the same
 * `client_id` string it received in the request.
 *
 * This is a DIFFERENT structure from the ISO 18013-7 Annex B `OID4VPHandover`
 * built by `buildOid4vpSessionTranscript` above (which uses an mdoc-generated
 * nonce and separate client_id/response_uri hashes). 1.0-Final wallets tested
 * by the OIDF `oid4vp-1final-verifier-*` modules require THIS layout.
 *
 * Layout confirmed against OID4VP 1.0 Final §B.2.6 and the suite class
 * net.openid.conformance.condition.client.AbstractCreateVP1FinalIsoMdocRedirectSessionTranscript
 * at tag release-v5.1.42: element order [clientId, nonce, thumb|null, responseUri];
 * thumbprint embedded as raw bytes; outer hash is SHA-256 over the CBOR of the
 * 4-element info array.
 */
export async function buildOpenID4VPHandoverSessionTranscript(params: {
    clientId: string;
    nonce: string;
    responseUri: string;
    verifierEncryptionJwk?: JsonWebKey;
}): Promise<Uint8Array> {
    const { clientId, nonce, responseUri, verifierEncryptionJwk } = params;
    const thumb = verifierEncryptionJwk ? await jwkSha256Thumbprint(verifierEncryptionJwk) : null;
    const infoHash = await sha256(new Uint8Array(enc.encode([clientId, nonce, thumb, responseUri])));
    return new Uint8Array(enc.encode([null, null, ['OpenID4VPHandover', infoHash]]));
}

/**
 * Build the OpenID4VP 1.0 (Final) `OpenID4VPDCAPIHandover` SessionTranscript
 * for a presentation made over the W3C Digital Credentials API (§B.2.6.2):
 *
 *   SessionTranscript = [ null, null, OpenID4VPDCAPIHandover ]
 *   OpenID4VPDCAPIHandover = [ "OpenID4VPDCAPIHandover", SHA-256(cbor(OpenID4VPDCAPIHandoverInfo)) ]
 *   OpenID4VPDCAPIHandoverInfo = [ origin, nonce, jwkThumbprint | null ]
 *
 * `origin` is the bare web origin the browser passed to the wallet (for
 * example `https://shop.example`) — §B.2.6.2 says it "MUST NOT be prefixed with
 * `origin:`", unlike the KB-JWT `aud`. `verifierEncryptionJwk` is the public
 * key the verifier advertised for `dc_api.jwt`; omit it for `dc_api`, which
 * puts CBOR `null` in the third element.
 */
export async function buildOpenID4VPDCAPIHandoverSessionTranscript(params: {
    origin: string;
    nonce: string;
    verifierEncryptionJwk?: JsonWebKey;
}): Promise<Uint8Array> {
    const { origin, nonce, verifierEncryptionJwk } = params;
    if (origin.startsWith('origin:')) {
        throw new TypeError('origin must be the bare web origin, without the "origin:" prefix (OpenID4VP 1.0 §B.2.6.2)');
    }
    const thumb = verifierEncryptionJwk ? await jwkSha256Thumbprint(verifierEncryptionJwk) : null;
    const infoHash = await sha256(new Uint8Array(enc.encode([origin, nonce, thumb])));
    return new Uint8Array(enc.encode([null, null, ['OpenID4VPDCAPIHandover', infoHash]]));
}
