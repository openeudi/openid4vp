/**
 * Presentation protocol identifiers of the W3C Digital Credentials API.
 *
 * This is the closed `DigitalCredentialPresentationProtocol` enumeration of
 * the W3C Editor's Draft (§7.8.2). User agents treat a request whose
 * `protocol` is not in it as a failure ("convert request protocol", §5.1), so
 * this library never emits any other string.
 */
export const DC_API_PRESENTATION_PROTOCOLS = [
    'openid4vp-v1-unsigned',
    'openid4vp-v1-signed',
    'openid4vp-v1-multisigned',
    'org-iso-mdoc',
] as const;

export type DcApiPresentationProtocol = (typeof DC_API_PRESENTATION_PROTOCOLS)[number];

/**
 * The OpenID4VP-over-DC-API protocols this library builds and verifies.
 * `openid4vp-v1-multisigned` (JWS JSON Serialization) is not supported.
 */
export type DcApiOpenId4VpProtocol = 'openid4vp-v1-unsigned' | 'openid4vp-v1-signed';

/** Every DC API protocol this library builds and verifies: OpenID4VP and ISO/IEC 18013-7 Annex C. */
export type DcApiSupportedProtocol = DcApiOpenId4VpProtocol | 'org-iso-mdoc';

const SUPPORTED: ReadonlySet<string> = new Set<DcApiSupportedProtocol>([
    'openid4vp-v1-unsigned',
    'openid4vp-v1-signed',
    'org-iso-mdoc',
]);
const KNOWN: ReadonlySet<string> = new Set<string>(DC_API_PRESENTATION_PROTOCOLS);

export function isDcApiPresentationProtocol(value: unknown): value is DcApiPresentationProtocol {
    return typeof value === 'string' && KNOWN.has(value);
}

export function isSupportedDcApiProtocol(value: unknown): value is DcApiSupportedProtocol {
    return typeof value === 'string' && SUPPORTED.has(value);
}

/** Human-readable reason a protocol string cannot be used, for error messages. */
export function describeUnsupportedProtocol(value: unknown): string {
    if (isDcApiPresentationProtocol(value)) {
        return `DC API protocol "${value}" is not supported by this library (supported: openid4vp-v1-unsigned, openid4vp-v1-signed, org-iso-mdoc)`;
    }
    return `"${String(value)}" is not a W3C Digital Credentials API presentation protocol (expected one of: ${DC_API_PRESENTATION_PROTOCOLS.join(', ')})`;
}

const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);

/**
 * Is `value` an ASCII-serialized web origin (`scheme://host[:port]`, no path,
 * no trailing slash) of a secure context? The DC API is only exposed in secure
 * contexts, so `http:` is accepted for loopback hosts only.
 *
 * Exact serialization matters: the wallet receives the origin from the
 * browser and copies it byte-for-byte into the KB-JWT `aud` and the mdoc
 * SessionTranscript, so a verifier configured with `https://shop.example/`
 * (trailing slash) would reject every response.
 */
export function isSecureSerializedOrigin(value: unknown): value is string {
    if (typeof value !== 'string' || value.length === 0) return false;
    let url: URL;
    try {
        url = new URL(value);
    } catch {
        return false;
    }
    if (url.origin !== value) return false;
    if (url.protocol === 'https:') return true;
    return url.protocol === 'http:' && LOOPBACK_HOSTS.has(url.hostname);
}
