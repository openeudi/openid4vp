import type { DcqlQuery } from '@openeudi/dcql';

import type {
    MultiLangString,
    RegistrarCredential,
    RegistrarDataset,
    RegistrarIdentifier,
    VerifierInfo,
} from './types/verifier-info.js';

/** ETSI TS 119 472-2 V1.3.1 OIDFVP-HAIP-COMMON-REQ-RO-04. */
const REGISTRAR_DATASET_FORMAT = 'registrar_dataset';
/** ETSI TS 119 472-2 V1.3.1 OIDFVP-HAIP-COMMON-REQ-RO-15. */
const REGISTRATION_CERT_FORMAT = 'registration_cert';
/** ETSI TS 119 475 V1.2.1 GEN-5.2.2-01 Table 5: `typ` of a JWT-formatted WRPRC. */
const WRPRC_JWT_TYP = 'rc-wrp+jwt';

/**
 * Formats ETSI TS 119 472-2 allows once per request object, and never with
 * `credential_ids` (RO-03, RO-14). ARF RPRC_19 also asks for "a single
 * registration certificate" per presentation request.
 */
const ETSI_SINGLETON_FORMATS = new Set([REGISTRAR_DATASET_FORMAT, REGISTRATION_CERT_FORMAT]);

const BASE64URL_SEGMENT = /^[A-Za-z0-9_-]+$/;

/**
 * Build the `registrar_dataset` element of `verifier_info` (ETSI TS 119 472-2
 * V1.3.1 §6.3.2.2, RO-02 to RO-12). TS 119 472-2 makes this element mandatory
 * in every request object (RO-01, RO-02).
 *
 * The values must be the ones registered with the RP Registrar: wallets may
 * check them against the Registrar API at `registryURI`.
 *
 * @throws TypeError when a required member is missing or empty.
 */
export function registrarDatasetVerifierInfo(dataset: RegistrarDataset): VerifierInfo {
    requireNonEmptyArray(dataset.identifier, 'identifier');
    dataset.identifier.forEach((id, i) => checkIdentifier(id, `identifier[${i}]`));
    checkMultiLangStrings(dataset.srvDescription, 'srvDescription');
    requireAbsoluteUrl(dataset.registryURI, 'registryURI');
    requireNonEmptyString(dataset.intendedUseIdentifier, 'intendedUseIdentifier');
    checkMultiLangStrings(dataset.purpose, 'purpose');
    requireAbsoluteUrl(dataset.policyURI, 'policyURI');
    if (dataset.credential !== undefined) {
        requireNonEmptyArray(dataset.credential, 'credential');
        dataset.credential.forEach((c, i) => checkCredential(c, `credential[${i}]`));
    }

    // Built member by member so a caller's extra properties never reach the wallet.
    const data: Record<string, unknown> = {
        identifier: dataset.identifier.map((id) => ({ type: id.type, identifier: id.identifier })),
        srvDescription: dataset.srvDescription.map(copyMultiLangString),
        registryURI: dataset.registryURI,
        intendedUseIdentifier: dataset.intendedUseIdentifier,
        purpose: dataset.purpose.map(copyMultiLangString),
        policyURI: dataset.policyURI,
    };
    if (dataset.credential !== undefined) data.credential = dataset.credential;

    return { format: REGISTRAR_DATASET_FORMAT, data };
}

/**
 * Build the `registration_cert` element of `verifier_info` (ETSI TS 119 472-2
 * V1.3.1 §6.3.2.2, RO-13 to RO-16) from a Wallet-Relying Party Registration
 * Certificate (WRPRC, ETSI TS 119 475).
 *
 * Pass a JWT-formatted WRPRC as its compact JWS string (header `typ`
 * `rc-wrp+jwt`), or a CWT-formatted one as its CBOR bytes. RO-16 requires
 * `data` to be "the base64url encoding of the serialized RP registration
 * certificate", so the serialization itself is base64url-encoded: for a JWT
 * that is the UTF-8 bytes of the compact JWS, which encodes it a second time.
 *
 * For an intermediated relying party, pass the WRPRC whose `sub` is the final
 * relying party and which names the intermediary (TS 119 475 §4.5,
 * GEN-5.2.4-09).
 *
 * @throws TypeError when the certificate is empty or a JWT is not a compact
 * JWS with header `typ` `rc-wrp+jwt`.
 */
export function registrationCertVerifierInfo(wrprc: string | Uint8Array): VerifierInfo {
    let bytes: Uint8Array;
    if (typeof wrprc === 'string') {
        checkWrprcJwt(wrprc);
        bytes = new TextEncoder().encode(wrprc);
    } else if (wrprc instanceof Uint8Array) {
        if (wrprc.length === 0) throw new TypeError('registration certificate must not be empty');
        bytes = wrprc;
    } else {
        throw new TypeError('registration certificate must be a compact JWS string or CWT bytes');
    }
    return { format: REGISTRATION_CERT_FORMAT, data: base64UrlEncode(bytes) };
}

/**
 * Check `verifier_info` against OpenID4VP 1.0 §5.1 and the ETSI TS 119 472-2
 * V1.3.1 rules for its two formats. Returns a description of the first problem,
 * or `undefined` when the value is acceptable, so each request builder can
 * raise its own error type.
 *
 * @internal
 */
export function verifierInfoProblem(entries: unknown, query: DcqlQuery): string | undefined {
    if (!Array.isArray(entries) || entries.length === 0) {
        return 'verifierInfo must be a non-empty array when present (OpenID4VP 1.0 §5.1)';
    }
    const credentialIds = new Set(query.credentials.map((c) => c.id));
    const seenSingletons = new Set<string>();

    for (let i = 0; i < entries.length; i++) {
        const entry: unknown = entries[i];
        const at = `verifierInfo[${i}]`;
        if (!isPlainObject(entry)) return `${at} must be an object`;
        const { format, data, credential_ids: ids } = entry;

        if (typeof format !== 'string' || format.length === 0) {
            return `${at}.format must be a non-empty string`;
        }
        if (typeof data === 'string') {
            if (data.length === 0) return `${at}.data must not be empty`;
        } else if (!isPlainObject(data)) {
            return `${at}.data must be a string or an object`;
        }

        if (ids !== undefined) {
            if (!Array.isArray(ids) || ids.length === 0) {
                return `${at}.credential_ids must be a non-empty array when present`;
            }
            for (const id of ids) {
                if (typeof id !== 'string' || !credentialIds.has(id)) {
                    return `${at}.credential_ids entry ${JSON.stringify(id)} does not match any DCQL credential id`;
                }
            }
        }

        if (ETSI_SINGLETON_FORMATS.has(format)) {
            if (ids !== undefined) {
                return `${at}: a "${format}" element must not carry credential_ids (ETSI TS 119 472-2 RO-03, RO-14)`;
            }
            if (seenSingletons.has(format)) {
                return `${at}: only one "${format}" element is allowed`;
            }
            seenSingletons.add(format);
        }
        if (format === REGISTRAR_DATASET_FORMAT && (!isPlainObject(data) || Object.keys(data).length === 0)) {
            return `${at}.data must be a non-empty object for "${format}" (ETSI TS 119 472-2 RO-05)`;
        }
        if (format === REGISTRATION_CERT_FORMAT && typeof data !== 'string') {
            return `${at}.data must be the base64url-encoded certificate for "${format}" (ETSI TS 119 472-2 RO-16)`;
        }
    }
    return undefined;
}

/**
 * The wire form of validated entries: only the three members OpenID4VP 1.0
 * §5.1 defines, so a caller's extra properties never reach the wallet.
 *
 * @internal
 */
export function serializeVerifierInfo(entries: VerifierInfo[]): VerifierInfo[] {
    return entries.map((e) => ({
        format: e.format,
        data: e.data,
        ...(e.credential_ids !== undefined ? { credential_ids: [...e.credential_ids] } : {}),
    }));
}

function checkWrprcJwt(jws: string): void {
    const segments = jws.split('.');
    if (segments.length !== 3 || !segments.every((s) => BASE64URL_SEGMENT.test(s))) {
        throw new TypeError('registration certificate string must be a compact JWS (header.payload.signature)');
    }
    let header: unknown;
    try {
        header = JSON.parse(new TextDecoder().decode(base64UrlDecode(segments[0])));
    } catch {
        throw new TypeError('registration certificate JWS header is not base64url-encoded JSON');
    }
    if (!isPlainObject(header) || header.typ !== WRPRC_JWT_TYP) {
        throw new TypeError(
            `registration certificate JWS header typ must be "${WRPRC_JWT_TYP}" (ETSI TS 119 475 GEN-5.2.2-01)`,
        );
    }
}

function checkIdentifier(id: RegistrarIdentifier, at: string): void {
    if (!isPlainObject(id)) throw new TypeError(`${at} must be an object`);
    requireNonEmptyString(id.type, `${at}.type`);
    requireNonEmptyString(id.identifier, `${at}.identifier`);
}

function checkMultiLangStrings(values: MultiLangString[], at: string): void {
    requireNonEmptyArray(values, at);
    values.forEach((v, i) => {
        if (!isPlainObject(v)) throw new TypeError(`${at}[${i}] must be an object`);
        requireNonEmptyString(v.lang, `${at}[${i}].lang`);
        requireNonEmptyString(v.content, `${at}[${i}].content`);
    });
}

function checkCredential(credential: RegistrarCredential, at: string): void {
    if (!isPlainObject(credential)) throw new TypeError(`${at} must be an object`);
    requireNonEmptyString(credential.format, `${at}.format`);
    if (typeof credential.meta !== 'string' && !isPlainObject(credential.meta)) {
        throw new TypeError(`${at}.meta must be a string or an object`);
    }
    if (credential.claim !== undefined) {
        requireNonEmptyArray(credential.claim, `${at}.claim`);
        credential.claim.forEach((claim, i) => {
            const path = isPlainObject(claim) ? claim.path : undefined;
            const validPath =
                (typeof path === 'string' && path.length > 0) || (Array.isArray(path) && path.length > 0);
            if (!validPath) throw new TypeError(`${at}.claim[${i}].path must be a non-empty string or array`);
        });
    }
}

function copyMultiLangString(v: MultiLangString): MultiLangString {
    return { lang: v.lang, content: v.content };
}

function requireNonEmptyString(value: unknown, name: string): void {
    if (typeof value !== 'string' || value.length === 0) {
        throw new TypeError(`${name} must be a non-empty string`);
    }
}

function requireNonEmptyArray(value: unknown, name: string): void {
    if (!Array.isArray(value) || value.length === 0) {
        throw new TypeError(`${name} must be a non-empty array`);
    }
}

function requireAbsoluteUrl(value: unknown, name: string): void {
    requireNonEmptyString(value, name);
    try {
        new URL(value as string);
    } catch {
        throw new TypeError(`${name} must be an absolute URI`);
    }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function base64UrlEncode(bytes: Uint8Array): string {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlDecode(segment: string): Uint8Array {
    const b64 = segment.replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
}
