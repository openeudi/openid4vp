import { Encoder as CborEncoder, Tag } from 'cbor-x';
import type { DcqlQuery } from '@openeudi/dcql';

import { hpkeOpenBase } from '../crypto/hpke.js';
import { buildDCAPIHandoverSessionTranscript } from '../crypto/session-transcript.js';
import { base64UrlToBytes, bytesToBase64Url } from '../encoding/base64url.js';
import { DcApiRequestBuildError, DcApiResponseError } from './errors.js';
import type { DcApiIsoMdocCredentialRequest } from './types.js';

// ISO/IEC 18013-7 Annex C (`org-iso-mdoc`) wire format. The ISO text is
// paywalled; every structure below agrees across multipaz, the EU AV iOS
// library, walt.id, A-SIT vck and Digital Bazaar, and the transcript and HPKE
// layer are pinned by walt.id's Annex C test vectors (tests/fixtures/annex-c).
//
//   request data     = { deviceRequest: b64url(cbor(DeviceRequest)), encryptionInfo: b64url(cbor(EncryptionInfo)) }
//   EncryptionInfo   = [ "dcapi", { "nonce": bstr, "recipientPublicKey": COSE_Key (EC2, P-256) } ]
//   response data    = { response: b64url(cbor(EncryptedResponse)) }
//   EncryptedResponse = [ "dcapi", { "enc": bstr, "cipherText": bstr } ]
//   plaintext        = HPKE-Open(base, P-256/HKDF-SHA256/AES-128-GCM, info = cbor(SessionTranscript), aad = "")
//                    = cbor(DeviceResponse)

const cbor = new CborEncoder({ mapsAsObjects: false, useRecords: false, tagUint8Array: false });

const DCAPI = 'dcapi';
const DEVICE_REQUEST_VERSION = '1.0';
const DEFAULT_NONCE_BYTES = 16;
const MIN_NONCE_BYTES = 16;
const P256_COORDINATE_BYTES = 32;

// COSE_Key labels and values (RFC 9052 §7, RFC 9053 §7.1).
const COSE_KTY = 1;
const COSE_KTY_EC2 = 2;
const COSE_EC2_CRV = -1;
const COSE_EC2_X = -2;
const COSE_EC2_Y = -3;
const COSE_CRV_P256 = 1;

/** One ISO 18013-5 `DocRequest`: docType and namespace → element → intentToRetain. */
export interface IsoMdocDocRequest {
    docType: string;
    nameSpaces: Map<string, Map<string, boolean>>;
}

export interface IsoMdocRequestMaterial {
    request: DcApiIsoMdocCredentialRequest;
    nonce: string;
    encryptionInfo: string;
    recipientPrivateJwk: JsonWebKey;
}

/**
 * Build the Annex C request for one document: a `DeviceRequest` 1.0 with no
 * `readerAuth`, and an `EncryptionInfo` with a fresh ephemeral P-256 recipient
 * key. Version 1.0 is what every implementation accepts; 1.1 is only needed for
 * `readerAuthAll` or `useCases`.
 */
export async function buildIsoMdocRequest(docRequest: IsoMdocDocRequest, nonce?: string): Promise<IsoMdocRequestMaterial> {
    const nonceBytes = resolveNonce(nonce);

    const pair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
    const jwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
    const recipientPrivateJwk: JsonWebKey = { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, d: jwk.d };
    const encryptionInfo = encodeEncryptionInfo(
        nonceBytes,
        base64UrlToBytes(jwk.x as string),
        base64UrlToBytes(jwk.y as string),
    );
    const deviceRequest = encodeDeviceRequest(docRequest);

    return {
        request: { protocol: 'org-iso-mdoc', data: { deviceRequest, encryptionInfo } },
        nonce: bytesToBase64Url(nonceBytes),
        encryptionInfo,
        recipientPrivateJwk,
    };
}

/**
 * Translate a DCQL query into the one `DocRequest` an Annex C request carries.
 * A `DeviceRequest` 1.0 has no alternatives and no value constraints, so only
 * a query the wallet can answer exactly as the verifier will check it is
 * accepted: one `mso_mdoc` credential, a `doctype_value`, at least one
 * `[namespace, element]` claim, and no `credential_sets`, `claim_sets`,
 * `values` or `multiple`.
 */
export function docRequestFromDcqlQuery(query: DcqlQuery): IsoMdocDocRequest {
    const unsupported = (detail: string): never => {
        throw new DcApiRequestBuildError('unsupported_query', `org-iso-mdoc cannot express this DCQL query: ${detail}`);
    };
    if (query.credential_sets !== undefined) unsupported('credential_sets');
    if (query.credentials.length !== 1) unsupported('exactly one credential query is supported');
    const credential = query.credentials[0];
    if (credential.format !== 'mso_mdoc') unsupported(`format "${credential.format}" (only mso_mdoc)`);
    if (credential.multiple === true) unsupported('multiple: true');
    if (credential.claim_sets !== undefined) unsupported('claim_sets');
    const docType = credential.meta?.doctype_value;
    if (typeof docType !== 'string' || docType.length === 0) unsupported('meta.doctype_value is required');
    if (!credential.claims || credential.claims.length === 0) unsupported('at least one claim is required');

    const nameSpaces = new Map<string, Map<string, boolean>>();
    for (const claim of credential.claims ?? []) {
        const [namespace, element] = claim.path;
        if (claim.path.length !== 2 || typeof namespace !== 'string' || typeof element !== 'string') {
            return unsupported('claim paths must be [namespace, element]');
        }
        if (claim.values !== undefined) unsupported('claim values');
        const elements = nameSpaces.get(namespace) ?? new Map<string, boolean>();
        elements.set(element, claim.intent_to_retain === true);
        nameSpaces.set(namespace, elements);
    }
    return { docType: docType as string, nameSpaces };
}

/** base64url(cbor(["dcapi", { nonce, recipientPublicKey: COSE_Key }])) for a P-256 key (x, y). */
export function encodeEncryptionInfo(nonce: Uint8Array, x: Uint8Array, y: Uint8Array): string {
    const recipientPublicKey = new Map<number, unknown>([
        [COSE_KTY, COSE_KTY_EC2],
        [COSE_EC2_CRV, COSE_CRV_P256],
        [COSE_EC2_X, x],
        [COSE_EC2_Y, y],
    ]);
    return bytesToBase64Url(
        cbor.encode([
            DCAPI,
            new Map<string, unknown>([
                ['nonce', nonce],
                ['recipientPublicKey', recipientPublicKey],
            ]),
        ]),
    );
}

/** base64url(cbor(DeviceRequest)): version "1.0", one DocRequest, `itemsRequest` as tag 24, no `readerAuth`. */
export function encodeDeviceRequest(docRequest: IsoMdocDocRequest): string {
    const itemsRequest = cbor.encode(
        new Map<string, unknown>([
            ['docType', docRequest.docType],
            ['nameSpaces', docRequest.nameSpaces],
        ]),
    );
    return bytesToBase64Url(
        cbor.encode(
            new Map<string, unknown>([
                ['version', DEVICE_REQUEST_VERSION],
                ['docRequests', [new Map([['itemsRequest', new Tag(new Uint8Array(itemsRequest), 24)]])]],
            ]),
        ),
    );
}

function resolveNonce(nonce: string | undefined): Uint8Array {
    if (nonce === undefined) {
        return crypto.getRandomValues(new Uint8Array(DEFAULT_NONCE_BYTES));
    }
    let bytes: Uint8Array | undefined;
    if (typeof nonce === 'string' && /^[A-Za-z0-9_-]+$/.test(nonce)) {
        try {
            bytes = base64UrlToBytes(nonce);
        } catch {
            bytes = undefined;
        }
    }
    if (bytes === undefined || bytes.length < MIN_NONCE_BYTES) {
        throw new DcApiRequestBuildError(
            'invalid_nonce',
            `nonce must be unpadded base64url of at least ${MIN_NONCE_BYTES} bytes`,
        );
    }
    return bytes;
}

export interface OpenIsoMdocResponseInput {
    origin: string;
    encryptionInfo: string;
    decryptionKey: CryptoKey | JsonWebKey;
    nonce?: string;
}

export interface OpenedIsoMdocResponse {
    /** CBOR `DeviceResponse` bytes. */
    deviceResponse: Uint8Array;
    /** CBOR `SessionTranscript` the device signature must cover. */
    sessionTranscript: Uint8Array;
    /** The `EncryptionInfo` nonce, base64url. */
    nonce: string;
}

/**
 * Decrypt the `data` of an `org-iso-mdoc` credential. The SessionTranscript is
 * built from the stored `encryptionInfo` and the caller's `origin` — never
 * from anything in the response — and is the HPKE `info`, so a response made
 * for another origin or another request fails here with
 * `DecryptionFailedError`.
 */
export async function openIsoMdocResponse(
    data: Record<string, unknown>,
    input: OpenIsoMdocResponseInput,
): Promise<OpenedIsoMdocResponse> {
    const info = decodeEncryptionInfo(input.encryptionInfo);
    const nonce = bytesToBase64Url(info.nonce);
    if (input.nonce !== undefined && input.nonce !== nonce) {
        throw new DcApiResponseError('nonce_mismatch', 'nonce does not match the nonce inside encryptionInfo');
    }

    if (typeof data.response !== 'string' || Object.keys(data).length !== 1) {
        throw new DcApiResponseError(
            'malformed_response',
            'org-iso-mdoc response data must be exactly { response: "<base64url EncryptedResponse>" }',
        );
    }
    const encrypted = decodeEncryptedResponse(data.response);

    const recipientPrivateKey = await resolveDecryptionKey(input.decryptionKey, info.x, info.y);
    const sessionTranscript = await buildDCAPIHandoverSessionTranscript({
        encryptionInfo: input.encryptionInfo,
        origin: input.origin,
    });
    const deviceResponse = await hpkeOpenBase({
        recipientPrivateKey,
        recipientPublicKey: concat(new Uint8Array([0x04]), info.x, info.y),
        enc: encrypted.enc,
        info: sessionTranscript,
        aad: new Uint8Array(),
        ciphertext: encrypted.cipherText,
    });
    return { deviceResponse, sessionTranscript, nonce };
}

function decodeEncryptionInfo(encryptionInfo: string): { nonce: Uint8Array; x: Uint8Array; y: Uint8Array } {
    const fail = (detail: string): never => {
        throw new DcApiResponseError('invalid_encryption_info', `encryptionInfo is not an Annex C EncryptionInfo: ${detail}`);
    };
    const decoded = decodeBase64UrlCbor(encryptionInfo, () => fail('not base64url CBOR'));
    if (!Array.isArray(decoded) || decoded.length !== 2 || decoded[0] !== DCAPI || !(decoded[1] instanceof Map)) {
        return fail('expected ["dcapi", { nonce, recipientPublicKey }]');
    }
    const params = decoded[1] as Map<unknown, unknown>;
    const nonce = params.get('nonce');
    const key = params.get('recipientPublicKey');
    if (!(nonce instanceof Uint8Array) || nonce.length === 0) return fail('nonce must be a non-empty bstr');
    if (
        !(key instanceof Map) ||
        key.get(COSE_KTY) !== COSE_KTY_EC2 ||
        key.get(COSE_EC2_CRV) !== COSE_CRV_P256 ||
        !isCoordinate(key.get(COSE_EC2_X)) ||
        !isCoordinate(key.get(COSE_EC2_Y))
    ) {
        return fail('recipientPublicKey must be an EC2 P-256 COSE_Key');
    }
    return { nonce, x: key.get(COSE_EC2_X) as Uint8Array, y: key.get(COSE_EC2_Y) as Uint8Array };
}

function decodeEncryptedResponse(response: string): { enc: Uint8Array; cipherText: Uint8Array } {
    const fail = (detail: string): never => {
        throw new DcApiResponseError('malformed_response', `org-iso-mdoc response is not an Annex C EncryptedResponse: ${detail}`);
    };
    const decoded = decodeBase64UrlCbor(response, () => fail('not base64url CBOR'));
    if (!Array.isArray(decoded) || decoded.length !== 2 || decoded[0] !== DCAPI || !(decoded[1] instanceof Map)) {
        return fail('expected ["dcapi", { enc, cipherText }]');
    }
    const params = decoded[1] as Map<unknown, unknown>;
    const enc = params.get('enc');
    const cipherText = params.get('cipherText');
    if (!(enc instanceof Uint8Array) || !(cipherText instanceof Uint8Array)) {
        return fail('enc and cipherText must be byte strings');
    }
    return { enc, cipherText };
}

function decodeBase64UrlCbor(value: string, onError: () => never): unknown {
    if (!/^[A-Za-z0-9_-]+$/.test(value)) onError();
    try {
        return cbor.decode(base64UrlToBytes(value));
    } catch {
        return onError();
    }
}

async function resolveDecryptionKey(key: CryptoKey | JsonWebKey, x: Uint8Array, y: Uint8Array): Promise<CryptoKey> {
    if (typeof CryptoKey !== 'undefined' && key instanceof CryptoKey) return key;
    const jwk = key as JsonWebKey;
    if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || typeof jwk.d !== 'string') {
        throw new DcApiResponseError('decryption_key_mismatch', 'decryptionKey must be a P-256 private JWK (with "d") or CryptoKey');
    }
    const expectedX = bytesToBase64Url(x);
    const expectedY = bytesToBase64Url(y);
    // A key whose public half is known can be matched before any decryption;
    // a bare `d` (as in some test vectors) gets the public half from EncryptionInfo.
    if ((jwk.x !== undefined && jwk.x !== expectedX) || (jwk.y !== undefined && jwk.y !== expectedY)) {
        throw new DcApiResponseError(
            'decryption_key_mismatch',
            'decryptionKey is not the recipient key of encryptionInfo (wrong session?)',
        );
    }
    try {
        return await crypto.subtle.importKey(
            'jwk',
            { kty: 'EC', crv: 'P-256', x: expectedX, y: expectedY, d: jwk.d },
            { name: 'ECDH', namedCurve: 'P-256' },
            false,
            ['deriveBits'],
        );
    } catch (err) {
        throw new DcApiResponseError('decryption_key_mismatch', 'decryptionKey is not a usable P-256 private key', {
            cause: err as Error,
        });
    }
}

function isCoordinate(value: unknown): value is Uint8Array {
    return value instanceof Uint8Array && value.length === P256_COORDINATE_BYTES;
}

function concat(...parts: Uint8Array[]): Uint8Array {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let offset = 0;
    for (const part of parts) {
        out.set(part, offset);
        offset += part.length;
    }
    return out;
}
