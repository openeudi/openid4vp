import { Encoder as CborEncoder, Tag } from 'cbor-x';

import { MalformedCredentialError, ExpiredCredentialError } from '../errors.js';

// Decoder that preserves CBOR maps as JS Maps (cbor-x default converts them to objects).
const decoder = new CborEncoder({ mapsAsObjects: false, useRecords: false });

export interface MobileSecurityObject {
    version: string;
    digestAlgorithm: string;
    valueDigests: Map<string, Map<number, Uint8Array>>;
    docType: string;
    validityInfo: {
        signed: Date;
        validFrom: Date;
        validUntil: Date;
        expectedUpdate?: Date;
    };
}

function decodeDateLike(value: unknown): Date {
    if (value instanceof Date) return value;
    if (value instanceof Tag) {
        // Tag 0 = RFC 3339 string; Tag 1 = epoch seconds; Tag 1004 = full-date (YYYY-MM-DD)
        if (value.tag === 0 && typeof value.value === 'string') {
            return new Date(value.value);
        }
        if (value.tag === 1 && typeof value.value === 'number') {
            return new Date(value.value * 1000);
        }
        if (value.tag === 1004 && typeof value.value === 'string') {
            return new Date(value.value);
        }
    }
    if (typeof value === 'string') {
        return new Date(value);
    }
    throw new MalformedCredentialError(`unsupported date encoding in MSO: ${typeof value}`);
}

export function decodeMso(payload: Uint8Array): MobileSecurityObject {
    let raw: unknown;
    try {
        raw = decoder.decode(payload);
        // Unwrap tag-24 (embedded CBOR): COSE payload may be tag-24 wrapped MSO bytes.
        // In production cbor-x decodes tag-24 as Tag(24, bytes); in test fixtures that register
        // a custom addExtension for tag-24 it decodes to an EmbeddedCbor-like object with .value.
        if (raw instanceof Tag && raw.tag === 24 && raw.value instanceof Uint8Array) {
            raw = decoder.decode(raw.value);
        } else if (
            raw !== null &&
            typeof raw === 'object' &&
            !(raw instanceof Tag) &&
            !(raw instanceof Map) &&
            !(raw instanceof Uint8Array) &&
            'value' in (raw as object) &&
            (raw as { value: unknown }).value instanceof Uint8Array
        ) {
            // TEST-FIXTURE COMPATIBILITY: tests/fixtures/mdoc-helpers.ts registers a custom
            // tag-24 addExtension globally, so cbor-x returns an EmbeddedCbor-like object
            // (with `.value: Uint8Array`) instead of Tag(24, bytes) during tests. The `!(raw
            // instanceof Tag)` guard ensures we don't misinterpret arbitrary Tag(N, bytes)
            // values as embedded CBOR in production.
            raw = decoder.decode((raw as { value: Uint8Array }).value);
        }
    } catch (err) {
        if (err instanceof MalformedCredentialError) throw err;
        throw new MalformedCredentialError('MSO payload is not decodable CBOR');
    }
    if (!(raw instanceof Map)) {
        throw new MalformedCredentialError('MSO must be a CBOR Map');
    }
    const m = raw as Map<string, unknown>;

    const version = m.get('version');
    if (typeof version !== 'string') {
        throw new MalformedCredentialError('MSO.version must be a string');
    }
    const digestAlgorithm = m.get('digestAlgorithm');
    if (typeof digestAlgorithm !== 'string') {
        throw new MalformedCredentialError('MSO.digestAlgorithm must be a string');
    }
    const docType = m.get('docType');
    if (typeof docType !== 'string') {
        throw new MalformedCredentialError('MSO.docType must be a string');
    }

    const vdRaw = m.get('valueDigests');
    if (!(vdRaw instanceof Map)) {
        throw new MalformedCredentialError('MSO.valueDigests must be a Map');
    }
    const valueDigests = new Map<string, Map<number, Uint8Array>>();
    for (const [ns, inner] of vdRaw.entries()) {
        if (typeof ns !== 'string' || !(inner instanceof Map)) {
            throw new MalformedCredentialError('MSO.valueDigests entry malformed');
        }
        const perNs = new Map<number, Uint8Array>();
        for (const [id, digest] of (inner as Map<unknown, unknown>).entries()) {
            if (typeof id !== 'number' || !(digest instanceof Uint8Array)) {
                throw new MalformedCredentialError('MSO digest entry must map number→bstr');
            }
            perNs.set(id, digest);
        }
        valueDigests.set(ns, perNs);
    }

    const viRaw = m.get('validityInfo');
    if (!(viRaw instanceof Map)) {
        throw new MalformedCredentialError('MSO.validityInfo must be a Map');
    }
    const vi = viRaw as Map<string, unknown>;
    const validityInfo: MobileSecurityObject['validityInfo'] = {
        signed: decodeDateLike(vi.get('signed')),
        validFrom: decodeDateLike(vi.get('validFrom')),
        validUntil: decodeDateLike(vi.get('validUntil')),
    };
    if (vi.has('expectedUpdate')) {
        validityInfo.expectedUpdate = decodeDateLike(vi.get('expectedUpdate'));
    }

    return { version, digestAlgorithm, valueDigests, docType, validityInfo };
}

/**
 * Validates the MSO's validityInfo block against a reference time.
 * Enforces strict ISO 18013-5 rules:
 *   - signed <= now
 *   - validFrom <= now
 *   - validFrom <= validUntil
 *   - signed within [validFrom, validUntil]
 *   - validUntil >= now (else ExpiredCredentialError)
 */
export function validateMsoValidity(mso: MobileSecurityObject, now: Date): void {
    const { signed, validFrom, validUntil } = mso.validityInfo;
    if (signed.getTime() > now.getTime()) {
        throw new MalformedCredentialError(`MSO signed=${signed.toISOString()} is in the future`);
    }
    if (validFrom.getTime() > now.getTime()) {
        throw new MalformedCredentialError(`MSO validFrom=${validFrom.toISOString()} is in the future`);
    }
    if (validFrom.getTime() > validUntil.getTime()) {
        throw new MalformedCredentialError('MSO validFrom is after validUntil');
    }
    if (signed.getTime() < validFrom.getTime() || signed.getTime() > validUntil.getTime()) {
        throw new MalformedCredentialError('MSO signed is outside the validity window');
    }
    if (validUntil.getTime() < now.getTime()) {
        throw new ExpiredCredentialError(`MSO validUntil=${validUntil.toISOString()} is in the past`);
    }
}

/**
 * Validates that the MSO's docType matches the expected one.
 * Used by callers who want to lock the accepted credential type.
 */
export function validateMsoDocType(mso: MobileSecurityObject, expectedDocType: string): void {
    if (mso.docType !== expectedDocType) {
        throw new MalformedCredentialError(`MSO docType=${mso.docType} does not match expected ${expectedDocType}`);
    }
}
