/**
 * Protected-header rules of RFC 9052 that a CBOR decoder cannot enforce on its
 * own, shared by IssuerAuth (COSE_Sign1) and the mdoc DeviceSignature.
 *
 * NOT exported from the package root.
 */
import { Encoder as CborEncoder } from 'cbor-x';

import { MalformedCredentialError } from '../errors.js';

const decoder = new CborEncoder({ mapsAsObjects: false, useRecords: false });

/** COSE `crit` header parameter label (RFC 9052 §3.1). */
const HEADER_CRIT = 2;

/**
 * Protected header labels this library processes, and so "understands" in
 * the sense of `crit`: only `alg` (1). Any other label in `crit` is refused.
 */
const UNDERSTOOD_LABELS: ReadonlySet<unknown> = new Set([1]);

/** Nesting limit for the CBOR scanner; a protected header is a flat map. */
const MAX_DEPTH = 16;

function malformed(context: string, reason: string): MalformedCredentialError {
    return new MalformedCredentialError(`${context} protected header ${reason}`);
}

interface Head {
    major: number;
    /** Argument (length, count or value); unused when `indefinite`. */
    arg: number;
    indefinite: boolean;
    /** Offset just past the head. */
    pos: number;
}

function readHead(b: Uint8Array, pos: number, context: string): Head {
    if (pos >= b.length) throw malformed(context, 'is truncated');
    const initial = b[pos++];
    const major = initial >> 5;
    const info = initial & 0x1f;
    if (info < 24) return { major, arg: info, indefinite: false, pos };
    if (info === 31) {
        if (major >= 2 && major <= 5) return { major, arg: 0, indefinite: true, pos };
        throw malformed(context, 'has an unexpected break or indefinite-length item');
    }
    if (info > 27) throw malformed(context, 'uses a reserved CBOR additional-information value');
    const n = 1 << (info - 24); // 1, 2, 4 or 8 argument bytes
    if (pos + n > b.length) throw malformed(context, 'is truncated');
    let arg = 0;
    for (let i = 0; i < n; i++) arg = arg * 256 + b[pos++];
    return { major, arg, indefinite: false, pos };
}

/** Return the offset just past the CBOR data item starting at `pos`. */
function skipItem(b: Uint8Array, pos: number, depth: number, context: string): number {
    if (depth > MAX_DEPTH) throw malformed(context, 'is nested too deeply');
    const h = readHead(b, pos, context);
    switch (h.major) {
        case 0:
        case 1:
        case 7:
            return h.pos;
        case 6:
            return skipItem(b, h.pos, depth + 1, context);
        case 2:
        case 3: {
            if (h.indefinite) return skipUntilBreak(b, h.pos, 1, depth, context);
            const end = h.pos + h.arg;
            if (end > b.length) throw malformed(context, 'is truncated');
            return end;
        }
        case 4:
        case 5: {
            const per = h.major === 5 ? 2 : 1;
            if (h.indefinite) return skipUntilBreak(b, h.pos, per, depth, context);
            let p = h.pos;
            for (let i = 0; i < h.arg * per; i++) p = skipItem(b, p, depth + 1, context);
            return p;
        }
        default:
            throw malformed(context, 'is not well-formed CBOR');
    }
}

function skipUntilBreak(b: Uint8Array, pos: number, per: number, depth: number, context: string): number {
    let p = pos;
    for (;;) {
        if (p >= b.length) throw malformed(context, 'is truncated');
        if (b[p] === 0xff) return p + 1;
        for (let i = 0; i < per; i++) p = skipItem(b, p, depth + 1, context);
    }
}

/**
 * RFC 9052 §3: "Labels in each of the maps MUST be unique. When processing
 * messages, if a label appears multiple times, the message MUST be rejected as
 * malformed." A decoder that builds a `Map` keeps one entry per label, so the
 * check runs on the encoded bytes. Labels are compared by value, so `1` and
 * its non-preferred encoding `0x18 0x01` count as the same label.
 */
function assertUniqueLabels(bytes: Uint8Array, context: string): void {
    if (bytes.length === 0) return; // a zero-length bstr is the empty map
    const head = readHead(bytes, 0, context);
    if (head.major !== 5) throw malformed(context, 'is not a CBOR map');
    const seen = new Set<string>();
    let p = head.pos;
    for (let i = 0; head.indefinite || i < head.arg; i++) {
        if (head.indefinite) {
            if (p >= bytes.length) throw malformed(context, 'is truncated');
            if (bytes[p] === 0xff) {
                p++;
                break;
            }
        }
        const keyStart = p;
        p = skipItem(bytes, p, 1, context);
        const label: unknown = decoder.decode(bytes.subarray(keyStart, p));
        const id = `${typeof label}:${String(label)}`;
        if (seen.has(id)) {
            throw malformed(context, `repeats label ${String(label)} (RFC 9052 §3)`);
        }
        seen.add(id);
        p = skipItem(bytes, p, 1, context);
    }
    if (p !== bytes.length) throw malformed(context, 'has trailing bytes after the map');
}

/**
 * RFC 9052 §3.1: `crit` lists the protected header parameters the recipient
 * must understand. It is a non-empty array of labels; a label this library
 * does not process, or one absent from the protected header, is refused.
 */
function assertCritUnderstood(header: Map<unknown, unknown>, context: string): void {
    if (!header.has(HEADER_CRIT)) return;
    const crit = header.get(HEADER_CRIT);
    if (!Array.isArray(crit) || crit.length === 0) {
        throw malformed(context, 'crit must be a non-empty array of labels (RFC 9052 §3.1)');
    }
    for (const label of crit) {
        if (typeof label !== 'number' && typeof label !== 'string') {
            throw malformed(context, 'crit must be a non-empty array of labels (RFC 9052 §3.1)');
        }
        if (!UNDERSTOOD_LABELS.has(label) || !header.has(label)) {
            throw malformed(context, `crit lists label ${String(label)}, which is not understood (RFC 9052 §3.1)`);
        }
    }
}

/**
 * Check a COSE protected header: `bytes` as signed, `header` as decoded from
 * them. Throws {@link MalformedCredentialError} on a repeated label or a
 * `crit` the verifier cannot honour.
 */
export function checkProtectedHeader(bytes: Uint8Array, header: Map<unknown, unknown>, context: string): void {
    assertUniqueLabels(bytes, context);
    assertCritUnderstood(header, context);
}
