import { base64url } from 'jose';

import { StatusListError } from '../errors.js';

/**
 * Token Status List codec (draft-ietf-oauth-status-list-21 §4, §7).
 *
 * Format-agnostic on purpose: the JWT (`statuslist+jwt`) and CWT
 * (`statuslist+cwt`) Status List Tokens both carry the same compressed byte
 * array, base64url-encoded in JSON and as a raw byte string in CBOR.
 */

/** Allowed `bits` values (§4.1 step 1). */
export type StatusListBits = 1 | 2 | 4 | 8;

/** Status Type names (§7.1). Any other value is reported as `'unknown'`. */
export type TokenStatusType = 'valid' | 'invalid' | 'suspended' | 'unknown';

const ALLOWED_BITS: ReadonlySet<number> = new Set([1, 2, 4, 8]);

/**
 * Default ceiling for a decompressed Status List. 16 MiB holds 134 million
 * 1-bit entries; the spec's own 2^20-entry examples need at most 1 MiB. The
 * cap stops a small DEFLATE "bomb" from expanding without bound.
 */
export const DEFAULT_MAX_STATUS_LIST_BYTES = 16 * 1024 * 1024;

export interface DecodedStatusList {
    bits: StatusListBits;
    /** The decompressed byte array. */
    bytes: Uint8Array;
    /** Number of addressable entries: `bytes.length * 8 / bits`. */
    size: number;
}

export function isStatusListBits(value: unknown): value is StatusListBits {
    return typeof value === 'number' && ALLOWED_BITS.has(value);
}

/**
 * Validates and decodes the `status_list` object of a JWT Status List Token
 * (§4.2): `bits` ∈ {1, 2, 4, 8}, `lst` = base64url(ZLIB(DEFLATE(bytes))).
 */
export async function decodeStatusList(
    statusList: unknown,
    options: { uri: string; maxBytes?: number },
): Promise<DecodedStatusList> {
    const { uri } = options;
    if (!statusList || typeof statusList !== 'object' || Array.isArray(statusList)) {
        throw new StatusListError('malformed_status_list', 'status_list must be a JSON object', { uri });
    }
    const { bits, lst } = statusList as Record<string, unknown>;
    if (!isStatusListBits(bits)) {
        throw new StatusListError(
            'malformed_status_list',
            `status_list.bits must be 1, 2, 4 or 8 (got ${JSON.stringify(bits)})`,
            { uri },
        );
    }
    if (typeof lst !== 'string' || lst.length === 0 || !/^[A-Za-z0-9_-]+$/.test(lst)) {
        throw new StatusListError('malformed_status_list', 'status_list.lst must be a non-empty base64url string', {
            uri,
        });
    }
    let compressed: Uint8Array;
    try {
        compressed = base64url.decode(lst);
    } catch (err) {
        throw new StatusListError('malformed_status_list', 'status_list.lst is not valid base64url', {
            uri,
            cause: err instanceof Error ? err : undefined,
        });
    }
    const bytes = await inflateStatusList(compressed, { uri, maxBytes: options.maxBytes });
    return { bits, bytes, size: (bytes.length * 8) / bits };
}

/**
 * Decompresses a ZLIB-wrapped (RFC 1950) DEFLATE (RFC 1951) byte array.
 *
 * Uses the Compression Streams API (`DecompressionStream('deflate')`, which is
 * the ZLIB format), available in browsers, Deno, Bun, workers and Node ≥ 18.
 * Falls back to `node:zlib` only where that API is missing. Output is bounded
 * by `maxBytes` while it is produced, not after.
 */
export async function inflateStatusList(
    compressed: Uint8Array,
    options: { uri: string; maxBytes?: number },
): Promise<Uint8Array> {
    const { uri } = options;
    const maxBytes = options.maxBytes ?? DEFAULT_MAX_STATUS_LIST_BYTES;
    const tooLarge = (): StatusListError =>
        new StatusListError('list_too_large', `decompressed status list exceeds ${maxBytes} bytes`, { uri });

    let out: Uint8Array;
    try {
        out =
            typeof globalThis.DecompressionStream === 'function'
                ? await inflateWithStreams(compressed, maxBytes, tooLarge)
                : await inflateWithNodeZlib(compressed, maxBytes, tooLarge);
    } catch (err) {
        if (err instanceof StatusListError) throw err;
        throw new StatusListError('malformed_status_list', 'status_list.lst is not a valid ZLIB/DEFLATE stream', {
            uri,
            cause: err instanceof Error ? err : undefined,
        });
    }
    if (out.length === 0) {
        throw new StatusListError('malformed_status_list', 'status list is empty after decompression', { uri });
    }
    return out;
}

async function inflateWithStreams(
    compressed: Uint8Array,
    maxBytes: number,
    tooLarge: () => Error,
): Promise<Uint8Array> {
    const stream = new DecompressionStream('deflate');
    const writer = stream.writable.getWriter();
    // Errors surface on the readable side; swallow them here so they are not
    // reported twice as unhandled rejections.
    writer.write(compressed as Uint8Array<ArrayBuffer>).catch(() => {});
    writer.close().catch(() => {});

    const reader = stream.readable.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    try {
        for (;;) {
            const { done, value } = await reader.read();
            if (done) break;
            total += value.byteLength;
            if (total > maxBytes) throw tooLarge();
            chunks.push(value);
        }
    } catch (err) {
        reader.cancel().catch(() => {});
        throw err;
    }
    return concat(chunks, total);
}

type NodeZlib = {
    inflateSync(buf: Uint8Array, options?: { maxOutputLength?: number }): Uint8Array;
};

let zlibModule: Promise<NodeZlib | undefined> | undefined;

function loadZlib(): Promise<NodeZlib | undefined> {
    zlibModule ??= (async () => {
        try {
            // Non-literal specifier so browser bundlers do not try to resolve a
            // Node built-in (same approach as `node:dns` in guarded-fetch.ts).
            const specifier = 'node:zlib';
            const mod = (await import(/* webpackIgnore: true */ /* @vite-ignore */ specifier)) as NodeZlib & {
                default?: NodeZlib;
            };
            return typeof mod.inflateSync === 'function' ? mod : mod.default;
        } catch {
            return undefined;
        }
    })();
    return zlibModule;
}

async function inflateWithNodeZlib(
    compressed: Uint8Array,
    maxBytes: number,
    tooLarge: () => Error,
): Promise<Uint8Array> {
    const zlib = await loadZlib();
    if (!zlib) {
        throw new Error('no DEFLATE implementation available (neither DecompressionStream nor node:zlib)');
    }
    try {
        return new Uint8Array(zlib.inflateSync(compressed, { maxOutputLength: maxBytes }));
    } catch (err) {
        // Node reports the output cap as RangeError ERR_BUFFER_TOO_LARGE.
        if ((err as { code?: string }).code === 'ERR_BUFFER_TOO_LARGE') throw tooLarge();
        throw err;
    }
}

function concat(chunks: readonly Uint8Array[], total: number): Uint8Array {
    const out = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
        out.set(chunk, offset);
        offset += chunk.byteLength;
    }
    return out;
}

/**
 * Reads the status value at `idx` (§4.1 step 3): entries are packed from the
 * least significant bit of each byte. An index past the end of the byte array
 * is out of range, and §8.3 step 6 says the Referenced Token MUST then be
 * rejected.
 */
export function readStatusValue(list: DecodedStatusList, idx: number, uri: string): number {
    if (!Number.isSafeInteger(idx) || idx < 0) {
        throw new StatusListError('invalid_reference', `status_list.idx must be a non-negative integer`, { uri });
    }
    if (idx >= list.size) {
        throw new StatusListError(
            'index_out_of_range',
            `status_list.idx ${idx} is out of range for a list of ${list.size} entries`,
            { uri },
        );
    }
    const entriesPerByte = 8 / list.bits;
    const byte = list.bytes[Math.floor(idx / entriesPerByte)];
    const shift = (idx % entriesPerByte) * list.bits;
    return (byte >> shift) & ((1 << list.bits) - 1);
}

/** Maps a raw Status Type value to its §7.1 name. */
export function toTokenStatusType(value: number): TokenStatusType {
    switch (value) {
        case 0x00:
            return 'valid';
        case 0x01:
            return 'invalid';
        case 0x02:
            return 'suspended';
        default:
            return 'unknown';
    }
}
