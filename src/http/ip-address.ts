/**
 * IP address classification for the guarded fetcher's SSRF checks.
 *
 * Pure (no `node:net`) so it works in every runtime the library builds for.
 * Anything that does not parse as an IPv4/IPv6 literal is treated as
 * non-public: the caller fails closed instead of guessing.
 */

/** Parses a dotted-quad IPv4 literal into 4 bytes, or `undefined`. */
export function parseIPv4(input: string): number[] | undefined {
    const parts = input.split('.');
    if (parts.length !== 4) return undefined;
    const bytes: number[] = [];
    for (const part of parts) {
        if (!/^\d{1,3}$/.test(part)) return undefined;
        const value = Number(part);
        if (value > 255) return undefined;
        bytes.push(value);
    }
    return bytes;
}

/** Parses an IPv6 literal (optionally with a `%zone` suffix) into 16 bytes, or `undefined`. */
export function parseIPv6(input: string): number[] | undefined {
    const address = input.split('%')[0];
    if (!address.includes(':')) return undefined;

    let head = address;
    let embeddedV4: number[] | undefined;
    const lastColon = address.lastIndexOf(':');
    const tail = address.slice(lastColon + 1);
    if (tail.includes('.')) {
        embeddedV4 = parseIPv4(tail);
        if (!embeddedV4) return undefined;
        head = address.slice(0, lastColon + 1) + '0:0';
    }

    const doubleColon = head.split('::');
    if (doubleColon.length > 2) return undefined;
    const toGroups = (s: string): string[] => (s === '' ? [] : s.split(':'));
    const left = toGroups(doubleColon[0]);
    const right = doubleColon.length === 2 ? toGroups(doubleColon[1]) : [];
    const missing = 8 - left.length - right.length;
    if (doubleColon.length === 2 ? missing < 1 : missing !== 0) return undefined;
    const groups = [...left, ...Array<string>(doubleColon.length === 2 ? missing : 0).fill('0'), ...right];

    const bytes: number[] = [];
    for (const group of groups) {
        if (!/^[0-9a-fA-F]{1,4}$/.test(group)) return undefined;
        const value = parseInt(group, 16);
        bytes.push(value >> 8, value & 0xff);
    }
    if (embeddedV4) bytes.splice(12, 4, ...embeddedV4);
    return bytes;
}

function inPrefix(bytes: readonly number[], prefix: readonly number[], bits: number): boolean {
    for (let i = 0; i < bits; i++) {
        const byte = i >> 3;
        const mask = 0x80 >> (i & 7);
        if ((bytes[byte] & mask) !== ((prefix[byte] ?? 0) & mask)) return false;
    }
    return true;
}

/**
 * IPv4 ranges that are not globally routable unicast: "this network",
 * RFC 1918 private, CGNAT, loopback, link-local (incl. the 169.254.169.254
 * cloud metadata endpoint), IETF protocol assignments, documentation,
 * 6to4 relay anycast, benchmarking, multicast, reserved and broadcast.
 */
const BLOCKED_V4: ReadonlyArray<[number[], number]> = [
    [[0, 0, 0, 0], 8],
    [[10, 0, 0, 0], 8],
    [[100, 64, 0, 0], 10],
    [[127, 0, 0, 0], 8],
    [[169, 254, 0, 0], 16],
    [[172, 16, 0, 0], 12],
    [[192, 0, 0, 0], 24],
    [[192, 0, 2, 0], 24],
    [[192, 88, 99, 0], 24],
    [[192, 168, 0, 0], 16],
    [[198, 18, 0, 0], 15],
    [[198, 51, 100, 0], 24],
    [[203, 0, 113, 0], 24],
    [[224, 0, 0, 0], 4],
    [[240, 0, 0, 0], 4],
];

function isPublicV4(bytes: readonly number[]): boolean {
    return !BLOCKED_V4.some(([prefix, bits]) => inPrefix(bytes, prefix, bits));
}

/** IPv6 ranges that are never a legitimate public fetch target. */
const BLOCKED_V6: ReadonlyArray<[number[], number]> = [
    [[0x01, 0x00], 64], // 100::/64 discard-only
    [[0x20, 0x01, 0x00, 0x00], 32], // 2001::/32 Teredo (embeds an obfuscated IPv4)
    [[0x20, 0x01, 0x0d, 0xb8], 32], // 2001:db8::/32 documentation
    [[0xfc], 7], // fc00::/7 unique local (incl. fd00:ec2::254 metadata)
    [[0xfe, 0x80], 10], // fe80::/10 link-local
    [[0xfe, 0xc0], 10], // fec0::/10 deprecated site-local
    [[0xff], 8], // ff00::/8 multicast
];

function isPublicV6(bytes: readonly number[]): boolean {
    // ::/96 covers :: (unspecified), ::1 (loopback) and the deprecated
    // IPv4-compatible form; ::ffff:0:0/96 is IPv4-mapped. Both are judged by
    // the embedded IPv4 address so `::ffff:169.254.169.254` cannot slip by.
    const first10Zero = bytes.slice(0, 10).every((b) => b === 0);
    if (first10Zero && bytes[10] === 0 && bytes[11] === 0) {
        const v4 = bytes.slice(12);
        if (v4.slice(0, 3).every((b) => b === 0)) return false; // ::, ::1, ::0.0.0.x
        return isPublicV4(v4);
    }
    if (first10Zero && bytes[10] === 0xff && bytes[11] === 0xff) return isPublicV4(bytes.slice(12));
    // 64:ff9b::/96 NAT64 well-known prefix — judge the translated IPv4.
    if (inPrefix(bytes, [0x00, 0x64, 0xff, 0x9b], 96)) return isPublicV4(bytes.slice(12));
    // 2002::/16 6to4 — the IPv4 is in bytes 2..5.
    if (inPrefix(bytes, [0x20, 0x02], 16)) return isPublicV4(bytes.slice(2, 6));
    return !BLOCKED_V6.some(([prefix, bits]) => inPrefix(bytes, prefix, bits));
}

/**
 * `true` only for a syntactically valid, globally routable unicast IPv4 or
 * IPv6 address. Loopback, private, link-local, metadata, multicast,
 * documentation and reserved ranges — and anything unparseable — are `false`.
 */
export function isPublicIpAddress(ip: string): boolean {
    const v4 = parseIPv4(ip);
    if (v4) return isPublicV4(v4);
    const v6 = parseIPv6(ip);
    if (v6) return isPublicV6(v6);
    return false;
}

/** `true` when `host` (already URL-normalised, brackets stripped) is an IP literal. */
export function isIpLiteral(host: string): boolean {
    return parseIPv4(host) !== undefined || parseIPv6(host) !== undefined;
}
