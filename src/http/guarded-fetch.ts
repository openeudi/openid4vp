import { GuardedFetchError } from '../errors.js';
import type { Fetcher } from '../trust/Fetcher.js';

import { isIpLiteral, isPublicIpAddress } from './ip-address.js';

/**
 * Resolves a hostname to every IP address it currently maps to. Must return
 * all records (A and AAAA): the guard rejects the host if ANY of them is
 * non-public.
 */
export type HostLookup = (hostname: string) => Promise<readonly string[]>;

export interface GuardedFetcherOptions {
    /**
     * Underlying transport. Defaults to `globalThis.fetch`, resolved at call
     * time. Must honour `redirect: 'manual'` and expose the `Location` header
     * of 3xx responses (Node's fetch/undici does; browsers return an opaque
     * redirect, which the guard rejects).
     */
    fetch?: Fetcher;
    /**
     * DNS resolver used for the private-address check. Defaults to
     * `node:dns` `lookup(host, { all: true })` when available. In runtimes
     * without `node:dns` (browsers, some edge workers) only IP-literal and
     * `localhost` targets are checked — inject a resolver there if needed.
     */
    lookup?: HostLookup;
    /** Permit `http:` targets. Default `false` (SD-JWT VC draft-19: HTTPS only). */
    allowHttp?: boolean;
    /** Permit loopback / private / link-local / metadata targets. Default `false`. */
    allowPrivateNetworks?: boolean;
    /** Maximum redirects followed; every hop is re-validated. Default 3. */
    maxRedirects?: number;
    /** Wall-clock budget for the whole exchange (DNS, redirects, body). Default 15 000 ms. */
    timeoutMs?: number;
    /** Maximum response body size, enforced while streaming. Default 16 MiB. */
    maxResponseBytes?: number;
}

export const GUARDED_FETCH_DEFAULTS = {
    maxRedirects: 3,
    timeoutMs: 15_000,
    maxResponseBytes: 16 * 1024 * 1024,
} as const;

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const NULL_BODY_STATUSES = new Set([101, 103, 204, 205, 304]);
/** Credentials must not follow a redirect to another origin (Fetch §4.4 step 13). */
const CROSS_ORIGIN_STRIPPED_HEADERS = ['authorization', 'cookie', 'proxy-authorization'];
const BODY_HEADERS = ['content-type', 'content-length', 'content-encoding', 'content-language', 'content-location'];

type DnsPromises = {
    lookup(hostname: string, options: { all: true; verbatim?: boolean }): Promise<Array<{ address: string }>>;
};

let dnsModule: Promise<DnsPromises | undefined> | undefined;

function loadDns(): Promise<DnsPromises | undefined> {
    dnsModule ??= (async () => {
        try {
            // Non-literal specifier so browser bundlers do not try to resolve a
            // Node built-in; absence is handled below (literal-only checks).
            const specifier = 'node:dns';
            const mod = (await import(/* webpackIgnore: true */ /* @vite-ignore */ specifier)) as {
                promises?: DnsPromises;
                default?: { promises?: DnsPromises };
            };
            return mod.promises ?? mod.default?.promises;
        } catch {
            return undefined;
        }
    })();
    return dnsModule;
}

const defaultLookup: HostLookup = async (hostname) => {
    const dns = await loadDns();
    if (!dns) return [];
    const records = await dns.lookup(hostname, { all: true, verbatim: true });
    return records.map((r) => r.address);
};

function toError(err: unknown): Error {
    return err instanceof Error ? err : new Error(String(err));
}

/**
 * Builds a {@link Fetcher} that applies the HTTP-retrieval rules of
 * draft-ietf-oauth-sd-jwt-vc-19 to every request:
 *
 *   - HTTPS only (unless `allowHttp`), and never an https → http downgrade
 *   - no loopback / private / link-local / cloud-metadata targets, checked
 *     on the URL host AND every address it resolves to (IPv4, IPv6,
 *     IPv4-mapped/compatible, NAT64, 6to4)
 *   - redirects handled manually, bounded, and re-validated hop by hop
 *   - a single timeout covering DNS, every hop and the body
 *   - a response-size cap enforced while streaming
 *
 * **DNS rebinding.** The guard resolves the host, validates the addresses,
 * then hands the *hostname* to the transport, which resolves it again. An
 * attacker-controlled DNS server can answer differently the second time
 * (TOCTOU). Closing that gap requires pinning the validated address at the
 * socket layer, which `fetch` does not expose portably. Deployments that
 * dereference attacker-influenced URLs should additionally route egress
 * through a filtering proxy or inject a transport whose connector validates
 * the connected address (e.g. an undici `Agent` with a checking
 * `connect.lookup`).
 *
 * Caching is out of scope here: the trust module caches CRL/OCSP/LOTL
 * artefacts through its own {@link Cache} plug.
 */
export function createGuardedFetcher(options: GuardedFetcherOptions = {}): Fetcher {
    const allowHttp = options.allowHttp ?? false;
    const allowPrivate = options.allowPrivateNetworks ?? false;
    const maxRedirects = options.maxRedirects ?? GUARDED_FETCH_DEFAULTS.maxRedirects;
    const timeoutMs = options.timeoutMs ?? GUARDED_FETCH_DEFAULTS.timeoutMs;
    const maxBytes = options.maxResponseBytes ?? GUARDED_FETCH_DEFAULTS.maxResponseBytes;
    const lookup = options.lookup ?? defaultLookup;
    const transport: Fetcher = options.fetch ?? ((url, init) => globalThis.fetch(url, init));

    return async (input: string, init: RequestInit = {}): Promise<Response> => {
        const controller = new AbortController();
        const timer = setTimeout(() => {
            controller.abort(
                new GuardedFetchError('timeout', `request to ${input} exceeded ${timeoutMs} ms`, { url: input }),
            );
        }, timeoutMs);
        const callerSignal = init.signal ?? undefined;
        const onCallerAbort = (): void => controller.abort(callerSignal?.reason);
        if (callerSignal?.aborted) onCallerAbort();
        else callerSignal?.addEventListener('abort', onCallerAbort, { once: true });

        const aborted = new Promise<never>((_, reject) => {
            const fail = (): void => reject(toError(controller.signal.reason));
            if (controller.signal.aborted) fail();
            else controller.signal.addEventListener('abort', fail, { once: true });
        });
        aborted.catch(() => {});
        const race = <T>(p: Promise<T>): Promise<T> => Promise.race([p, aborted]);

        try {
            let url = await race(validateTarget(input, undefined));
            let method = (init.method ?? 'GET').toUpperCase();
            let body = init.body;
            const headers = new Headers(init.headers);

            for (let hop = 0; ; hop++) {
                const response = await race(
                    transport(url.href, { ...init, method, body, headers, redirect: 'manual', signal: controller.signal }),
                );

                if (response.type === 'opaqueredirect') {
                    throw new GuardedFetchError(
                        'invalid_redirect',
                        `redirect from ${url.href} cannot be inspected by this transport`,
                        { url: url.href },
                    );
                }

                if (!REDIRECT_STATUSES.has(response.status)) {
                    const bytes = await readBounded(response, url.href, maxBytes, race);
                    return new Response(NULL_BODY_STATUSES.has(response.status) ? null : bytes, {
                        status: response.status,
                        statusText: response.statusText,
                        headers: response.headers,
                    });
                }

                await response.body?.cancel().catch(() => {});
                if (hop >= maxRedirects) {
                    throw new GuardedFetchError(
                        'too_many_redirects',
                        `more than ${maxRedirects} redirects starting at ${input}`,
                        { url: url.href },
                    );
                }
                const location = response.headers.get('location');
                if (!location) {
                    throw new GuardedFetchError(
                        'invalid_redirect',
                        `HTTP ${response.status} from ${url.href} has no Location header`,
                        { url: url.href },
                    );
                }
                let next: URL;
                try {
                    next = new URL(location, url);
                } catch (err) {
                    throw new GuardedFetchError('invalid_redirect', `unparseable Location from ${url.href}`, {
                        url: url.href,
                        cause: toError(err),
                    });
                }
                const nextUrl = await race(validateTarget(next.href, url));

                // Fetch §4.4: 303, and 301/302 after POST, continue as a body-less GET.
                if (response.status === 303 || ((response.status === 301 || response.status === 302) && method === 'POST')) {
                    if (method !== 'HEAD') method = 'GET';
                    body = undefined;
                    for (const h of BODY_HEADERS) headers.delete(h);
                }
                if (nextUrl.origin !== url.origin) {
                    for (const h of CROSS_ORIGIN_STRIPPED_HEADERS) headers.delete(h);
                }
                url = nextUrl;
            }
        } catch (err) {
            if (controller.signal.aborted) throw toError(controller.signal.reason);
            throw err;
        } finally {
            clearTimeout(timer);
            callerSignal?.removeEventListener('abort', onCallerAbort);
        }
    };

    async function validateTarget(raw: string, previous: URL | undefined): Promise<URL> {
        let url: URL;
        try {
            url = new URL(raw);
        } catch (err) {
            throw new GuardedFetchError('invalid_url', `not an absolute URL: ${raw}`, { url: raw, cause: toError(err) });
        }

        if (url.protocol !== 'https:' && !(allowHttp && url.protocol === 'http:')) {
            throw new GuardedFetchError('insecure_scheme', `refusing ${url.protocol} URL ${url.href}: HTTPS is required`, {
                url: url.href,
            });
        }
        if (previous?.protocol === 'https:' && url.protocol !== 'https:') {
            throw new GuardedFetchError('insecure_scheme', `refusing https -> http redirect to ${url.href}`, {
                url: url.href,
            });
        }
        if (allowPrivate) return url;

        const host = url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
        if (host === 'localhost' || host.endsWith('.localhost')) {
            throw new GuardedFetchError('private_address', `refusing loopback host ${host}`, { url: url.href });
        }
        if (isIpLiteral(host)) {
            if (!isPublicIpAddress(host)) {
                throw new GuardedFetchError('private_address', `refusing non-public address ${host}`, { url: url.href });
            }
            return url;
        }

        let addresses: readonly string[];
        try {
            addresses = await lookup(host);
        } catch (err) {
            throw new GuardedFetchError('dns_resolution_failed', `could not resolve ${host}`, {
                url: url.href,
                cause: toError(err),
            });
        }
        const blocked = addresses.find((a) => !isPublicIpAddress(a));
        if (blocked !== undefined) {
            throw new GuardedFetchError('private_address', `${host} resolves to non-public address ${blocked}`, {
                url: url.href,
            });
        }
        return url;
    }
}

async function readBounded(
    response: Response,
    url: string,
    maxBytes: number,
    race: <T>(p: Promise<T>) => Promise<T>,
): Promise<Uint8Array<ArrayBuffer> | null> {
    const tooLarge = (): GuardedFetchError =>
        new GuardedFetchError('response_too_large', `response from ${url} exceeds ${maxBytes} bytes`, { url });

    const declared = response.headers.get('content-length');
    if (declared !== null && Number(declared) > maxBytes) {
        await response.body?.cancel().catch(() => {});
        throw tooLarge();
    }
    if (!response.body) return null;

    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    try {
        for (;;) {
            const { done, value } = await race(reader.read());
            if (done) break;
            total += value.byteLength;
            if (total > maxBytes) throw tooLarge();
            chunks.push(value);
        }
    } catch (err) {
        reader.cancel().catch(() => {});
        throw err;
    }

    const out = new Uint8Array(new ArrayBuffer(total));
    let offset = 0;
    for (const chunk of chunks) {
        out.set(chunk, offset);
        offset += chunk.byteLength;
    }
    return out;
}

/**
 * Default transport for the trust module (LOTL / national TL, CRL, OCSP).
 *
 * `allowHttp` is on because RFC 5280 CRL distribution points and RFC 6960
 * OCSP responders are conventionally plain HTTP, and every artefact fetched
 * here is itself signed and verified (XAdES, CRL/OCSP signatures). The SSRF,
 * redirect, timeout and size guards all still apply.
 */
export function createDefaultTrustFetcher(): Fetcher {
    return createGuardedFetcher({ allowHttp: true });
}
