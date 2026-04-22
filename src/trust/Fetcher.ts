/**
 * HTTP transport plug. Defaults to `globalThis.fetch` when unset in
 * `ParseOptions`. Consumers may inject a custom implementation for proxies,
 * timeouts, retry policies, request tracing, or test doubles.
 *
 * MUST be safe to call concurrently.
 */
export type Fetcher = (url: string, init?: RequestInit) => Promise<Response>;
