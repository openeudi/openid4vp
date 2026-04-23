/**
 * Content-addressed cache for CRL responses, OCSP responses, and LOTL
 * snapshots. Keys are library-defined strings; values are raw bytes.
 *
 * Implementations MUST be safe to call concurrently.
 */
export interface Cache {
    get(key: string): Promise<Uint8Array | null>;
    set(key: string, value: Uint8Array, ttlSeconds: number): Promise<void>;
}

interface Entry {
    value: Uint8Array;
    expiresAt: number; // epoch ms
}

/**
 * Default `Cache` implementation — bounded-size LRU with wall-clock TTL.
 * Cache dies with the process; inject a persistent `Cache` impl for
 * servers that should survive restarts.
 */
export class InMemoryCache implements Cache {
    private readonly entries = new Map<string, Entry>();
    private readonly maxEntries: number;

    constructor(opts?: { maxEntries?: number }) {
        this.maxEntries = opts?.maxEntries ?? 1000;
    }

    async get(key: string): Promise<Uint8Array | null> {
        const entry = this.entries.get(key);
        if (!entry) return null;
        if (Date.now() > entry.expiresAt) {
            this.entries.delete(key);
            return null;
        }
        // refresh LRU position
        this.entries.delete(key);
        this.entries.set(key, entry);
        return entry.value;
    }

    async set(key: string, value: Uint8Array, ttlSeconds: number): Promise<void> {
        // delete-then-set so overwrites move the key to MRU position
        this.entries.delete(key);
        this.entries.set(key, {
            value,
            expiresAt: Date.now() + ttlSeconds * 1000,
        });
        while (this.entries.size > this.maxEntries) {
            const oldest = this.entries.keys().next().value;
            if (oldest === undefined) break;
            this.entries.delete(oldest);
        }
    }
}
