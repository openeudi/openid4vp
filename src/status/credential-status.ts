import { StatusListError, type StatusListErrorReason } from '../errors.js';

import type { StatusListResolver, StatusListTokenFormat } from './StatusListResolver.js';
import type { TokenStatusType } from './status-list.js';

/**
 * How a credential's `status` claim is treated:
 *
 * - `'skip'` — not checked (default in 0.x).
 * - `'prefer'` — checked. A definitive non-VALID status (INVALID, SUSPENDED,
 *   any other value) or an out-of-range index rejects. When no statement can
 *   be made (list unreachable, untrusted, expired, malformed), the credential
 *   is accepted and `credentialStatus.outcome` is `'unavailable'` with a
 *   `warning`.
 * - `'require'` — as `'prefer'`, but "no statement can be made" throws
 *   {@link StatusListError}.
 *
 * In both checking modes a `status` claim that is present but malformed
 * (HAIP 1.0 §6.1: it MUST contain `status_list`) rejects.
 */
export type StatusPolicy = 'skip' | 'prefer' | 'require';

/** Outcome of the credential status check, on `PresentationResult.credentialStatus`. */
export interface CredentialStatusResult {
    policy: Exclude<StatusPolicy, 'skip'>;
    /**
     * - `'checked'` — the list was resolved and `status` / `value` are set.
     * - `'unavailable'` — no statement could be made (only under `'prefer'`).
     * - `'absent'` — the credential carries no `status` claim.
     * - `'rejected'` — the reference is malformed or `idx` is out of range.
     */
    outcome: 'checked' | 'unavailable' | 'absent' | 'rejected';
    uri?: string;
    idx?: number;
    status?: TokenStatusType;
    value?: number;
    /** Set when `outcome` is `'unavailable'` or `'rejected'`. */
    reason?: StatusListErrorReason;
    /** Human-readable explanation for `'unavailable'`. */
    warning?: string;
    /** `true` when the list was served from the resolver cache. */
    fromCache?: boolean;
    checkedAt: Date;
}

export interface CredentialStatusOptions {
    statusPolicy?: StatusPolicy;
    statusListResolver?: StatusListResolver;
}

export interface CredentialStatusCheck {
    result?: CredentialStatusResult;
    /** Present when the credential must be rejected; used as `PresentationResult.error`. */
    rejection?: string;
}

/** Reasons that are a definitive statement about the credential, not about the list's availability. */
const DEFINITIVE_REASONS: ReadonlySet<StatusListErrorReason> = new Set(['invalid_reference', 'index_out_of_range']);

const POLICIES: ReadonlySet<string> = new Set(['skip', 'prefer', 'require']);

/**
 * Applies `statusPolicy` to the `status` claim of an already-verified
 * credential payload (draft-ietf-oauth-status-list-21 §8.3: the Referenced
 * Token is validated first; status is evaluated only afterwards).
 *
 * `payload.status` is the JOSE `status` claim of an SD-JWT VC, whose list is a
 * `statuslist+jwt` (`format: 'jwt'`, the default), or the mdoc MSO `status`
 * (§6.3) with its maps converted to objects, whose list is a `statuslist+cwt`
 * (`format: 'cwt'`). Both carry `status_list: { idx, uri }`.
 */
export async function checkCredentialStatus(
    payload: Record<string, unknown>,
    options: CredentialStatusOptions,
    format: StatusListTokenFormat = 'jwt',
): Promise<CredentialStatusCheck> {
    const policy = options.statusPolicy ?? 'skip';
    if (!POLICIES.has(policy)) {
        throw new StatusListError('configuration', `Unknown statusPolicy ${JSON.stringify(policy)}`);
    }
    if (policy === 'skip') return {};
    const resolver = options.statusListResolver;
    if (!resolver) {
        throw new StatusListError(
            'configuration',
            `statusPolicy '${policy}' requires a statusListResolver (new StatusListResolver({ trustStore }))`,
        );
    }

    const checkedAt = new Date();
    const status = payload['status'];
    if (status === undefined) {
        return { result: { policy, outcome: 'absent', checkedAt } };
    }

    const reject = (reason: StatusListErrorReason, message: string, extra: Partial<CredentialStatusResult> = {}) => ({
        result: { policy, outcome: 'rejected' as const, reason, checkedAt, ...extra },
        rejection: message,
    });

    if (!isObject(status)) {
        return reject(
            'invalid_reference',
            format === 'cwt'
                ? 'MSO status must be a map with text keys'
                : 'Credential status claim must be a JSON object',
        );
    }
    const reference = (status as Record<string, unknown>)['status_list'];
    if (reference === undefined) {
        return reject('invalid_reference', 'Credential status claim must contain status_list (HAIP 1.0 §6.1)');
    }

    const refUri = isObject(reference) && typeof reference['uri'] === 'string' ? reference['uri'] : undefined;
    const refIdx = isObject(reference) && typeof reference['idx'] === 'number' ? reference['idx'] : undefined;
    const where = { ...(refUri !== undefined ? { uri: refUri } : {}), ...(refIdx !== undefined ? { idx: refIdx } : {}) };

    let lookup;
    try {
        lookup = await resolver.resolve(reference as { idx: number; uri: string }, { format });
    } catch (err) {
        if (!(err instanceof StatusListError)) throw err;
        if (DEFINITIVE_REASONS.has(err.reason)) {
            return reject(err.reason, `Credential status check failed: ${err.message}`, where);
        }
        if (policy === 'require') throw err;
        return {
            result: {
                policy,
                outcome: 'unavailable',
                reason: err.reason,
                warning: `Credential status could not be determined: ${err.message}`,
                checkedAt,
                ...where,
            },
        };
    }

    const result: CredentialStatusResult = {
        policy,
        outcome: 'checked',
        uri: lookup.uri,
        idx: lookup.idx,
        status: lookup.status,
        value: lookup.value,
        fromCache: lookup.fromCache,
        checkedAt,
    };
    if (lookup.status === 'valid') return { result };
    const label =
        lookup.status === 'unknown' ? `unrecognised (0x${lookup.value.toString(16).padStart(2, '0')})` : lookup.status;
    return { result, rejection: `Credential status is ${label}` };
}

function isObject(value: unknown): value is Record<string, unknown> {
    return (
        !!value &&
        typeof value === 'object' &&
        !Array.isArray(value) &&
        !(value instanceof Map) &&
        !(value instanceof Uint8Array)
    );
}
