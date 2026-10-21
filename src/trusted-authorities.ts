import type { CredentialTrustedAuthority, DcqlQuery } from '@openeudi/dcql';

import { base64UrlToBytes, bytesToHex } from './encoding/base64url.js';
import type { TrustEvaluationResult } from './trust/TrustEvaluator.js';

/**
 * Typed `trusted_authorities` matching (OpenID4VP 1.0 §6.1.1).
 *
 * dcql 0.2.0 put the values of every `trusted_authorities` entry into one set
 * and compared them with the credential's untyped `trusted_authority_ids`, so
 * an `etsi_tl` entry could be satisfied by an `aki` id. Since 0.14.0 both
 * sides are prefixed with their type (`aki:…`, `etsi_tl:…`); the rewritten
 * query is used for matching only. dcql 0.3.0 matches the typed
 * `DecodedCredential.trusted_authorities` per type itself, which this now
 * fills. The prefixing is kept so the 0.14.0 behaviour and its tests stay
 * unchanged; it is redundant with per-type matching, not contrary to it.
 *
 * Until 0.14.0 `aki` ids were the anchor SKI in hex, while OpenID4VP 1.0
 * §6.1.1.1 specifies base64url of the AuthorityKeyIdentifier keyIdentifier.
 * For one release a query `aki` value in that hex form still matches, with a
 * one-time deprecation warning.
 */
export interface TrustedAuthorityMatching {
    /** The query to give `matchQuery`; the original is returned when it has no `trusted_authorities`. */
    query: DcqlQuery;
    /** Type-tagged ids (`aki:…`); undefined when there are none. */
    ids: string[] | undefined;
    /**
     * The same type-tagged ids grouped by type, for the typed
     * `DecodedCredential.trusted_authorities` (dcql 0.3.0); undefined when
     * there are none.
     */
    trustedAuthorities: CredentialTrustedAuthority[] | undefined;
}

let hexAkiWarningShown = false;

const tag = (type: string, value: string): string => `${type}:${value}`;

const HEX_PATTERN = /^(?:[0-9a-f]{2})+$/i;

export function prepareTrustedAuthorityMatching(
    query: DcqlQuery,
    trust: TrustEvaluationResult | undefined
): TrustedAuthorityMatching {
    const typed = trust?.trustedAuthorities ?? [];
    const ids = typed.length > 0 ? typed.map((t) => tag(t.type, t.value)) : undefined;
    const trustedAuthorities = typed.length > 0 ? groupByType(typed) : undefined;

    if (!query.credentials.some((c) => c.trusted_authorities && c.trusted_authorities.length > 0)) {
        return { query, ids, trustedAuthorities };
    }

    // Deprecated hex alias → the base64url id it denotes.
    const akiValues = new Set(typed.filter((t) => t.type === 'aki').map((t) => t.value));
    const hexToAki = new Map<string, string>();
    for (const value of akiValues) {
        try {
            hexToAki.set(bytesToHex(base64UrlToBytes(value)), value);
        } catch {
            // Not base64url (a custom store's untyped id) — no hex alias.
        }
    }

    const rewriteValue = (type: string, value: string): string => {
        if (type === 'aki' && !akiValues.has(value) && HEX_PATTERN.test(value)) {
            const aki = hexToAki.get(value.toLowerCase());
            if (aki !== undefined) {
                warnHexAkiOnce();
                return tag(type, aki);
            }
        }
        return tag(type, value);
    };

    return {
        ids,
        trustedAuthorities,
        query: {
            ...query,
            credentials: query.credentials.map((c) =>
                c.trusted_authorities
                    ? {
                          ...c,
                          trusted_authorities: c.trusted_authorities.map((ta) => ({
                              ...ta,
                              values: ta.values.map((v) => rewriteValue(ta.type, v)),
                          })),
                      }
                    : c
            ),
        },
    };
}

function groupByType(typed: ReadonlyArray<{ type: string; value: string }>): CredentialTrustedAuthority[] {
    const byType = new Map<string, string[]>();
    for (const t of typed) {
        const values = byType.get(t.type) ?? [];
        values.push(tag(t.type, t.value));
        byType.set(t.type, values);
    }
    return [...byType].map(([type, values]) => ({ type, values }));
}

function warnHexAkiOnce(): void {
    if (hexAkiWarningShown) return;
    hexAkiWarningShown = true;
    console.warn(
        '[openid4vp] DCQL trusted_authorities "aki" value matched in the deprecated hex SKI form. ' +
            'OpenID4VP 1.0 §6.1.1.1 specifies base64url of the AuthorityKeyIdentifier keyIdentifier; ' +
            'the hex form stops matching in the next minor release.'
    );
}
