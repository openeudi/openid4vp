import type { DcqlQuery } from '@openeudi/dcql';

import { base64UrlToBytes, bytesToHex } from './encoding/base64url.js';
import type { TrustEvaluationResult } from './trust/TrustEvaluator.js';

/**
 * Typed `trusted_authorities` matching on top of @openeudi/dcql 0.2.0.
 *
 * dcql 0.2.0 puts the values of every `trusted_authorities` entry into one
 * set and compares them with the credential's untyped
 * `trusted_authority_ids`, so an `etsi_tl` entry could be satisfied by an
 * `aki` id. Prefixing both sides with their type (`aki:…`, `etsi_tl:…`) keeps
 * the types apart without changing dcql: the rewritten query is used for
 * matching only.
 *
 * Until 0.14.0 `aki` ids were the anchor SKI in hex, while OpenID4VP 1.0
 * §6.1.1.1 specifies base64url of the AuthorityKeyIdentifier keyIdentifier.
 * For one release a query `aki` value in that hex form still matches, with a
 * one-time deprecation warning.
 */
export interface TrustedAuthorityMatching {
    /** The query to give `matchQuery`; the original is returned when it has no `trusted_authorities`. */
    query: DcqlQuery;
    /** Type-tagged ids for `DecodedCredential.trusted_authority_ids`; undefined when there are none. */
    ids: string[] | undefined;
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

    if (!query.credentials.some((c) => c.trusted_authorities && c.trusted_authorities.length > 0)) {
        return { query, ids };
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

function warnHexAkiOnce(): void {
    if (hexAkiWarningShown) return;
    hexAkiWarningShown = true;
    console.warn(
        '[openid4vp] DCQL trusted_authorities "aki" value matched in the deprecated hex SKI form. ' +
            'OpenID4VP 1.0 §6.1.1.1 specifies base64url of the AuthorityKeyIdentifier keyIdentifier; ' +
            'the hex form stops matching in the next minor release.'
    );
}
