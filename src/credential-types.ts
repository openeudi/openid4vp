import type { DcqlQuery } from '@openeudi/dcql';

import type { PresentationResult } from './types/presentation.js';

type CredentialQuery = DcqlQuery['credentials'][number];

/** Bounds the walk through `vctAncestors`, which is caller configuration but may contain cycles. */
const MAX_VCT_TYPES = 32;

/**
 * Every type an SD-JWT VC is "of", in preference order: its `vct`, the
 * issuer-signed `aka_vcts` (draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.2), then the
 * ancestors configured out of band in `vctAncestors` (transitively, for the
 * `vct` and each `aka_vcts` value).
 *
 * OpenID4VP 1.0 Appendix B.3.5 lets a wallet return a credential that inherits
 * from a requested type — e.g. a national PID `urn:eudi:pid:de:1` for
 * `vct_values: ['urn:eudi:pid:1']` (PID Rulebook PID_14). Type Metadata is
 * never fetched here; inheritance is only what the issuer signed or the caller
 * configured.
 *
 * Returns `[]` for anything but an SD-JWT VC with a `vct`.
 */
export function credentialTypes(
    parsed: PresentationResult,
    vctAncestors: Readonly<Record<string, readonly string[]>> | undefined
): string[] {
    if (parsed.format !== 'sd-jwt-vc' || typeof parsed.vct !== 'string') return [];
    const types: string[] = [];
    const add = (vct: string) => {
        if (types.length < MAX_VCT_TYPES && !types.includes(vct)) types.push(vct);
    };
    add(parsed.vct);
    for (const aka of parsed.akaVcts ?? []) add(aka);
    // Breadth-first over the configured ancestors; `types` doubles as the visited set.
    for (let i = 0; i < types.length; i++) {
        const parents = vctAncestors && Object.hasOwn(vctAncestors, types[i]) ? vctAncestors[types[i]] : [];
        for (const parent of parents) if (typeof parent === 'string') add(parent);
    }
    return types;
}

/**
 * Does the query entry demand a holder-bound presentation? OpenID4VP 1.0
 * §6.1: `require_cryptographic_holder_binding` defaults to `true`.
 */
export function requiresHolderBinding(credentialQuery: CredentialQuery | undefined): boolean {
    return credentialQuery?.require_cryptographic_holder_binding !== false;
}

/**
 * Whether a compact SD-JWT presentation carries a Key Binding JWT: the
 * segment after the last `~` is the KB-JWT, and is empty without one
 * (RFC 9901 §4). The parser has already verified a KB-JWT that is present.
 */
export function hasKeyBindingJwt(vpToken: unknown): boolean {
    if (typeof vpToken !== 'string') return false;
    return vpToken.slice(vpToken.lastIndexOf('~') + 1).length > 0;
}
