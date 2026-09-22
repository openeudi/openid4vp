import type {
    DcqlQuery,
    CredentialQuery,
    ClaimsQuery,
    CredentialSetQuery,
} from '@openeudi/dcql';
import { HaipValidationError } from './errors.js';
import type { HaipQueryInput, CredentialSetQueryInput } from './types/haip.js';

export const HAIP_DOCTYPE_NAMESPACES: Record<string, string> = {
    'org.iso.18013.5.1.mDL': 'org.iso.18013.5.1',
    'eu.europa.ec.eudi.pid.1': 'eu.europa.ec.eudi.pid.1',
};

export function buildHaipQuery(input: HaipQueryInput): DcqlQuery {
    if (input.claims.length === 0) {
        throw new HaipValidationError(
            'NO_CLAIMS',
            `credential '${input.credentialId}' must declare at least one claim`,
            input.credentialId,
        );
    }

    let meta: CredentialQuery['meta'];
    let claims: ClaimsQuery[];

    if (input.format === 'dc+sd-jwt') {
        if (!input.vctValues || input.vctValues.length === 0) {
            throw new HaipValidationError(
                'MISSING_SDJWT_META',
                `credential '${input.credentialId}' with format 'dc+sd-jwt' must provide non-empty vctValues`,
                input.credentialId,
            );
        }
        meta = { vct_values: input.vctValues };
        claims = input.claims.map((c) => ({ path: [c] }));
    } else {
        if (!input.doctypeValue) {
            throw new HaipValidationError(
                'MISSING_MDOC_META',
                `credential '${input.credentialId}' with format 'mso_mdoc' must provide doctypeValue`,
                input.credentialId,
            );
        }
        meta = { doctype_value: input.doctypeValue };
        const namespace = HAIP_DOCTYPE_NAMESPACES[input.doctypeValue] ?? input.doctypeValue;
        claims = input.claims.map((c) => ({ path: [namespace, c] }));
    }

    const credential: CredentialQuery = {
        id: input.credentialId,
        format: input.format,
        meta,
        claims,
    };

    if (input.trustedAuthorities && input.trustedAuthorities.length > 0) {
        credential.trusted_authorities = input.trustedAuthorities;
    }

    return { credentials: [credential] };
}

/**
 * Build a DCQL query offering the wallet a choice between several credentials —
 * a `credential_sets` disjunction.
 *
 * The motivating case is a proof-of-age check: ask for a Proof-of-Age
 * attestation (`mso_mdoc`, `age_over_18` in namespace `eu.europa.ec.av.1`) OR a
 * PID (`dc+sd-jwt`, `birth_date`), because the PID carries no age attribute and
 * proof-of-age attestations have almost no issuer coverage yet. The wallet
 * satisfies ONE option and returns ONE presentation.
 *
 * This is deliberately NOT HAIP-minimal: `validateHaipQuery` rejects
 * `credential_sets`, and `isHaipQuery` returns `false` for what this produces.
 * That boundary is intentional — use `validateCredentialSetQuery` instead.
 *
 * Each option is built through {@link buildHaipQuery}, so per-credential
 * validation and its `HaipValidationError` codes are identical.
 */
export function buildCredentialSetQuery(input: CredentialSetQueryInput): DcqlQuery {
    if (input.options.length === 0) {
        throw new HaipValidationError(
            'EMPTY_OPTIONS',
            'a credential set must offer at least one option',
        );
    }

    const seen = new Set<string>();
    for (const option of input.options) {
        if (seen.has(option.credentialId)) {
            throw new HaipValidationError(
                'DUPLICATE_CREDENTIAL_ID',
                `credential '${option.credentialId}' is declared by more than one option; ` +
                    'credential ids must be unique for credential_sets to reference them',
                option.credentialId,
            );
        }
        seen.add(option.credentialId);
    }

    const credentials = input.options.map((option) => buildHaipQuery(option).credentials[0]);

    const credentialSet: CredentialSetQuery = {
        options: input.options.map((option) => [option.credentialId]),
    };
    // `required` defaults to true in DCQL, so only an explicit opt-out is emitted.
    if (input.required === false) {
        credentialSet.required = false;
    }

    return { credentials, credential_sets: [credentialSet] };
}

const HAIP_FORMATS = new Set<string>(['dc+sd-jwt', 'mso_mdoc']);

export function validateHaipQuery(query: DcqlQuery): void {
    if (!query.credentials || query.credentials.length === 0) {
        throw new HaipValidationError(
            'EMPTY_QUERY',
            'query.credentials must have at least one entry',
        );
    }

    if (query.credential_sets !== undefined) {
        throw new HaipValidationError(
            'CREDENTIAL_SETS_DISALLOWED',
            'credential_sets are not permitted in HAIP-minimal',
        );
    }

    for (const credential of query.credentials) {
        validateCredential(credential);
    }
}

/**
 * Per-credential rules shared by `validateHaipQuery` and
 * `validateCredentialSetQuery` — the two profiles differ only on whether
 * top-level `credential_sets` is allowed, never on what a credential may say.
 */
function validateCredential(credential: CredentialQuery): void {
    if (!HAIP_FORMATS.has(credential.format)) {
        throw new HaipValidationError(
            'UNSUPPORTED_FORMAT',
            `credential '${credential.id}' uses unsupported format '${credential.format}' (allowed: dc+sd-jwt, mso_mdoc)`,
            credential.id,
        );
    }

    if (credential.format === 'dc+sd-jwt') {
        const vctValues = credential.meta?.vct_values;
        if (!vctValues || vctValues.length === 0) {
            throw new HaipValidationError(
                'MISSING_SDJWT_META',
                `credential '${credential.id}' with format 'dc+sd-jwt' must set meta.vct_values`,
                credential.id,
            );
        }
    }

    if (credential.format === 'mso_mdoc') {
        if (typeof credential.meta?.doctype_value !== 'string') {
            throw new HaipValidationError(
                'MISSING_MDOC_META',
                `credential '${credential.id}' with format 'mso_mdoc' must set meta.doctype_value`,
                credential.id,
            );
        }
    }

    if (!credential.claims || credential.claims.length === 0) {
        throw new HaipValidationError(
            'NO_CLAIMS',
            `credential '${credential.id}' must declare at least one claim`,
            credential.id,
        );
    }

    if (credential.claim_sets !== undefined) {
        throw new HaipValidationError(
            'CLAIM_SETS_DISALLOWED',
            `credential '${credential.id}' uses claim_sets, not permitted in HAIP-minimal`,
            credential.id,
        );
    }
}

/**
 * Validate a DCQL query that offers the wallet a choice — the profile
 * `buildCredentialSetQuery` produces. Per-credential rules are identical to
 * HAIP-minimal; the difference is that `credential_sets` is REQUIRED here
 * rather than forbidden.
 */
export function validateCredentialSetQuery(query: DcqlQuery): void {
    if (!query.credentials || query.credentials.length === 0) {
        throw new HaipValidationError(
            'EMPTY_QUERY',
            'query.credentials must have at least one entry',
        );
    }

    if (!query.credential_sets || query.credential_sets.length === 0) {
        throw new HaipValidationError(
            'MISSING_CREDENTIAL_SETS',
            'a credential-set query must declare at least one credential_sets entry',
        );
    }

    for (const credential of query.credentials) {
        validateCredential(credential);
    }

    const declaredIds = new Set(query.credentials.map((c) => c.id));
    for (const credentialSet of query.credential_sets) {
        if (!credentialSet.options || credentialSet.options.length === 0) {
            throw new HaipValidationError(
                'EMPTY_OPTIONS',
                'a credential set must offer at least one option',
            );
        }

        for (const option of credentialSet.options) {
            for (const id of option) {
                if (!declaredIds.has(id)) {
                    throw new HaipValidationError(
                        'UNKNOWN_OPTION_REFERENCE',
                        `credential_sets option references '${id}', which is not declared in query.credentials`,
                        id,
                    );
                }
            }
        }
    }
}

export function isHaipQuery(query: DcqlQuery): boolean {
    try {
        validateHaipQuery(query);
        return true;
    } catch {
        return false;
    }
}
