import { describe, it, expect } from 'vitest';
import {
    buildHaipQuery,
    HAIP_DOCTYPE_NAMESPACES,
    validateHaipQuery,
    isHaipQuery,
    buildCredentialSetQuery,
    validateCredentialSetQuery,
} from '../src/haip.js';
import { HaipValidationError } from '../src/errors.js';
import type { DcqlQuery } from '@openeudi/dcql';
import type { HaipQueryInput } from '../src/types/haip.js';

describe('buildHaipQuery', () => {
    it('produces a DCQL query with flat claim paths for sd-jwt', () => {
        const query = buildHaipQuery({
            credentialId: 'pid',
            format: 'dc+sd-jwt',
            vctValues: ['https://pid.eu/v1'],
            claims: ['age_over_18', 'given_name'],
        });

        expect(query).toEqual({
            credentials: [
                {
                    id: 'pid',
                    format: 'dc+sd-jwt',
                    meta: { vct_values: ['https://pid.eu/v1'] },
                    claims: [{ path: ['age_over_18'] }, { path: ['given_name'] }],
                },
            ],
        });
    });

    it('produces a DCQL query with auto-namespaced paths for known mdoc doctype (mDL)', () => {
        const query = buildHaipQuery({
            credentialId: 'mdl',
            format: 'mso_mdoc',
            doctypeValue: 'org.iso.18013.5.1.mDL',
            claims: ['age_over_18', 'portrait'],
        });

        expect(query.credentials[0].claims).toEqual([
            { path: ['org.iso.18013.5.1', 'age_over_18'] },
            { path: ['org.iso.18013.5.1', 'portrait'] },
        ]);
        expect(query.credentials[0].meta).toEqual({ doctype_value: 'org.iso.18013.5.1.mDL' });
    });

    it('produces auto-namespaced paths for EUDI PID (namespace = doctype)', () => {
        const query = buildHaipQuery({
            credentialId: 'pid',
            format: 'mso_mdoc',
            doctypeValue: 'eu.europa.ec.eudi.pid.1',
            claims: ['family_name'],
        });

        expect(query.credentials[0].claims).toEqual([
            { path: ['eu.europa.ec.eudi.pid.1', 'family_name'] },
        ]);
    });

    it('falls back to full doctype as namespace for unknown mdoc doctypes', () => {
        const query = buildHaipQuery({
            credentialId: 'custom',
            format: 'mso_mdoc',
            doctypeValue: 'com.example.custom.v1',
            claims: ['custom_claim'],
        });

        expect(query.credentials[0].claims).toEqual([
            { path: ['com.example.custom.v1', 'custom_claim'] },
        ]);
    });

    it('throws MISSING_SDJWT_META when format=dc+sd-jwt without vctValues', () => {
        expect(() =>
            buildHaipQuery({
                credentialId: 'pid',
                format: 'dc+sd-jwt',
                claims: ['age_over_18'],
            }),
        ).toThrow(
            expect.objectContaining({
                name: 'HaipValidationError',
                code: 'MISSING_SDJWT_META',
            }),
        );
    });

    it('throws MISSING_MDOC_META when format=mso_mdoc without doctypeValue', () => {
        expect(() =>
            buildHaipQuery({
                credentialId: 'mdl',
                format: 'mso_mdoc',
                claims: ['age_over_18'],
            }),
        ).toThrow(
            expect.objectContaining({
                name: 'HaipValidationError',
                code: 'MISSING_MDOC_META',
            }),
        );
    });

    it('throws NO_CLAIMS when claims is empty', () => {
        expect(() =>
            buildHaipQuery({
                credentialId: 'pid',
                format: 'dc+sd-jwt',
                vctValues: ['https://pid.eu/v1'],
                claims: [],
            }),
        ).toThrow(
            expect.objectContaining({
                name: 'HaipValidationError',
                code: 'NO_CLAIMS',
            }),
        );
    });

    it('passes trustedAuthorities through to the output', () => {
        const query = buildHaipQuery({
            credentialId: 'pid',
            format: 'dc+sd-jwt',
            vctValues: ['https://pid.eu/v1'],
            claims: ['age_over_18'],
            trustedAuthorities: [{ type: 'etsi_tl', values: ['https://lotl.europa.eu'] }],
        });

        expect(query.credentials[0].trusted_authorities).toEqual([
            { type: 'etsi_tl', values: ['https://lotl.europa.eu'] },
        ]);
    });

    it('is deterministic — same input produces deep-equal output', () => {
        const input = {
            credentialId: 'pid',
            format: 'dc+sd-jwt' as const,
            vctValues: ['https://pid.eu/v1'],
            claims: ['age_over_18'],
        };
        expect(buildHaipQuery(input)).toEqual(buildHaipQuery(input));
    });

    it('exports HAIP_DOCTYPE_NAMESPACES with the known EUDI mappings', () => {
        expect(HAIP_DOCTYPE_NAMESPACES['org.iso.18013.5.1.mDL']).toBe('org.iso.18013.5.1');
        expect(HAIP_DOCTYPE_NAMESPACES['eu.europa.ec.eudi.pid.1']).toBe('eu.europa.ec.eudi.pid.1');
    });
});

describe('validateHaipQuery', () => {
    const validSdJwtQuery: DcqlQuery = {
        credentials: [
            {
                id: 'pid',
                format: 'dc+sd-jwt',
                meta: { vct_values: ['https://pid.eu/v1'] },
                claims: [{ path: ['age_over_18'] }],
            },
        ],
    };

    const validMdocQuery: DcqlQuery = {
        credentials: [
            {
                id: 'mdl',
                format: 'mso_mdoc',
                meta: { doctype_value: 'org.iso.18013.5.1.mDL' },
                claims: [{ path: ['org.iso.18013.5.1', 'age_over_18'] }],
            },
        ],
    };

    it('passes on a valid single-sd-jwt query', () => {
        expect(() => validateHaipQuery(validSdJwtQuery)).not.toThrow();
    });

    it('passes on a valid single-mdoc query', () => {
        expect(() => validateHaipQuery(validMdocQuery)).not.toThrow();
    });

    it('throws EMPTY_QUERY when credentials is empty', () => {
        expect(() => validateHaipQuery({ credentials: [] })).toThrow(
            expect.objectContaining({ code: 'EMPTY_QUERY' }),
        );
    });

    it('throws UNSUPPORTED_FORMAT for non-HAIP formats like jwt_vc_json', () => {
        expect(() =>
            validateHaipQuery({
                credentials: [
                    {
                        id: 'x',
                        format: 'jwt_vc_json',
                        claims: [{ path: ['a'] }],
                    },
                ],
            }),
        ).toThrow(expect.objectContaining({ code: 'UNSUPPORTED_FORMAT', credentialId: 'x' }));
    });

    it('throws MISSING_SDJWT_META when dc+sd-jwt lacks vct_values', () => {
        expect(() =>
            validateHaipQuery({
                credentials: [
                    {
                        id: 'pid',
                        format: 'dc+sd-jwt',
                        claims: [{ path: ['a'] }],
                    },
                ],
            }),
        ).toThrow(expect.objectContaining({ code: 'MISSING_SDJWT_META', credentialId: 'pid' }));
    });

    it('throws MISSING_MDOC_META when mso_mdoc lacks doctype_value', () => {
        expect(() =>
            validateHaipQuery({
                credentials: [
                    {
                        id: 'mdl',
                        format: 'mso_mdoc',
                        claims: [{ path: ['a', 'b'] }],
                    },
                ],
            }),
        ).toThrow(expect.objectContaining({ code: 'MISSING_MDOC_META', credentialId: 'mdl' }));
    });

    it('throws NO_CLAIMS when a credential has no claims', () => {
        expect(() =>
            validateHaipQuery({
                credentials: [
                    {
                        id: 'pid',
                        format: 'dc+sd-jwt',
                        meta: { vct_values: ['v'] },
                    },
                ],
            }),
        ).toThrow(expect.objectContaining({ code: 'NO_CLAIMS', credentialId: 'pid' }));
    });

    it('throws CLAIM_SETS_DISALLOWED when claim_sets is present', () => {
        expect(() =>
            validateHaipQuery({
                credentials: [
                    {
                        id: 'pid',
                        format: 'dc+sd-jwt',
                        meta: { vct_values: ['v'] },
                        claims: [{ id: 'a', path: ['a'] }],
                        claim_sets: [['a']],
                    },
                ],
            }),
        ).toThrow(
            expect.objectContaining({ code: 'CLAIM_SETS_DISALLOWED', credentialId: 'pid' }),
        );
    });

    it('throws CREDENTIAL_SETS_DISALLOWED when top-level credential_sets is present', () => {
        expect(() =>
            validateHaipQuery({
                ...validSdJwtQuery,
                credential_sets: [{ options: [['pid']] }],
            }),
        ).toThrow(expect.objectContaining({ code: 'CREDENTIAL_SETS_DISALLOWED' }));
    });

    it('sets credentialId for per-credential violations and leaves it unset for top-level ones', () => {
        try {
            validateHaipQuery({ credentials: [] });
        } catch (e) {
            expect((e as HaipValidationError).credentialId).toBeUndefined();
        }

        try {
            validateHaipQuery({
                credentials: [{ id: 'x', format: 'jwt_vc_json', claims: [{ path: ['a'] }] }],
            });
        } catch (e) {
            expect((e as HaipValidationError).credentialId).toBe('x');
        }
    });
});

describe('isHaipQuery', () => {
    it('returns true for a valid query', () => {
        expect(
            isHaipQuery({
                credentials: [
                    {
                        id: 'pid',
                        format: 'dc+sd-jwt',
                        meta: { vct_values: ['v'] },
                        claims: [{ path: ['a'] }],
                    },
                ],
            }),
        ).toBe(true);
    });

    it('returns false for a query with jwt_vc_json format', () => {
        expect(
            isHaipQuery({
                credentials: [{ id: 'x', format: 'jwt_vc_json', claims: [{ path: ['a'] }] }],
            }),
        ).toBe(false);
    });

    it('returns false for an empty credentials query', () => {
        expect(isHaipQuery({ credentials: [] })).toBe(false);
    });
});

// ---------------------------------------------------------------------------
// buildCredentialSetQuery — the "proof-of-age attestation OR PID" disjunction.
//
// A verifier asking "is this user over 18?" has two credentials it can ask, in
// two formats, and the PID carries no age attribute at all (CIR (EU) 2024/2977
// Annex has no age_over_*), so the threshold must be computed from birth_date.
// Offering both in ONE request needs a DCQL credential_sets disjunction, which
// buildHaipQuery cannot express.
//
// Proof-of-Age doctype/namespace per av-doc-technical-specification Annex A
// §A.4.1-§A.4.2 @ commit 8b97287 (spec 1.1.0, merged 2026-09-02 via PR #66;
// newest tag is still v1.0.6, so this is pinned to the commit, not a tag).
// ---------------------------------------------------------------------------
describe('buildCredentialSetQuery', () => {
    const AV_DOCTYPE = 'eu.europa.ec.av.1';

    const ageOption: HaipQueryInput = {
        credentialId: 'age-attestation',
        format: 'mso_mdoc',
        doctypeValue: AV_DOCTYPE,
        claims: ['age_over_18'],
    };

    const pidOption: HaipQueryInput = {
        credentialId: 'pid',
        format: 'dc+sd-jwt',
        vctValues: ['urn:eu.europa.ec.eudi:pid:1'],
        claims: ['birth_date'],
    };

    it('emits both credentials and a credential_sets disjunction in the given order', () => {
        const query = buildCredentialSetQuery({ options: [ageOption, pidOption] });

        expect(query).toEqual({
            credentials: [
                {
                    id: 'age-attestation',
                    format: 'mso_mdoc',
                    meta: { doctype_value: AV_DOCTYPE },
                    claims: [{ path: [AV_DOCTYPE, 'age_over_18'] }],
                },
                {
                    id: 'pid',
                    format: 'dc+sd-jwt',
                    meta: { vct_values: ['urn:eu.europa.ec.eudi:pid:1'] },
                    claims: [{ path: ['birth_date'] }],
                },
            ],
            credential_sets: [{ options: [['age-attestation'], ['pid']] }],
        });
    });

    it('derives the AV namespace from the doctype without a HAIP_DOCTYPE_NAMESPACES entry', () => {
        // The Proof-of-Age doctype and its namespace are the SAME string
        // ('eu.europa.ec.av.1', Annex A §A.4.1/§A.4.2), so buildHaipQuery's
        // `?? input.doctypeValue` fallback already yields the correct two-segment
        // claim path. Pinned so nobody "fixes" this by adding a redundant entry.
        expect(HAIP_DOCTYPE_NAMESPACES[AV_DOCTYPE]).toBeUndefined();

        const query = buildCredentialSetQuery({ options: [ageOption, pidOption] });

        expect(query.credentials[0].claims).toEqual([
            { path: ['eu.europa.ec.av.1', 'age_over_18'] },
        ]);
    });

    it('omits `required` when it defaults to true', () => {
        const query = buildCredentialSetQuery({ options: [ageOption, pidOption] });

        expect(query.credential_sets![0]).not.toHaveProperty('required');
    });

    it('emits `required: false` for an optional credential set', () => {
        const query = buildCredentialSetQuery({
            options: [ageOption, pidOption],
            required: false,
        });

        expect(query.credential_sets![0].required).toBe(false);
    });

    it('preserves caller-supplied option order as the privacy preference signal', () => {
        const query = buildCredentialSetQuery({ options: [pidOption, ageOption] });

        expect(query.credentials.map((c) => c.id)).toEqual(['pid', 'age-attestation']);
        expect(query.credential_sets![0].options).toEqual([['pid'], ['age-attestation']]);
    });

    it('carries trustedAuthorities through onto the option that declares them', () => {
        const query = buildCredentialSetQuery({
            options: [
                { ...ageOption, trustedAuthorities: [{ type: 'aki', values: ['abc'] }] },
                pidOption,
            ],
        });

        expect(query.credentials[0].trusted_authorities).toEqual([
            { type: 'aki', values: ['abc'] },
        ]);
        expect(query.credentials[1]).not.toHaveProperty('trusted_authorities');
    });

    describe('per-option validation reuses buildHaipQuery error codes', () => {
        it('throws NO_CLAIMS naming the offending option', () => {
            expect(() =>
                buildCredentialSetQuery({
                    options: [{ ...ageOption, claims: [] }, pidOption],
                }),
            ).toThrow(
                expect.objectContaining({
                    code: 'NO_CLAIMS',
                    credentialId: 'age-attestation',
                }),
            );
        });

        it('throws MISSING_MDOC_META when an mso_mdoc option omits doctypeValue', () => {
            expect(() =>
                buildCredentialSetQuery({
                    options: [{ ...ageOption, doctypeValue: undefined }, pidOption],
                }),
            ).toThrow(
                expect.objectContaining({
                    code: 'MISSING_MDOC_META',
                    credentialId: 'age-attestation',
                }),
            );
        });

        it('throws MISSING_SDJWT_META when a dc+sd-jwt option omits vctValues', () => {
            expect(() =>
                buildCredentialSetQuery({
                    options: [ageOption, { ...pidOption, vctValues: [] }],
                }),
            ).toThrow(
                expect.objectContaining({
                    code: 'MISSING_SDJWT_META',
                    credentialId: 'pid',
                }),
            );
        });
    });

    it('throws EMPTY_OPTIONS when no options are supplied', () => {
        expect(() => buildCredentialSetQuery({ options: [] })).toThrow(
            expect.objectContaining({ code: 'EMPTY_OPTIONS' }),
        );
    });

    it('throws DUPLICATE_CREDENTIAL_ID when two options share a credentialId', () => {
        // Two credentials with the same id make the credential_sets reference
        // ambiguous and the DCQL query unresolvable — fail loud at build time.
        expect(() =>
            buildCredentialSetQuery({
                options: [ageOption, { ...pidOption, credentialId: 'age-attestation' }],
            }),
        ).toThrow(
            expect.objectContaining({
                code: 'DUPLICATE_CREDENTIAL_ID',
                credentialId: 'age-attestation',
            }),
        );
    });

    describe('profile boundary — a disjunction is NOT HAIP-minimal', () => {
        it('validateHaipQuery still throws CREDENTIAL_SETS_DISALLOWED on the built query', () => {
            const query = buildCredentialSetQuery({ options: [ageOption, pidOption] });

            expect(() => validateHaipQuery(query)).toThrow(
                expect.objectContaining({ code: 'CREDENTIAL_SETS_DISALLOWED' }),
            );
        });

        it('isHaipQuery returns false for the built query', () => {
            const query = buildCredentialSetQuery({ options: [ageOption, pidOption] });

            expect(isHaipQuery(query)).toBe(false);
        });
    });

    describe('validateCredentialSetQuery', () => {
        it('accepts a query produced by buildCredentialSetQuery', () => {
            const query = buildCredentialSetQuery({ options: [ageOption, pidOption] });

            expect(() => validateCredentialSetQuery(query)).not.toThrow();
        });

        it('throws MISSING_CREDENTIAL_SETS on a plain HAIP query', () => {
            const query = buildHaipQuery(pidOption);

            expect(() => validateCredentialSetQuery(query)).toThrow(
                expect.objectContaining({ code: 'MISSING_CREDENTIAL_SETS' }),
            );
        });

        it('throws UNKNOWN_OPTION_REFERENCE when an option names an absent credential', () => {
            const query = buildCredentialSetQuery({ options: [ageOption, pidOption] });
            query.credential_sets![0].options = [['age-attestation'], ['not-declared']];

            expect(() => validateCredentialSetQuery(query)).toThrow(
                expect.objectContaining({ code: 'UNKNOWN_OPTION_REFERENCE' }),
            );
        });

        it('applies the same per-credential rules as validateHaipQuery', () => {
            const query = buildCredentialSetQuery({ options: [ageOption, pidOption] });
            query.credentials[1].format = 'jwt_vc_json';

            expect(() => validateCredentialSetQuery(query)).toThrow(
                expect.objectContaining({ code: 'UNSUPPORTED_FORMAT', credentialId: 'pid' }),
            );
        });

        it('throws EMPTY_OPTIONS when a credential set declares no options', () => {
            const query = buildCredentialSetQuery({ options: [ageOption, pidOption] });
            query.credential_sets![0].options = [];

            expect(() => validateCredentialSetQuery(query)).toThrow(
                expect.objectContaining({ code: 'EMPTY_OPTIONS' }),
            );
        });
    });
});
