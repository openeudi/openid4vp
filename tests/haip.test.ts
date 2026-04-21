import { describe, it, expect } from 'vitest';
import {
    buildHaipQuery,
    HAIP_DOCTYPE_NAMESPACES,
    validateHaipQuery,
    isHaipQuery,
} from '../src/haip.js';
import { HaipValidationError } from '../src/errors.js';
import type { DcqlQuery } from '@openeudi/dcql';

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
