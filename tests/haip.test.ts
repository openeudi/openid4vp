import { describe, it, expect } from 'vitest';
import { buildHaipQuery, HAIP_DOCTYPE_NAMESPACES } from '../src/haip.js';
import { HaipValidationError } from '../src/errors.js';

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
