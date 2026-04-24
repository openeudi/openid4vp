import { describe, expect, it } from 'vitest';
import { ProvenanceResolver } from '../../src/trust/ProvenanceResolver.js';
import type { NationalTlSnapshot } from '../../src/trust/lotl-types.js';
import { createCa } from './helpers/synthetic-ca.js';

describe('ProvenanceResolver — LOTL match', () => {
    it('maps a CA/QC + granted service to qualified=true', async () => {
        const anchor = await createCa({ name: 'CN=ANTS Root' });
        const tl: NationalTlSnapshot = {
            country: 'FR',
            issueDate: new Date('2026-04-01'),
            nextUpdate: null,
            services: [
                {
                    providerName: 'ANTS',
                    country: 'FR',
                    serviceTypeIdentifier:
                        'http://uri.etsi.org/TrstSvc/Svctype/CA/QC',
                    serviceStatus:
                        'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted',
                    serviceName: 'ANTS Qualified CA',
                    certificates: [anchor.certificate],
                    additionalServiceInformationUris: [],
                },
            ],
        };
        const resolver = new ProvenanceResolver();
        const out = resolver.resolve(anchor.certificate, [tl]);
        expect(out).toBeDefined();
        expect(out!.provenance.qualified).toBe(true);
        expect(out!.provenance.country).toBe('FR');
        expect(out!.provenance.serviceName).toBe('ANTS Qualified CA');
        expect(out!.provenance.loa).toBeUndefined();
        expect(out!.trustedAuthorityIds).toHaveLength(1);
    });

    it('maps eIDAS-high URI to loa=high', async () => {
        const anchor = await createCa();
        const tl: NationalTlSnapshot = {
            country: 'DE',
            issueDate: new Date('2026-04-01'),
            nextUpdate: null,
            services: [
                {
                    providerName: 'BSI',
                    country: 'DE',
                    serviceTypeIdentifier:
                        'http://uri.etsi.org/TrstSvc/Svctype/CA/QC',
                    serviceStatus:
                        'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted',
                    serviceName: 'BSI eID Service',
                    certificates: [anchor.certificate],
                    additionalServiceInformationUris: [
                        'http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/eIDASnotified-high',
                    ],
                },
            ],
        };
        const out = new ProvenanceResolver().resolve(anchor.certificate, [tl]);
        expect(out!.provenance.loa).toBe('high');
    });

    it('non-QC service → qualified=false', async () => {
        const anchor = await createCa();
        const tl: NationalTlSnapshot = {
            country: 'ES',
            issueDate: new Date('2026-04-01'),
            nextUpdate: null,
            services: [
                {
                    providerName: 'FNMT',
                    country: 'ES',
                    serviceTypeIdentifier:
                        'http://uri.etsi.org/TrstSvc/Svctype/CA/PKC',
                    serviceStatus:
                        'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted',
                    serviceName: 'FNMT PKC',
                    certificates: [anchor.certificate],
                    additionalServiceInformationUris: [],
                },
            ],
        };
        const out = new ProvenanceResolver().resolve(anchor.certificate, [tl]);
        expect(out!.provenance.qualified).toBe(false);
    });

    it('returns null when no service matches the anchor', async () => {
        const anchor = await createCa();
        const unrelated = await createCa({ name: 'CN=Other' });
        const tl: NationalTlSnapshot = {
            country: 'IT',
            issueDate: new Date('2026-04-01'),
            nextUpdate: null,
            services: [
                {
                    providerName: 'AgID',
                    country: 'IT',
                    serviceTypeIdentifier:
                        'http://uri.etsi.org/TrstSvc/Svctype/CA/QC',
                    serviceStatus:
                        'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted',
                    serviceName: 'AgID CA',
                    certificates: [unrelated.certificate],
                    additionalServiceInformationUris: [],
                },
            ],
        };
        const out = new ProvenanceResolver().resolve(anchor.certificate, [tl]);
        expect(out).toBeNull();
    });
});
