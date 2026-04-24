import { describe, expect, it } from 'vitest';
import {
    OpenID4VPError,
    TrustAnchorNotFoundError,
    CertificateChainError,
    RevokedCertificateError,
    RevocationCheckFailedError,
    LotlFetchError,
    LotlSignatureError,
} from '../../src/errors.js';

describe('OpenID4VPError base', () => {
    it('exposes stable code and optional cause', () => {
        const cause = new Error('underlying');
        class Fake extends OpenID4VPError {
            readonly code = 'fake_code' as const;
        }
        const err = new Fake('fake message', { cause });
        expect(err).toBeInstanceOf(Error);
        expect(err).toBeInstanceOf(OpenID4VPError);
        expect(err.message).toBe('fake message');
        expect(err.code).toBe('fake_code');
        expect(err.cause).toBe(cause);
        expect(err.name).toBe('Fake');
    });

    it('preserves prototype chain for instanceof across class boundaries', () => {
        class Fake extends OpenID4VPError {
            readonly code = 'x' as const;
        }
        const err = new Fake('m');
        expect(err instanceof OpenID4VPError).toBe(true);
        expect(err instanceof Error).toBe(true);
    });
});

describe('TrustAnchorNotFoundError', () => {
    it('has code "trust_anchor_not_found"', () => {
        const err = new TrustAnchorNotFoundError('no anchor for issuer CN=Foo');
        expect(err.code).toBe('trust_anchor_not_found');
        expect(err).toBeInstanceOf(OpenID4VPError);
        expect(err.name).toBe('TrustAnchorNotFoundError');
    });
});

describe('CertificateChainError', () => {
    it('carries a typed reason', () => {
        const err = new CertificateChainError('sig failed', { reason: 'signature' });
        expect(err.code).toBe('chain_invalid');
        expect(err.reason).toBe('signature');
    });

    it('accepts all reason kinds', () => {
        const reasons = [
            'signature',
            'validity',
            'name_constraints',
            'key_usage',
            'basic_constraints',
            'path_length',
            'algorithm_disallowed',
            'aki_ski_mismatch',
        ] as const;
        for (const reason of reasons) {
            const err = new CertificateChainError('m', { reason });
            expect(err.reason).toBe(reason);
        }
    });
});

describe('RevokedCertificateError', () => {
    it('extends OpenID4VPError and has stable code', () => {
        const err = new RevokedCertificateError('revoked', {
            serial: 'ABCDEF01',
            revokedAt: new Date('2026-01-01T00:00:00Z'),
        });
        expect(err).toBeInstanceOf(OpenID4VPError);
        expect(err.code).toBe('certificate_revoked');
        expect(err.serial).toBe('ABCDEF01');
        expect(err.revokedAt.toISOString()).toBe('2026-01-01T00:00:00.000Z');
        expect(err.name).toBe('RevokedCertificateError');
    });

    it('optional reason field is preserved', () => {
        const err = new RevokedCertificateError('revoked', {
            serial: 'AA',
            revokedAt: new Date(0),
            reason: 'keyCompromise',
        });
        expect(err.reason).toBe('keyCompromise');
    });
});

describe('RevocationCheckFailedError', () => {
    it('extends OpenID4VPError, carries code and cause', () => {
        const cause = new Error('network down');
        const err = new RevocationCheckFailedError('check failed', { cause });
        expect(err).toBeInstanceOf(OpenID4VPError);
        expect(err.code).toBe('revocation_check_failed');
        expect((err as { cause?: unknown }).cause).toBe(cause);
    });
});

describe('LotlFetchError', () => {
    it('extends OpenID4VPError, carries code, url, and cause', () => {
        const cause = new Error('connection reset');
        const err = new LotlFetchError('failed to fetch LOTL', {
            url: 'https://ec.europa.eu/tools/lotl/eu-lotl.xml',
            cause,
        });
        expect(err).toBeInstanceOf(OpenID4VPError);
        expect(err.code).toBe('lotl_fetch_failed');
        expect(err.url).toBe('https://ec.europa.eu/tools/lotl/eu-lotl.xml');
        expect((err as { cause?: unknown }).cause).toBe(cause);
        expect(err.name).toBe('LotlFetchError');
    });
});

describe('LotlSignatureError', () => {
    it('extends OpenID4VPError and has stable code', () => {
        const err = new LotlSignatureError('signature did not verify');
        expect(err).toBeInstanceOf(OpenID4VPError);
        expect(err.code).toBe('lotl_signature_invalid');
        expect(err.name).toBe('LotlSignatureError');
    });

    it('preserves cause when provided', () => {
        const cause = new Error('xmldsig core failure');
        const err = new LotlSignatureError('sig invalid', { cause });
        expect((err as { cause?: unknown }).cause).toBe(cause);
    });
});
