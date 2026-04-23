import { describe, expect, it } from 'vitest';
import {
    OpenID4VPError,
    TrustAnchorNotFoundError,
    CertificateChainError,
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
