import { describe, it, expect } from 'vitest';
import { createAuthorizationRequest } from '../src/authorization.js';
import { buildHaipQuery } from '../src/haip.js';
import type { DcqlQuery } from '@openeudi/dcql';

const pidQuery: DcqlQuery = buildHaipQuery({
    credentialId: 'pid',
    format: 'dc+sd-jwt',
    vctValues: ['https://pid.eu/v1'],
    claims: ['age_over_18'],
});

describe('createAuthorizationRequest', () => {
    const baseInput = {
        clientId: 'x509_san_dns:verifier.example.com',
        responseUri: 'https://verifier.example.com/callback',
        nonce: 'test-nonce-abc123',
    };

    it('emits dcql_query in the URI (not presentation_definition)', () => {
        const req = createAuthorizationRequest(baseInput, pidQuery);
        const params = new URL(req.uri.replace('openid4vp://', 'https://dummy/')).searchParams;

        expect(params.get('dcql_query')).not.toBeNull();
        expect(params.get('presentation_definition')).toBeNull();
    });

    it('round-trips the DCQL query via JSON.parse', () => {
        const req = createAuthorizationRequest(baseInput, pidQuery);
        const params = new URL(req.uri.replace('openid4vp://', 'https://dummy/')).searchParams;
        const parsed = JSON.parse(params.get('dcql_query')!);

        expect(parsed).toEqual(pidQuery);
    });

    it('defaults response_type to vp_token and response_mode to direct_post', () => {
        const req = createAuthorizationRequest(baseInput, pidQuery);
        const params = new URL(req.uri.replace('openid4vp://', 'https://dummy/')).searchParams;

        expect(params.get('response_type')).toBe('vp_token');
        expect(params.get('response_mode')).toBe('direct_post');
    });

    it('supports response_mode=direct_post.jwt when requested', () => {
        const req = createAuthorizationRequest(
            { ...baseInput, responseMode: 'direct_post.jwt' },
            pidQuery,
        );
        const params = new URL(req.uri.replace('openid4vp://', 'https://dummy/')).searchParams;

        expect(params.get('response_mode')).toBe('direct_post.jwt');
    });

    it('auto-generates state when omitted; echoes it verbatim when provided', () => {
        const autoReq = createAuthorizationRequest(baseInput, pidQuery);
        expect(autoReq.state).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);

        const fixed = createAuthorizationRequest({ ...baseInput, state: 'custom-state' }, pidQuery);
        expect(fixed.state).toBe('custom-state');
    });

    it('returns dcqlQuery in the result object', () => {
        const req = createAuthorizationRequest(baseInput, pidQuery);
        expect(req.dcqlQuery).toEqual(pidQuery);
    });

    it('throws TypeError when clientId is missing', () => {
        expect(() =>
            createAuthorizationRequest({ ...baseInput, clientId: '' }, pidQuery),
        ).toThrow(TypeError);
    });

    it('throws TypeError when nonce is missing', () => {
        expect(() =>
            createAuthorizationRequest({ ...baseInput, nonce: '' }, pidQuery),
        ).toThrow(TypeError);
    });

    it('throws TypeError when responseUri is missing', () => {
        expect(() =>
            createAuthorizationRequest({ ...baseInput, responseUri: '' }, pidQuery),
        ).toThrow(TypeError);
    });

    it('preserves response_uri query params through URLSearchParams encoding', () => {
        const req = createAuthorizationRequest(
            { ...baseInput, responseUri: 'https://verifier.example.com/cb?session=abc&tenant=eu' },
            pidQuery,
        );
        const params = new URL(req.uri.replace('openid4vp://', 'https://dummy/')).searchParams;
        expect(params.get('response_uri')).toBe('https://verifier.example.com/cb?session=abc&tenant=eu');
    });

    it('round-trips dcql_query with special characters in vct_values', () => {
        const trickyQuery = buildHaipQuery({
            credentialId: 'pid',
            format: 'dc+sd-jwt',
            vctValues: ['https://issuer.eu/pid?v=1&realm=eu'],
            claims: ['age_over_18'],
        });
        const req = createAuthorizationRequest(baseInput, trickyQuery);
        const params = new URL(req.uri.replace('openid4vp://', 'https://dummy/')).searchParams;
        const parsed = JSON.parse(params.get('dcql_query')!);
        expect(parsed.credentials[0].meta.vct_values[0]).toBe('https://issuer.eu/pid?v=1&realm=eu');
    });
});
