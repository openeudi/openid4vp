import { describe, it, expect } from 'vitest';

import { createAuthorizationRequest } from '../src/authorization.js';

describe('createAuthorizationRequest', () => {
    const baseInput = {
        requestedAttributes: ['age_over_18', 'resident_country'],
        acceptedFormats: ['sd-jwt-vc', 'mdoc'] as const,
        responseUri: 'https://api.eidas-pro.eu/verification/abc-123/callback',
        nonce: 'session-nonce-xyz',
        clientId: 'https://eidas-pro.eu',
    };

    it('generates a valid OpenID4VP URI', () => {
        const result = createAuthorizationRequest(baseInput);
        expect(result.uri).toContain('openid4vp://');
        expect(result.uri).toContain('response_uri=');
        expect(result.uri).toContain('nonce=');
        expect(result.uri).toContain('client_id=');
    });

    it('includes presentation_definition with requested attributes', () => {
        const result = createAuthorizationRequest(baseInput);
        expect(result.presentationDefinition).toBeDefined();
        const pd = result.presentationDefinition as Record<string, unknown>;
        expect(pd).toHaveProperty('input_descriptors');
    });

    it('sets nonce and state on the result', () => {
        const result = createAuthorizationRequest(baseInput);
        expect(result.nonce).toBe('session-nonce-xyz');
        expect(result.state).toBeDefined();
        expect(typeof result.state).toBe('string');
    });

    it('uses provided state if given', () => {
        const result = createAuthorizationRequest({ ...baseInput, state: 'custom-state' });
        expect(result.state).toBe('custom-state');
    });

    it('encodes responseUri in the URI', () => {
        const result = createAuthorizationRequest(baseInput);
        expect(result.uri).toContain(encodeURIComponent(baseInput.responseUri));
    });

    it('handles single attribute request', () => {
        const result = createAuthorizationRequest({
            ...baseInput,
            requestedAttributes: ['age_over_18'],
        });
        expect(result.presentationDefinition).toBeDefined();
    });
});
