/**
 * EU Age Verification profile — OpenID4VP fallback request (AV Annex A §A.6).
 */
import { validateQuery } from '@openeudi/dcql';
import { describe, expect, it } from 'vitest';

import { AvRequestBuildError } from '../../src/av/errors.js';
import { createAvAuthorizationRequest } from '../../src/av/request.js';
import * as pkg from '../../src/index.js';
import { ANNEX_A_REQUEST, ANNEX_A_REQUEST_QUERY } from '../fixtures/av-annex-a-example.js';

function randomResponseUri(): string {
    return `https://rp-${crypto.randomUUID()}.example/av/response/${crypto.randomUUID()}`;
}

function parse(uri: string): { url: URL; params: URLSearchParams } {
    const url = new URL(uri);
    return { url, params: url.searchParams };
}

function expectBuildError(fn: () => unknown, code: string): void {
    try {
        fn();
    } catch (err) {
        expect(err).toBeInstanceOf(AvRequestBuildError);
        expect((err as AvRequestBuildError).code).toBe(code);
        return;
    }
    throw new Error(`expected AvRequestBuildError(${code})`);
}

describe('createAvAuthorizationRequest', () => {
    it('builds an unsigned by-value av:// request with the Annex A §A.6 parameters', () => {
        const responseUri = randomResponseUri();
        const request = createAvAuthorizationRequest({ responseUri });

        expect(request.uri.startsWith('av://?')).toBe(true);
        const { url, params } = parse(request.uri);
        expect(url.protocol).toBe('av:');
        expect(url.host).toBe('');

        expect(params.get('response_type')).toBe('vp_token');
        expect(params.get('response_mode')).toBe('direct_post');
        expect(params.get('client_id')).toBe(`redirect_uri:${responseUri}`);
        expect(params.get('response_uri')).toBe(responseUri);
        expect(params.get('nonce')).toBe(request.nonce);
        // No JAR, no request_uri, no state unless supplied.
        expect(params.has('request')).toBe(false);
        expect(params.has('request_uri')).toBe(false);
        expect(params.has('state')).toBe(false);
        expect(request.state).toBeUndefined();

        expect(JSON.parse(params.get('dcql_query')!)).toEqual({
            credentials: [
                {
                    id: 'proof_of_age',
                    format: 'mso_mdoc',
                    meta: { doctype_value: 'eu.europa.ec.av.1' },
                    claims: [{ path: ['eu.europa.ec.av.1', 'age_over_18'] }],
                },
            ],
        });
        expect(JSON.parse(params.get('client_metadata')!)).toEqual({
            vp_formats_supported: {
                mso_mdoc: { issuerauth_alg_values: [-7, -35, -36], deviceauth_alg_values: [-7, -35, -36] },
            },
        });

        expect(request).toMatchObject({
            clientId: `redirect_uri:${responseUri}`,
            responseUri,
            ageThreshold: 18,
            ageOverAttribute: 'age_over_18',
            requestedAgeOverAttributes: ['age_over_18'],
            credentialId: 'proof_of_age',
        });
        expect(request.dcqlQuery).toEqual(JSON.parse(params.get('dcql_query')!));
        expect(request.clientMetadata).toEqual(JSON.parse(params.get('client_metadata')!));
    });

    it('generates a fresh 256-bit base64url nonce per request', () => {
        const responseUri = randomResponseUri();
        const a = createAvAuthorizationRequest({ responseUri });
        const b = createAvAuthorizationRequest({ responseUri });
        expect(a.nonce).toMatch(/^[A-Za-z0-9_-]{43}$/);
        expect(a.nonce).not.toBe(b.nonce);
    });

    it('carries a supplied nonce and state through to the URL and the result', () => {
        const nonce = crypto.randomUUID();
        const state = crypto.randomUUID();
        const request = createAvAuthorizationRequest({ responseUri: randomResponseUri(), nonce, state });
        const { params } = parse(request.uri);
        expect(params.get('nonce')).toBe(nonce);
        expect(params.get('state')).toBe(state);
        expect(request).toMatchObject({ nonce, state });
    });

    it('requests age_over_NN for another threshold', () => {
        const request = createAvAuthorizationRequest({ responseUri: randomResponseUri(), ageThreshold: 21 });
        const { params } = parse(request.uri);
        expect(JSON.parse(params.get('dcql_query')!).credentials[0].claims).toEqual([
            { path: ['eu.europa.ec.av.1', 'age_over_21'] },
        ]);
        expect(request.ageOverAttribute).toBe('age_over_21');
    });

    it('asks for age_over_NN alone, without claim ids or claim_sets, from 18 up', () => {
        const threshold = 18 + Math.floor(Math.random() * 82);
        const request = createAvAuthorizationRequest({ responseUri: randomResponseUri(), ageThreshold: threshold });
        const credential = JSON.parse(parse(request.uri).params.get('dcql_query')!).credentials[0];

        expect(credential.claims).toEqual([{ path: ['eu.europa.ec.av.1', `age_over_${threshold}`] }]);
        expect(credential).not.toHaveProperty('claim_sets');
        expect(request.requestedAgeOverAttributes).toEqual([`age_over_${threshold}`]);
    });

    it('below 18 accepts age_over_NN or age_over_18 through claim_sets, age_over_NN first', () => {
        const threshold = Math.floor(Math.random() * 18);
        const nn = `age_over_${String(threshold).padStart(2, '0')}`;
        const request = createAvAuthorizationRequest({ responseUri: randomResponseUri(), ageThreshold: threshold });
        const dcqlQuery = JSON.parse(parse(request.uri).params.get('dcql_query')!);

        expect(dcqlQuery.credentials[0]).toEqual({
            id: 'proof_of_age',
            format: 'mso_mdoc',
            meta: { doctype_value: 'eu.europa.ec.av.1' },
            claims: [
                { id: nn, path: ['eu.europa.ec.av.1', nn] },
                { id: 'age_over_18', path: ['eu.europa.ec.av.1', 'age_over_18'] },
            ],
            claim_sets: [[nn], ['age_over_18']],
        });
        expect(validateQuery(dcqlQuery)).toEqual(dcqlQuery);
        expect(request.dcqlQuery).toEqual(dcqlQuery);
        expect(request).toMatchObject({
            ageThreshold: threshold,
            ageOverAttribute: nn,
            requestedAgeOverAttributes: [nn, 'age_over_18'],
        });
    });

    it('produces the Annex A §A.11 example request when given its inputs (plus client_metadata)', () => {
        const request = createAvAuthorizationRequest({
            responseUri: ANNEX_A_REQUEST.responseUri,
            nonce: ANNEX_A_REQUEST.nonce,
            state: ANNEX_A_REQUEST.state,
        });
        const ours = parse(request.uri).params;
        const annex = new URLSearchParams(ANNEX_A_REQUEST_QUERY);
        for (const [name, value] of annex) {
            if (name === 'dcql_query') {
                expect(JSON.parse(ours.get(name)!)).toEqual(JSON.parse(value));
            } else {
                expect(ours.get(name)).toBe(value);
            }
        }
        expect([...ours.keys()].sort()).toEqual([...annex.keys(), 'client_metadata'].sort());
        expect(request.clientId).toBe(ANNEX_A_REQUEST.clientId);
    });

    it('omits client_metadata when vpFormatsSupported is null, like the Annex A example', () => {
        const request = createAvAuthorizationRequest({ responseUri: randomResponseUri(), vpFormatsSupported: null });
        expect(parse(request.uri).params.has('client_metadata')).toBe(false);
        expect(request.clientMetadata).toBeUndefined();
    });

    it('appends to a custom base URI such as an https app link', () => {
        const base = `https://av-${crypto.randomUUID()}.example/open`;
        const request = createAvAuthorizationRequest({ responseUri: randomResponseUri(), baseUri: base });
        expect(request.uri.startsWith(`${base}?response_type=vp_token`)).toBe(true);

        const withQuery = createAvAuthorizationRequest({ responseUri: randomResponseUri(), baseUri: `${base}?x=1` });
        expect(withQuery.uri.startsWith(`${base}?x=1&response_type=vp_token`)).toBe(true);
    });

    it('rejects a response_uri that is not an absolute https URL', () => {
        expectBuildError(() => createAvAuthorizationRequest({ responseUri: '' }), 'invalid_response_uri');
        expectBuildError(() => createAvAuthorizationRequest({ responseUri: '/relative' }), 'invalid_response_uri');
        expectBuildError(
            () => createAvAuthorizationRequest({ responseUri: `http://rp-${crypto.randomUUID()}.example/cb` }),
            'invalid_response_uri',
        );
        expectBuildError(
            () => createAvAuthorizationRequest({ responseUri: `${randomResponseUri()}#frag` }),
            'invalid_response_uri',
        );
    });

    it('rejects a weak or unsafe nonce', () => {
        const responseUri = randomResponseUri();
        expectBuildError(() => createAvAuthorizationRequest({ responseUri, nonce: 'short' }), 'invalid_nonce');
        expectBuildError(
            () => createAvAuthorizationRequest({ responseUri, nonce: `${crypto.randomUUID()} &x=1` }),
            'invalid_nonce',
        );
    });

    it('rejects invalid age thresholds, credential ids, states and base URIs', () => {
        const responseUri = randomResponseUri();
        for (const ageThreshold of [100, -1, 17.5, Number.NaN]) {
            expectBuildError(() => createAvAuthorizationRequest({ responseUri, ageThreshold }), 'invalid_age_threshold');
        }
        expectBuildError(
            () => createAvAuthorizationRequest({ responseUri, credentialId: 'proof of age' }),
            'invalid_credential_id',
        );
        expectBuildError(() => createAvAuthorizationRequest({ responseUri, state: '' }), 'invalid_state');
        expectBuildError(
            () => createAvAuthorizationRequest({ responseUri, baseUri: 'http://av.example/' }),
            'invalid_base_uri',
        );
        expectBuildError(() => createAvAuthorizationRequest({ responseUri, baseUri: 'not a uri' }), 'invalid_base_uri');
    });

    it('is exported from the package entry point', () => {
        expect(pkg.createAvAuthorizationRequest).toBe(createAvAuthorizationRequest);
        expect(typeof pkg.verifyAvPresentation).toBe('function');
        expect(pkg.AV_DOCTYPE).toBe('eu.europa.ec.av.1');
        expect(pkg.AV_DOCUMENT_SIGNER_EKU).toBe('1.3.130.2.0.0.1.2');
        expect(pkg.AvRequestBuildError).toBe(AvRequestBuildError);
        expect(typeof pkg.AvResponseError).toBe('function');
    });
});
