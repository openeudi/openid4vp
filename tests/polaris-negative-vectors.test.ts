/**
 * Negative test vectors: presentations a verifier must judge, each with the
 * verdict a correct verifier reaches, run here against `verifyPresentation`.
 * SD-JWT VC presentations under OpenID4VP 1.0 and HAIP 1.0, and ISO/IEC
 * 18013-5 mdoc DeviceResponses over OpenID4VP 1.0. Every negative is a valid
 * control with one thing changed and names the clauses its verdict rests on;
 * every negative judged here also carries its repaired twin, which must be
 * accepted, so a refusal cannot come from a broken fixture.
 *
 * Vectors: EgorKhaklin/polaris-id @ 5d0c68f6 (Apache-2.0),
 * `lab/interop/negative-vectors/`, copied unchanged into
 * tests/fixtures/polaris-negative-vectors/ (see the README there). The SHA-256
 * of both files is checked below, and nothing is read from the network.
 *
 * What is asserted is read from each vector's own `class` and `layer`:
 * - `control`: accepted;
 * - `spec` and `spec-implied`: refused, with the reason this library gives;
 * - `policy`: skipped. No sentence requires the refusal, so the verdict is the
 *   relying party's choice;
 * - layer `status-list` (Token Status List): left out.
 */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

import {
    buildOpenID4VPDCAPIHandoverSessionTranscript,
    buildOpenID4VPHandoverSessionTranscript,
} from '../src/crypto/session-transcript.js';
import { StaticTrustStore } from '../src/trust/TrustStore.js';
import type { VerifyResult } from '../src/types/verify.js';
import { verifyPresentation } from '../src/verify.js';

const FIXTURES = new URL('./fixtures/polaris-negative-vectors/', import.meta.url);
const SHA256 = {
    'vectors.json': '9c95fd6d678936f05fe9eb6ab12d014cc807d96bdd28bb2ad5fdba151202257a',
    'mdoc-vectors.json': '2525e629f92adad0a4a44649f7868eb9ecab84bc60135a126862f118a28857de',
};

/** Layers this suite leaves out, whatever a vector's class. */
const LAYERS_LEFT_OUT = ['status-list'];

interface Vector {
    id: string;
    class: 'control' | 'spec' | 'spec-implied' | 'policy';
    layer: string;
    expected: 'accept' | 'reject';
    changed: string;
}

function load<V extends Vector, S>(name: keyof typeof SHA256): { settings: S; vectors: V[]; sha256: string } {
    const bytes = readFileSync(new URL(name, FIXTURES));
    const file = JSON.parse(bytes.toString('utf8')) as { settings: S; vectors: V[] };
    return { ...file, sha256: createHash('sha256').update(bytes).digest('hex') };
}

function split<V extends Vector>(vectors: V[]) {
    const judged = vectors.filter((vector) => !LAYERS_LEFT_OUT.includes(vector.layer));
    return {
        leftOut: vectors.filter((vector) => LAYERS_LEFT_OUT.includes(vector.layer)),
        controls: judged.filter((vector) => vector.class === 'control'),
        mustRefuse: judged.filter((vector) => vector.class === 'spec' || vector.class === 'spec-implied'),
        policy: judged.filter((vector) => vector.class === 'policy'),
    };
}

/** Why a presentation was refused, in this library's words; `undefined` when it was accepted. */
async function refusal(verify: () => Promise<VerifyResult>): Promise<string | undefined> {
    try {
        const result = await verify();
        if (result.valid) return undefined;
        return result.parsed.error ?? `dcql: ${result.match.unmatched.map((entry) => entry.reason).join(', ')}`;
    } catch (error) {
        return `${(error as Error).name}: ${(error as Error).message}`;
    }
}

// Every vector is signed for one instant, which the SD-JWT file states once and the mdoc file on each vector.
beforeAll(() => {
    vi.useFakeTimers({ toFake: ['Date'] });
});
afterAll(() => {
    vi.useRealTimers();
});

describe('Polaris negative vectors: SD-JWT VC presentations', () => {
    interface SdJwtVector extends Vector {
        trust: 'x5c' | 'jwks';
        presentation: string;
        repaired?: { presentation: string };
    }
    interface Settings {
        now: number;
        nonce: string;
        audience: string;
        vct: string;
        trust_anchors_pem: string[];
        issuer_jwks: JsonWebKey[];
    }
    const { settings, vectors, sha256 } = load<SdJwtVector, Settings>('vectors.json');
    const { leftOut, controls, mustRefuse, policy } = split(vectors);

    // The reason each `spec` and `spec-implied` vector is refused with.
    const reasons: Record<string, string> = {
        'issuer-crit': 'Issuer JWT signature verification failed',
        'kb-crit': 'Key binding JWT signature verification failed',
        'kb-aud-array': 'Key binding JWT aud must be a single string',
        'kb-aud-no-prefix': 'Key binding JWT aud does not match the expected audience',
        'digest-twice': 'A disclosure digest appears more than once in the SD-JWT',
        'claim-overwrite': 'Disclosure claim name given_name already exists at its level (RFC 9901 §7.1)',
        'disclosed-exp': 'Claim exp MUST NOT be selectively disclosed (SD-JWT VC §2.2.2.3)',
        'disclosed-iss': 'Claim iss MUST NOT be selectively disclosed (SD-JWT VC §2.2.2.3)',
        'disclosure-four-elements': 'Disclosure must be a 2- or 3-element array',
        'disclosure-named-sd': 'Disclosure claim name _sd is reserved (RFC 9901 §7.1)',
        'kb-typ-jwt': "Unsupported KB-JWT typ: JWT (expected 'kb+jwt')",
        'kb-alg-none': 'Unsupported KB-JWT algorithm: none',
        'kb-alg-hs256': 'Unsupported KB-JWT algorithm: HS256',
        'kb-iat-nan': 'Key binding JWT signature verification failed',
        'kb-exp-string': 'Key binding JWT claim validation failed: "exp" claim must be a number',
        'issuer-sig-der': 'Issuer JWT signature verification failed',
        'x5c-self-signed': 'TrustAnchorNotFoundError: no trust anchor for issuer=CN=Negative Vectors Test Issuer',
        'x5c-includes-anchor': 'x5c must not include the trust anchor certificate (HAIP 1.0 §6.1.1)',
        'x5c-unknown-root': 'TrustAnchorNotFoundError: no trust anchor for issuer=CN=Negative Vectors Unknown Root',
        'x5c-leaf-expired':
            'CertificateChainError: certificate CN=Negative Vectors Test Issuer expired (notAfter=2026-06-01T00:00:00.000Z)',
        'x5c-intermediate-not-ca':
            'CertificateChainError: certificate CN=Negative Vectors Test Intermediate is not a CA (BasicConstraints cA=false or absent)',
        'kb-aud-missing': 'Key binding JWT claim validation failed: missing required "aud" claim',
        'kb-nonce-missing': 'Key binding JWT claim validation failed: missing required "nonce" claim',
        'disclosure-unreferenced': 'Disclosure hash mismatch',
    };

    const query = {
        credentials: [
            {
                id: 'pid',
                format: 'dc+sd-jwt',
                meta: { vct_values: [settings.vct] },
                claims: [{ path: ['given_name'] }, { path: ['family_name'] }, { path: ['birthdate'] }],
            },
        ],
    };

    const verify = (vector: SdJwtVector, presentation: string): Promise<VerifyResult> => {
        vi.setSystemTime(new Date(settings.now * 1000));
        return verifyPresentation(presentation, query, {
            nonce: settings.nonce,
            audience: settings.audience,
            ...(vector.trust === 'jwks'
                ? { trustedIssuerJwks: settings.issuer_jwks }
                : { trustStore: new StaticTrustStore(settings.trust_anchors_pem) }),
        });
    };

    it('reads the pinned file: 2 controls, 24 vectors to refuse each with its repaired twin, 3 policy, 8 left out', () => {
        expect(sha256).toBe(SHA256['vectors.json']);
        expect(vectors).toHaveLength(37);
        expect(controls).toHaveLength(2);
        expect(mustRefuse).toHaveLength(24);
        expect(mustRefuse.filter((vector) => vector.repaired !== undefined)).toHaveLength(24);
        expect(policy).toHaveLength(3);
        expect(leftOut).toHaveLength(8);
        expect(mustRefuse.map((vector) => vector.id).sort()).toEqual(Object.keys(reasons).sort());
    });

    it.each(controls)('accepts the control $id', async (vector) => {
        expect(vector.expected).toBe('accept');
        expect(await refusal(() => verify(vector, vector.presentation))).toBeUndefined();
    });

    it.each(mustRefuse)('refuses $id ($layer, $class)', async (vector) => {
        expect(vector.expected).toBe('reject');
        const reason = await refusal(() => verify(vector, vector.presentation));
        expect(reason, `${vector.id} was accepted`).toBeDefined();
        expect(reason).toBe(reasons[vector.id]);
    });

    it.each(mustRefuse)('accepts the repaired twin of $id', async (vector) => {
        const repaired = vector.repaired as NonNullable<SdJwtVector['repaired']>;
        expect(await refusal(() => verify(vector, repaired.presentation))).toBeUndefined();
    });

    it.skip.each(policy)('policy, the relying party decides: $id ($changed)', () => {});
});

describe('Polaris negative vectors: mdoc DeviceResponses', () => {
    interface Inputs {
        response_mode: 'direct_post.jwt' | 'dc_api.jwt';
        nonce: string;
        client_id?: string;
        response_uri?: string;
        origin?: string;
        encryption_jwk: JsonWebKey;
        doctype_value: string;
        claims?: Array<{ id?: string; path: string[]; values?: string[] }>;
        claim_sets?: string[][];
    }
    interface MdocVector extends Vector {
        at: string;
        trust_anchors_pem: string[];
        inputs: Inputs;
        response: string;
        repaired?: { response: string; inputs: Inputs };
    }
    const { vectors, sha256 } = load<MdocVector, unknown>('mdoc-vectors.json');
    const { leftOut, controls, mustRefuse, policy } = split(vectors);

    // The reason each `spec` and `spec-implied` vector is refused with.
    const reasons: Record<string, string> = {
        'md-st-nonce': 'mDOC device authentication (DeviceSignature) failed to verify',
        'md-st-client-id-other': 'mDOC device authentication (DeviceSignature) failed to verify',
        'md-st-client-id-no-prefix': 'mDOC device authentication (DeviceSignature) failed to verify',
        'md-st-response-uri': 'mDOC device authentication (DeviceSignature) failed to verify',
        'md-st-thumbprint-other-key': 'mDOC device authentication (DeviceSignature) failed to verify',
        'md-st-thumbprint-absent': 'mDOC device authentication (DeviceSignature) failed to verify',
        'md-st-dcapi-handover-on-redirect': 'mDOC device authentication (DeviceSignature) failed to verify',
        'md-st-redirect-handover-on-dcapi': 'mDOC device authentication (DeviceSignature) failed to verify',
        'md-st-dcapi-origin-prefixed': 'mDOC device authentication (DeviceSignature) failed to verify',
        'md-st-dcapi-origin-other': 'mDOC device authentication (DeviceSignature) failed to verify',
        'md-devicesig-other-key': 'mDOC device authentication (DeviceSignature) failed to verify',
        'md-devicesig-missing': 'deviceAuth.deviceSignature must be a COSE_Sign1 array',
        'md-devicesig-not-detached': 'DeviceSignature payload must be detached (nil)',
        'md-devicesig-doctype-other': 'mDOC device authentication (DeviceSignature) failed to verify',
        'md-devicesigned-unauthorized-ns':
            'device-signed element org.example.device/device_note is not covered by the MSO KeyAuthorizations',
        'md-devicekey-kty-crv': 'Unsupported COSE key type for device key: 1',
        'md-doctype-not-requested': 'dcql: doctype_mismatch',
        'md-issuerauth-sig-flipped': 'COSE_Sign1 signature verification failed',
        'md-issuerauth-sig-der': 'COSE_Sign1 signature verification failed',
        'md-issuerauth-crit-unknown':
            'MalformedCredentialError: COSE_Sign1 protected header crit lists label -65537, which is not understood (RFC 9052 §3.1)',
        'md-issuerauth-dup-label':
            'MalformedCredentialError: COSE_Sign1 protected header repeats label 1 (RFC 9052 §3)',
        'md-mso-not-tag24':
            'MalformedCredentialError: IssuerAuth payload must be MobileSecurityObjectBytes (tag 24 wrapping the MSO)',
        'md-digest-value-modified': 'MalformedCredentialError: digest mismatch for ns=org.iso.18013.5.1 digestID=0',
        'md-digest-reencoded-item': 'MalformedCredentialError: digest mismatch for ns=org.iso.18013.5.1 digestID=0',
        'md-digest-id-absent':
            'MalformedCredentialError: digestID 2 missing from MSO valueDigests[org.iso.18013.5.1]',
        'md-digest-alg-sha1': 'MalformedCredentialError: Unknown digest algorithm: SHA-1',
        'md-digest-length': 'MalformedCredentialError: digest mismatch for ns=org.iso.18013.5.1 digestID=0',
        'md-doctype-vs-mso':
            'MalformedCredentialError: document.docType=org.iso.18013.5.1.mDL does not match MSO docType=eu.europa.ec.eudi.pid.1 (ISO/IEC 18013-5 §9.3.1)',
        'md-sd-claim-absent': 'dcql: missing_claims',
        'md-sd-claim-sets-unmet': 'dcql: missing_claims',
    };

    // The verifier builds the SessionTranscript from its own request (`inputs`), never from the response.
    const sessionTranscript = (inputs: Inputs): Promise<Uint8Array> =>
        inputs.response_mode === 'dc_api.jwt'
            ? buildOpenID4VPDCAPIHandoverSessionTranscript({
                  origin: inputs.origin as string,
                  nonce: inputs.nonce,
                  verifierEncryptionJwk: inputs.encryption_jwk,
              })
            : buildOpenID4VPHandoverSessionTranscript({
                  clientId: inputs.client_id as string,
                  nonce: inputs.nonce,
                  responseUri: inputs.response_uri as string,
                  verifierEncryptionJwk: inputs.encryption_jwk,
              });

    const verify = async (vector: MdocVector, response: string, inputs: Inputs): Promise<VerifyResult> => {
        vi.setSystemTime(new Date(vector.at));
        const credential = {
            id: 'mdl',
            format: 'mso_mdoc',
            meta: { doctype_value: inputs.doctype_value },
            ...(inputs.claims ? { claims: inputs.claims } : {}),
            ...(inputs.claim_sets ? { claim_sets: inputs.claim_sets } : {}),
        };
        return verifyPresentation(
            new Uint8Array(Buffer.from(response, 'base64url')),
            { credentials: [credential] },
            {
                nonce: inputs.nonce,
                mdocSessionTranscript: await sessionTranscript(inputs),
                trustStore: new StaticTrustStore(vector.trust_anchors_pem),
            }
        );
    };

    it('reads the pinned file: 2 controls, 30 vectors to refuse each with its repaired twin, 2 policy vectors', () => {
        expect(sha256).toBe(SHA256['mdoc-vectors.json']);
        expect(vectors).toHaveLength(34);
        expect(controls).toHaveLength(2);
        expect(mustRefuse).toHaveLength(30);
        expect(mustRefuse.filter((vector) => vector.repaired !== undefined)).toHaveLength(30);
        expect(policy).toHaveLength(2);
        expect(leftOut).toHaveLength(0);
        expect(mustRefuse.map((vector) => vector.id).sort()).toEqual(Object.keys(reasons).sort());
    });

    it.each(controls)('accepts the control $id', async (vector) => {
        expect(vector.expected).toBe('accept');
        expect(await refusal(() => verify(vector, vector.response, vector.inputs))).toBeUndefined();
    });

    it.each(mustRefuse)('refuses $id ($layer, $class)', async (vector) => {
        expect(vector.expected).toBe('reject');
        const reason = await refusal(() => verify(vector, vector.response, vector.inputs));
        expect(reason, `${vector.id} was accepted`).toBeDefined();
        expect(reason).toBe(reasons[vector.id]);
    });

    it.each(mustRefuse)('accepts the repaired twin of $id', async (vector) => {
        const repaired = vector.repaired as NonNullable<MdocVector['repaired']>;
        expect(await refusal(() => verify(vector, repaired.response, repaired.inputs))).toBeUndefined();
    });

    it.skip.each(policy)('policy, the relying party decides: $id ($changed)', () => {});
});
