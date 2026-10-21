import type { DcqlQuery } from '@openeudi/dcql';

import type { CredentialStatusResult, StatusPolicy } from '../status/credential-status.js';
import type { StatusListResolver } from '../status/StatusListResolver.js';
import type { Cache } from '../trust/Cache.js';
import type { Fetcher } from '../trust/Fetcher.js';
import type { TrustEvaluationResult } from '../trust/TrustEvaluator.js';
import type { TrustStore } from '../trust/TrustStore.js';
import type { IssuerInfo } from '../types/issuer.js';

export interface AvAuthorizationRequestInput {
    /**
     * Absolute `https:` URL the AV app POSTs the response to. The `client_id`
     * is derived from it (`redirect_uri:<responseUri>`), as Annex A §A.6
     * requires.
     */
    responseUri: string;
    /**
     * Request nonce. Generated (256 bits, base64url) when omitted. A supplied
     * nonce must be at least 22 characters of the URL-safe set `[A-Za-z0-9._~-]`.
     */
    nonce?: string;
    /** Optional `state` (Annex A §A.6: "optional"). Not generated when omitted. */
    state?: string;
    /** Age threshold NN of the requested `age_over_NN`. Default 18. */
    ageThreshold?: number;
    /**
     * Where the request is sent. Default `av://` (Annex A §A.6). An `https:`
     * universal / app link of an AV app is also accepted. The query string is
     * appended to it.
     */
    baseUri?: string;
    /** DCQL credential query id. Default `proof_of_age`. */
    credentialId?: string;
    /**
     * `client_metadata.vp_formats_supported`. Default
     * `{ mso_mdoc: { issuerauth_alg_values: [-7, -35, -36], deviceauth_alg_values: [-7, -35, -36] } }`
     * (ES256/ES384/ES512, as the AV reference verifier advertises). `null`
     * omits `client_metadata`, like the Annex A §A.11 example.
     */
    vpFormatsSupported?: Record<string, unknown> | null;
}

/** The request plus every value `verifyAvPresentation` needs. Persist it server-side. */
export interface AvAuthorizationRequest {
    /** The request URL (`av://?response_type=vp_token&…`) to open, link or render as a QR code. */
    uri: string;
    /** `redirect_uri:<responseUri>` — bound into the mdoc SessionTranscript. */
    clientId: string;
    responseUri: string;
    nonce: string;
    state?: string;
    ageThreshold: number;
    /** The requested element identifier, e.g. `age_over_18`. */
    ageOverAttribute: string;
    credentialId: string;
    dcqlQuery: DcqlQuery;
    /** The `client_metadata` object sent in the request; absent when `vpFormatsSupported: null`. */
    clientMetadata?: Record<string, unknown>;
}

/** What `verifyAvPresentation` needs from the request it answers. */
export type AvVerificationContext = Pick<AvAuthorizationRequest, 'responseUri' | 'nonce'> &
    Partial<Pick<AvAuthorizationRequest, 'clientId' | 'state' | 'ageThreshold' | 'credentialId'>>;

/**
 * The AV app's `direct_post` body: the raw `application/x-www-form-urlencoded`
 * string, a `URLSearchParams`, or an already-parsed object (e.g. Express
 * `req.body`). `vp_token` may be the JSON string from the form or an object.
 */
export type AvAuthorizationResponseInput = string | URLSearchParams | Record<string, unknown>;

export interface VerifyAvPresentationOptions {
    /** The persisted request (`createAvAuthorizationRequest` result or the {@link AvVerificationContext} subset). */
    request: AvVerificationContext;
    /**
     * Trust anchors of authorised Proof of Age Attestation Providers — the
     * Commission's AV trusted list. Keep it separate from PID-provider anchors:
     * a PID provider is not authorised to issue Proof of Age attestations.
     */
    trustStore: TrustStore;
    /**
     * Document Signer EKUs accepted when the chain is built to a CA anchor.
     * Default `['1.3.130.2.0.0.1.2', '1.0.18013.5.1.2']` (AV reference issuer, ISO 18013-5).
     */
    documentSignerEkus?: readonly string[];
    /** Allowed COSE algorithms. Default `['ES256', 'ES384', 'ES512']`. */
    allowedAlgorithms?: string[];
    /** Default `'skip'` (AV specification §3.4.3: "Attestation revocation is not required"). */
    revocationPolicy?: 'skip' | 'prefer' | 'require';
    fetcher?: Fetcher;
    cache?: Cache;
    /** Seconds, for certificate validity. Default 60. */
    clockSkewTolerance?: number;
    /**
     * How the attestation's MSO `status` (Token Status List, `statuslist+cwt`)
     * is checked. Default `'skip'`: Proof of Age attestations are short-lived
     * and normally carry no `status` (AV specification §3.4.3). Under
     * `'prefer'` / `'require'` an attestation without `status` still verifies
     * (`credentialStatus.outcome: 'absent'`); one with a `status` is checked
     * as on every other mdoc path. Requires {@link statusListResolver}.
     */
    statusPolicy?: StatusPolicy;
    /** Resolver for Status List Tokens; give it the status-list signer anchors. */
    statusListResolver?: StatusListResolver;
}

export type AvVerificationFailure =
    /** Signature, digest, device authentication (nonce / transcript), validity or algorithm check failed. */
    | 'invalid_credential'
    /** DeviceResponse is not exactly one `eu.europa.ec.av.1` document with status 0. */
    | 'wrong_doctype'
    | 'malformed_credential'
    /** A namespace other than `eu.europa.ec.av.1`, or an element other than `age_over_NN`. */
    | 'unexpected_attribute'
    /** An `age_over_NN` element whose value is not a boolean. */
    | 'invalid_attribute_value'
    /** The requested `age_over_NN` was not disclosed. */
    | 'missing_attribute'
    /** `deviceSigned.nameSpaces` is not empty. */
    | 'device_signed_elements'
    /**
     * The MSO `status` names a non-VALID status, an out-of-range index, or is
     * malformed (only under `statusPolicy` `'prefer'` / `'require'`).
     */
    | 'credential_status';

export interface AvVerificationResult {
    /** The presentation is a valid, trusted, device-bound Proof of Age attestation that discloses the requested attribute. */
    valid: boolean;
    /**
     * `valid && ageOver === true` — the one flag to gate access on. A valid
     * presentation can still prove the holder is NOT over the threshold.
     */
    ageVerified: boolean;
    /** Value of the requested `age_over_NN`; `undefined` unless `valid`. */
    ageOver: boolean | undefined;
    ageThreshold: number;
    ageOverAttribute: string;
    issuer: IssuerInfo;
    /** Validated chain and matched anchor. Present when `valid`. */
    trust?: TrustEvaluationResult;
    /** `state` echoed by the wallet, if any. */
    state?: string;
    /** Token Status List outcome; set when `statusPolicy` is `'prefer'` or `'require'` and the check ran. */
    credentialStatus?: CredentialStatusResult;
    failure?: AvVerificationFailure;
    error?: string;
}
