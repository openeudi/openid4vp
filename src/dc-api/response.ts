import { Encoder as CborEncoder } from 'cbor-x';
import type { DcqlQuery } from '@openeudi/dcql';

import { AV_DOCTYPE } from '../av/constants.js';
import { buildOpenID4VPDCAPIHandoverSessionTranscript } from '../crypto/session-transcript.js';
import { decryptAuthorizationResponse } from '../decrypt-response.js';
import {
    MissingDecryptionKeyError,
    MissingVerifierEncryptionKeyError,
    MultipleCredentialsNotSupportedError,
    PerCredentialOptionsError,
} from '../errors.js';
import { validatePerCredentialOptions } from '../per-credential.js';
import { verifyAuthorizationResponse, verifyPresentation } from '../verify.js';
import type { VerifyResult } from '../types/verify.js';
import { isoMdocResponseData, parseDcApiData, throwIfDcApiWalletError } from './data.js';
import { DcApiResponseError } from './errors.js';
import { openIsoMdocResponse } from './iso-mdoc.js';
import {
    describeUnsupportedProtocol,
    isSecureSerializedOrigin,
    isSupportedDcApiProtocol,
} from './protocols.js';
import type { DcApiResponse, VerifyDcApiIsoMdocResponseOptions, VerifyDcApiResponseOptions } from './types.js';

const cborDecoder = new CborEncoder({ mapsAsObjects: false, useRecords: false });

/**
 * Verify the response to an OpenID4VP request made over the W3C Digital
 * Credentials API (OpenID4VP 1.0 Appendix A.4).
 *
 * `response` is the `{ protocol, data }` of the `DigitalCredential` the
 * browser resolved with. The checks, in order:
 *
 * 1. `protocol` is `openid4vp-v1-unsigned` or `openid4vp-v1-signed` (and equals
 *    `options.protocol` when set).
 * 2. `data` is not a wallet error (`{ error }` → {@link WalletErrorResponseError}).
 * 3. The envelope matches `options.responseMode` (default `dc_api.jwt`): a JWE
 *    `{ response }` for `dc_api.jwt`, a plain `{ vp_token }` for `dc_api`. An
 *    unencrypted response to a `dc_api.jwt` request is rejected.
 * 4. The presentation is verified with the origin as the audience: SD-JWT
 *    KB-JWT `aud` MUST be `origin:<origin>` (§A.4, also for signed requests,
 *    §B.3.6), and an mdoc's device signature MUST cover the
 *    `OpenID4VPDCAPIHandover` SessionTranscript (§B.2.6.2).
 *
 * There is no `state` over the DC API (§A.2); bind the response to the
 * server-side session through the `nonce` instead.
 *
 * `options.perCredential` selects the trust and status options per DCQL
 * credential query, exactly as on `verifyAuthorizationResponse` (OpenID4VP
 * protocols only; refused with `org-iso-mdoc`).
 *
 * With `options.protocol: 'org-iso-mdoc'` (ISO/IEC 18013-7 Annex C), the
 * response must be `org-iso-mdoc`, and:
 *
 * 1. `data` is exactly `{ response }`, a base64url `EncryptedResponse`, and
 *    not a wallet error.
 * 2. HPKE (base mode, DHKEM P-256 / HKDF-SHA256 / AES-128-GCM, empty aad)
 *    opens it with `decryptionKey`; the HPKE `info` is the Annex C
 *    SessionTranscript over the stored `encryptionInfo` and `origin`
 *    (`buildDCAPIHandoverSessionTranscript`).
 * 3. The `DeviceResponse` has status 0 and exactly one document, which is not
 *    an `eu.europa.ec.av.1` attestation (`av_profile_required`: use
 *    `verifyAvDcApiResponse`).
 * 4. The document is verified as on every mdoc path, with its device
 *    signature over that SessionTranscript, and matched against `query`.
 */
export async function verifyDcApiResponse(
    response: DcApiResponse,
    query: DcqlQuery,
    options: VerifyDcApiResponseOptions | VerifyDcApiIsoMdocResponseOptions,
): Promise<VerifyResult> {
    if (options.protocol === 'org-iso-mdoc') {
        // perCredential selects trust per OpenID4VP vp_token key; an Annex C
        // response has none. Refuse it rather than verify with other trust.
        if ((options as { perCredential?: unknown }).perCredential !== undefined) {
            throw new PerCredentialOptionsError(
                'invalid_per_credential_options',
                'perCredential applies to the openid4vp-v1-* protocols only, not org-iso-mdoc',
            );
        }
        return verifyIsoMdocDcApiResponse(response, query, options);
    }
    validatePerCredentialOptions(query, options.perCredential);
    const {
        origin,
        responseMode: requestedResponseMode,
        protocol: expectedProtocol,
        decryptionKey,
        verifierEncryptionJwk,
        ...parseOptions
    } = options;
    const responseMode = requestedResponseMode ?? 'dc_api.jwt';

    if (!isSecureSerializedOrigin(origin)) {
        throw new DcApiResponseError(
            'invalid_origin',
            `origin "${String(origin)}" is not a serialized https origin (scheme://host[:port], no path or trailing slash, no "origin:" prefix)`,
        );
    }
    const audience = `origin:${origin}`;
    const callerAudience = (options as { audience?: unknown }).audience;
    if (callerAudience !== undefined && callerAudience !== audience) {
        throw new DcApiResponseError(
            'audience_conflict',
            `audience is derived from origin over the DC API ("${audience}"); do not pass a different audience`,
        );
    }

    if (typeof response !== 'object' || response === null) {
        throw new DcApiResponseError('malformed_response', 'DC API response must be an object with protocol and data');
    }
    if (!isSupportedDcApiProtocol(response.protocol)) {
        throw new DcApiResponseError('unsupported_protocol', describeUnsupportedProtocol(response.protocol));
    }
    if (response.protocol === 'org-iso-mdoc') {
        throw new DcApiResponseError(
            'protocol_mismatch',
            'an org-iso-mdoc response needs the org-iso-mdoc options (protocol: "org-iso-mdoc", encryptionInfo, decryptionKey)',
        );
    }
    if (expectedProtocol !== undefined && response.protocol !== expectedProtocol) {
        throw new DcApiResponseError(
            'protocol_mismatch',
            `response protocol "${response.protocol}" does not match the requested "${expectedProtocol}"`,
        );
    }

    const data = parseDcApiData(response.data);
    throwIfDcApiWalletError(data);

    let envelope: Record<string, unknown>;
    if (responseMode === 'dc_api.jwt') {
        if (!isJweEnvelope(data)) {
            throw new DcApiResponseError(
                'vp_token' in data ? 'unencrypted_response' : 'malformed_response',
                'dc_api.jwt was requested, so data must be exactly { response: "<JWE>" }',
            );
        }
        if (!decryptionKey) {
            throw new MissingDecryptionKeyError('decryptionKey is required to verify a dc_api.jwt response');
        }
        envelope = (await decryptAuthorizationResponse(data.response, decryptionKey)) as Record<string, unknown>;
        if (typeof envelope !== 'object' || envelope === null || Array.isArray(envelope)) {
            throw new DcApiResponseError('malformed_response', 'decrypted dc_api.jwt payload is not a JSON object');
        }
        throwIfDcApiWalletError(envelope);
    } else if (responseMode === 'dc_api') {
        if ('response' in data) {
            throw new DcApiResponseError(
                'unexpected_encrypted_response',
                'dc_api was requested, but data carries an encrypted "response"',
            );
        }
        envelope = data;
    } else {
        throw new DcApiResponseError(
            'malformed_response',
            `responseMode must be "dc_api" or "dc_api.jwt", got "${String(responseMode)}"`,
        );
    }

    const vpToken = envelope.vp_token;
    if (typeof vpToken !== 'object' || vpToken === null || Array.isArray(vpToken)) {
        throw new DcApiResponseError('malformed_response', 'response must contain vp_token as a JSON object (OpenID4VP 1.0 §8.1)');
    }

    let mdocSessionTranscript = parseOptions.mdocSessionTranscript;
    if (mdocSessionTranscript === undefined && presentsMdoc(vpToken, query)) {
        // dc_api.jwt binds the encryption key's thumbprint into the transcript;
        // without the public JWK the device signature cannot be checked, so
        // say so instead of failing later as an opaque device-auth error.
        if (responseMode === 'dc_api.jwt' && verifierEncryptionJwk === undefined) {
            throw new MissingVerifierEncryptionKeyError(
                'verifierEncryptionJwk is required to build the OpenID4VPDCAPIHandover SessionTranscript for a dc_api.jwt mso_mdoc response',
            );
        }
        mdocSessionTranscript = await buildOpenID4VPDCAPIHandoverSessionTranscript({
            origin,
            nonce: parseOptions.nonce,
            verifierEncryptionJwk: responseMode === 'dc_api.jwt' ? verifierEncryptionJwk : undefined,
        });
    }

    return verifyAuthorizationResponse({ vp_token: vpToken as Record<string, Array<string | object>> }, query, {
        ...parseOptions,
        audience,
        requireKeyBinding: parseOptions.requireKeyBinding ?? true,
        mdocSessionTranscript,
    });
}

/**
 * ISO/IEC 18013-7 Annex C: open the HPKE `EncryptedResponse` with the stored
 * recipient key and the `dcapi` SessionTranscript over the stored
 * `encryptionInfo` and the caller's origin, then verify the `DeviceResponse`
 * like any other mdoc presentation (issuer signature, digests, validity,
 * trust, device signature over that transcript) and match it against the DCQL
 * query the request was built from.
 */
async function verifyIsoMdocDcApiResponse(
    response: DcApiResponse,
    query: DcqlQuery,
    options: VerifyDcApiIsoMdocResponseOptions,
): Promise<VerifyResult> {
    const { origin, encryptionInfo, decryptionKey, nonce, protocol: _protocol, ...parseOptions } = options;
    if (!isSecureSerializedOrigin(origin)) {
        throw new DcApiResponseError(
            'invalid_origin',
            `origin "${String(origin)}" is not a serialized https origin (scheme://host[:port], no path or trailing slash, no "origin:" prefix)`,
        );
    }
    const data = isoMdocResponseData(response);
    const opened = await openIsoMdocResponse(data, { origin, encryptionInfo, decryptionKey, nonce });
    checkSingleNonAvDocument(opened.deviceResponse);

    return verifyPresentation(opened.deviceResponse, query, {
        ...parseOptions,
        nonce: opened.nonce,
        mdocSessionTranscript: opened.sessionTranscript,
    });
}

/**
 * The `DeviceResponse` checks the generic mdoc parser leaves out: status 0,
 * exactly one document (the parser reads only the first), and no Proof of Age
 * attestation, whose data-model checks only `verifyAvDcApiResponse` applies.
 */
function checkSingleNonAvDocument(bytes: Uint8Array): void {
    let deviceResponse: unknown;
    try {
        deviceResponse = cborDecoder.decode(bytes);
    } catch (err) {
        throw new DcApiResponseError('malformed_response', 'decrypted org-iso-mdoc payload is not CBOR', {
            cause: err as Error,
        });
    }
    if (!(deviceResponse instanceof Map)) {
        throw new DcApiResponseError('malformed_response', 'decrypted org-iso-mdoc payload is not a DeviceResponse map');
    }
    const status = deviceResponse.get('status');
    if (status !== undefined && status !== 0) {
        throw new DcApiResponseError('device_response_error', `DeviceResponse status is ${String(status)}, expected 0`);
    }
    const documents = deviceResponse.get('documents');
    if (!Array.isArray(documents) || documents.length === 0) {
        throw new DcApiResponseError('malformed_response', 'DeviceResponse has no documents');
    }
    if (documents.length > 1) {
        throw new MultipleCredentialsNotSupportedError(1, documents.length);
    }
    const document = documents[0];
    if (document instanceof Map && document.get('docType') === AV_DOCTYPE) {
        throw new DcApiResponseError(
            'av_profile_required',
            `${AV_DOCTYPE} must be verified with verifyAvDcApiResponse, which applies the AV profile checks`,
        );
    }
}

function isJweEnvelope(data: Record<string, unknown>): data is { response: string } {
    return typeof data.response === 'string' && Object.keys(data).length === 1;
}

function presentsMdoc(vpToken: object, query: DcqlQuery): boolean {
    return Object.keys(vpToken).some(
        (id) => query.credentials.find((c) => c.id === id)?.format === 'mso_mdoc',
    );
}
