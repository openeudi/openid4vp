import { isoMdocResponseData } from '../dc-api/data.js';
import { DcApiRequestBuildError, DcApiResponseError } from '../dc-api/errors.js';
import { buildIsoMdocRequest, openIsoMdocResponse } from '../dc-api/iso-mdoc.js';
import { isSecureSerializedOrigin } from '../dc-api/protocols.js';
import type { DcApiResponse } from '../dc-api/types.js';
import { AV_DEFAULT_AGE_THRESHOLD, AV_DOCTYPE, AV_NAMESPACE, avAgeOverAttribute } from './constants.js';
import { AvRequestBuildError, AvResponseError } from './errors.js';
import type { AvDcApiRequest, AvDcApiRequestInput, AvVerificationResult, VerifyAvDcApiResponseOptions } from './types.js';
import { verifyAvDeviceResponse } from './verify.js';

/**
 * Build the EU Age Verification request for the W3C Digital Credentials API —
 * the profile's default transport (AV Annex A §A.6, "The W3C Digital
 * Credentials API is used as specified in [ISO/IEC 18013-7], Annex C").
 *
 * - `protocol: 'org-iso-mdoc'`, the only DC API protocol the AV apps accept.
 * - `deviceRequest`: an ISO 18013-5 `DeviceRequest` 1.0 for docType
 *   `eu.europa.ec.av.1`, element `age_over_NN` (default 18) with
 *   `intentToRetain: false` — byte-identical to the Annex A §A.11 example.
 * - No reader authentication ("Reader authentication is not required") and no
 *   `zkRequest`: both AV apps then answer with a plain mdoc.
 * - `encryptionInfo`: the nonce and a fresh ephemeral P-256 recipient key.
 *
 * Persist the result (or at least `encryptionInfo`, `recipientPrivateJwk` and
 * `ageThreshold`) together with the page origin, and hand them to
 * {@link verifyAvDcApiResponse}. Use each request once.
 */
export async function createAvDcApiRequest(input: AvDcApiRequestInput = {}): Promise<AvDcApiRequest> {
    const ageThreshold = input.ageThreshold ?? AV_DEFAULT_AGE_THRESHOLD;
    let ageOverAttribute: string;
    try {
        ageOverAttribute = avAgeOverAttribute(ageThreshold);
    } catch (err) {
        throw new AvRequestBuildError('invalid_age_threshold', (err as Error).message);
    }

    let built: Awaited<ReturnType<typeof buildIsoMdocRequest>>;
    try {
        built = await buildIsoMdocRequest(
            {
                docType: AV_DOCTYPE,
                nameSpaces: new Map([[AV_NAMESPACE, new Map([[ageOverAttribute, false]])]]),
            },
            input.nonce,
        );
    } catch (err) {
        if (err instanceof DcApiRequestBuildError && err.code === 'invalid_nonce') {
            throw new AvRequestBuildError('invalid_nonce', err.message);
        }
        throw err;
    }
    return { ...built, ageThreshold, ageOverAttribute };
}

/**
 * Verify the AV app's answer to {@link createAvDcApiRequest}: an `org-iso-mdoc`
 * credential whose `data.response` is an HPKE-encrypted ISO mdoc
 * `DeviceResponse` (ISO/IEC 18013-7 Annex C).
 *
 * Checks, in order:
 * 1. `protocol` is `org-iso-mdoc`; `data` is not a wallet error object
 *    (`WalletErrorResponseError`).
 * 2. HPKE (DHKEM P-256 / HKDF-SHA256 / AES-128-GCM, base mode) opens the
 *    response with the stored recipient key. The HPKE `info` is the Annex C
 *    SessionTranscript `[null, null, ["dcapi", sha256(cbor([encryptionInfo, origin]))]]`
 *    over the stored `encryptionInfo` and `options.origin`, so a response the
 *    browser bound to another origin, or made for another request, fails here
 *    (`DecryptionFailedError`).
 * 3. The same AV checks as {@link verifyAvPresentation} on the redirect path:
 *    exactly one `eu.europa.ec.av.1` document, only boolean `age_over_NN`
 *    elements, no device-signed elements, issuer signature, digests, MSO
 *    validity and docType, issuer chain against `trustStore` with the AV
 *    Document Signer EKUs, device authentication over that SessionTranscript,
 *    optional status, and the requested `age_over_NN` disclosed.
 *
 * Credential failures return `{ valid: false, failure, error }`. Gate access
 * on `ageVerified`.
 */
export async function verifyAvDcApiResponse(
    response: DcApiResponse,
    options: VerifyAvDcApiResponseOptions,
): Promise<AvVerificationResult> {
    const { request, trustStore, origin, decryptionKey } = options;
    if (typeof request?.encryptionInfo !== 'string' || request.encryptionInfo.length === 0) {
        throw new AvResponseError('invalid_context', 'request.encryptionInfo is required');
    }
    if (!trustStore) {
        throw new AvResponseError('invalid_context', 'trustStore is required: pass the AV Attestation Provider anchors');
    }
    if (!decryptionKey) {
        throw new AvResponseError('invalid_context', 'decryptionKey is required: pass the stored recipientPrivateJwk');
    }
    if (!isSecureSerializedOrigin(origin)) {
        throw new DcApiResponseError(
            'invalid_origin',
            `origin "${String(origin)}" is not a serialized https origin (scheme://host[:port], no path or trailing slash)`,
        );
    }
    const ageThreshold = request.ageThreshold ?? AV_DEFAULT_AGE_THRESHOLD;
    avAgeOverAttribute(ageThreshold); // a bad threshold is a caller error: throw before decrypting

    const data = isoMdocResponseData(response);
    const opened = await openIsoMdocResponse(data, {
        origin,
        encryptionInfo: request.encryptionInfo,
        decryptionKey,
        nonce: request.nonce,
    });
    return verifyAvDeviceResponse(
        opened.deviceResponse,
        { sessionTranscript: opened.sessionTranscript, nonce: opened.nonce, ageThreshold },
        options,
    );
}
