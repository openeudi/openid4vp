// Load the reflect-metadata polyfill before any module that transitively pulls
// in @peculiar/x509 (→ tsyringe), which reads decorator metadata while its
// module body evaluates.
//
// Being first in this file is NOT sufficient for the published bundles — the
// bundler hoists external named imports above bare side-effect imports. The
// build therefore also injects this same module ahead of the entry; see
// `inject` in tsup.config.ts and tests/bundle-polyfill-order.test.ts.
import './reflect-polyfill';

export const VERSION = '0.15.0';

// Builders
export { createAuthorizationRequest } from './authorization.js';
export { createSignedAuthorizationRequest } from './signed-authorization.js';
export { registrarDatasetVerifierInfo, registrationCertVerifierInfo } from './verifier-info.js';
export {
    buildHaipQuery,
    validateHaipQuery,
    isHaipQuery,
    HAIP_DOCTYPE_NAMESPACES,
    buildCredentialSetQuery,
    validateCredentialSetQuery,
} from './haip.js';

// Parsers / verifiers
export { parsePresentation } from './presentation.js';
export { verifyPresentation, verifyAuthorizationResponse } from './verify.js';
export { decryptAuthorizationResponse } from './decrypt-response.js';
export {
    buildOid4vpSessionTranscript,
    buildOpenID4VPHandoverSessionTranscript,
    buildOpenID4VPDCAPIHandoverSessionTranscript,
} from './crypto/session-transcript.js';

// W3C Digital Credentials API (OpenID4VP 1.0 Appendix A)
export { createDcApiRequest } from './dc-api/request.js';
export { verifyDcApiResponse } from './dc-api/response.js';
export { DC_API_PRESENTATION_PROTOCOLS } from './dc-api/protocols.js';
export {
    DcApiRequestBuildError,
    DcApiResponseError,
    type DcApiRequestBuildErrorCode,
    type DcApiResponseErrorCode,
} from './dc-api/errors.js';
export type {
    DcApiPresentationProtocol,
    DcApiOpenId4VpProtocol,
} from './dc-api/protocols.js';
export type {
    DcApiResponseMode,
    DcApiRequestInput,
    DcApiUnsignedRequestInput,
    DcApiSignedRequestInput,
    DcApiCredentialRequest,
    DcApiRequest,
    DcApiResponse,
    VerifyDcApiResponseOptions,
} from './dc-api/types.js';
// EU Age Verification (AV app) profile — OpenID4VP fallback (AV Annex A §A.6)
export { createAvAuthorizationRequest } from './av/request.js';
export { verifyAvPresentation } from './av/verify.js';
export {
    AV_DOCTYPE,
    AV_NAMESPACE,
    AV_DEFAULT_BASE_URI,
    AV_DEFAULT_CREDENTIAL_ID,
    AV_DOCUMENT_SIGNER_EKU,
} from './av/constants.js';
export {
    AvRequestBuildError,
    AvResponseError,
    type AvRequestBuildErrorCode,
    type AvResponseErrorCode,
} from './av/errors.js';
export type {
    AvAuthorizationRequestInput,
    AvAuthorizationRequest,
    AvVerificationContext,
    AvAuthorizationResponseInput,
    VerifyAvPresentationOptions,
    AvVerificationFailure,
    AvVerificationResult,
} from './av/types.js';
export { SdJwtParser } from './parsers/sd-jwt.parser.js';
export { MdocParser } from './parsers/mdoc.parser.js';
export type { ICredentialParser, ParseOptions } from './parsers/parser.interface.js';

// Own errors
export {
    InvalidSignatureError,
    ExpiredCredentialError,
    UnsupportedFormatError,
    MalformedCredentialError,
    NonceValidationError,
    HaipValidationError,
} from './errors.js';
export type { HaipValidationCode } from './errors.js';

// Re-exports from @openeudi/dcql
export { DcqlValidationError, DcqlMatchError } from '@openeudi/dcql';
export type { DcqlValidationErrorCode } from '@openeudi/dcql';
export type { DcqlQuery, DcqlMatchResult, DcqlSubmission } from '@openeudi/dcql';

// Own types
export type {
    CredentialFormat,
    CredentialClaims,
    PresentationResult,
    IssuerInfo,
    AuthorizationRequestInput,
    AuthorizationRequest,
    SignedAuthorizationRequestInput,
    SignedAuthorizationRequest,
    AuthorizationResponse,
    EncryptedResponse,
    VerifyOptions,
    VerifyAuthorizationResponseOptions,
    SessionTranscriptProfile,
    VerifyResult,
    HaipQueryInput,
    CredentialSetQueryInput,
    VerifierInfo,
    RegistrarDataset,
    RegistrarIdentifier,
    RegistrarCredential,
    RegistrarClaim,
    MultiLangString,
} from './types/index.js';

// -------------------------------------------------------------------
// 0.5.0 trust module — public plug interfaces and implementations.
// TrustEvaluator, ChainBuilder, and EU_LOTL_SIGNING_ANCHORS are
// intentionally NOT exported — they are internal.
// -------------------------------------------------------------------
export type { TrustAnchor, LotlAnchorMetadata, TrustedAuthorityId } from './trust/TrustAnchor.js';
export type { Fetcher } from './trust/Fetcher.js';
export { InMemoryCache, type Cache } from './trust/Cache.js';
export {
    createGuardedFetcher,
    GUARDED_FETCH_DEFAULTS,
    type GuardedFetcherOptions,
    type HostLookup,
} from './http/guarded-fetch.js';
export {
    StaticTrustStore,
    CompositeTrustStore,
    LotlTrustStore,
    type TrustStore,
    type TrustStoreHint,
    type TrustStoreInput,
    type LotlTrustStoreOptions,
} from './trust/index.js';

// Token Status List (draft-ietf-oauth-status-list-21) — credential revocation
export {
    StatusListResolver,
    STATUS_LIST_JWT_TYP,
    STATUS_LIST_JWT_MEDIA_TYPE,
    decodeStatusList,
    readStatusValue,
    type StatusListResolverOptions,
    type StatusListReference,
    type StatusListLookup,
    type VerifiedStatusList,
    type DecodedStatusList,
    type StatusListBits,
    type TokenStatusType,
    type CredentialStatusResult,
    type StatusPolicy,
} from './status/index.js';

// Error classes added in 0.5.0
export {
    OpenID4VPError,
    TrustAnchorNotFoundError,
    CertificateChainError,
    RevokedCertificateError,
    RevocationCheckFailedError,
    LotlFetchError,
    LotlSignatureError,
    LotlConfigurationError,
    SignedRequestBuildError,
    UnsupportedJweError,
    DecryptionFailedError,
    MissingDecryptionKeyError,
    MissingVerifierEncryptionKeyError,
    MultipleCredentialsNotSupportedError,
    MissingAudienceError,
    WalletErrorResponseError,
    GuardedFetchError,
    StatusListError,
    type StatusListErrorReason,
    type GuardedFetchRejectReason,
    type ChainErrorReason,
    type SignedRequestBuildErrorCode,
} from './errors.js';
