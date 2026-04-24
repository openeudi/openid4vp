export const VERSION = '0.5.0';

// Builders
export { createAuthorizationRequest } from './authorization.js';
export { createSignedAuthorizationRequest } from './signed-authorization.js';
export {
    buildHaipQuery,
    validateHaipQuery,
    isHaipQuery,
    HAIP_DOCTYPE_NAMESPACES,
} from './haip.js';

// Parsers / verifiers
export { parsePresentation } from './presentation.js';
export { verifyPresentation, verifyAuthorizationResponse } from './verify.js';
export { decryptAuthorizationResponse } from './decrypt-response.js';
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
    VerifyOptions,
    VerifyResult,
    HaipQueryInput,
} from './types/index.js';

// -------------------------------------------------------------------
// 0.5.0 trust module — public plug interfaces and implementations.
// TrustEvaluator, ChainBuilder, and EU_LOTL_SIGNING_ANCHORS are
// intentionally NOT exported — they are internal.
// -------------------------------------------------------------------
export type { TrustAnchor, LotlAnchorMetadata } from './trust/TrustAnchor.js';
export type { Fetcher } from './trust/Fetcher.js';
export { InMemoryCache, type Cache } from './trust/Cache.js';
export {
    StaticTrustStore,
    CompositeTrustStore,
    LotlTrustStore,
    type TrustStore,
    type TrustStoreHint,
    type TrustStoreInput,
    type LotlTrustStoreOptions,
} from './trust/index.js';

// Error classes added in 0.5.0
export {
    OpenID4VPError,
    TrustAnchorNotFoundError,
    CertificateChainError,
    RevokedCertificateError,
    RevocationCheckFailedError,
    LotlFetchError,
    LotlSignatureError,
    SignedRequestBuildError,
    UnsupportedJweError,
    DecryptionFailedError,
    MissingDecryptionKeyError,
    MultipleCredentialsNotSupportedError,
    type ChainErrorReason,
    type SignedRequestBuildErrorCode,
} from './errors.js';
