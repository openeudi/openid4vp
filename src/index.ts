export const VERSION = '0.4.0';

// Builders
export { createAuthorizationRequest } from './authorization.js';
export {
    buildHaipQuery,
    validateHaipQuery,
    isHaipQuery,
    HAIP_DOCTYPE_NAMESPACES,
} from './haip.js';

// Parsers / verifiers
export { parsePresentation } from './presentation.js';
export { verifyPresentation } from './verify.js';
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
    VerifyOptions,
    VerifyResult,
    HaipQueryInput,
} from './types/index.js';
