export const VERSION = '0.2.1';

export type {
    CredentialFormat,
    CredentialClaims,
    PresentationResult,
    IssuerInfo,
    AuthorizationRequestInput,
    AuthorizationRequest,
} from './types/index.js';

export type { ICredentialParser, ParseOptions } from './parsers/parser.interface.js';

export { SdJwtParser } from './parsers/sd-jwt.parser.js';
export { MdocParser } from './parsers/mdoc.parser.js';

export {
    InvalidSignatureError,
    ExpiredCredentialError,
    UnsupportedFormatError,
    MalformedCredentialError,
    NonceValidationError,
} from './errors.js';

export { createAuthorizationRequest } from './authorization.js';

export { parsePresentation } from './presentation.js';
