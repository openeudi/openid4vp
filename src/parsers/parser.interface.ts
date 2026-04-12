import type { CredentialFormat, PresentationResult } from '../types/presentation.js';

export interface ParseOptions {
    trustedCertificates: Uint8Array[];
    nonce: string;
    /** Expected audience for key binding JWT verification. Optional. */
    audience?: string;
    /** Allowed JWT signature algorithms. Defaults to ['ES256', 'ES384', 'ES512']. */
    allowedAlgorithms?: string[];
}

export interface ICredentialParser {
    readonly format: CredentialFormat;
    canParse(vpToken: unknown): boolean;
    parse(vpToken: unknown, options: ParseOptions): Promise<PresentationResult>;
}
