import type { CredentialFormat, PresentationResult } from '../types/presentation.js';

export interface ParseOptions {
    trustedCertificates: Uint8Array[];
    nonce: string;
}

export interface ICredentialParser {
    readonly format: CredentialFormat;
    canParse(vpToken: unknown): boolean;
    parse(vpToken: unknown, options: ParseOptions): Promise<PresentationResult>;
}
