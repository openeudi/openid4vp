import type { CredentialFormat, PresentationResult } from '../types/presentation.js';

export interface ParseOptions {
    trustedCertificates: Uint8Array[];
    nonce: string;
    /** Expected audience for key binding JWT verification. Optional. */
    audience?: string;
    /** Allowed JWT signature algorithms. Defaults to ['ES256', 'ES384', 'ES512']. */
    allowedAlgorithms?: string[];
    /**
     * Explicit opt-in to skip the trust check. When omitted or `false`,
     * `trustedCertificates` must be non-empty — otherwise parsing throws
     * `MalformedCredentialError`. Set to `true` for demo/mock environments
     * where no trusted issuer set is available.
     */
    skipTrustCheck?: boolean;
    /**
     * When set, the parsed credential's `docType` (mDOC) or `vct` (SD-JWT)
     * must equal this value — otherwise parsing throws `MalformedCredentialError`.
     * Defends against doc-type confusion attacks when the verifier expects a
     * specific credential class (e.g. `'eu.europa.ec.eudi.pid.1'`).
     */
    expectedDocType?: string;
}

export interface ICredentialParser {
    readonly format: CredentialFormat;
    canParse(vpToken: unknown): boolean;
    parse(vpToken: unknown, options: ParseOptions): Promise<PresentationResult>;
}
