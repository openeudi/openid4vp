/**
 * One element of the OpenID4VP 1.0 §5.1 `verifier_info` request parameter: an
 * attestation about the Verifier, such as a registration certificate.
 *
 * `credential_ids`, when present, lists the DCQL Credential Query `id`s the
 * attestation applies to; when omitted it applies to every requested
 * Credential.
 */
export interface VerifierInfo {
    format: string;
    data: string | Record<string, unknown>;
    credential_ids?: string[];
}

/** ETSI TS 119 475 V1.2.1 Annex B.2.6 `MultiLangString`. */
export interface MultiLangString {
    /** Language of `content`. TS 119 475 B.2.6 asks for an ISO 639 Set 1 code. */
    lang: string;
    content: string;
}

/** ETSI TS 119 475 V1.2.1 Annex B.2.5 `Identifier` of the relying party. */
export interface RegistrarIdentifier {
    /** Identifier type URI, e.g. `http://data.europa.eu/eudi/id/LEI`. */
    type: string;
    identifier: string;
}

/** ETSI TS 119 475 V1.2.1 Annex B.2.10 `Claim`. */
export interface RegistrarClaim {
    /**
     * Path to the claim. TS 119 472-2 V1.3.1 types it `tstr`, while the
     * TS 119 475 Annex C example uses a DCQL-style array, so both are accepted
     * and passed through unchanged.
     */
    path: string | Array<string | number | null>;
    values?: Array<string | number | boolean>;
}

/** ETSI TS 119 475 V1.2.1 Annex B.2.9 `Credential`, as registered for the intended use. */
export interface RegistrarCredential {
    format: string;
    /**
     * Format-specific metadata. TS 119 472-2 V1.3.1 types it `tstr`, while the
     * TS 119 475 Annex C example uses a DCQL-style object, so both are accepted
     * and passed through unchanged.
     */
    meta: string | Record<string, unknown>;
    claim?: RegistrarClaim[];
}

/**
 * The RP Registrar-provided data a request object carries in its
 * `registrar_dataset` `verifier_info` element (ETSI TS 119 472-2 V1.3.1
 * §6.3.2.2, OIDFVP-HAIP-COMMON-REQ-RO-06 to RO-12). Member names follow the
 * ETSI data model exactly.
 *
 * For an intermediated relying party, `identifier` is the final relying
 * party's identifier, not the intermediary's (RO-12 NOTE 2).
 */
export interface RegistrarDataset {
    /** RO-06: the relying party's identifier(s), non-empty. */
    identifier: RegistrarIdentifier[];
    /** RO-07: registered user-friendly descriptions of the service, non-empty. */
    srvDescription: MultiLangString[];
    /** RO-08: URI of the RP Registrar's API. */
    registryURI: string;
    /** RO-09: Registrar-provided identifier of the intended use. */
    intendedUseIdentifier: string;
    /** RO-10: registered purposes of the intended data processing, non-empty. */
    purpose: MultiLangString[];
    /** RO-11: privacy policy URI of the registered intended use. */
    policyURI: string;
    /** RO-12 (optional): the attestations and attributes registered for the intended use. */
    credential?: RegistrarCredential[];
}
