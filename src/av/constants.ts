// EU Age Verification (AV) profile constants.
// Source: av-doc-technical-specification, Annex A "Age Verification Profile".

/** Annex A §A.4.1: "The document type for Proof of Age attestation SHALL be `eu.europa.ec.av.1`." */
export const AV_DOCTYPE = 'eu.europa.ec.av.1';

/** Annex A §A.4.2: "All attributes belong to namespace `eu.europa.ec.av.1`". */
export const AV_NAMESPACE = 'eu.europa.ec.av.1';

/** DCQL credential query id used by the Annex A §A.11 examples and the reference verifier. */
export const AV_DEFAULT_CREDENTIAL_ID = 'proof_of_age';

/** Annex A §A.6: "at least a custom URL scheme av:// MUST be supported". */
export const AV_DEFAULT_BASE_URI = 'av://';

/** Annex A §A.4.2: `age_over_18` is present in every Proof of Age attestation. */
export const AV_DEFAULT_AGE_THRESHOLD = 18;

/**
 * Extended key usage on the Document Signer certificates of the EU Age
 * Verification reference Attestation Provider (Annex A §A.11 example,
 * "Age Verification DS - 001": `ExtendedKeyUsage: critical, 1.3.130.2.0.0.1.2`).
 * It is not the ISO 18013-5 `id-mdl-kp-mdlDS` (`1.0.18013.5.1.2`).
 */
export const AV_DOCUMENT_SIGNER_EKU = '1.3.130.2.0.0.1.2';

/** ISO 18013-5 `age_over_NN`: NN is two digits. */
const AGE_OVER_PATTERN = /^age_over_(\d{2})$/;

/** `18` → `'age_over_18'`. Throws a TypeError for anything but an integer 0–99. */
export function avAgeOverAttribute(threshold: number): string {
    if (!Number.isInteger(threshold) || threshold < 0 || threshold > 99) {
        throw new TypeError(`age threshold must be an integer from 0 to 99, got ${String(threshold)}`);
    }
    return `age_over_${String(threshold).padStart(2, '0')}`;
}

/** True for an `age_over_NN` element identifier — the only attributes Annex A §A.4.2 allows. */
export function isAvAgeOverAttribute(identifier: string): boolean {
    return AGE_OVER_PATTERN.test(identifier);
}
