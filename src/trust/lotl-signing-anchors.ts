import type { X509Certificate } from '@peculiar/x509';

/**
 * EU LOTL signing certificates, bundled at release time. Populated in
 * workstream A.3. A.1 ships this as an empty array so the module shape is
 * stable and downstream imports don't churn between releases.
 */
export const EU_LOTL_SIGNING_ANCHORS: readonly X509Certificate[] = [];
