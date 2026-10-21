import { AsnConvert } from "@peculiar/asn1-schema";
import {
  Certificate as AsnCertificate,
  GeneralName as Asn1GeneralName,
  GeneralSubtree,
  Name as AsnName,
  NameConstraints,
} from "@peculiar/asn1-x509";
import {
  AuthorityKeyIdentifierExtension,
  BasicConstraintsExtension,
  ExtendedKeyUsageExtension,
  KeyUsageFlags,
  KeyUsagesExtension,
  Name as X509Name,
  SubjectAlternativeNameExtension,
  SubjectKeyIdentifierExtension,
  X509Certificate,
} from "@peculiar/x509";
import { CertificateChainError } from "../errors.js";
import { certificatesEqual } from "./x509-utils.js";

const NAME_CONSTRAINTS_OID = "2.5.29.30";

/** ISO/IEC 18013-5 Annex B `id-mdl-kp-mdlDS` — Document Signer extended key usage. */
export const ISO_18013_5_DS_EKU = "1.0.18013.5.1.2";

/**
 * Extensions this validator recognises when they are marked critical
 * (RFC 5280 §4.2: a certificate with any other critical extension MUST be
 * rejected). Each is either enforced here or carries no constraint on
 * signature verification:
 *
 * - basicConstraints, keyUsage, extKeyUsage, nameConstraints, AKI / SKI:
 *   enforced by this class.
 * - subjectAltName: read for nameConstraints.
 * - cRLDistributionPoints, authorityInfoAccess: used for revocation.
 * - qcStatements (RFC 3739, ETSI EN 319 412-5): statements about the
 *   certificate (QC compliance, QSCD, type, PDS) that do not restrict how its
 *   key may be used to verify signatures. At least one EU PID provider
 *   certificate in the PID-providers trusted list marks it critical.
 *
 * certificatePolicies, policyConstraints, policyMappings and inhibitAnyPolicy
 * are deliberately absent: policy processing is not implemented, so a CA that
 * relies on them by marking them critical is rejected rather than ignored.
 */
export const RECOGNISED_CRITICAL_EXTENSIONS: ReadonlySet<string> = new Set([
  "2.5.29.19", // basicConstraints
  "2.5.29.15", // keyUsage
  "2.5.29.37", // extKeyUsage
  "2.5.29.17", // subjectAltName
  "2.5.29.30", // nameConstraints
  "2.5.29.35", // authorityKeyIdentifier
  "2.5.29.14", // subjectKeyIdentifier
  "2.5.29.31", // cRLDistributionPoints
  "1.3.6.1.5.5.7.1.1", // authorityInfoAccess
  "1.3.6.1.5.5.7.1.3", // qcStatements
]);

/** Default ceiling on chain length, leaf and anchor included. */
export const DEFAULT_MAX_CHAIN_LENGTH = 5;

/**
 * Default ceiling on signature verifications per `build`. A legitimate path —
 * even through re-issued or cross-signed intermediates — needs a handful.
 */
export const DEFAULT_MAX_SIGNATURE_CHECKS = 32;

/** Mutable state threaded through one path search. */
interface PathSearch {
  /** Signature verifications left before the search is abandoned. */
  remaining: number;
  /** Most recent failure of a check on a concrete certificate. */
  specific?: Error;
  /** Most recent "nothing usable at this step" outcome. */
  fallback?: Error;
}

/** Errors that abort the whole search rather than just the current branch. */
const searchAborts = new WeakSet<Error>();

/**
 * Certificate profile the chain is validated against.
 *
 * - `generic` — RFC 5280 rules only. Used for SD-JWT VC (`x5c`), where no
 *   profile mandates a specific EKU on the issuer certificate.
 * - `iso18013-5` — additionally enforces the ISO/IEC 18013-5 Annex B
 *   certificate profile on built chains: the Document Signer MUST carry
 *   keyUsage `digitalSignature` and EKU `1.0.18013.5.1.2`, and every CA
 *   (IACA) MUST carry keyUsage `keyCertSign`. Used for `mso_mdoc`.
 */
export type CertificateProfile = "generic" | "iso18013-5";

type SubtreeName =
  | { type: "dn"; value: string }
  | { type: "dns"; value: string }
  | { type: "email"; value: string }
  | { type: "uri"; value: string };

export interface ChainBuilderOptions {
  /** Clock-skew tolerance in seconds applied to `notBefore`/`notAfter`. Default 60. */
  clockSkewTolerance?: number;
  /**
   * Certificate signature algorithms accepted for chain links.
   * Defaults to ES256, ES384, EdDSA, RS256, PS256.
   */
  allowedAlgorithms?: string[];
  /** Override "now" (used by tests). Defaults to `new Date()`. */
  now?: () => Date;
  /** Certificate profile. Default `generic`. */
  profile?: CertificateProfile;
  /**
   * Under the `iso18013-5` profile, the Document Signer must carry at least
   * one of these extended key usages. Default `[ISO_18013_5_DS_EKU]`. Other
   * mdoc ecosystems use their own DS EKU (e.g. the EU Age Verification
   * reference issuer's `1.3.130.2.0.0.1.2`). Ignored by the `generic` profile.
   */
  documentSignerEkus?: readonly string[];
  /**
   * Maximum number of certificates in a chain, leaf and anchor included.
   * Default {@link DEFAULT_MAX_CHAIN_LENGTH}. Bounds work on attacker-supplied
   * `x5c` / `x5chain` pools independently of any pathLenConstraint.
   */
  maxChainLength?: number;
  /**
   * Maximum number of certificate signature verifications one `build` may
   * spend searching for a path, closure attempts at anchors included. The
   * search backtracks across candidates that share a Subject DN, so without
   * a ceiling an attacker-supplied `x5c` / `x5chain` pool could force work
   * exponential in its size. Default {@link DEFAULT_MAX_SIGNATURE_CHECKS}.
   */
  maxSignatureChecks?: number;
}

export interface BuildContext {
  /**
   * When the credential was signed (mDOC `validityInfo.signed`, SD-JWT `iat`).
   * When set, every certificate in the chain must also have been valid then,
   * in addition to being valid now.
   */
  issuedAt?: Date;
}

const DEFAULT_ALGORITHMS = [
  "ES256",
  "ES384",
  "ES512",
  "EdDSA",
  "RS256",
  "RS384",
  "RS512",
  "PS256",
  "PS384",
  "PS512",
];

/**
 * Pragmatic RFC 5280 chain validator. Private — consumed only by
 * `TrustEvaluator`. Not exported from the package root.
 *
 * Scope: signature, validity period, algorithm allowlist, DN chaining,
 * AKI/SKI match, basicConstraints, keyUsage, nameConstraints, and rejection
 * of unrecognised critical extensions on every certificate of the path (the
 * trust anchor itself is configuration, not part of the path, RFC 5280 §6.1).
 * Explicitly omits policy mapping / policy constraints / anyPolicy handling —
 * which is why those extensions are refused when critical.
 */
export class ChainBuilder {
  constructor(private readonly opts: ChainBuilderOptions = {}) {}

  /**
   * Build and validate a chain from `leaf` to one of the `anchors`,
   * optionally using additional intermediates. Returns the ordered chain
   * (leaf → anchor). Throws `CertificateChainError` on any validation
   * failure.
   *
   * Trust is by presence in the anchor set and is established ONLY by (a) the
   * leaf being byte-identical to an anchor, or (b) a verified signature by an
   * anchor's key on the last certificate of the path. Subject/Issuer DN
   * equality is used to select candidates, never to conclude trust
   * (GHSA-4c2f-96cf-f5fc).
   *
   * The search is depth-first and backtracks: when several intermediates share
   * a Subject DN — a re-issued certificate next to its expired predecessor, or
   * cross-signed copies under different roots — a candidate that fails a check
   * or leads nowhere does not end the search. The result therefore does not
   * depend on the order of `intermediates`. Work is bounded by
   * `maxChainLength` and `maxSignatureChecks`.
   */
  async build(
    leaf: X509Certificate,
    anchors: X509Certificate[],
    intermediates: X509Certificate[] = [],
    context: BuildContext = {}
  ): Promise<X509Certificate[]> {
    // One budget for the whole call: trying more anchors must not multiply
    // the work an attacker-supplied pool can force.
    const search: PathSearch = {
      remaining: this.opts.maxSignatureChecks ?? DEFAULT_MAX_SIGNATURE_CHECKS,
    };
    // Anchors are tried in order and the first that closes a valid chain wins,
    // so callers keep control over which anchor (and provenance) is preferred.
    let lastFailure: Error | undefined;
    for (const anchor of anchors) {
      search.specific = undefined;
      search.fallback = undefined;
      try {
        const chain = await this.tryBuild(leaf, anchor, intermediates, context, search);
        if (chain) return chain;
        lastFailure = search.specific ?? search.fallback;
      } catch (err) {
        if (searchAborts.has(err as Error)) throw err;
        lastFailure = err as Error;
      }
    }
    // All anchors failed — rethrow the most informative error.
    if (lastFailure instanceof CertificateChainError) throw lastFailure;
    throw new CertificateChainError("no valid chain to any anchor", {
      reason: "signature",
      cause: lastFailure,
    });
  }

  /** Search for a path from `leaf` that closes at `anchor`. */
  private async tryBuild(
    leaf: X509Certificate,
    anchor: X509Certificate,
    intermediates: X509Certificate[],
    context: BuildContext,
    search: PathSearch
  ): Promise<X509Certificate[] | undefined> {
    this.checkPerCert(leaf, context);
    this.checkCriticalExtensions(leaf);

    // Direct match: the presented signer IS the listed anchor. The anchor is
    // trusted by presence, so no issuer is needed and the CA/profile rules
    // for built chains do not apply — only usability as a signer.
    if (certificatesEqual(leaf, anchor)) {
      this.checkLeafKeyUsage(leaf, "generic");
      return [leaf];
    }

    const profile = this.opts.profile ?? "generic";
    this.checkLeafKeyUsage(leaf, profile);
    this.checkLeafExtendedKeyUsage(leaf, profile);

    // The anchor closes via signature, never via the pool; the leaf is never
    // its own issuer. Both are excluded so a pool copy cannot short-circuit.
    const pool = intermediates.filter(
      (c) => !certificatesEqual(c, anchor) && !certificatesEqual(c, leaf)
    );
    return this.extendPath([leaf], anchor, pool, context, search);
  }

  /**
   * Try to complete `chain` (leaf first) to `anchor`. Returns the completed
   * chain, or `undefined` when no extension of this prefix works — failures
   * are recorded on `search` so the caller can report the most specific one.
   * Throws only to abandon the whole search (signature budget exhausted).
   */
  private async extendPath(
    chain: X509Certificate[],
    anchor: X509Certificate,
    pool: X509Certificate[],
    context: BuildContext,
    search: PathSearch
  ): Promise<X509Certificate[] | undefined> {
    const leaf = chain[0];
    const current = chain[chain.length - 1];
    const maxLength = this.opts.maxChainLength ?? DEFAULT_MAX_CHAIN_LENGTH;
    if (chain.length + 1 > maxLength) {
      search.specific = new CertificateChainError(
        `chain from ${leaf.subject} exceeds the maximum length of ${maxLength} certificates`,
        { reason: "path_length" }
      );
      return undefined;
    }
    const nonLeafDepth = chain.length - 1; // CAs already between leaf and the next issuer

    if (current.issuer === anchor.subject) {
      try {
        await this.closeAtAnchor(current, anchor, nonLeafDepth, context, search);
        const closed = [...chain, anchor];
        this.checkNameConstraints(leaf, closed.slice(1));
        return closed;
      } catch (err) {
        if (searchAborts.has(err as Error)) throw err;
        search.specific = err as Error;
      }
    }

    // Otherwise extend through every pool certificate that actually issued
    // `current`, backing out of any branch that fails a check or dead-ends.
    const candidates = pool.filter(
      (c) => c.subject === current.issuer && !chain.some((x) => certificatesEqual(x, c))
    );
    let verified = 0;
    for (const candidate of candidates) {
      if (!(await this.signatureVerifies(current, candidate, search))) continue;
      verified++;
      try {
        this.checkPerCert(candidate, context);
        this.checkCriticalExtensions(candidate);
        this.checkCaAndPathLen(candidate, nonLeafDepth);
        this.checkAkiSkiMatch(current, candidate);
      } catch (err) {
        search.specific = err as Error;
        continue;
      }
      const found = await this.extendPath([...chain, candidate], anchor, pool, context, search);
      if (found) return found;
    }

    search.fallback = new CertificateChainError(
      candidates.length > 0 && verified === 0
        ? `signature verification failed for ${current.subject}`
        : `no issuer certificate found for ${current.subject}`,
      { reason: "signature" }
    );
    return undefined;
  }

  private async closeAtAnchor(
    current: X509Certificate,
    anchor: X509Certificate,
    nonLeafDepth: number,
    context: BuildContext,
    search: PathSearch
  ): Promise<void> {
    this.checkPerCert(anchor, context);
    this.checkCaAndPathLen(anchor, nonLeafDepth);
    this.checkAkiSkiMatch(current, anchor);
    this.spendSignatureCheck(search);
    await this.verifySignature(current, anchor);
  }

  /** Charge one signature verification to the search, or abandon it. */
  private spendSignatureCheck(search: PathSearch): void {
    if (search.remaining <= 0) {
      const limit = this.opts.maxSignatureChecks ?? DEFAULT_MAX_SIGNATURE_CHECKS;
      const err = new CertificateChainError(
        `certificate path search exceeded ${limit} signature checks`,
        { reason: "path_length" }
      );
      searchAborts.add(err);
      throw err;
    }
    search.remaining--;
  }

  /**
   * Enforce nameConstraints asserted by any CA above the leaf against the
   * leaf's identities. RFC 5280 §4.2.1.10 requires both permitted (leaf must
   * match at least one) and excluded (leaf must match none) to hold for each
   * name type that appears in the constraint.
   */
  private checkNameConstraints(leaf: X509Certificate, chainAboveLeaf: X509Certificate[]): void {
    const leafNames = collectLeafNames(leaf);
    const types: SubtreeName["type"][] = ["dn", "dns", "email", "uri"];
    for (const ca of chainAboveLeaf) {
      const ext = ca.extensions.find((e) => e.type === NAME_CONSTRAINTS_OID);
      if (!ext) continue;
      const nc = AsnConvert.parse(ext.value, NameConstraints);
      const permitted = extractSubtrees(nc.permittedSubtrees);
      const excluded = extractSubtrees(nc.excludedSubtrees);
      for (const type of types) {
        this.applyConstraintsForType(leaf, leafNames, permitted, excluded, type, ca.subject);
      }
    }
  }

  private applyConstraintsForType(
    leaf: X509Certificate,
    leafNames: SubtreeName[],
    permitted: SubtreeName[],
    excluded: SubtreeName[],
    type: SubtreeName["type"],
    enforcingCa: string
  ): void {
    const permittedForType = permitted.filter((p) => p.type === type);
    const excludedForType = excluded.filter((p) => p.type === type);
    const leafForType = leafNames.filter((n) => n.type === type);
    if (permittedForType.length > 0) {
      // Every leaf name of this type must fall under at least one permitted subtree.
      for (const ln of leafForType) {
        const ok = permittedForType.some((sub) => matchesSubtree(ln, sub));
        if (!ok) {
          throw new CertificateChainError(
            `leaf ${leaf.subject}: ${type} "${ln.value}" is outside permitted subtrees asserted by ${enforcingCa}`,
            { reason: "name_constraints" }
          );
        }
      }
    }
    for (const ln of leafForType) {
      for (const sub of excludedForType) {
        if (matchesSubtree(ln, sub)) {
          throw new CertificateChainError(
            `leaf ${leaf.subject}: ${type} "${ln.value}" is under excluded subtree "${sub.value}" asserted by ${enforcingCa}`,
            { reason: "name_constraints" }
          );
        }
      }
    }
  }

  private checkCaAndPathLen(cert: X509Certificate, nonLeafDepth: number): void {
    this.checkCaKeyUsage(cert, this.opts.profile ?? "generic");
    const bc = cert.getExtension(BasicConstraintsExtension);
    if (!bc || !bc.ca) {
      throw new CertificateChainError(
        `certificate ${cert.subject} is not a CA (BasicConstraints cA=false or absent)`,
        { reason: "basic_constraints" }
      );
    }
    if (typeof bc.pathLength === "number" && nonLeafDepth > bc.pathLength) {
      throw new CertificateChainError(
        `path length ${nonLeafDepth} exceeds pathLenConstraint ${bc.pathLength} on ${cert.subject}`,
        { reason: "path_length" }
      );
    }
  }

  private checkLeafKeyUsage(leaf: X509Certificate, profile: CertificateProfile): void {
    const ext = leaf.getExtension(KeyUsagesExtension);
    if (!ext) {
      // RFC 5280: absent keyUsage → no restriction. ISO 18013-5 Annex B makes
      // it mandatory on the Document Signer.
      if (profile === "iso18013-5") {
        throw new CertificateChainError(
          `document signer ${leaf.subject} has no keyUsage extension (ISO 18013-5 requires digitalSignature)`,
          { reason: "key_usage" }
        );
      }
      return;
    }
    if ((ext.usages & KeyUsageFlags.digitalSignature) === 0) {
      throw new CertificateChainError(
        `leaf ${leaf.subject} does not assert digitalSignature key usage`,
        { reason: "key_usage" }
      );
    }
  }

  private checkLeafExtendedKeyUsage(leaf: X509Certificate, profile: CertificateProfile): void {
    if (profile !== "iso18013-5") return;
    const ext = leaf.getExtension(ExtendedKeyUsageExtension);
    const usages = (ext?.usages ?? []).map(String);
    const accepted = this.opts.documentSignerEkus ?? [ISO_18013_5_DS_EKU];
    if (!accepted.some((oid) => usages.includes(oid))) {
      throw new CertificateChainError(
        `document signer ${leaf.subject} lacks extended key usage ${accepted.join(" or ")}` +
          (accepted.length === 1 && accepted[0] === ISO_18013_5_DS_EKU ? " (id-mdl-kp-mdlDS)" : ""),
        { reason: "extended_key_usage" }
      );
    }
  }

  private checkCaKeyUsage(cert: X509Certificate, profile: CertificateProfile): void {
    const ext = cert.getExtension(KeyUsagesExtension);
    if (!ext) {
      if (profile === "iso18013-5") {
        throw new CertificateChainError(
          `CA ${cert.subject} has no keyUsage extension (ISO 18013-5 requires keyCertSign)`,
          { reason: "key_usage" }
        );
      }
      return;
    }
    if ((ext.usages & KeyUsageFlags.keyCertSign) === 0) {
      throw new CertificateChainError(
        `CA ${cert.subject} does not assert keyCertSign key usage`,
        { reason: "key_usage" }
      );
    }
  }

  /**
   * RFC 5280 §4.2: reject a certificate carrying a critical extension this
   * validator does not process. Read from the raw ASN.1 rather than
   * `cert.extensions`, whose typed decoding throws on some malformed
   * non-critical extensions found in real certificates.
   */
  private checkCriticalExtensions(cert: X509Certificate): void {
    const extensions =
      AsnConvert.parse(cert.rawData, AsnCertificate).tbsCertificate.extensions ?? [];
    for (const ext of extensions) {
      if (ext.critical && !RECOGNISED_CRITICAL_EXTENSIONS.has(ext.extnID)) {
        throw new CertificateChainError(
          `certificate ${cert.subject} has unrecognised critical extension ${ext.extnID}`,
          { reason: "unrecognised_critical_extension" }
        );
      }
    }
  }

  private checkAkiSkiMatch(child: X509Certificate, issuer: X509Certificate): void {
    const aki = child.getExtension(AuthorityKeyIdentifierExtension);
    const ski = issuer.getExtension(SubjectKeyIdentifierExtension);
    if (!aki || !ski) return; // extension-less certs permitted
    const akiKeyId = aki.keyId;
    const skiKeyId = ski.keyId;
    if (akiKeyId && skiKeyId && akiKeyId.toLowerCase() !== skiKeyId.toLowerCase()) {
      throw new CertificateChainError(
        `AKI of ${child.subject} does not match SKI of ${issuer.subject}`,
        { reason: "aki_ski_mismatch" }
      );
    }
  }

  /**
   * Signature check used to select among DN-matching candidates. Never throws
   * on a bad signature; throws only when the search budget is exhausted.
   */
  private async signatureVerifies(
    child: X509Certificate,
    issuer: X509Certificate,
    search: PathSearch
  ): Promise<boolean> {
    this.spendSignatureCheck(search);
    try {
      return await child.verify({ publicKey: issuer.publicKey, signatureOnly: true });
    } catch {
      return false;
    }
  }

  private async verifySignature(child: X509Certificate, issuer: X509Certificate): Promise<void> {
    // `signatureOnly: true` skips @peculiar/x509's internal validity check —
    // we own validity enforcement via `checkValidity` with clock-skew tolerance.
    const ok = await child.verify({ publicKey: issuer.publicKey, signatureOnly: true });
    if (!ok) {
      throw new CertificateChainError(`signature verification failed for ${child.subject}`, { reason: "signature" });
    }
  }

  private checkPerCert(cert: X509Certificate, context: BuildContext = {}): void {
    const now = (this.opts.now ?? (() => new Date()))();
    this.checkValidity(cert, now, "");
    if (context.issuedAt) {
      this.checkValidity(cert, context.issuedAt, ` at issuance time ${context.issuedAt.toISOString()}`);
    }
    this.checkAlgorithm(cert);
  }

  private checkValidity(cert: X509Certificate, at: Date, label: string): void {
    const time = at.getTime();
    const skewMs = (this.opts.clockSkewTolerance ?? 60) * 1000;
    const notBefore = cert.notBefore.getTime();
    const notAfter = cert.notAfter.getTime();
    if (time + skewMs < notBefore) {
      throw new CertificateChainError(
        `certificate ${cert.subject} not yet valid${label} (notBefore=${cert.notBefore.toISOString()})`,
        { reason: "validity" }
      );
    }
    if (time - skewMs > notAfter) {
      throw new CertificateChainError(
        `certificate ${cert.subject} expired${label} (notAfter=${cert.notAfter.toISOString()})`,
        { reason: "validity" }
      );
    }
  }

  private checkAlgorithm(cert: X509Certificate): void {
    const allowed = this.opts.allowedAlgorithms ?? DEFAULT_ALGORITHMS;
    const algName = mapX509AlgoToJwaName(cert);
    if (!allowed.includes(algName)) {
      throw new CertificateChainError(
        `certificate ${cert.subject} uses disallowed signature algorithm ${algName}`,
        { reason: "algorithm_disallowed" }
      );
    }
  }
}

function mapX509AlgoToJwaName(cert: X509Certificate): string {
  // `@peculiar/x509` surfaces the signature alg via `signatureAlgorithm.name`
  // plus hash on ECDSA/RSA-PSS. We map to JWA names per RFC 7518 + RFC 8037.
  const alg = cert.signatureAlgorithm as unknown as {
    name?: string;
    hash?: { name?: string };
  };
  const name = alg?.name ?? "";
  const hash = alg?.hash?.name ?? "";
  if (name === "ECDSA" && hash === "SHA-256") return "ES256";
  if (name === "ECDSA" && hash === "SHA-384") return "ES384";
  if (name === "ECDSA" && hash === "SHA-512") return "ES512";
  if (name === "Ed25519" || name === "EdDSA") return "EdDSA";
  if (name === "RSASSA-PKCS1-v1_5" && hash === "SHA-256") return "RS256";
  if (name === "RSASSA-PKCS1-v1_5" && hash === "SHA-384") return "RS384";
  if (name === "RSASSA-PKCS1-v1_5" && hash === "SHA-512") return "RS512";
  if (name === "RSA-PSS" && hash === "SHA-256") return "PS256";
  if (name === "RSA-PSS" && hash === "SHA-384") return "PS384";
  if (name === "RSA-PSS" && hash === "SHA-512") return "PS512";
  return `${name}-${hash}`;
}

/**
 * Collect all identities asserted by the leaf that name constraints can
 * apply to: subject DN plus any SAN entries of supported types.
 *
 * Note: `@peculiar/x509`'s `GeneralName.type` uses the literal `'url'` for
 * URIs (URL constant), while the constraint side in `@peculiar/asn1-x509`
 * uses `uniformResourceIdentifier`, which `generalNameToSubtree` maps to
 * `{type: 'uri', ...}`. We normalize SAN entries here to `'uri'` so both
 * read paths agree on one canonical type tag.
 */
function collectLeafNames(leaf: X509Certificate): SubtreeName[] {
  const out: SubtreeName[] = [{ type: "dn", value: leaf.subject }];
  const san = leaf.getExtension(SubjectAlternativeNameExtension);
  if (san?.names?.items) {
    for (const name of san.names.items) {
      if (name.type === "dns") out.push({ type: "dns", value: name.value });
      else if (name.type === "email") out.push({ type: "email", value: name.value });
      else if (name.type === "url") out.push({ type: "uri", value: name.value });
    }
  }
  return out;
}

/**
 * Collapse a parsed `GeneralSubtrees` into the simple shape used by
 * the synthetic-ca helpers: `{type, value}`. Any name kind we do not yet
 * enforce is returned as-is so later tasks can extend this.
 */
function extractSubtrees(subtrees: GeneralSubtree[] | undefined): SubtreeName[] {
  if (!subtrees) return [];
  const out: SubtreeName[] = [];
  for (const s of subtrees) {
    const name = generalNameToSubtree(s.base);
    if (name) out.push(name);
  }
  return out;
}

function generalNameToSubtree(gn: Asn1GeneralName): SubtreeName | null {
  if (gn.directoryName) {
    // `directoryName` is an ASN.1 `Name`. Serialize to DER and parse with
    // @peculiar/x509's `Name` to get a canonical RFC 4514 string — same
    // path the synthetic-ca helper uses on the write side.
    const der = AsnConvert.serialize(gn.directoryName as AsnName);
    const dn = new X509Name(new Uint8Array(der)).toString();
    return { type: "dn", value: dn };
  }
  if (typeof gn.dNSName === "string") return { type: "dns", value: gn.dNSName };
  if (typeof gn.rfc822Name === "string") return { type: "email", value: gn.rfc822Name };
  if (typeof gn.uniformResourceIdentifier === "string") {
    return { type: "uri", value: gn.uniformResourceIdentifier };
  }
  return null;
}

function matchesSubtree(leafName: SubtreeName, subtree: SubtreeName): boolean {
  if (leafName.type !== subtree.type) return false;
  switch (subtree.type) {
    case "dn":
      return dnIsUnder(leafName.value, subtree.value);
    case "dns":
      return dnsIsUnder(leafName.value, subtree.value);
    case "email":
      return emailIsUnder(leafName.value, subtree.value);
    case "uri":
      return uriIsUnder(leafName.value, subtree.value);
  }
}

/**
 * DNS subtree match per RFC 5280 §4.2.1.10: case-insensitive exact match,
 * or left-side label(s) extension (`api.example.com` is under `example.com`).
 */
function dnsIsUnder(leafDns: string, subtree: string): boolean {
  const leaf = leafDns.toLowerCase();
  const sub = subtree.toLowerCase();
  if (leaf === sub) return true;
  return leaf.endsWith(`.${sub}`);
}

/**
 * rfc822Name subtree match per RFC 5280 §4.2.1.10. Three shapes:
 *  - full mailbox (`user@host`): exact match;
 *  - host (`host.example`): match by leaf's domain part;
 *  - dot-prefixed (`.example.com`): any descendant host, including the
 *    bare domain (`example.com`) per §4.2.1.6 conventions.
 */
function emailIsUnder(leafEmail: string, subtree: string): boolean {
  const leaf = leafEmail.toLowerCase();
  const sub = subtree.toLowerCase();
  if (sub.includes("@")) return leaf === sub;
  const at = leaf.indexOf("@");
  if (at < 0) return false;
  const leafHost = leaf.slice(at + 1);
  if (sub.startsWith(".")) {
    const bare = sub.slice(1);
    return leafHost === bare || leafHost.endsWith(sub);
  }
  return leafHost === sub;
}

/**
 * URI subtree match per RFC 5280 §4.2.1.10: parse the leaf URI and run the
 * DNS subtree comparison on its hostname.
 */
function uriIsUnder(leafUri: string, subtree: string): boolean {
  try {
    const url = new URL(leafUri);
    return dnsIsUnder(url.hostname, subtree);
  } catch {
    return false;
  }
}

/**
 * RDN-level suffix match per RFC 5280 §4.2.1.10. This is a pragmatic
 * comparison — case-insensitive on attribute values, matching on whole
 * RDN tokens after splitting on `,`. It is not a full DN canonicalization
 * but handles EU TSP certificates correctly.
 */
function dnIsUnder(childDn: string, subtreeDn: string): boolean {
  const normalize = (dn: string) =>
    dn
      .split(",")
      .map((rdn) => rdn.trim())
      .filter(Boolean)
      .reverse();
  const child = normalize(childDn);
  const subtree = normalize(subtreeDn);
  if (subtree.length > child.length) return false;
  for (let i = 0; i < subtree.length; i++) {
    if (child[i].toLowerCase() !== subtree[i].toLowerCase()) return false;
  }
  return true;
}
