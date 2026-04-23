import { AsnConvert } from "@peculiar/asn1-schema";
import {
  GeneralName as Asn1GeneralName,
  GeneralSubtree,
  Name as AsnName,
  NameConstraints,
} from "@peculiar/asn1-x509";
import {
  AuthorityKeyIdentifierExtension,
  BasicConstraintsExtension,
  KeyUsageFlags,
  KeyUsagesExtension,
  Name as X509Name,
  SubjectAlternativeNameExtension,
  SubjectKeyIdentifierExtension,
  X509Certificate,
  X509Certificates,
} from "@peculiar/x509";
import { CertificateChainError } from "../errors.js";

const NAME_CONSTRAINTS_OID = "2.5.29.30";

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
}

const DEFAULT_ALGORITHMS = ["ES256", "ES384", "EdDSA", "RS256", "PS256"];

/**
 * Pragmatic RFC 5280 chain validator. Private — consumed only by
 * `TrustEvaluator`. Not exported from the package root.
 *
 * Scope: signature, validity period, algorithm allowlist, DN chaining,
 * AKI/SKI match, basicConstraints, keyUsage, nameConstraints. Explicitly
 * omits policy mapping / policy constraints / anyPolicy handling.
 */
export class ChainBuilder {
  constructor(private readonly opts: ChainBuilderOptions = {}) {}

  /**
   * Build and validate a chain from `leaf` to one of the `anchors`,
   * optionally using additional intermediates. Returns the ordered chain
   * (leaf → anchor). Throws `CertificateChainError` on any validation
   * failure.
   */
  async build(
    leaf: X509Certificate,
    anchors: X509Certificate[],
    intermediates: X509Certificate[] = []
  ): Promise<X509Certificate[]> {
    // Try each anchor; first one that closes a valid chain wins.
    const errors: Error[] = [];
    for (const anchor of anchors) {
      try {
        return await this.tryBuild(leaf, anchor, intermediates);
      } catch (err) {
        errors.push(err as Error);
      }
    }
    // All anchors failed — rethrow the most informative error.
    const last = errors[errors.length - 1];
    if (last instanceof CertificateChainError) throw last;
    throw new CertificateChainError("no valid chain to any anchor", {
      reason: "signature",
      cause: last,
    });
  }

  private async tryBuild(
    leaf: X509Certificate,
    anchor: X509Certificate,
    intermediates: X509Certificate[]
  ): Promise<X509Certificate[]> {
    this.checkPerCert(leaf);
    this.checkLeafKeyUsage(leaf);
    const chain: X509Certificate[] = [leaf];
    let current = leaf;
    const pool = new X509Certificates(intermediates);
    let nonLeafDepth = 0; // how many non-self-issued CAs above leaf

    while (current.subject !== anchor.subject) {
      const issuer = pool.find((c) => c.subject === current.issuer);
      if (!issuer) {
        if (current.issuer !== anchor.subject) {
          throw new CertificateChainError(`no issuer certificate found for ${current.subject}`, {
            reason: "signature",
          });
        }
        // climbed to the anchor
        this.checkPerCert(anchor);
        this.checkCaAndPathLen(anchor, nonLeafDepth);
        this.checkAkiSkiMatch(current, anchor);
        await this.verifySignature(current, anchor);
        chain.push(anchor);
        this.checkNameConstraints(leaf, chain.slice(1));
        return chain;
      }
      this.checkPerCert(issuer);
      this.checkCaAndPathLen(issuer, nonLeafDepth);
      this.checkAkiSkiMatch(current, issuer);
      await this.verifySignature(current, issuer);
      chain.push(issuer);
      current = issuer;
      nonLeafDepth += 1;
    }
    this.checkNameConstraints(leaf, chain.slice(1));
    return chain;
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
    this.checkCaKeyUsage(cert);
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

  private checkLeafKeyUsage(leaf: X509Certificate): void {
    const ext = leaf.getExtension(KeyUsagesExtension);
    if (!ext) return; // no keyUsage → no restriction
    if ((ext.usages & KeyUsageFlags.digitalSignature) === 0) {
      throw new CertificateChainError(
        `leaf ${leaf.subject} does not assert digitalSignature key usage`,
        { reason: "key_usage" }
      );
    }
  }

  private checkCaKeyUsage(cert: X509Certificate): void {
    const ext = cert.getExtension(KeyUsagesExtension);
    if (!ext) return;
    if ((ext.usages & KeyUsageFlags.keyCertSign) === 0) {
      throw new CertificateChainError(
        `CA ${cert.subject} does not assert keyCertSign key usage`,
        { reason: "key_usage" }
      );
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

  private async verifySignature(child: X509Certificate, issuer: X509Certificate): Promise<void> {
    // `signatureOnly: true` skips @peculiar/x509's internal validity check —
    // we own validity enforcement via `checkValidity` with clock-skew tolerance.
    const ok = await child.verify({ publicKey: issuer.publicKey, signatureOnly: true });
    if (!ok) {
      throw new CertificateChainError(`signature verification failed for ${child.subject}`, { reason: "signature" });
    }
  }

  private checkPerCert(cert: X509Certificate): void {
    this.checkValidity(cert);
    this.checkAlgorithm(cert);
  }

  private checkValidity(cert: X509Certificate): void {
    const now = (this.opts.now ?? (() => new Date()))().getTime();
    const skewMs = (this.opts.clockSkewTolerance ?? 60) * 1000;
    const notBefore = cert.notBefore.getTime();
    const notAfter = cert.notAfter.getTime();
    if (now + skewMs < notBefore) {
      throw new CertificateChainError(
        `certificate ${cert.subject} not yet valid (notBefore=${cert.notBefore.toISOString()})`,
        { reason: "validity" }
      );
    }
    if (now - skewMs > notAfter) {
      throw new CertificateChainError(
        `certificate ${cert.subject} expired (notAfter=${cert.notAfter.toISOString()})`,
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
  if (name === "RSA-PSS" && hash === "SHA-256") return "PS256";
  if (name === "RSA-PSS" && hash === "SHA-384") return "PS384";
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
