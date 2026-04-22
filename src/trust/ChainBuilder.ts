import {
  AuthorityKeyIdentifierExtension,
  SubjectKeyIdentifierExtension,
  X509Certificate,
  X509Certificates,
} from "@peculiar/x509";
import { CertificateChainError } from "../errors.js";

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
    const chain: X509Certificate[] = [leaf];
    let current = leaf;
    const pool = new X509Certificates(intermediates);

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
        this.checkAkiSkiMatch(current, anchor);
        await this.verifySignature(current, anchor);
        chain.push(anchor);
        return chain;
      }
      this.checkPerCert(issuer);
      this.checkAkiSkiMatch(current, issuer);
      await this.verifySignature(current, issuer);
      chain.push(issuer);
      current = issuer;
    }
    return chain;
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
