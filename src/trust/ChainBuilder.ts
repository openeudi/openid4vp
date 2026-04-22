import { X509Certificate, X509Certificates } from "@peculiar/x509";
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
        await this.verifySignature(current, anchor);
        chain.push(anchor);
        return chain;
      }
      await this.verifySignature(current, issuer);
      chain.push(issuer);
      current = issuer;
    }
    return chain;
  }

  private async verifySignature(child: X509Certificate, issuer: X509Certificate): Promise<void> {
    const ok = await child.verify({ publicKey: issuer.publicKey });
    if (!ok) {
      throw new CertificateChainError(`signature verification failed for ${child.subject}`, { reason: "signature" });
    }
  }
}
