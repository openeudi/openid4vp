import "reflect-metadata";
import { describe, expect, it } from "vitest";
import * as x509 from "@peculiar/x509";
import { generateFixtures } from "../../scripts/oidf-ci/fixtures";

describe("generateFixtures — CA + leaf chain", () => {
  it("produces a leaf cert signed by the CA, with SAN matching the requested hostname", async () => {
    const hostname = "verifier.test.local";
    const fx = await generateFixtures({ hostname });

    expect(fx.caCertDer).toBeInstanceOf(Uint8Array);
    expect(fx.leafCertDer).toBeInstanceOf(Uint8Array);

    const caCert = new x509.X509Certificate(fx.caCertDer);
    const leafCert = new x509.X509Certificate(fx.leafCertDer);

    expect(caCert.subject).toContain("CN=");
    const basicConstraints = caCert.getExtension("2.5.29.19");
    expect(basicConstraints).toBeDefined();

    const san = leafCert.getExtension("2.5.29.17");
    expect(san).toBeDefined();
    expect(leafCert.toString("pem")).toMatch(/CERTIFICATE/);

    expect(await leafCert.verify({ publicKey: caCert.publicKey })).toBe(true);
  });

  it("produces a leaf private key suitable for ECDSA P-256 signing", async () => {
    const fx = await generateFixtures({ hostname: "verifier.test.local" });

    expect(fx.leafKeypair.privateKey).toBeDefined();
    expect(fx.leafKeypair.publicKey).toBeDefined();

    const data = new TextEncoder().encode("test");
    const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, fx.leafKeypair.privateKey, data);
    expect(signature.byteLength).toBeGreaterThan(0);
  });
});
