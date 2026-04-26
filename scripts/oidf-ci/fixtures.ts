import "reflect-metadata";
import * as x509 from "@peculiar/x509";

export interface GenerateFixturesInput {
  hostname: string;
}

export interface Fixtures {
  hostname: string;
  caKeypair: CryptoKeyPair;
  caCertDer: Uint8Array;
  leafKeypair: CryptoKeyPair;
  leafCertDer: Uint8Array;
}

const SIGNING_ALG = { name: "ECDSA", namedCurve: "P-256" } as const;
const HASH = "SHA-256";

export async function generateFixtures(input: GenerateFixturesInput): Promise<Fixtures> {
  const caKeypair = (await crypto.subtle.generateKey(SIGNING_ALG, true, ["sign", "verify"])) as CryptoKeyPair;
  const caCert = await x509.X509CertificateGenerator.create({
    serialNumber: "01",
    subject: "CN=oidf-ci-test-ca",
    issuer: "CN=oidf-ci-test-ca",
    notBefore: new Date(Date.now() - 60_000),
    notAfter: new Date(Date.now() + 24 * 3600_000),
    signingAlgorithm: { name: "ECDSA", hash: HASH },
    publicKey: caKeypair.publicKey,
    signingKey: caKeypair.privateKey,
    extensions: [
      new x509.BasicConstraintsExtension(true, undefined, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
    ],
  });

  const leafKeypair = (await crypto.subtle.generateKey(SIGNING_ALG, true, ["sign", "verify"])) as CryptoKeyPair;
  const leafCert = await x509.X509CertificateGenerator.create({
    serialNumber: "02",
    subject: `CN=${input.hostname}`,
    issuer: caCert.subject,
    notBefore: new Date(Date.now() - 60_000),
    notAfter: new Date(Date.now() + 24 * 3600_000),
    signingAlgorithm: { name: "ECDSA", hash: HASH },
    publicKey: leafKeypair.publicKey,
    signingKey: caKeypair.privateKey,
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
      new x509.SubjectAlternativeNameExtension([{ type: "dns", value: input.hostname }]),
    ],
  });

  return {
    hostname: input.hostname,
    caKeypair,
    caCertDer: new Uint8Array(caCert.rawData),
    leafKeypair,
    leafCertDer: new Uint8Array(leafCert.rawData),
  };
}
