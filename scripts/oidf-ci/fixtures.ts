import "reflect-metadata";
import * as x509 from "@peculiar/x509";
import type { DcqlQuery } from "../../src/index.js";

export type { DcqlQuery };

export interface GenerateFixturesInput {
  hostname: string;
}

/** JsonWebKey extended with the `kid` field (missing from lib.dom.d.ts). */
type JWK = JsonWebKey & { kid?: string };

export interface Fixtures {
  hostname: string;

  caKeypair: CryptoKeyPair;
  caCertDer: Uint8Array;
  leafKeypair: CryptoKeyPair;
  leafCertDer: Uint8Array;

  issuerKeypair: CryptoKeyPair;
  issuerSigningJwkPrivate: JWK;
  issuerSigningJwkPublic: JWK;
  issuerCertDer: Uint8Array;

  encryptionKeypair: CryptoKeyPair;
  encryptionPublicJwk: JWK;

  dcqlQuery: DcqlQuery;
}

const SIGNING_ALG = { name: "ECDSA", namedCurve: "P-256" } as const;
const HASH = "SHA-256";

async function generateChainCerts(hostname: string) {
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
    subject: `CN=${hostname}`,
    issuer: caCert.subject,
    notBefore: new Date(Date.now() - 60_000),
    notAfter: new Date(Date.now() + 24 * 3600_000),
    signingAlgorithm: { name: "ECDSA", hash: HASH },
    publicKey: leafKeypair.publicKey,
    signingKey: caKeypair.privateKey,
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
      new x509.SubjectAlternativeNameExtension([{ type: "dns", value: hostname }]),
    ],
  });

  return {
    caKeypair,
    caCertDer: new Uint8Array(caCert.rawData),
    leafKeypair,
    leafCertDer: new Uint8Array(leafCert.rawData),
  };
}

async function generateIssuer() {
  const issuerKeypair = (await crypto.subtle.generateKey(SIGNING_ALG, true, ["sign", "verify"])) as CryptoKeyPair;
  const issuerCert = await x509.X509CertificateGenerator.create({
    serialNumber: "01",
    subject: "CN=oidf-ci-test-issuer",
    issuer: "CN=oidf-ci-test-issuer",
    notBefore: new Date(Date.now() - 60_000),
    notAfter: new Date(Date.now() + 24 * 3600_000),
    signingAlgorithm: { name: "ECDSA", hash: HASH },
    publicKey: issuerKeypair.publicKey,
    signingKey: issuerKeypair.privateKey,
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
    ],
  });

  const issuerSigningJwkPrivate = (await crypto.subtle.exportKey("jwk", issuerKeypair.privateKey)) as JWK;
  issuerSigningJwkPrivate.kid = "issuer-1";
  issuerSigningJwkPrivate.alg = "ES256";
  issuerSigningJwkPrivate.use = "sig";

  const issuerSigningJwkPublic = (await crypto.subtle.exportKey("jwk", issuerKeypair.publicKey)) as JWK;
  issuerSigningJwkPublic.kid = "issuer-1";
  issuerSigningJwkPublic.alg = "ES256";
  issuerSigningJwkPublic.use = "sig";

  return {
    issuerKeypair,
    issuerCertDer: new Uint8Array(issuerCert.rawData),
    issuerSigningJwkPrivate,
    issuerSigningJwkPublic,
  };
}

async function generateEncryption() {
  const encryptionKeypair = (await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, [
    "deriveBits",
    "deriveKey",
  ])) as CryptoKeyPair;

  const encryptionPublicJwk = (await crypto.subtle.exportKey("jwk", encryptionKeypair.publicKey)) as JWK;
  encryptionPublicJwk.alg = "ECDH-ES";
  encryptionPublicJwk.use = "enc";
  encryptionPublicJwk.kid = "enc-1";

  return { encryptionKeypair, encryptionPublicJwk };
}

function buildDcqlQuery(): DcqlQuery {
  return {
    credentials: [
      {
        id: "pid",
        format: "dc+sd-jwt",
        meta: { vct_values: ["urn:eudi:pid:1"] },
        claims: [{ path: ["given_name"] }],
      },
    ],
  };
}

export async function generateFixtures(input: GenerateFixturesInput): Promise<Fixtures> {
  const chain = await generateChainCerts(input.hostname);
  const issuer = await generateIssuer();
  const enc = await generateEncryption();

  return {
    hostname: input.hostname,
    ...chain,
    ...issuer,
    ...enc,
    dcqlQuery: buildDcqlQuery(),
  };
}
