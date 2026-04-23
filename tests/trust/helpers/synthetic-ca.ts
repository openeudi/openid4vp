import { AsnConvert } from '@peculiar/asn1-schema';
import {
    AccessDescription,
    AlgorithmIdentifier,
    AuthorityInfoAccessSyntax,
    CertificateList,
    CRLDistributionPoints,
    DistributionPoint,
    DistributionPointName,
    GeneralName as AsnGeneralName,
    GeneralNames as Asn1GeneralNames,
    GeneralSubtree,
    GeneralSubtrees,
    Name as AsnName,
    NameConstraints,
    RevokedCertificate,
    TBSCertList,
    Time,
    Version,
} from '@peculiar/asn1-x509';
import * as x509 from '@peculiar/x509';
import { Crypto as PeculiarCrypto } from '@peculiar/webcrypto';

// @peculiar/x509 needs a WebCrypto provider set once per process.
const provider = new PeculiarCrypto();
x509.cryptoProvider.set(provider as unknown as Crypto);

export type GeneratedCa = {
    certificate: x509.X509Certificate;
    keys: CryptoKeyPair;
};

export type SyntheticNameKind = 'dn' | 'dns' | 'email' | 'uri';

export interface SyntheticSubtree {
    type: SyntheticNameKind;
    value: string;
}

export interface CreateCaOpts {
    name?: string;
    notBefore?: Date;
    notAfter?: Date;
    pathLenConstraint?: number;
}

export interface CreateIntermediateOpts extends CreateCaOpts {
    nameConstraintsPermitted?: SyntheticSubtree[];
    nameConstraintsExcluded?: SyntheticSubtree[];
}

export interface CreateLeafOpts {
    name?: string;
    notBefore?: Date;
    notAfter?: Date;
    keyUsage?: x509.KeyUsageFlags;
    subjectAlternativeName?: Array<
        | { type: 'dns'; value: string }
        | { type: 'email'; value: string }
        | { type: 'url'; value: string }
    >;
    ocspUrl?: string;
    crlUrls?: string[];
}

export interface Leaf {
    certificate: x509.X509Certificate;
    keys: CryptoKeyPair;
}

const NAME_CONSTRAINTS_OID = '2.5.29.30';

async function generateEcKeys(): Promise<CryptoKeyPair> {
    return (await provider.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['sign', 'verify']
    )) as CryptoKeyPair;
}

function toAsnGeneralName(subtree: SyntheticSubtree): AsnGeneralName {
    switch (subtree.type) {
        case 'dn': {
            const der = new x509.Name(subtree.value).toArrayBuffer();
            const asnName = AsnConvert.parse(der, AsnName);
            return new AsnGeneralName({ directoryName: asnName });
        }
        case 'dns':
            return new AsnGeneralName({ dNSName: subtree.value });
        case 'email':
            return new AsnGeneralName({ rfc822Name: subtree.value });
        case 'uri':
            return new AsnGeneralName({ uniformResourceIdentifier: subtree.value });
    }
}

function buildNameConstraintsExtension(
    permitted?: SyntheticSubtree[],
    excluded?: SyntheticSubtree[]
): x509.Extension {
    const nc = new NameConstraints();
    if (permitted && permitted.length > 0) {
        nc.permittedSubtrees = new GeneralSubtrees(
            permitted.map(
                (s) =>
                    new GeneralSubtree({
                        base: toAsnGeneralName(s),
                    })
            )
        );
    }
    if (excluded && excluded.length > 0) {
        nc.excludedSubtrees = new GeneralSubtrees(
            excluded.map(
                (s) =>
                    new GeneralSubtree({
                        base: toAsnGeneralName(s),
                    })
            )
        );
    }
    const encoded = AsnConvert.serialize(nc);
    return new x509.Extension(NAME_CONSTRAINTS_OID, true, encoded);
}

function buildSanExtension(
    sans: NonNullable<CreateLeafOpts['subjectAlternativeName']>
): x509.Extension {
    const names = sans.map((san) => {
        if (san.type === 'dns')
            return new AsnGeneralName({ dNSName: san.value });
        if (san.type === 'email')
            return new AsnGeneralName({ rfc822Name: san.value });
        return new AsnGeneralName({ uniformResourceIdentifier: san.value });
    });
    // Build a GeneralNames SEQUENCE and wrap in an Extension for OID 2.5.29.17
    // @peculiar/asn1-x509 exports GeneralNames as a SEQUENCE of GeneralName.
    return new x509.SubjectAlternativeNameExtension(
        sans.map((san) => {
            if (san.type === 'dns') return new x509.GeneralName('dns', san.value);
            if (san.type === 'email')
                return new x509.GeneralName('email', san.value);
            return new x509.GeneralName('url', san.value);
        })
    );
}

export async function createCa(opts: CreateCaOpts = {}): Promise<GeneratedCa> {
    const keys = await generateEcKeys();
    const now = new Date();
    const cert = await x509.X509CertificateGenerator.createSelfSigned({
        serialNumber: randomSerial(),
        name: opts.name ?? 'CN=Test Root CA',
        notBefore: opts.notBefore ?? new Date(now.getTime() - 1000),
        notAfter:
            opts.notAfter ?? new Date(now.getTime() + 365 * 24 * 3600 * 1000),
        signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
        keys,
        extensions: [
            new x509.BasicConstraintsExtension(true, opts.pathLenConstraint, true),
            new x509.KeyUsagesExtension(
                x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign,
                true
            ),
            await x509.SubjectKeyIdentifierExtension.create(keys.publicKey),
        ],
    });
    return { certificate: cert, keys };
}

export async function createIntermediate(
    parent: GeneratedCa,
    opts: CreateIntermediateOpts = {}
): Promise<GeneratedCa> {
    const keys = await generateEcKeys();
    const now = new Date();
    const extensions: x509.Extension[] = [
        new x509.BasicConstraintsExtension(true, opts.pathLenConstraint, true),
        new x509.KeyUsagesExtension(
            x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign,
            true
        ),
        await x509.SubjectKeyIdentifierExtension.create(keys.publicKey),
        await x509.AuthorityKeyIdentifierExtension.create(parent.certificate, false),
    ];
    if (
        (opts.nameConstraintsPermitted && opts.nameConstraintsPermitted.length > 0) ||
        (opts.nameConstraintsExcluded && opts.nameConstraintsExcluded.length > 0)
    ) {
        extensions.push(
            buildNameConstraintsExtension(
                opts.nameConstraintsPermitted,
                opts.nameConstraintsExcluded
            )
        );
    }
    const cert = await x509.X509CertificateGenerator.create({
        serialNumber: randomSerial(),
        subject: opts.name ?? 'CN=Test Intermediate CA',
        issuer: parent.certificate.subject,
        notBefore: opts.notBefore ?? new Date(now.getTime() - 1000),
        notAfter:
            opts.notAfter ?? new Date(now.getTime() + 180 * 24 * 3600 * 1000),
        publicKey: keys.publicKey,
        signingKey: parent.keys.privateKey,
        signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
        extensions,
    });
    return { certificate: cert, keys };
}

export async function createLeaf(
    issuer: GeneratedCa,
    opts: CreateLeafOpts = {}
): Promise<Leaf> {
    const keys = await generateEcKeys();
    const now = new Date();
    const extensions: x509.Extension[] = [
        new x509.BasicConstraintsExtension(false, undefined, true),
        new x509.KeyUsagesExtension(
            opts.keyUsage ?? x509.KeyUsageFlags.digitalSignature,
            true
        ),
        await x509.SubjectKeyIdentifierExtension.create(keys.publicKey),
        await x509.AuthorityKeyIdentifierExtension.create(issuer.certificate, false),
    ];
    if (opts.subjectAlternativeName && opts.subjectAlternativeName.length > 0) {
        extensions.push(buildSanExtension(opts.subjectAlternativeName));
    }
    if (opts.ocspUrl) {
        const aia = new AuthorityInfoAccessSyntax([
            new AccessDescription({
                accessMethod: '1.3.6.1.5.5.7.48.1', // id-ad-ocsp
                accessLocation: new AsnGeneralName({
                    uniformResourceIdentifier: opts.ocspUrl,
                }),
            }),
        ]);
        extensions.push(
            new x509.Extension(
                '1.3.6.1.5.5.7.1.1',
                false,
                AsnConvert.serialize(aia)
            )
        );
    }
    if (opts.crlUrls && opts.crlUrls.length > 0) {
        const cdp = new CRLDistributionPoints(
            opts.crlUrls.map(
                (url) =>
                    new DistributionPoint({
                        distributionPoint: new DistributionPointName({
                            fullName: new Asn1GeneralNames([
                                new AsnGeneralName({
                                    uniformResourceIdentifier: url,
                                }),
                            ]),
                        }),
                    })
            )
        );
        extensions.push(
            new x509.Extension(
                '2.5.29.31',
                false,
                AsnConvert.serialize(cdp)
            )
        );
    }
    const cert = await x509.X509CertificateGenerator.create({
        serialNumber: randomSerial(),
        subject: opts.name ?? 'CN=Leaf',
        issuer: issuer.certificate.subject,
        notBefore: opts.notBefore ?? new Date(now.getTime() - 1000),
        notAfter:
            opts.notAfter ?? new Date(now.getTime() + 90 * 24 * 3600 * 1000),
        publicKey: keys.publicKey,
        signingKey: issuer.keys.privateKey,
        signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
        extensions,
    });
    return { certificate: cert, keys };
}

function randomSerial(): string {
    const bytes = new Uint8Array(16);
    provider.getRandomValues(bytes);
    return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export interface CreateOcspResponderOpts {
    name?: string;
    notBefore?: Date;
    notAfter?: Date;
    ocspNoCheck?: boolean;
}

export async function createOcspResponder(
    issuer: { certificate: x509.X509Certificate; keys: CryptoKeyPair },
    opts: CreateOcspResponderOpts = {}
): Promise<Leaf> {
    const keys = await generateEcKeys();
    const now = new Date();
    const extensions: x509.Extension[] = [
        new x509.BasicConstraintsExtension(false, undefined, true),
        new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
        new x509.ExtendedKeyUsageExtension(['1.3.6.1.5.5.7.3.9'], true), // id-kp-OCSPSigning
        await x509.SubjectKeyIdentifierExtension.create(keys.publicKey),
        await x509.AuthorityKeyIdentifierExtension.create(issuer.certificate, false),
    ];
    if (opts.ocspNoCheck) {
        // id-pkix-ocsp-nocheck, extension value = ASN.1 NULL (0x05 0x00)
        extensions.push(
            new x509.Extension(
                '1.3.6.1.5.5.7.48.1.5',
                false,
                new Uint8Array([0x05, 0x00])
            )
        );
    }
    const certificate = await x509.X509CertificateGenerator.create({
        serialNumber: randomSerial(),
        subject: opts.name ?? 'CN=OCSP Responder',
        issuer: issuer.certificate.subject,
        notBefore: opts.notBefore ?? new Date(now.getTime() - 1000),
        notAfter:
            opts.notAfter ?? new Date(now.getTime() + 365 * 24 * 3600 * 1000),
        publicKey: keys.publicKey,
        signingKey: issuer.keys.privateKey,
        signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
        extensions,
    });
    return { certificate, keys };
}

export interface CreateCrlOpts {
    revokedSerials: Array<{ serialHex: string; revokedAt: Date; reason?: number }>;
    thisUpdate: Date;
    nextUpdate: Date;
}

export interface CrlResult {
    der: Uint8Array;
}

export async function createCrl(
    issuer: { certificate: x509.X509Certificate; keys: CryptoKeyPair },
    opts: CreateCrlOpts
): Promise<CrlResult> {
    // Build tbsCertList.
    const tbs = new TBSCertList({
        version: Version.v2,
        signature: new AlgorithmIdentifier({ algorithm: '1.2.840.10045.4.3.2' }), // ecdsa-with-SHA256
        issuer: AsnConvert.parse(
            issuer.certificate.subjectName.toArrayBuffer(),
            AsnName
        ),
        thisUpdate: new Time(opts.thisUpdate),
        nextUpdate: new Time(opts.nextUpdate),
        revokedCertificates: opts.revokedSerials.length
            ? opts.revokedSerials.map(
                  (r) =>
                      new RevokedCertificate({
                          userCertificate: hexToBigIntBytes(r.serialHex),
                          revocationDate: new Time(r.revokedAt),
                      })
              )
            : undefined,
    });

    // Sign tbsCertList with the issuer's private key.
    // Use the peculiar provider (same one that generated the keys) to avoid
    // cross-provider CryptoKey incompatibilities under Node.
    const tbsDer = AsnConvert.serialize(tbs);
    const signatureBytes = await provider.subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' },
        issuer.keys.privateKey,
        tbsDer
    );
    const signatureDer = ecdsaIeeeToDer(new Uint8Array(signatureBytes));

    const crl = new CertificateList({
        tbsCertList: tbs,
        signatureAlgorithm: new AlgorithmIdentifier({ algorithm: '1.2.840.10045.4.3.2' }),
        signature: signatureDer,
    });
    return { der: new Uint8Array(AsnConvert.serialize(crl)) };
}

/** Convert a hex string (optionally with leading zeros) into the big-endian BigInteger bytes the ASN.1 layer wants. */
function hexToBigIntBytes(hex: string): Uint8Array {
    const clean = hex.replace(/[^0-9a-fA-F]/g, '');
    const padded = clean.length % 2 === 0 ? clean : '0' + clean;
    const bytes = new Uint8Array(padded.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(padded.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
}

/**
 * WebCrypto returns ECDSA signatures in IEEE P1363 format (r||s fixed-width).
 * ASN.1 CertificateList.signature expects DER-encoded SEQUENCE { r, s }.
 */
function ecdsaIeeeToDer(ieee: Uint8Array): Uint8Array {
    const half = ieee.length / 2;
    const r = trimLeadingZerosAndAddSignByte(ieee.slice(0, half));
    const s = trimLeadingZerosAndAddSignByte(ieee.slice(half));
    const seqLen = 2 + r.length + 2 + s.length;
    const out = new Uint8Array(2 + seqLen);
    out[0] = 0x30;
    out[1] = seqLen;
    out[2] = 0x02;
    out[3] = r.length;
    out.set(r, 4);
    out[4 + r.length] = 0x02;
    out[5 + r.length] = s.length;
    out.set(s, 6 + r.length);
    return out;
}

function trimLeadingZerosAndAddSignByte(bytes: Uint8Array): Uint8Array {
    let start = 0;
    while (start < bytes.length - 1 && bytes[start] === 0) start++;
    const trimmed = bytes.slice(start);
    if (trimmed[0] & 0x80) {
        const padded = new Uint8Array(trimmed.length + 1);
        padded[0] = 0;
        padded.set(trimmed, 1);
        return padded;
    }
    return trimmed;
}
