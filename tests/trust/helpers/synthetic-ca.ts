import { AsnConvert } from '@peculiar/asn1-schema';
import {
    GeneralName as AsnGeneralName,
    GeneralSubtree,
    GeneralSubtrees,
    Name as AsnName,
    NameConstraints,
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
