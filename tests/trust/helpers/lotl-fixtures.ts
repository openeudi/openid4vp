import * as x509 from '@peculiar/x509';
import { Crypto as PeculiarCrypto } from '@peculiar/webcrypto';
import * as xmldsig from 'xmldsigjs';
import { DOMParser, XMLSerializer } from '@xmldom/xmldom';

// Reuse the provider already set by synthetic-ca.ts — calling setSync again
// is a no-op. Import ordering in tests ensures this runs after synthetic-ca.
const provider = new PeculiarCrypto();
x509.cryptoProvider.set(provider as unknown as Crypto);

// xmldsigjs requires a WebCrypto engine to be registered once per process.
// Calling setEngine again is idempotent and harmless.
xmldsig.Application.setEngine('NodeJS', provider as unknown as Crypto);

// xml-core (xmldsigjs's internal dep) checks `typeof DOMParser !== 'undefined'`
// before falling back to `getNodeDependency('DOMParser')`. Setting the globals
// here ensures Sign() and Stringify() work in the Node.js test environment
// without having to import xml-core's setNodeDependencies directly (xml-core
// is not available as a top-level package — it only exists under
// node_modules/xmldsigjs/node_modules/xml-core).
const g = globalThis as Record<string, unknown>;
if (typeof g['DOMParser'] === 'undefined') {
    g['DOMParser'] = DOMParser;
}
if (typeof g['XMLSerializer'] === 'undefined') {
    g['XMLSerializer'] = XMLSerializer;
}

export interface LotlSigner {
    readonly certificate: x509.X509Certificate;
    readonly keys: CryptoKeyPair;
}

export interface CreateLotlSignerOpts {
    readonly name?: string;
    readonly notBefore?: Date;
    readonly notAfter?: Date;
}

/**
 * Build a self-signed cert suitable for signing LOTL / national-TL XML in
 * tests. Distinct from `createCa` in `synthetic-ca.ts` because LOTL signers
 * are NOT CAs — they do not issue subordinate certs.
 */
export async function createLotlSigner(
    opts: CreateLotlSignerOpts = {}
): Promise<LotlSigner> {
    const keys = await provider.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['sign', 'verify']
    );
    const now = opts.notBefore ?? new Date();
    const end = opts.notAfter ?? new Date(now.getTime() + 365 * 24 * 3600_000);
    const certificate = await x509.X509CertificateGenerator.createSelfSigned({
        name: opts.name ?? 'CN=LOTL Test Signer',
        serialNumber: '01',
        notBefore: now,
        notAfter: end,
        keys,
        signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
        extensions: [
            new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
        ],
    });
    return { certificate, keys };
}

// ---------------------------------------------------------------------------
// XML builder types
// ---------------------------------------------------------------------------

const TSL_NS = 'http://uri.etsi.org/02231/v2#';

export interface BuildLotlOpts {
    readonly issueDate: Date;
    readonly nextUpdate: Date | null;
    readonly pointers: ReadonlyArray<{
        readonly country: string;
        readonly tslLocation: string;
        readonly signingCertificates: ReadonlyArray<x509.X509Certificate>;
    }>;
}

export interface BuildNationalTlOpts {
    readonly country: string;
    readonly issueDate: Date;
    readonly nextUpdate: Date | null;
    readonly services: ReadonlyArray<{
        readonly providerName: string;
        readonly serviceTypeIdentifier: string;
        readonly serviceStatus: string;
        readonly serviceName: string;
        readonly certificates: ReadonlyArray<x509.X509Certificate>;
        readonly additionalServiceInformationUris: readonly string[];
    }>;
}

// ---------------------------------------------------------------------------
// Public builders
// ---------------------------------------------------------------------------

export async function buildSignedLotlXml(
    signer: LotlSigner,
    opts: BuildLotlOpts
): Promise<string> {
    const pointersXml = opts.pointers
        .map((p) => {
            const certsXml = p.signingCertificates
                .map((c) => `<X509Certificate>${certToBase64(c)}</X509Certificate>`)
                .join('');
            return `
<OtherTSLPointer>
  <TSLLocation>${escapeXml(p.tslLocation)}</TSLLocation>
  <AdditionalInformation>
    <OtherInformation>
      <SchemeTerritory>${escapeXml(p.country)}</SchemeTerritory>
      <ServiceDigitalIdentities>
        <ServiceDigitalIdentity>
          <DigitalId>
            ${certsXml}
          </DigitalId>
        </ServiceDigitalIdentity>
      </ServiceDigitalIdentities>
    </OtherInformation>
  </AdditionalInformation>
</OtherTSLPointer>`;
        })
        .join('');

    const nextUpdateXml = opts.nextUpdate
        ? `<NextUpdate><dateTime>${opts.nextUpdate.toISOString()}</dateTime></NextUpdate>`
        : '<NextUpdate/>';

    const xml = `<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="${TSL_NS}" Id="tsl-root">
  <SchemeInformation>
    <TSLVersionIdentifier>5</TSLVersionIdentifier>
    <TSLSequenceNumber>1</TSLSequenceNumber>
    <ListIssueDateTime>${opts.issueDate.toISOString()}</ListIssueDateTime>
    ${nextUpdateXml}
    <PointersToOtherTSL>${pointersXml}</PointersToOtherTSL>
  </SchemeInformation>
</TrustServiceStatusList>`;
    return signXml(xml, signer);
}

export async function buildSignedNationalTlXml(
    signer: LotlSigner,
    opts: BuildNationalTlOpts
): Promise<string> {
    const servicesXml = opts.services
        .map((s) => {
            const certsXml = s.certificates
                .map((c) => `<X509Certificate>${certToBase64(c)}</X509Certificate>`)
                .join('');
            const asiXml = s.additionalServiceInformationUris
                .map(
                    (u) =>
                        `<AdditionalServiceInformation><URI>${escapeXml(u)}</URI></AdditionalServiceInformation>`
                )
                .join('');
            return `
<TSPService>
  <ServiceInformation>
    <ServiceTypeIdentifier>${escapeXml(s.serviceTypeIdentifier)}</ServiceTypeIdentifier>
    <ServiceName><Name xml:lang="en">${escapeXml(s.serviceName)}</Name></ServiceName>
    <ServiceDigitalIdentity><DigitalId>${certsXml}</DigitalId></ServiceDigitalIdentity>
    <ServiceStatus>${escapeXml(s.serviceStatus)}</ServiceStatus>
    <ServiceInformationExtensions>${asiXml}</ServiceInformationExtensions>
  </ServiceInformation>
</TSPService>`;
        })
        .join('');

    const providerName = opts.services[0]?.providerName ?? 'Unknown';
    const nextUpdateXml = opts.nextUpdate
        ? `<NextUpdate><dateTime>${opts.nextUpdate.toISOString()}</dateTime></NextUpdate>`
        : '<NextUpdate/>';

    const xml = `<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="${TSL_NS}" Id="tsl-root">
  <SchemeInformation>
    <TSLVersionIdentifier>5</TSLVersionIdentifier>
    <TSLSequenceNumber>1</TSLSequenceNumber>
    <SchemeTerritory>${escapeXml(opts.country)}</SchemeTerritory>
    <ListIssueDateTime>${opts.issueDate.toISOString()}</ListIssueDateTime>
    ${nextUpdateXml}
  </SchemeInformation>
  <TrustServiceProviderList>
    <TrustServiceProvider>
      <TSPInformation>
        <TSPName><Name xml:lang="en">${escapeXml(providerName)}</Name></TSPName>
      </TSPInformation>
      <TSPServices>${servicesXml}</TSPServices>
    </TrustServiceProvider>
  </TrustServiceProviderList>
</TrustServiceStatusList>`;
    return signXml(xml, signer);
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Sign an XML string with an enveloped ECDSA-SHA-256 signature over the
 * element whose Id="tsl-root". The signer cert is embedded in the
 * <X509Data> block so xmldsigjs can verify without an external key argument.
 *
 * Deviation from the reference snippet: Sign() returns Promise<Signature>
 * (an xml-core XmlObject), NOT an Element. We call signed.GetXml() to obtain
 * the DOM Element and append it to the document root ourselves.
 */
async function signXml(xml: string, signer: LotlSigner): Promise<string> {
    const doc = new DOMParser().parseFromString(xml, 'application/xml');
    const signed = new xmldsig.SignedXml();
    await signed.Sign(
        { name: 'ECDSA', hash: 'SHA-256' } as EcdsaParams,
        signer.keys.privateKey,
        doc,
        {
            references: [
                {
                    uri: '#tsl-root',
                    hash: 'SHA-256',
                    transforms: ['enveloped', 'c14n'],
                },
            ],
            keyValue: signer.keys.publicKey,
            x509: [certToBase64(signer.certificate)],
        }
    );

    // Sign() mutates the internal signature object and returns it, but does
    // NOT append to the document. Retrieve the Element and append manually.
    const sigElement = signed.GetXml();
    if (!sigElement) {
        throw new Error('xmldsigjs Sign() produced no element');
    }
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    doc.documentElement!.appendChild(sigElement as any);
    return new XMLSerializer().serializeToString(doc);
}

function certToBase64(cert: x509.X509Certificate): string {
    const der = new Uint8Array(cert.rawData);
    return bytesToBase64(der);
}

function bytesToBase64(bytes: Uint8Array): string {
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return (globalThis as unknown as { btoa: (s: string) => string }).btoa(bin);
}

function escapeXml(s: string): string {
    return s
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&apos;');
}
