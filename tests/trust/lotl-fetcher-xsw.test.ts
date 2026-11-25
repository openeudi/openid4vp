import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { DOMParser, XMLSerializer } from '@xmldom/xmldom';
import type { Document as XmlDocument, Element as XmlElement } from '@xmldom/xmldom';
import { LotlFetcher } from '../../src/trust/LotlFetcher.js';
import { LotlParser } from '../../src/trust/LotlParser.js';
import { EU_LOTL_SIGNING_ANCHORS } from '../../src/trust/lotl-signing-anchors.js';
import { firstChild } from '../../src/trust/xml-util.js';
import { LotlSignatureError } from '../../src/errors.js';
import type { Fetcher } from '../../src/trust/Fetcher.js';
import {
    buildSignedLotlXml,
    buildSignedNationalTlXml,
    createLotlSigner,
    type LotlSigner,
} from './helpers/lotl-fixtures.js';

/**
 * XML Signature Wrapping (GHSA-28mg-45r4-j8jr). A trusted list may only be
 * read from content its one enveloped signature covers: the signature must sit
 * directly under the root and reference the root itself, nothing unsigned may
 * hide in it, and the document handed back carries no signature at all.
 */

const TSL_NS = 'http://uri.etsi.org/02231/v2#';
const DS_NS = 'http://www.w3.org/2000/09/xmldsig#';
const URL = 'http://ec.test/eu-lotl.xml';

function respond(xml: string): Response {
    return new Response(xml, { status: 200, headers: { 'content-type': 'application/xml' } });
}

function fetcherFor(xml: string): LotlFetcher {
    const fetcher: Fetcher = async () => respond(xml);
    return new LotlFetcher({ fetcher });
}

function parse(xml: string): XmlDocument {
    return new DOMParser().parseFromString(xml, 'application/xml');
}

function serialize(doc: XmlDocument): string {
    return new XMLSerializer().serializeToString(doc);
}

function child(parent: XmlElement, ns: string, name: string): XmlElement {
    for (let n = parent.firstChild; n; n = n.nextSibling) {
        const el = n as XmlElement;
        if (n.nodeType === 1 && el.namespaceURI === ns && el.localName === name) return el;
    }
    throw new Error(`fixture has no {${ns}}${name} under ${parent.localName}`);
}

function signatureOf(doc: XmlDocument): XmlElement {
    return child(doc.documentElement!, DS_NS, 'Signature');
}

async function genuineLotl(signer: LotlSigner): Promise<string> {
    return buildSignedLotlXml(signer, {
        issueDate: new Date('2026-04-01'),
        nextUpdate: new Date('2026-10-01'),
        pointers: [],
    });
}

/** An unsigned SchemeInformation that points DE at an attacker's list. */
async function forgedScheme(rogue: LotlSigner): Promise<XmlElement> {
    const forged = parse(
        await buildSignedLotlXml(rogue, {
            issueDate: new Date('2026-04-01'),
            nextUpdate: new Date('2026-10-01'),
            pointers: [
                {
                    country: 'DE',
                    tslLocation: 'http://attacker.example/de-tl.xml',
                    signingCertificates: [rogue.certificate],
                },
            ],
        })
    );
    return child(forged.documentElement!, TSL_NS, 'SchemeInformation');
}

describe('LotlFetcher — signature wrapping (GHSA-28mg-45r4-j8jr)', () => {
    it('refuses a signed list wrapped in an unsigned root that carries its own SchemeInformation', async () => {
        const trusted = await createLotlSigner({ name: 'CN=Trusted LOTL Signer' });
        const rogue = await createLotlSigner({ name: 'CN=Rogue National Signer' });
        const signed = parse(await genuineLotl(trusted));

        const wrapper = parse(`<TrustServiceStatusList xmlns="${TSL_NS}"/>`);
        wrapper.documentElement!.appendChild(wrapper.importNode(await forgedScheme(rogue), true));
        wrapper.documentElement!.appendChild(wrapper.importNode(signed.documentElement!, true));

        await expect(
            fetcherFor(serialize(wrapper)).fetchSigned(URL, [trusted.certificate])
        ).rejects.toBeInstanceOf(LotlSignatureError);
    });

    it('refuses an unsigned SchemeInformation hidden in a ds:Object of a signature moved before the content', async () => {
        const trusted = await createLotlSigner({ name: 'CN=Trusted LOTL Signer' });
        const rogue = await createLotlSigner({ name: 'CN=Rogue National Signer' });
        const doc = parse(await genuineLotl(trusted));
        const root = doc.documentElement!;
        const signature = signatureOf(doc);

        const object = doc.createElementNS(DS_NS, 'ds:Object');
        object.appendChild(doc.importNode(await forgedScheme(rogue), true));
        signature.appendChild(object);
        root.removeChild(signature);
        root.insertBefore(signature, root.firstChild);

        await expect(
            fetcherFor(serialize(doc)).fetchSigned(URL, [trusted.certificate])
        ).rejects.toBeInstanceOf(LotlSignatureError);
    });

    it('refuses an unsigned TrustServiceProviderList hidden in a ds:Object of a national TL', async () => {
        const trusted = await createLotlSigner({ name: 'CN=Trusted DE TL Signer' });
        const rogue = await createLotlSigner({ name: 'CN=Rogue CA' });
        const doc = parse(
            await buildSignedNationalTlXml(trusted, {
                country: 'DE',
                issueDate: new Date('2026-04-01'),
                nextUpdate: new Date('2026-10-01'),
                services: [],
            })
        );
        const forged = parse(
            await buildSignedNationalTlXml(rogue, {
                country: 'DE',
                issueDate: new Date('2026-04-01'),
                nextUpdate: new Date('2026-10-01'),
                services: [
                    {
                        providerName: 'Rogue',
                        serviceTypeIdentifier: 'http://uri.etsi.org/TrstSvc/Svctype/CA/QC',
                        serviceStatus: 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted',
                        serviceName: 'Rogue CA',
                        certificates: [rogue.certificate],
                        additionalServiceInformationUris: [],
                    },
                ],
            })
        );
        const root = doc.documentElement!;
        const signature = signatureOf(doc);
        const object = doc.createElementNS(DS_NS, 'ds:Object');
        object.appendChild(
            doc.importNode(child(forged.documentElement!, TSL_NS, 'TrustServiceProviderList'), true)
        );
        signature.appendChild(object);
        root.removeChild(signature);
        root.insertBefore(signature, child(root, TSL_NS, 'SchemeInformation').nextSibling);

        await expect(
            fetcherFor(serialize(doc)).fetchSigned('http://ec.test/de-tl.xml', [trusted.certificate])
        ).rejects.toBeInstanceOf(LotlSignatureError);
    });

    it('refuses a signature that is not a direct child of the root', async () => {
        const trusted = await createLotlSigner();
        const doc = parse(await genuineLotl(trusted));
        const root = doc.documentElement!;
        const signature = signatureOf(doc);
        root.removeChild(signature);
        child(root, TSL_NS, 'SchemeInformation').appendChild(signature);

        await expect(
            fetcherFor(serialize(doc)).fetchSigned(URL, [trusted.certificate])
        ).rejects.toBeInstanceOf(LotlSignatureError);
    });

    it('refuses a document with a second ds:Signature', async () => {
        const trusted = await createLotlSigner();
        const doc = parse(await genuineLotl(trusted));
        const signature = signatureOf(doc);
        doc.documentElement!.appendChild(signature.cloneNode(true));

        await expect(
            fetcherFor(serialize(doc)).fetchSigned(URL, [trusted.certificate])
        ).rejects.toBeInstanceOf(LotlSignatureError);
    });

    it('refuses a reference whose Id is carried by a second element', async () => {
        const trusted = await createLotlSigner();
        const doc = parse(await genuineLotl(trusted));
        const decoy = doc.createElementNS(TSL_NS, 'Decoy');
        decoy.setAttribute('Id', 'tsl-root');
        signatureOf(doc).appendChild(decoy);

        await expect(
            fetcherFor(serialize(doc)).fetchSigned(URL, [trusted.certificate])
        ).rejects.toBeInstanceOf(LotlSignatureError);
    });

    it('returns the verified document without its ds:Signature', async () => {
        const trusted = await createLotlSigner();
        const doc = await fetcherFor(await genuineLotl(trusted)).fetchSigned(URL, [trusted.certificate]);

        expect(doc.getElementsByTagNameNS(DS_NS, 'Signature').length).toBe(0);
        expect(new LotlParser().parse(doc as unknown as Document).issueDate.toISOString()).toBe(
            '2026-04-01T00:00:00.000Z'
        );
    });

    it('still verifies the committed EU LOTL snapshot against the built-in signing anchors', async () => {
        const xml = readFileSync(new globalThis.URL('../fixtures/lotl-snapshot-2026-04-23.xml', import.meta.url), 'utf8');
        const doc = await fetcherFor(xml).fetchSigned(URL, EU_LOTL_SIGNING_ANCHORS);

        expect(doc.getElementsByTagNameNS(DS_NS, 'Signature').length).toBe(0);
        expect(new LotlParser().parse(doc as unknown as Document).pointers.length).toBeGreaterThan(20);
    });
});

describe('firstChild', () => {
    it('returns a direct child, never a deeper descendant that comes first', () => {
        const doc = parse(
            `<TrustServiceStatusList xmlns="${TSL_NS}" xmlns:ds="${DS_NS}">` +
                '<ds:Signature><ds:Object><SchemeInformation><TSLSequenceNumber>9</TSLSequenceNumber></SchemeInformation></ds:Object></ds:Signature>' +
                '<SchemeInformation><TSLSequenceNumber>1</TSLSequenceNumber></SchemeInformation>' +
                '</TrustServiceStatusList>'
        );
        const scheme = firstChild(doc.documentElement!, TSL_NS, 'SchemeInformation');
        expect(scheme?.parentNode).toBe(doc.documentElement);
        expect(scheme?.textContent).toBe('1');
    });

    it('returns null when the name only occurs deeper down', () => {
        const doc = parse(
            `<TrustServiceStatusList xmlns="${TSL_NS}"><Wrapper><SchemeInformation/></Wrapper></TrustServiceStatusList>`
        );
        expect(firstChild(doc.documentElement!, TSL_NS, 'SchemeInformation')).toBeNull();
    });
});
