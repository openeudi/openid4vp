import { X509Certificate } from '@peculiar/x509';
import type { Document as XmlDocument, Element as XmlElement } from '@xmldom/xmldom';
import type { LotlFetcher } from './LotlFetcher.js';
import type {
    LotlSnapshot,
    NationalTlSnapshot,
    TspService,
} from './lotl-types.js';
import { base64DerToCert, firstChild, textOfDeep } from './xml-util.js';

const TSL_NS = 'http://uri.etsi.org/02231/v2#';

export interface NationalTlResolverOptions {
    fetcher: LotlFetcher;
}

/**
 * Private — NOT exported from the package root. Given a verified
 * `LotlSnapshot`, fetches + parses every national TL it points to.
 * Fetches run in parallel; individual failures are logged via
 * `console.warn` and skipped (spec §8.4 graceful degradation).
 */
export class NationalTlResolver {
    constructor(private readonly opts: NationalTlResolverOptions) {}

    async resolve(lotl: LotlSnapshot): Promise<NationalTlSnapshot[]> {
        const tasks = lotl.pointers.map(async (pointer) => {
            try {
                const doc = await this.opts.fetcher.fetchSigned(
                    pointer.tslLocation,
                    pointer.signingCertificates
                );
                return parseNationalTl(doc, pointer.country);
            } catch (err) {
                console.warn(
                    `[openid4vp] national TL for ${pointer.country} failed: ${(err as Error).message}`
                );
                return null;
            }
        });
        const results = await Promise.all(tasks);
        return results.filter((r): r is NationalTlSnapshot => r !== null);
    }
}

function parseNationalTl(doc: XmlDocument, country: string): NationalTlSnapshot {
    const root = doc.documentElement!;
    const scheme = firstChild(root, TSL_NS, 'SchemeInformation');
    if (!scheme) {
        throw new Error(
            `national TL for ${country}: missing SchemeInformation element`
        );
    }
    const issueText = firstChild(scheme, TSL_NS, 'ListIssueDateTime')
        ?.textContent?.trim();
    if (!issueText) {
        throw new Error(
            `national TL for ${country}: missing ListIssueDateTime element`
        );
    }
    const issueDate = new Date(issueText);
    if (isNaN(issueDate.getTime())) {
        throw new Error(
            `national TL for ${country}: invalid ListIssueDateTime "${issueText}"`
        );
    }
    const nextUpdate = parseNextUpdate(scheme);
    const services: TspService[] = [];
    const tspListEl = firstChild(root, TSL_NS, 'TrustServiceProviderList');
    if (tspListEl) {
        const providers = tspListEl.getElementsByTagNameNS(
            TSL_NS,
            'TrustServiceProvider'
        );
        for (let i = 0; i < providers.length; i++) {
            const provider = providers.item(i)!;
            // Provider name may be under TSPInformation/TSPName/Name or TSPName/Name.
            // Use deep search to handle both structures.
            const providerName =
                textOfDeep(provider as XmlElement, TSL_NS, 'Name') ??
                'Unknown';
            const servicesContainer = firstChild(provider as XmlElement, TSL_NS, 'TSPServices');
            if (!servicesContainer) continue;
            const serviceEls = servicesContainer.getElementsByTagNameNS(
                TSL_NS,
                'TSPService'
            );
            for (let j = 0; j < serviceEls.length; j++) {
                const s = parseService(
                    serviceEls.item(j)! as XmlElement,
                    providerName,
                    country
                );
                if (s) services.push(s);
            }
        }
    }
    return { country, issueDate, nextUpdate, services };
}

function parseService(
    el: XmlElement,
    providerName: string,
    country: string
): TspService | null {
    const info = firstChild(el, TSL_NS, 'ServiceInformation');
    if (!info) return null;
    const typeId = firstChild(info, TSL_NS, 'ServiceTypeIdentifier')
        ?.textContent?.trim();
    const status = firstChild(info, TSL_NS, 'ServiceStatus')
        ?.textContent?.trim();
    if (!typeId || !status) return null;
    const nameEl = firstChild(info, TSL_NS, 'ServiceName');
    const serviceName =
        (nameEl &&
            nameEl.getElementsByTagNameNS(TSL_NS, 'Name').item(0)?.textContent?.trim()) ||
        'Unknown Service';
    const digitalId = firstChild(info, TSL_NS, 'ServiceDigitalIdentity');
    const certs: X509Certificate[] = [];
    if (digitalId) {
        const certEls = digitalId.getElementsByTagNameNS(TSL_NS, 'X509Certificate');
        for (let i = 0; i < certEls.length; i++) {
            const cert = base64DerToCert(certEls.item(i)!.textContent ?? '');
            if (cert) certs.push(cert);
        }
    }
    const asiContainer = firstChild(info, TSL_NS, 'ServiceInformationExtensions');
    const asiUris: string[] = [];
    if (asiContainer) {
        const uris = asiContainer.getElementsByTagNameNS(TSL_NS, 'URI');
        for (let i = 0; i < uris.length; i++) {
            const u = uris.item(i)!.textContent?.trim();
            if (u) asiUris.push(u);
        }
    }
    return {
        providerName,
        country,
        serviceTypeIdentifier: typeId,
        serviceStatus: status,
        serviceName,
        certificates: certs,
        additionalServiceInformationUris: asiUris,
    };
}

function parseNextUpdate(scheme: XmlElement | null): Date | null {
    if (!scheme) return null;
    const nu = firstChild(scheme, TSL_NS, 'NextUpdate');
    if (!nu) return null;
    const dt = firstChild(nu, TSL_NS, 'dateTime')?.textContent?.trim();
    if (!dt) return null;
    const d = new Date(dt);
    return isNaN(d.getTime()) ? null : d;
}

