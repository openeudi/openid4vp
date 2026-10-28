/**
 * A simulated `org-iso-mdoc` wallet (ISO/IEC 18013-7 Annex C), built the way
 * multipaz and the EU AV iOS library answer: read `encryptionInfo` from the
 * request, bind the device signature to the `dcapi` SessionTranscript, and
 * HPKE-seal the CBOR DeviceResponse to the recipient key with the transcript
 * as `info`.
 *
 * The transcript is computed here with cbor-x directly rather than with
 * `buildDCAPIHandoverSessionTranscript`, so the round-trip tests do not
 * check the library against itself. HPKE uses the library's seal, which is
 * pinned by the RFC 9180 A.3.1 vector (tests/crypto/hpke.spec.ts).
 */
import { Encoder as CborEncoder } from 'cbor-x';

import { hpkeSealBase } from '../../src/crypto/hpke.js';
import type { TestKeyMaterial } from './crypto-helpers.js';
import { buildSignedMdoc } from './mdoc-helpers.js';

const cbor = new CborEncoder({ mapsAsObjects: false, useRecords: false, tagUint8Array: false });

export interface IsoMdocRequestData {
    deviceRequest: string;
    encryptionInfo: string;
}

export interface WalletAnswerOptions {
    /** `request.data` exactly as the browser passed it to the wallet. */
    data: IsoMdocRequestData;
    /** The origin the browser gives the wallet. */
    origin: string;
    issuerKey: TestKeyMaterial;
    deviceKey?: TestKeyMaterial;
    /** Default: the docType of the first DocRequest. */
    docType?: string;
    /** Issuer-signed element values by namespace. */
    namespaces: Record<string, Record<string, unknown>>;
    x5chain?: Uint8Array[];
    /** Sign DeviceAuthentication over a transcript for this origin instead (HPKE still uses `origin`). */
    signingOrigin?: string;
    /** Replace the encryptionInfo string the wallet binds (HPKE info and signature). */
    boundEncryptionInfo?: string;
}

export interface IsoMdocCredential {
    protocol: 'org-iso-mdoc';
    data: { response: string };
}

export async function dcapiSessionTranscript(encryptionInfo: string, origin: string): Promise<Uint8Array> {
    const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', cbor.encode([encryptionInfo, origin])));
    return new Uint8Array(cbor.encode([null, null, ['dcapi', hash]]));
}

export function requestedDocType(deviceRequestB64: string): string {
    const request = cbor.decode(Buffer.from(deviceRequestB64, 'base64url')) as Map<string, unknown>;
    const docRequest = (request.get('docRequests') as Map<string, unknown>[])[0];
    const tagged = docRequest.get('itemsRequest') as { value: Uint8Array } | Uint8Array;
    const itemsBytes = tagged instanceof Uint8Array ? tagged : tagged.value;
    const items = cbor.decode(itemsBytes) as Map<string, unknown>;
    return items.get('docType') as string;
}

/** Answer the request: `{ protocol: 'org-iso-mdoc', data: { response } }`. */
export async function answerIsoMdocRequest(opts: WalletAnswerOptions): Promise<IsoMdocCredential> {
    const encryptionInfo = opts.boundEncryptionInfo ?? opts.data.encryptionInfo;
    const recipientPublicKey = recipientKeyOf(encryptionInfo);

    const hpkeInfo = await dcapiSessionTranscript(encryptionInfo, opts.origin);
    const signedTranscript =
        opts.signingOrigin === undefined ? hpkeInfo : await dcapiSessionTranscript(encryptionInfo, opts.signingOrigin);

    const mdoc = await buildSignedMdoc({
        issuerKey: opts.issuerKey,
        deviceKey: opts.deviceKey,
        docType: opts.docType ?? requestedDocType(opts.data.deviceRequest),
        namespaces: opts.namespaces,
        sessionTranscript: signedTranscript,
        x5chain: opts.x5chain,
    });

    return sealDeviceResponse(mdoc.mdocBytes, recipientPublicKey, hpkeInfo);
}

/** HPKE-seal arbitrary DeviceResponse bytes (for malformed-plaintext tests). */
export async function sealDeviceResponse(
    deviceResponse: Uint8Array,
    recipientPublicKey: Uint8Array,
    hpkeInfo: Uint8Array,
): Promise<IsoMdocCredential> {
    const sealed = await hpkeSealBase({ recipientPublicKey, info: hpkeInfo, aad: new Uint8Array(), plaintext: deviceResponse });
    const encrypted = cbor.encode([
        'dcapi',
        new Map<string, Uint8Array>([
            ['enc', sealed.enc],
            ['cipherText', sealed.ciphertext],
        ]),
    ]);
    return { protocol: 'org-iso-mdoc', data: { response: Buffer.from(encrypted).toString('base64url') } };
}

/** The uncompressed recipient key inside a request's encryptionInfo. */
export function recipientKeyOf(encryptionInfo: string): Uint8Array {
    const [, params] = cbor.decode(Buffer.from(encryptionInfo, 'base64url')) as [string, Map<string, unknown>];
    const key = params.get('recipientPublicKey') as Map<number, Uint8Array>;
    return new Uint8Array([0x04, ...key.get(-2)!, ...key.get(-3)!]);
}
