import { WalletErrorResponseError } from '../errors.js';
import { DcApiResponseError } from './errors.js';
import { describeUnsupportedProtocol, isSupportedDcApiProtocol } from './protocols.js';
import type { DcApiResponse } from './types.js';

/** The credential's `data` as an object; a JSON string (as some frontends post it) is parsed. */
export function parseDcApiData(raw: unknown): Record<string, unknown> {
    let data = raw;
    if (typeof data === 'string') {
        try {
            data = JSON.parse(data);
        } catch (err) {
            throw new DcApiResponseError('malformed_response', 'DC API response data is a string but not valid JSON', {
                cause: err as Error,
            });
        }
    }
    if (typeof data !== 'object' || data === null || Array.isArray(data)) {
        throw new DcApiResponseError('malformed_response', 'DC API response data must be a JSON object');
    }
    return data as Record<string, unknown>;
}

export function throwIfDcApiWalletError(data: Record<string, unknown>): void {
    if (!('error' in data)) return;
    // Any `error` member is a wallet error here, even a malformed one: it must
    // never fall through to presentation parsing.
    const error = typeof data.error === 'string' ? data.error : 'invalid_response';
    throw new WalletErrorResponseError({ ...data, error });
}

/**
 * The `data` of an `org-iso-mdoc` credential: the response must be an object
 * whose `protocol` is `org-iso-mdoc`, and `data` must not be a wallet error.
 */
export function isoMdocResponseData(response: DcApiResponse): Record<string, unknown> {
    if (typeof response !== 'object' || response === null) {
        throw new DcApiResponseError('malformed_response', 'DC API response must be an object with protocol and data');
    }
    if (!isSupportedDcApiProtocol(response.protocol)) {
        throw new DcApiResponseError('unsupported_protocol', describeUnsupportedProtocol(response.protocol));
    }
    if (response.protocol !== 'org-iso-mdoc') {
        throw new DcApiResponseError(
            'protocol_mismatch',
            `response protocol "${response.protocol}" does not match the requested "org-iso-mdoc"`,
        );
    }
    const data = parseDcApiData(response.data);
    throwIfDcApiWalletError(data);
    return data;
}
