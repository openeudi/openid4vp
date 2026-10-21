import type { DcqlQuery } from '@openeudi/dcql';

import { buildOpenID4VPDCAPIHandoverSessionTranscript } from '../crypto/session-transcript.js';
import { decryptAuthorizationResponse } from '../decrypt-response.js';
import {
    MissingDecryptionKeyError,
    MissingVerifierEncryptionKeyError,
    WalletErrorResponseError,
} from '../errors.js';
import { verifyAuthorizationResponse } from '../verify.js';
import type { VerifyResult } from '../types/verify.js';
import { DcApiResponseError } from './errors.js';
import {
    describeUnsupportedProtocol,
    isSecureSerializedOrigin,
    isSupportedDcApiProtocol,
} from './protocols.js';
import type { DcApiResponse, VerifyDcApiResponseOptions } from './types.js';

/**
 * Verify the response to an OpenID4VP request made over the W3C Digital
 * Credentials API (OpenID4VP 1.0 Appendix A.4).
 *
 * `response` is the `{ protocol, data }` of the `DigitalCredential` the
 * browser resolved with. The checks, in order:
 *
 * 1. `protocol` is `openid4vp-v1-unsigned` or `openid4vp-v1-signed` (and equals
 *    `options.protocol` when set).
 * 2. `data` is not a wallet error (`{ error }` → {@link WalletErrorResponseError}).
 * 3. The envelope matches `options.responseMode` (default `dc_api.jwt`): a JWE
 *    `{ response }` for `dc_api.jwt`, a plain `{ vp_token }` for `dc_api`. An
 *    unencrypted response to a `dc_api.jwt` request is rejected.
 * 4. The presentation is verified with the origin as the audience: SD-JWT
 *    KB-JWT `aud` MUST be `origin:<origin>` (§A.4, also for signed requests,
 *    §B.3.6), and an mdoc's device signature MUST cover the
 *    `OpenID4VPDCAPIHandover` SessionTranscript (§B.2.6.2).
 *
 * There is no `state` over the DC API (§A.2); bind the response to the
 * server-side session through the `nonce` instead.
 */
export async function verifyDcApiResponse(
    response: DcApiResponse,
    query: DcqlQuery,
    options: VerifyDcApiResponseOptions,
): Promise<VerifyResult> {
    const {
        origin,
        responseMode: requestedResponseMode,
        protocol: expectedProtocol,
        decryptionKey,
        verifierEncryptionJwk,
        ...parseOptions
    } = options;
    const responseMode = requestedResponseMode ?? 'dc_api.jwt';

    if (!isSecureSerializedOrigin(origin)) {
        throw new DcApiResponseError(
            'invalid_origin',
            `origin "${String(origin)}" is not a serialized https origin (scheme://host[:port], no path or trailing slash, no "origin:" prefix)`,
        );
    }
    const audience = `origin:${origin}`;
    const callerAudience = (options as { audience?: unknown }).audience;
    if (callerAudience !== undefined && callerAudience !== audience) {
        throw new DcApiResponseError(
            'audience_conflict',
            `audience is derived from origin over the DC API ("${audience}"); do not pass a different audience`,
        );
    }

    if (typeof response !== 'object' || response === null) {
        throw new DcApiResponseError('malformed_response', 'DC API response must be an object with protocol and data');
    }
    if (!isSupportedDcApiProtocol(response.protocol)) {
        throw new DcApiResponseError('unsupported_protocol', describeUnsupportedProtocol(response.protocol));
    }
    if (expectedProtocol !== undefined && response.protocol !== expectedProtocol) {
        throw new DcApiResponseError(
            'protocol_mismatch',
            `response protocol "${response.protocol}" does not match the requested "${expectedProtocol}"`,
        );
    }

    const data = parseData(response.data);
    throwIfWalletError(data);

    let envelope: Record<string, unknown>;
    if (responseMode === 'dc_api.jwt') {
        if (!isJweEnvelope(data)) {
            throw new DcApiResponseError(
                'vp_token' in data ? 'unencrypted_response' : 'malformed_response',
                'dc_api.jwt was requested, so data must be exactly { response: "<JWE>" }',
            );
        }
        if (!decryptionKey) {
            throw new MissingDecryptionKeyError('decryptionKey is required to verify a dc_api.jwt response');
        }
        envelope = (await decryptAuthorizationResponse(data.response, decryptionKey)) as Record<string, unknown>;
        if (typeof envelope !== 'object' || envelope === null || Array.isArray(envelope)) {
            throw new DcApiResponseError('malformed_response', 'decrypted dc_api.jwt payload is not a JSON object');
        }
        throwIfWalletError(envelope);
    } else if (responseMode === 'dc_api') {
        if ('response' in data) {
            throw new DcApiResponseError(
                'unexpected_encrypted_response',
                'dc_api was requested, but data carries an encrypted "response"',
            );
        }
        envelope = data;
    } else {
        throw new DcApiResponseError(
            'malformed_response',
            `responseMode must be "dc_api" or "dc_api.jwt", got "${String(responseMode)}"`,
        );
    }

    const vpToken = envelope.vp_token;
    if (typeof vpToken !== 'object' || vpToken === null || Array.isArray(vpToken)) {
        throw new DcApiResponseError('malformed_response', 'response must contain vp_token as a JSON object (OpenID4VP 1.0 §8.1)');
    }

    let mdocSessionTranscript = parseOptions.mdocSessionTranscript;
    if (mdocSessionTranscript === undefined && presentsMdoc(vpToken, query)) {
        // dc_api.jwt binds the encryption key's thumbprint into the transcript;
        // without the public JWK the device signature cannot be checked, so
        // say so instead of failing later as an opaque device-auth error.
        if (responseMode === 'dc_api.jwt' && verifierEncryptionJwk === undefined) {
            throw new MissingVerifierEncryptionKeyError(
                'verifierEncryptionJwk is required to build the OpenID4VPDCAPIHandover SessionTranscript for a dc_api.jwt mso_mdoc response',
            );
        }
        mdocSessionTranscript = await buildOpenID4VPDCAPIHandoverSessionTranscript({
            origin,
            nonce: parseOptions.nonce,
            verifierEncryptionJwk: responseMode === 'dc_api.jwt' ? verifierEncryptionJwk : undefined,
        });
    }

    return verifyAuthorizationResponse({ vp_token: vpToken as Record<string, Array<string | object>> }, query, {
        ...parseOptions,
        audience,
        requireKeyBinding: parseOptions.requireKeyBinding ?? true,
        mdocSessionTranscript,
    });
}

function parseData(raw: unknown): Record<string, unknown> {
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

function throwIfWalletError(data: Record<string, unknown>): void {
    if (!('error' in data)) return;
    // Any `error` member is a wallet error here, even a malformed one: it must
    // never fall through to presentation parsing.
    const error = typeof data.error === 'string' ? data.error : 'invalid_response';
    throw new WalletErrorResponseError({ ...data, error });
}

function isJweEnvelope(data: Record<string, unknown>): data is { response: string } {
    return typeof data.response === 'string' && Object.keys(data).length === 1;
}

function presentsMdoc(vpToken: object, query: DcqlQuery): boolean {
    return Object.keys(vpToken).some(
        (id) => query.credentials.find((c) => c.id === id)?.format === 'mso_mdoc',
    );
}
