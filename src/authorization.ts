import { v4 as uuidv4 } from 'uuid';
import type { DcqlQuery } from '@openeudi/dcql';

import type { AuthorizationRequestInput, AuthorizationRequest } from './types/authorization.js';
import { serializeVerifierInfo, verifierInfoProblem } from './verifier-info.js';

export function createAuthorizationRequest(
    input: AuthorizationRequestInput,
    query: DcqlQuery,
): AuthorizationRequest {
    if (!input.clientId) throw new TypeError('clientId is required');
    if (!input.nonce) throw new TypeError('nonce is required');
    if (!input.responseUri) throw new TypeError('responseUri is required');
    if (input.verifierInfo !== undefined) {
        const problem = verifierInfoProblem(input.verifierInfo, query);
        if (problem) throw new TypeError(problem);
    }

    const state = input.state ?? uuidv4();
    const responseMode = input.responseMode ?? 'direct_post';

    const params = new URLSearchParams({
        response_type: 'vp_token',
        response_mode: responseMode,
        response_uri: input.responseUri,
        client_id: input.clientId,
        nonce: input.nonce,
        state,
        dcql_query: JSON.stringify(query),
    });
    if (input.verifierInfo !== undefined) {
        params.set('verifier_info', JSON.stringify(serializeVerifierInfo(input.verifierInfo)));
    }

    return {
        uri: `openid4vp://authorize?${params.toString()}`,
        dcqlQuery: query,
        nonce: input.nonce,
        state,
    };
}
