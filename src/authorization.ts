import { v4 as uuidv4 } from 'uuid';
import type { DcqlQuery } from '@openeudi/dcql';

import type { AuthorizationRequestInput, AuthorizationRequest } from './types/authorization.js';

export function createAuthorizationRequest(
    input: AuthorizationRequestInput,
    query: DcqlQuery,
): AuthorizationRequest {
    if (!input.clientId) throw new TypeError('clientId is required');
    if (!input.nonce) throw new TypeError('nonce is required');
    if (!input.responseUri) throw new TypeError('responseUri is required');

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

    return {
        uri: `openid4vp://authorize?${params.toString()}`,
        dcqlQuery: query,
        nonce: input.nonce,
        state,
    };
}
