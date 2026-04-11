import { v4 as uuidv4 } from 'uuid';

import type { AuthorizationRequestInput, AuthorizationRequest } from './types/authorization.js';

export function createAuthorizationRequest(input: AuthorizationRequestInput): AuthorizationRequest {
    const state = input.state ?? uuidv4();

    const presentationDefinition = {
        id: uuidv4(),
        input_descriptors: input.requestedAttributes.map((attr, index) => ({
            id: `descriptor_${index}`,
            format: Object.fromEntries(
                input.acceptedFormats.map((fmt) => {
                    if (fmt === 'sd-jwt-vc') return ['vc+sd-jwt', { 'sd-jwt_alg_values': ['ES256'] }];
                    return ['mso_mdoc', { alg: ['ES256'] }];
                })
            ),
            constraints: {
                fields: [
                    {
                        path: [`$.${attr}`, `$['${attr}']`],
                        filter: { type: attr.startsWith('age_over') ? 'boolean' : 'string' },
                    },
                ],
            },
        })),
    };

    const params = new URLSearchParams({
        response_type: 'vp_token',
        response_mode: 'direct_post',
        response_uri: input.responseUri,
        client_id: input.clientId,
        nonce: input.nonce,
        state,
        presentation_definition: JSON.stringify(presentationDefinition),
    });

    return {
        uri: `openid4vp://authorize?${params.toString()}`,
        presentationDefinition,
        nonce: input.nonce,
        state,
    };
}
