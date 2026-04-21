import type { DcqlQuery } from '@openeudi/dcql';

export interface AuthorizationRequestInput {
    clientId: string;
    responseUri: string;
    nonce: string;
    state?: string;
    responseMode?: 'direct_post' | 'direct_post.jwt';
}

export interface AuthorizationRequest {
    uri: string;
    dcqlQuery: DcqlQuery;
    nonce: string;
    state: string;
}
