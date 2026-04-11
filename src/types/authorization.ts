import type { CredentialFormat } from './presentation.js';

export interface AuthorizationRequestInput {
    requestedAttributes: string[];
    acceptedFormats: CredentialFormat[];
    responseUri: string;
    nonce: string;
    clientId: string;
    state?: string;
}

export interface AuthorizationRequest {
    uri: string;
    presentationDefinition: object;
    nonce: string;
    state: string;
}
