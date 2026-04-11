import { MdocParser } from './parsers/mdoc.parser.js';
import type { ParseOptions, ICredentialParser } from './parsers/parser.interface.js';
import { SdJwtParser } from './parsers/sd-jwt.parser.js';
import type { PresentationResult } from './types/presentation.js';

const parsers: ICredentialParser[] = [new SdJwtParser(), new MdocParser()];

export async function parsePresentation(vpToken: unknown, options: ParseOptions): Promise<PresentationResult> {
    for (const parser of parsers) {
        if (parser.canParse(vpToken)) {
            return parser.parse(vpToken, options);
        }
    }

    return {
        valid: false,
        format: 'sd-jwt-vc',
        claims: {},
        issuer: { certificate: new Uint8Array(), country: '' },
        error: 'Unsupported credential format',
    };
}

export type { ParseOptions } from './parsers/parser.interface.js';
