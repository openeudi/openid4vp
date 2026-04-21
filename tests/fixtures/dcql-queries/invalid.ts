import type { DcqlQuery } from '@openeudi/dcql';

export const emptyQuery: DcqlQuery = { credentials: [] };

export const unsupportedFormatQuery: DcqlQuery = {
    credentials: [
        {
            id: 'jwt',
            format: 'jwt_vc_json',
            claims: [{ path: ['a'] }],
        },
    ],
};

export const sdJwtMissingVctQuery: DcqlQuery = {
    credentials: [
        {
            id: 'pid',
            format: 'dc+sd-jwt',
            claims: [{ path: ['age_over_18'] }],
        },
    ],
};

export const mdocMissingDoctypeQuery: DcqlQuery = {
    credentials: [
        {
            id: 'mdl',
            format: 'mso_mdoc',
            claims: [{ path: ['ns', 'a'] }],
        },
    ],
};

export const noClaimsQuery: DcqlQuery = {
    credentials: [
        {
            id: 'pid',
            format: 'dc+sd-jwt',
            meta: { vct_values: ['v'] },
        },
    ],
};

export const withClaimSetsQuery: DcqlQuery = {
    credentials: [
        {
            id: 'pid',
            format: 'dc+sd-jwt',
            meta: { vct_values: ['v'] },
            claims: [{ id: 'a', path: ['a'] }],
            claim_sets: [['a']],
        },
    ],
};

export const withCredentialSetsQuery: DcqlQuery = {
    credentials: [
        {
            id: 'pid',
            format: 'dc+sd-jwt',
            meta: { vct_values: ['v'] },
            claims: [{ path: ['a'] }],
        },
    ],
    credential_sets: [{ options: [['pid']] }],
};
