import type { DcqlQuery } from '@openeudi/dcql';

export const pidSdJwtQuery: DcqlQuery = {
    credentials: [
        {
            id: 'pid',
            format: 'dc+sd-jwt',
            meta: { vct_values: ['https://credentials.example.com/pid'] },
            claims: [{ path: ['age_over_18'] }, { path: ['given_name'] }],
        },
    ],
};

export const pidAgeOnlyQuery: DcqlQuery = {
    credentials: [
        {
            id: 'pid',
            format: 'dc+sd-jwt',
            meta: { vct_values: ['https://credentials.example.com/pid'] },
            claims: [{ path: ['age_over_18'] }],
        },
    ],
};

export const pidWithTrustedAuthorities: DcqlQuery = {
    credentials: [
        {
            id: 'pid',
            format: 'dc+sd-jwt',
            meta: { vct_values: ['https://credentials.example.com/pid'] },
            claims: [{ path: ['age_over_18'] }],
            trusted_authorities: [{ type: 'etsi_tl', values: ['https://lotl.europa.eu/test'] }],
        },
    ],
};
