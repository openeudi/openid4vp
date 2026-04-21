import type { DcqlQuery } from '@openeudi/dcql';

export const mdlMdocQuery: DcqlQuery = {
    credentials: [
        {
            id: 'mdl',
            format: 'mso_mdoc',
            meta: { doctype_value: 'org.iso.18013.5.1.mDL' },
            claims: [{ path: ['org.iso.18013.5.1', 'age_over_18'] }],
        },
    ],
};
