import type { DcqlQuery } from '@openeudi/dcql';

export const mdlMdocQuery: DcqlQuery = {
    credentials: [
        {
            id: 'mdl',
            format: 'mso_mdoc',
            meta: { doctype_value: 'eu.europa.ec.eudi.pid.1' },
            claims: [{ path: ['eu.europa.ec.eudi.pid.1', 'age_over_18'] }],
        },
    ],
};
