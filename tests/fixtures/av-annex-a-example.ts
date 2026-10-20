/**
 * The OpenID4VP example of the EU Age Verification technical specification,
 * Annex A §A.11 "OpenID for Verifiable Presentations" (Request, Response,
 * Session Transcript), from
 * https://github.com/eu-digital-identity-wallet/av-doc-technical-specification
 * at commit 8b9728752bd8d8eede6077ade4be8900949de2d9.
 *
 * The DeviceResponse was produced by the AV reference implementation: its DS
 * certificate is "Age Verification DS - 001" (EKU 1.3.130.2.0.0.1.2), valid
 * 2025-07-01 → 2026-09-24; the MSO is valid 2026-02-05 → 2026-05-06. Tests
 * that verify it pin the clock inside both windows.
 */

const RESPONSE_URI =
    'https://verifier-backend.ageverification.dev/wallet/direct_post/' +
    'X2b8D86wXoyQIzFcIC3o8vpq_ebw_u2Ulzjx0JrcmNNYlaNGb2cf0GYubMlwWM2XD0UWL8Zhz1z0RfimJd3oKg';

export const ANNEX_A_REQUEST = {
    responseUri: RESPONSE_URI,
    clientId: `redirect_uri:${RESPONSE_URI}`,
    nonce: 'a541f48f-e31c-4244-9b10-86af3150d454',
    state: 'X2b8D86wXoyQIzFcIC3o8vpq_ebw_u2Ulzjx0JrcmNNYlaNGb2cf0GYubMlwWM2XD0UWL8Zhz1z0RfimJd3oKg',
} as const;

/** The query string of the Annex A example `GET /authorize?…`, verbatim. */
export const ANNEX_A_REQUEST_QUERY =
    'response_type=vp_token' +
    '&response_mode=direct_post' +
    '&client_id=redirect_uri%3Ahttps%3A%2F%2Fverifier-backend.ageverification.dev%2Fwallet%2Fdirect_post%2FX2b8D86wXoyQIzFcIC3o8vpq_ebw_u2Ulzjx0JrcmNNYlaNGb2cf0GYubMlwWM2XD0UWL8Zhz1z0RfimJd3oKg' +
    '&response_uri=https%3A%2F%2Fverifier-backend.ageverification.dev%2Fwallet%2Fdirect_post%2FX2b8D86wXoyQIzFcIC3o8vpq_ebw_u2Ulzjx0JrcmNNYlaNGb2cf0GYubMlwWM2XD0UWL8Zhz1z0RfimJd3oKg' +
    '&dcql_query=%7B%22credentials%22%3A%5B%7B%22id%22%3A%22proof_of_age%22%2C%22format%22%3A%22mso_mdoc%22%2C%22meta%22%3A%7B%22doctype_value%22%3A%22eu.europa.ec.av.1%22%7D%2C%22claims%22%3A%5B%7B%22path%22%3A%5B%22eu.europa.ec.av.1%22%2C%22age_over_18%22%5D%7D%5D%7D%5D%7D' +
    '&nonce=a541f48f-e31c-4244-9b10-86af3150d454' +
    '&state=X2b8D86wXoyQIzFcIC3o8vpq_ebw_u2Ulzjx0JrcmNNYlaNGb2cf0GYubMlwWM2XD0UWL8Zhz1z0RfimJd3oKg';

/** "The Session Transcript for the above response", hex. */
export const ANNEX_A_SESSION_TRANSCRIPT_HEX =
    '83f6f682714f70656e494434565048616e646f76657258205d5454853ef21216f8c5dfe774aeb35029cf2e860bbe59aaf79afce879897331';

/** The `proof_of_age` presentation of the example VP Token (base64url DeviceResponse). */
export const ANNEX_A_DEVICE_RESPONSE =
    'o2d2ZXJzaW9uYzEuMGlkb2N1bWVudHOBo2dkb2NUeXBlcWV1LmV1cm9wYS5lYy5hdi4xbGlzc3VlclNpZ25lZKJqbmFtZVNwYWNl' +
    'c6FxZXUuZXVyb3BhLmVjLmF2LjGB2BhYYKRoZGlnZXN0SUQAZnJhbmRvbVggsE66dma5arpjDx0y7RcpOmCT_lOYq9HJlOJ0h9_f' +
    'TP9xZWxlbWVudElkZW50aWZpZXJrYWdlX292ZXJfMThsZWxlbWVudFZhbHVl9Wppc3N1ZXJBdXRohEOhASahGCFZAsEwggK9MIIC' +
    'Y6ADAgECAhRwdsHQFeq8P9Z7P9eqeKbP480vhTAKBggqhkjOPQQDAjBpMSYwJAYDVQQDDB1BZ2UgVmVyaWZpY2F0aW9uIElzc3Vl' +
    'ciBDQSAwMTEyMDAGA1UECgwpQWdlIFZlcmlmaWNhdGlvbiBSZWZlcmVuY2UgSW1wbGVtZW50YXRpb24xCzAJBgNVBAYTAkVVMB4X' +
    'DTI1MDcwMTEwNTcxMVoXDTI2MDkyNDEwNTcxMFowZTEiMCAGA1UEAwwZQWdlIFZlcmlmaWNhdGlvbiBEUyAtIDAwMTEyMDAGA1UE' +
    'CgwpQWdlIFZlcmlmaWNhdGlvbiBSZWZlcmVuY2UgSW1wbGVtZW50YXRpb24xCzAJBgNVBAYTAkVVMFkwEwYHKoZIzj0CAQYIKoZI' +
    'zj0DAQcDQgAEZ4npbnl-LgT388u1ShJBBBJBDbAA-21j3Jd9i101pPk7cfKX2dMIui6VXoVjr6BgSDOq4Q7LGq775BWbW4uQV6OB' +
    '7DCB6TAfBgNVHSMEGDAWgBTLcJWATJke3G0LfP7r4EHKIlQu2DAWBgNVHSUBAf8EDDAKBggrgQICAAABAjBEBgNVHR8EPTA7MDmg' +
    'N6A1hjNodHRwczovL2lzc3Vlci5hZ2V2ZXJpZmljYXRpb24uZGV2L3BraS9FVV9DQV8wMS5jcmwwHQYDVR0OBBYEFP8bupeyyn71' +
    'rqMwFIbx-8mLRZj6MA4GA1UdDwEB_wQEAwIHgDA5BgNVHRIEMjAwBgNVHRIEKTAngiVodHRwczovL2NvbW1pc3Npb24uZXVyb3Bh' +
    'LmV1L2luZGV4X2VuMAoGCCqGSM49BAMCA0gAMEUCIEqvW4Z-bxIC4PSSTei2iTGUcfnOazuctzVfpooBTiY3AiEA3bMms8CJ31WP' +
    'VzLqql6HwNXVFAYkYC81mK_avxgNtmpZAVjYGFkBU6ZnZG9jVHlwZXFldS5ldXJvcGEuZWMuYXYuMWd2ZXJzaW9uYzEuMGx2YWxp' +
    'ZGl0eUluZm-jZnNpZ25lZMB0MjAyNi0wMi0wNVQwMDowMDowMFppdmFsaWRGcm9twHQyMDI2LTAyLTA1VDAwOjAwOjAwWmp2YWxp' +
    'ZFVudGlswHQyMDI2LTA1LTA2VDAwOjAwOjAwWmx2YWx1ZURpZ2VzdHOhcWV1LmV1cm9wYS5lYy5hdi4xoQBYINnnIeVoImnxUHad' +
    'PLft5g9brTw5NiSKDMgxasoA6sUnbWRldmljZUtleUluZm-haWRldmljZUtleaQBAiABIVggfF_NUSbw5rySuQVoMRhjTnPbgjF6' +
    'txpNJFNcCd4E1TsiWCBUUJItFB1pN6wdAjTMZ1yeNBemeTv7-GhJP9X5sUGp8m9kaWdlc3RBbGdvcml0aG1nU0hBLTI1NlhA8nKJ' +
    'weTxmtJK8s6wPRdFiVUoMwWA-2YA0Yrbl4LVGwS3oaMq6K8YZ2AW_UsjOhivJXLaNMN7IGA8XJ4zNghLa2xkZXZpY2VTaWduZWSi' +
    'am5hbWVTcGFjZXPYGEGgamRldmljZUF1dGihb2RldmljZVNpZ25hdHVyZYRDoQEmoPZYQH5z2MDTO76cJTP1l0lgWi4TxjCAwWn3' +
    'LpwcTwcagauTkXqVp-jJfkjZCZa10UwbftWlmHLNprN7DpgmYXhDFT9mc3RhdHVzAA';

/** A moment inside both the DS certificate and the MSO validity windows. */
export const ANNEX_A_VERIFICATION_TIME = new Date('2026-03-01T12:00:00Z');
