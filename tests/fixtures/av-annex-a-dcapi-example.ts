/**
 * The "W3C Digital Credentials API" example of the EU Age Verification
 * technical specification, Annex A §A.11 (Request, Response, DeviceResponse,
 * Session Transcript), from
 * https://github.com/eu-digital-identity-wallet/av-doc-technical-specification
 * at commit 8b97287 (2026-09-02).
 *
 * The example gives neither the origin nor the recipient private key, so the
 * encrypted `response` cannot be opened and the transcript cannot be
 * recomputed. What it does pin:
 * - the request bytes (`deviceRequest`, `encryptionInfo`);
 * - the SessionTranscript layout (`[null, null, ["dcapi", h'…']]`);
 * - a DeviceResponse produced by the AV reference implementation whose device
 *   signature covers that transcript. The spec prints it in CBOR diagnostic
 *   notation; `ANNEX_A_DCAPI_DEVICE_RESPONSE` re-encodes it (definite lengths,
 *   map keys in the printed order) — its issuer signature and digests verify,
 *   so the encoding matches the original bytes.
 *
 * Same AV reference PKI as av-annex-a-example.ts: DS "Age Verification DS -
 * 001", valid 2025-07-01 → 2026-09-24; MSO valid 2026-02-05 → 2026-05-06.
 */

/** `data.deviceRequest` of the example request, verbatim. */
export const ANNEX_A_DCAPI_DEVICE_REQUEST =
    'omd2ZXJzaW9uYzEuMGtkb2NSZXF1ZXN0c4GhbGl0ZW1zUmVxdWVzdNgYWEeiZ2RvY1R5cGVxZXUuZXVyb3BhLmVjLmF2LjFqbmFt' +
    'ZVNwYWNlc6FxZXUuZXVyb3BhLmVjLmF2LjGha2FnZV9vdmVyXzE49A';

/** `data.encryptionInfo` of the example request, verbatim. */
export const ANNEX_A_DCAPI_ENCRYPTION_INFO =
    'gmVkY2FwaaJlbm9uY2VQtJvGiCZ0egQII8fQgu960HJyZWNpcGllbnRQdWJsaWNLZXmkAQIgASFYIMmliVBWgs8KKpAychO3py0E' +
    'qagows-CrraFX1rVOniXIlggIMvYr_x55AY4LKiWZLHBlQJmX1R9Y5BkUfnuSddAmyE';

/** "The Session Transcript for the above response", hex. */
export const ANNEX_A_DCAPI_SESSION_TRANSCRIPT_HEX =
    '83f6f68265646361706958204a292708fcf38ad55a7969f1c97ead9decf7756b7e9d8cfee942fe9f31b8db0a';

/** The example's decrypted DeviceResponse, re-encoded from diagnostic notation (base64url). */
export const ANNEX_A_DCAPI_DEVICE_RESPONSE =
    'o2d2ZXJzaW9uYzEuMGlkb2N1bWVudHOBo2dkb2NUeXBlcWV1LmV1cm9wYS5lYy5hdi4xbGlzc3VlclNpZ25lZKJqbmFtZVNwYWNl' +
    'c6FxZXUuZXVyb3BhLmVjLmF2LjGB2BhYYKRoZGlnZXN0SUQAZnJhbmRvbVggTqw7XypDmvS3gpmyTHa5I-_D8MOaHdMFrGSZ-qzE' +
    'iZxxZWxlbWVudElkZW50aWZpZXJrYWdlX292ZXJfMThsZWxlbWVudFZhbHVl9Wppc3N1ZXJBdXRohEOhASahGCFZAsEwggK9MIIC' +
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
    'ZFVudGlswHQyMDI2LTA1LTA2VDAwOjAwOjAwWmx2YWx1ZURpZ2VzdHOhcWV1LmV1cm9wYS5lYy5hdi4xoQBYIPG3tY2AbAd73eg6' +
    'zhayMs6cq85Gni-cYXxSeZWqtuqibWRldmljZUtleUluZm-haWRldmljZUtleaQBAiABIVggGeWSCWFn6Sfox3fK7_C5-7ZvK4fh' +
    'fSowTVxbfUr__F0iWCBL2XcdroDMuAhlUmDv_0nr1t1DFytktzoBjPLz7IlWrG9kaWdlc3RBbGdvcml0aG1nU0hBLTI1NlhAIzR5' +
    'nqNT4_egRXuObTAKo8sMILimHpBQnpeoGfsad4wcB9jslQsMdfeqOX22B1WNCwwaVVxg7R0kf0MHMhDbzWxkZXZpY2VTaWduZWSi' +
    'am5hbWVTcGFjZXPYGEGgamRldmljZUF1dGihb2RldmljZVNpZ25hdHVyZYRDoQEmoPZYQG_dCB3YyxV0uZNedA3NgTLJuJRwrklO' +
    'rtuzzzejpaogbsXSzRr9mlKNx8nWBRJxgvAbbeMshWQn4zu56CdYefNmc3RhdHVzAA';
