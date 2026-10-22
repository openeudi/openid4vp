/**
 * "Age Verification Issuer CA 01", O=Age Verification Reference Implementation:
 * the CA of the EU age-verification reference issuer, as listed (service type
 * `.../age-verification/service-type/paa`) on the acceptance AV-TL,
 * https://acceptance.trust.tech.ec.europa.eu/lists/age-verification/av-tl.xml
 * (fetched 2026-10-22). It signs the Document Signer of the AV spec's Annex A
 * example (`av-annex-a-example.ts`).
 *
 * Its IssuerAltName is encoded as a nested Extension instead of GeneralNames,
 * which @peculiar/x509 cannot decode (EID-216).
 *
 * SHA-256: ED:AC:F9:68:27:F6:DF:C2:80:41:17:92:A0:0A:B6:D0:02:BE:CD:A0:99:AA:7F:1E:1A:DA:01:9B:A8:6A:08:C5
 */
export const AV_REFERENCE_ISSUER_CA_DER_BASE64 =
    'MIIC0zCCAnigAwIBAgIUVDLDFa4rz+IkYiwCyN+cH86e3bcwCgYIKoZIzj0EAwMwaTEmMCQGA1UEAwwdQWdlIFZlcmlmaWNhdGlvbiBJc3N1ZXIgQ0EgMDExMjAwBgNVBAoMKUFnZSBWZXJpZmljYXRpb24gUmVmZXJlbmNlIEltcGxlbWVudGF0aW9uMQswCQYDVQQGEwJFVTAeFw0yNTA3MDExMDI0MjJaFw0zNDA5MjcxMDI0MjFaMGkxJjAkBgNVBAMMHUFnZSBWZXJpZmljYXRpb24gSXNzdWVyIENBIDAxMTIwMAYDVQQKDClBZ2UgVmVyaWZpY2F0aW9uIFJlZmVyZW5jZSBJbXBsZW1lbnRhdGlvbjELMAkGA1UEBhMCRVUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARZWSqRomweuXy6u3fvxPpQcGk1XGy6FermzmY6KMuc6jGzIp10NglnbdRMxMt1oxbFK322VvoDZKgDs2sokynDo4H9MIH6MBIGA1UdEwEB/wQIMAYBAf8CAQAwHwYDVR0jBBgwFoAUy3CVgEyZHtxtC3z+6+BByiJULtgwEwYDVR0lBAwwCgYIK4ECAgAAAQcwRAYDVR0fBD0wOzA5oDegNYYzaHR0cHM6Ly9pc3N1ZXIuYWdldmVyaWZpY2F0aW9uLmRldi9wa2kvRVVfQ0FfMDEuY3JsMB0GA1UdDgQWBBTLcJWATJke3G0LfP7r4EHKIlQu2DAOBgNVHQ8BAf8EBAMCAQYwOQYDVR0SBDIwMAYDVR0SBCkwJ4IlaHR0cHM6Ly9jb21taXNzaW9uLmV1cm9wYS5ldS9pbmRleF9lbjAKBggqhkjOPQQDAwNJADBGAiEAqaDOzWyw0piVvMYplBkRHchgXxONwAG5W70Ent/WDQUCIQDZvjN/4xosNu91CEql+F52u+5g0NRPR5GyGpJGwpRf1A==';
