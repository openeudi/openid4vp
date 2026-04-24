import { X509Certificate } from '@peculiar/x509';

/**
 * EU LOTL signing anchors, bundled at release time. Sourced from the
 * European Commission's LOTL at
 * https://ec.europa.eu/tools/lotl/eu-lotl.xml (retrieved 2026-04-23,
 * sequence number 385, issued 2026-04-15T06:30:37Z).
 *
 * The Commission rotates these roughly every 2-3 years. When a rotation
 * happens:
 *  1. Fetch the current LOTL and extract the <ds:X509Certificate> from the
 *     <ds:Signature> block at the end of the document.
 *  2. Append the new cert to this array (retain the old one for one release
 *     cycle so consumers with cached LOTL snapshots signed by the prior
 *     cert can continue verifying).
 *  3. Cut a patch release (0.5.N) with the new anchors.
 *
 * Consumers may also override via `new LotlTrustStore({ signingAnchors: ... })`
 * for test / emergency-rotation scenarios.
 *
 * Current anchor:
 *   Subject : CN=EUROPEAN COMMISSION, O=EUROPEAN COMMISSION,
 *             OU=Directorate-General for Digital Services (DIGIT),
 *             organizationIdentifier=LEIXG-254900ZNYA1FLUQ9U393, C=LU
 *   Issuer  : CN=DIGITALSIGN QUALIFIED CA G1,
 *             O=DigitalSign Certificadora Digital, C=PT
 *   Serial  : 73:C2:1C:49:4B:55:10:A0:0C:32:F1:E6:F5:05:94:D3:99:17:B0:F5
 *   notAfter: 2027-11-17
 */
const PEM_ANCHORS: readonly string[] = [
    `-----BEGIN CERTIFICATE-----
MIIIoDCCBoigAwIBAgIUc8IcSUtVEKAMMvHm9QWU05kXsPUwDQYJKoZIhvcNAQEN
BQAwXzELMAkGA1UEBhMCUFQxKjAoBgNVBAoMIURpZ2l0YWxTaWduIENlcnRpZmlj
YWRvcmEgRGlnaXRhbDEkMCIGA1UEAwwbRElHSVRBTFNJR04gUVVBTElGSUVEIENB
IEcxMB4XDTIzMTExNzEwMTE0NloXDTI3MTExNzEwMTE0NlowggEVMQswCQYDVQQG
EwJMVTFDMEEGA1UECww6Q2VydGlmaWNhdGUgUHJvZmlsZSAtIFF1YWxpZmllZCBD
ZXJ0aWZpY2F0ZSAtIE9yZ2FuaXphdGlvbjE5MDcGA1UECwwwRGlyZWN0b3JhdGUt
R2VuZXJhbCBmb3IgRGlnaXRhbCBTZXJ2aWNlcyAoRElHSVQpMSMwIQYDVQRhDBpM
RUlYRy0yNTQ5MDBaTllBMUZMVVE5VTM5MzEcMBoGA1UECgwTRVVST1BFQU4gQ09N
TUlTU0lPTjElMCMGCSqGSIb3DQEJARYWZGlnaXQtZG1vQGVjLmV1cm9wYS5ldTEc
MBoGA1UEAwwTRVVST1BFQU4gQ09NTUlTU0lPTjCCAiIwDQYJKoZIhvcNAQEBBQAD
ggIPADCCAgoCggIBAKWYeBA9kYARElGnHoJRNpbby44G+TSJcgHI9QtyXlYjB234
hSAYyJvW+gKvoownskrogfUP6GOmQgEFZX335Y0sBwfppVemEoe9H9Aj/cpT14Iq
dB05V4a88ASRfR0Va1xmQJrDsBZWqZHx0EEHBctIF5BjyTMAcQybha+4AOIotp3d
F/7ZA3Cu4GYbN9BuQyyqfqrjMduDzzDjVwKC17aEsLev60C1FnIJ/FVEda3lJSGi
lD5JyUceTaRcot1rw6gjKrOVhwP/UHfevJ3JCsQsuAzkf7ivzHzYuPPPR9Ussecw
r7O95Fr4wbPYIyX2AOTlieAC7GMVXHN1/+4LH74ndvoJYEScXwmN9Skib3+G6Tqu
OCQxvNXzHPZb95btCoSnVprCn14O3CXUTZMEKkhPuKW8dI6pR2JSGbtT+xBkcc1w
YVlUnzE3d+YK5SSevUT2COwJM+AcjSoUaRTBINsD/ezDDvv7vtbF1XccaJjoCNku
rzayTsMszGDvAF171LY69lNY6yK0uzrS+3c/hEHctXa5KIC3PpWrBGQ5mw73KerR
vnAhzDZemVquPk1D59aJNfHoHXmy1bS52rHWYOwHH+2qbODdh8GkHwHXBzSpFit1
Kg2brpavhztNaGlj6GsLFAbr8okCUJllOOLQ8Tfy9Vnn5Rq0+7VTdd8dAxg9AgMB
AAGjggKaMIICljAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFHNJ8UAcFAR8mhJ/
+i/NXGcjGOkUMIGGBggrBgEFBQcBAQR6MHgwRgYIKwYBBQUHMAKGOmh0dHBzOi8v
cWNhLWcxLmRpZ2l0YWxzaWduLnB0L0RJR0lUQUxTSUdOUVVBTElGSUVEQ0FHMS5w
N2IwLgYIKwYBBQUHMAGGImh0dHBzOi8vcWNhLWcxLmRpZ2l0YWxzaWduLnB0L29j
c3AwIQYDVR0RBBowGIEWZGlnaXQtZG1vQGVjLmV1cm9wYS5ldTBfBgNVHSAEWDBW
MDcGCysGAQQBgcd8BAEBMCgwJgYIKwYBBQUHAgEWGmh0dHBzOi8vcGtpLmRpZ2l0
YWxzaWduLnB0MBAGDisGAQQBgcd8BAIBAQEGMAkGBwQAi+xAAQMwHQYDVR0lBBYw
FAYIKwYBBQUHAwIGCCsGAQUFBwMEMIG8BggrBgEFBQcBAwSBrzCBrDAVBggrBgEF
BQcLAjAJBgcEAIvsSQECMAgGBgQAjkYBATAIBgYEAI5GAQQwEwYGBACORgEGMAkG
BwQAjkYBBgIwagYGBACORgEFMGAwLhYoaHR0cHM6Ly9xY2EtZzEuZGlnaXRhbHNp
Z24ucHQvUERTX2VuLnBkZhMCZW4wLhYoaHR0cHM6Ly9xY2EtZzEuZGlnaXRhbHNp
Z24ucHQvUERTX3B0LnBkZhMCcHQwSwYDVR0fBEQwQjBAoD6gPIY6aHR0cHM6Ly9x
Y2EtZzEuZGlnaXRhbHNpZ24ucHQvRElHSVRBTFNJR05RVUFMSUZJRURDQUcxLmNy
bDAdBgNVHQ4EFgQUlO5hwcl9/63issm59r+TIHeJSZwwDgYDVR0PAQH/BAQDAgZA
MA0GCSqGSIb3DQEBDQUAA4ICAQCn8qjJhTe3SsD7cB8S8kDzt+CBnJJm7bOFc9t9
IU6iKntVtjPU4T+cYiPk8TnT+/w7dBphRzjZCL1sDfSJGQ5JPBw+hBPuvzEqP4xV
i5i4Jhg/GpYSaa2+dkFXlKe6Sd+ii/RnwBSnfqVfNZtasj7yX+oujGau5LSUPIkQ
xDrMie8KjsNtlkFjQDoioGAx8b0u6WyhAuqwEacCznft20Dim3sC7XJw8GHumrnW
52rUzl4sbXoTBAt8F1zPCbEbjU0oc8SbFNPIChh+9sHUorEmHIlcg30LBHihkDCx
4mK8J60Jybk57D4U2RO29VsJfDmnvNxfJZxfLHEJ2tkh+AMqlJXPDlvXQ+rZ1NmL
HrbXkcHOlqR3F8BakTi2Mi5AZZfkfjZjkigEStN6Enaq6gwF7EsslqEKmhSQ8Xlh
xWSRqljK/cnEUw+NhrvR4WuKlvYmxlCLQj6q89Hh121aUGUhL2L2WCVBjVXqux7s
4mvECDzrucl5ilaVT32HO3g8qNLGD5lum53U5v/Nv68ItyHH96unztwBebmgox8g
iVRdzPhmPrpSfbmeNNDKj1p9SCeOvd3P9jCUvChVvH2P2ZUjc24tWe+tzclsCJi7
GbKr6kjHc1jFudjehflAbm1IZAYdDNrhXamnsRVsz7iSH20eygCArlwSQ//WIQZP
FrRffg==
-----END CERTIFICATE-----`,
];

export const EU_LOTL_SIGNING_ANCHORS: readonly X509Certificate[] = Object.freeze(
    PEM_ANCHORS.map((pem) => new X509Certificate(pem))
);
