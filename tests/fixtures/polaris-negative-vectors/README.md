# Polaris negative vectors

Presentations a verifier must judge, each with the verdict a correct verifier reaches, copied
unchanged for `tests/polaris-negative-vectors.test.ts`. Every negative is a valid control with one
thing changed and names the clauses its verdict rests on; every negative the test judges also
carries its repaired twin, which a correct verifier accepts.

- Source: <https://github.com/EgorKhaklin/polaris-id/tree/eb962649f8ad32e7d3f8173c3d1413abc7daf4f8/lab/interop/negative-vectors>,
  commit `eb962649f8ad32e7d3f8173c3d1413abc7daf4f8`
- `vectors.json` (version 0.6.0): SD-JWT VC presentations under OpenID4VP 1.0 and HAIP 1.0.
  SHA-256 `e3166e6fb30ff5dabd6b81284bd9a95c5ab0b41db077e82a32f5d67a2357778c`
- `mdoc-vectors.json` (version 0.2.0): ISO/IEC 18013-5 mdoc DeviceResponses over OpenID4VP 1.0.
  SHA-256 `097bdf1b121da340d1b8eeeaa2267ab3628b4002738fdfea4c15f96690fe88bc`
- Licence: Apache-2.0, Copyright 2026 Egor Khaklin, in `LICENSE` and `NOTICE` beside this file

The test checks both SHA-256 values and reads nothing from the network. The keys and certificates
in the files are test material, derived from public seeds: never trust them.

Do not edit the two files. To update them, replace both with a newer commit of the same directory
and update the commit and the SHA-256 values here and in the test.
