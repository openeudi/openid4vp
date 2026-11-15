# Polaris negative vectors

Presentations a verifier must judge, each with the verdict a correct verifier reaches, copied
unchanged for `tests/polaris-negative-vectors.test.ts`. Every negative is a valid control with one
thing changed and names the clauses its verdict rests on; every negative the test judges also
carries its repaired twin, which a correct verifier accepts.

- Source: <https://github.com/EgorKhaklin/polaris-id/tree/5d0c68f678cd75e88f481af5b89eff6cb0534a15/lab/interop/negative-vectors>,
  commit `5d0c68f678cd75e88f481af5b89eff6cb0534a15`
- `vectors.json` (version 0.5.0): SD-JWT VC presentations under OpenID4VP 1.0 and HAIP 1.0.
  SHA-256 `9c95fd6d678936f05fe9eb6ab12d014cc807d96bdd28bb2ad5fdba151202257a`
- `mdoc-vectors.json` (version 0.1.0): ISO/IEC 18013-5 mdoc DeviceResponses over OpenID4VP 1.0.
  SHA-256 `2525e629f92adad0a4a44649f7868eb9ecab84bc60135a126862f118a28857de`
- Licence: Apache-2.0, Copyright 2026 Egor Khaklin, in `LICENSE` and `NOTICE` beside this file

The test checks both SHA-256 values and reads nothing from the network. The keys and certificates
in the files are test material, derived from public seeds: never trust them.

Do not edit the two files. To update them, replace both with a newer commit of the same directory
and update the commit and the SHA-256 values here and in the test.
