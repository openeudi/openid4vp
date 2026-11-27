# Polaris negative vectors

Presentations a verifier must judge, each with the verdict a correct verifier reaches, copied
unchanged for `tests/polaris-negative-vectors.test.ts`. Every negative is a valid control with one
thing changed and names the clauses its verdict rests on; every negative the test judges also
carries its repaired twin, which a correct verifier accepts.

- Source: <https://github.com/EgorKhaklin/polaris-id/tree/32a683bb3176d3b8e5de20911d526d28e931ed47/lab/interop/negative-vectors>,
  commit `32a683bb3176d3b8e5de20911d526d28e931ed47`. `vectors.json` is unchanged there since commit
  `647e804d8c00ad510983120ecad03deecd9769ec`, and is published byte for byte on npm as
  [`polaris-negative-vectors@0.1.0`](https://www.npmjs.com/package/polaris-negative-vectors).
- `vectors.json` (version 0.7.0): SD-JWT VC presentations under OpenID4VP 1.0 and HAIP 1.0.
  SHA-256 `1d3a382d638eb6c484f4899938899cfdf56618b00dff3ee1525d67ecadf43346`
- `mdoc-vectors.json` (version 0.3.1): ISO/IEC 18013-5 mdoc DeviceResponses over OpenID4VP 1.0.
  SHA-256 `0ebfe4d570dad2c432eddf38bf5cb1bb7aa7c013bb5cfa3136c3fff56fb172dd`
- Licence: Apache-2.0, Copyright 2026 Egor Khaklin, in `LICENSE` and `NOTICE` beside this file

The test checks both SHA-256 values and reads nothing from the network. The keys and certificates
in the files are test material, derived from public seeds: never trust them.

Do not edit the two files. To update them, replace both with a newer commit of the same directory
and update the commit and the SHA-256 values here and in the test.
