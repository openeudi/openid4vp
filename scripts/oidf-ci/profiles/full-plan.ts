import type { Fixtures } from "../fixtures";
import type { ProfileBuildOutput } from "./happy-flow";

/**
 * Release conformance profile. Runs the ID3 verifier **happy-flow** module —
 * the one the CI harness can actually drive end-to-end (a single positive
 * wallet interaction). `moduleName` was previously set to the *plan* name
 * (`oid4vp-id3-verifier-test-plan`), which is not a runnable test module, so
 * `POST /api/runner?test=...` returned 404 and every tag build failed here.
 *
 * NOTE: this is not yet a true "run every module in the plan" execution — the
 * orchestrator drives one module with one happy-path wallet trigger, and most
 * of the plan's negative/error modules need per-module wallet behaviour that
 * the harness doesn't script. Genuine multi-module coverage is future work
 * (enumerate the plan's modules from the /api/plan response and drive each).
 */
export function buildFullPlanProfile(fx: Fixtures): ProfileBuildOutput {
  return {
    planName: "oid4vp-id3-verifier-test-plan",
    moduleName: "oid4vp-id3-verifier-happy-flow",
    variant: {
      credential_format: "sd_jwt_vc",
      client_id_scheme: "x509_san_dns",
      request_method: "request_uri_signed",
      query_language: "dcql",
      response_mode: "direct_post.jwt",
    },
    config: {
      alias: "oidf-ci-release",
      description: "Automated release conformance run from CI",
      publish: "no",
      client: {
        // Bare hostname; suite's OID4VPSetClientIdToIncludeClientIdScheme prepends
        // the `x509_san_dns:` scheme prefix at runtime to match the auth request.
        client_id: fx.hostname,
      },
      credential: {
        signing_jwk: fx.issuerSigningJwkPrivate,
      },
    },
  };
}
