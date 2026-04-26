import type { Fixtures } from "../fixtures";
import type { ProfileBuildOutput } from "./happy-flow";

export function buildFullPlanProfile(fx: Fixtures): ProfileBuildOutput {
  return {
    planName: "oid4vp-id3-verifier-test-plan",
    moduleName: "oid4vp-id3-verifier-test-plan",
    variant: {
      credential_format: "sd_jwt_vc",
      client_id_scheme: "x509_san_dns",
      request_method: "request_uri_signed",
      query_language: "dcql",
      response_mode: "direct_post.jwt",
    },
    config: {
      alias: "oidf-ci-full-plan",
      description: "Automated full-plan run from CI",
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
