import type { Fixtures } from "../fixtures";

export interface ProfileBuildOutput {
  planName: string;
  moduleName: string;
  variant: Record<string, string>;
  config: Record<string, unknown>;
}

export function buildHappyFlowProfile(fx: Fixtures): ProfileBuildOutput {
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
      alias: "oidf-ci-happy-flow",
      description: "Automated happy-flow run from CI",
      publish: "no",
      client_id: `x509_san_dns:${fx.hostname}`,
      credential: {
        signing_jwk: fx.issuerSigningJwkPrivate,
      },
    },
  };
}
