import type { Fixtures, CredentialFormat } from "../fixtures";

export interface ProfileBuildOutput {
  planName: string;
  moduleName: string;
  variant: Record<string, string>;
  config: Record<string, unknown>;
  /** Whether the suite module is expected to accept or reject the verifier's response. */
  expect: "accept" | "reject";
  /** Credential format threaded into `generateFixtures` so DCQL/vp_formats match the module's variant. */
  credentialFormat: CredentialFormat;
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
    expect: "accept",
    credentialFormat: "dc+sd-jwt",
    config: {
      alias: "oidf-ci-happy-flow",
      description: "Automated happy-flow run from CI",
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
