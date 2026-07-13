import type { Fixtures } from "../fixtures";
import type { ProfileBuildOutput } from "./happy-flow";
import { buildHappyFlowProfile } from "./happy-flow";
import { buildFullPlanProfile } from "./full-plan";

/**
 * A registry entry. `credentialFormat` and `expect` are lifted out to the
 * top level (duplicated from what `build()` will eventually return) because
 * `generateFixtures` needs to know the credential format *before* fixtures
 * exist — and `build` itself takes `Fixtures` as its only argument. Every
 * entry's `credentialFormat`/`expect` MUST match what its `build(fx)` output
 * reports; there is no runtime check enforcing that, so keep them in sync
 * when adding profiles.
 */
export interface ProfileDescriptor {
  credentialFormat: "dc+sd-jwt" | "mso_mdoc";
  expect: "accept" | "reject";
  build: (fx: Fixtures) => ProfileBuildOutput;
  /**
   * Marks a `reject`-mode profile as a KNOWN, DOCUMENTED divergence between our
   * verifier's behaviour and the suite's expectation — NOT a bug. When set, the
   * orchestrator treats a verifier ACCEPT on this specific profile as non-blocking
   * (exit 0) instead of a gate failure, while every other reject-profile keeps the
   * strict "must reject, must never accept" gate.
   *
   * Deliberately profile-scoped rather than a global `allowlist.json` entry: the
   * allowlist matches by check `src` (e.g. `EnsureHttpStatusCodeIs4xx`) across EVERY
   * profile run, so allowlisting that check would also silently mask a genuine
   * "verifier wrongly accepted" regression on the real negative profiles
   * (1final-neg-session-transcript, -kb-jwt-nonce, -kb-jwt-aud, -kb-jwt-signature,
   * -sd-hash, -credential-signature). A profile-level flag can't leak that way.
   */
  knownDivergence?: { reason: string };
}

/**
 * OID4VP-1.0-FINAL verifier test plan.
 *
 * Confirmed via the running suite (2026-07-12, oidf-conformance-suite server
 * image ghcr.io/openeudi/oidf-conformance-suite:release-v5.1.42):
 *
 *   - `GET /api/runner/available` lists all 10 module `testName`s below under
 *     `profile: "OID4VP-1FINAL"`, and their `variants` block exposes
 *     `client_id_prefix` (NOT `client_id_scheme`, which is an ID3-only key —
 *     the id3 plan's variant dimension is named differently). Confirmed
 *     variant values: `client_id_prefix: x509_san_dns` (requires
 *     `client.client_id` config field, matching the existing x509 fixture
 *     chain) and `request_method: request_uri_signed` both exist for 1final.
 *   - The suite's `/api/plan` list/query endpoints don't expose a plan-name
 *     field directly (DataTables-style endpoint, needs server-side plan
 *     rows already created to list anything), so the plan name was confirmed
 *     by extracting the running container's
 *     `/server/fapi-test-suite.jar!/BOOT-INF/classes/net/openid/conformance/vp1finalverifier/VP1FinalVerifierTestPlan.class`
 *     and reading its `@PublishTestPlan` annotation constant pool entries:
 *       testPlanName = "oid4vp-1final-verifier-test-plan"
 *     and its static `testModules` list, which enumerates exactly the 10
 *     module classes this registry targets (VP1FinalVerifierHappyFlow,
 *     VP1FinalVerifierInvalidSessionTranscript, VP1FinalVerifierInvalidKbJwt-
 *     {Nonce,Aud,Signature}, VP1FinalVerifierInvalidSdHash,
 *     VP1FinalVerifierInvalidCredentialSignature, VP1FinalVerifierKbJwtIatIn-
 *     {Past,Future}, plus VP1FinalVerifierMinimalCnfJwk and
 *     VP1FinalVerifierRequestUriMethodPost which this registry doesn't use).
 *     This is authoritative (source-derived), not inferred from naming
 *     convention.
 */
const ONE_FINAL_PLAN_NAME = "oid4vp-1final-verifier-test-plan";

function oneFinalVariant(
  credentialFormat: "sd_jwt_vc" | "iso_mdl",
  overrides: Record<string, string> = {}
): Record<string, string> {
  return {
    credential_format: credentialFormat,
    client_id_prefix: "x509_san_dns",
    request_method: "request_uri_signed",
    // The 1final verifier modules require response_mode explicitly (unlike id3).
    // direct_post.jwt (encrypted) is mandatory for iso_mdl — the JWE carries the
    // response and, for OpenID4VPHandover, the verifier's encryption-key thumbprint
    // binds the mdoc device auth. Our verifier-server decrypts, so we use it for
    // sd_jwt_vc too. vp_profile=haip matches the HAIP request our verifier builds.
    response_mode: "direct_post.jwt",
    vp_profile: "haip",
    ...overrides,
  };
}

function oneFinalConfig(fx: Fixtures, alias: string): Record<string, unknown> {
  return {
    alias,
    description: "Automated 1final run from CI",
    publish: "no",
    client: {
      // Bare hostname; suite's OID4VPSetClientIdToIncludeClientIdScheme prepends
      // the `x509_san_dns:` prefix at runtime to match the auth request.
      client_id: fx.hostname,
    },
    credential: {
      // Required by the module config schema even for iso_mdl modules, where
      // it goes unused (mdl signing uses the mdoc issuer keys, not this JWK).
      signing_jwk: fx.issuerSigningJwkPrivate,
    },
  };
}

function oneFinalProfile(
  profileName: string,
  moduleName: string,
  credentialFormat: "sd_jwt_vc" | "iso_mdl",
  expect: "accept" | "reject",
  knownDivergence?: { reason: string }
): ProfileDescriptor {
  const resolvedFormat: "dc+sd-jwt" | "mso_mdoc" = credentialFormat === "iso_mdl" ? "mso_mdoc" : "dc+sd-jwt";
  return {
    credentialFormat: resolvedFormat,
    expect,
    knownDivergence,
    build: (fx: Fixtures) => ({
      planName: ONE_FINAL_PLAN_NAME,
      moduleName,
      variant: oneFinalVariant(credentialFormat),
      config: oneFinalConfig(fx, `oidf-ci-${profileName}`),
      expect,
      credentialFormat: resolvedFormat,
    }),
  };
}

/**
 * KB-JWT `iat` recency/freshness is intentionally NOT enforced by the verifier (no
 * `maxTokenAge` check): replay is already bound by the mandatory `nonce` check, so an
 * implausible `iat` alone isn't a security gap. This is a Plan A decision, documented
 * in CHANGELOG/README, and out of scope for GHSA-h548 — a future hardening candidate,
 * not a regression. The two `1final-neg-iat-*` profiles below therefore make the
 * verifier ACCEPT where the suite's `EnsureHttpStatusCodeIs4xx` check expects a 4xx,
 * which is why they're flagged as known divergences rather than left to fail the gate.
 */
const KB_JWT_IAT_KNOWN_DIVERGENCE = {
  reason:
    "KB-JWT `iat` recency/freshness is not enforced (no maxTokenAge); replay is bound by the mandatory " +
    "nonce check. Documented in CHANGELOG/README. Out of scope for GHSA-h548; future hardening candidate.",
};

/** Registry of every profile name resolvable via `--profile`. */
export const PROFILE_REGISTRY: Record<string, ProfileDescriptor> = {
  // Back-compat aliases (id3 verifier plan). Both hardcode credentialFormat/expect
  // because buildHappyFlowProfile/buildFullPlanProfile bake fixed values into their
  // returned ProfileBuildOutput regardless of the fixtures passed in.
  "happy-flow": { credentialFormat: "dc+sd-jwt", expect: "accept", build: buildHappyFlowProfile },
  full: { credentialFormat: "dc+sd-jwt", expect: "accept", build: buildFullPlanProfile },

  // OID4VP-1.0-FINAL verifier plan — happy paths.
  "1final-happy-sdjwt": oneFinalProfile(
    "1final-happy-sdjwt",
    "oid4vp-1final-verifier-happy-flow",
    "sd_jwt_vc",
    "accept"
  ),
  "1final-happy-mdl": oneFinalProfile("1final-happy-mdl", "oid4vp-1final-verifier-happy-flow", "iso_mdl", "accept"),

  // OID4VP-1.0-FINAL verifier plan — negative paths (mso_mdoc).
  "1final-neg-session-transcript": oneFinalProfile(
    "1final-neg-session-transcript",
    "oid4vp-1final-verifier-invalid-session-transcript",
    "iso_mdl",
    "reject"
  ),

  // OID4VP-1.0-FINAL verifier plan — negative paths (sd_jwt_vc).
  "1final-neg-kb-jwt-nonce": oneFinalProfile(
    "1final-neg-kb-jwt-nonce",
    "oid4vp-1final-verifier-invalid-kb-jwt-nonce",
    "sd_jwt_vc",
    "reject"
  ),
  "1final-neg-kb-jwt-aud": oneFinalProfile(
    "1final-neg-kb-jwt-aud",
    "oid4vp-1final-verifier-invalid-kb-jwt-aud",
    "sd_jwt_vc",
    "reject"
  ),
  "1final-neg-kb-jwt-signature": oneFinalProfile(
    "1final-neg-kb-jwt-signature",
    "oid4vp-1final-verifier-invalid-kb-jwt-signature",
    "sd_jwt_vc",
    "reject"
  ),
  "1final-neg-sd-hash": oneFinalProfile(
    "1final-neg-sd-hash",
    "oid4vp-1final-verifier-invalid-sd-hash",
    "sd_jwt_vc",
    "reject"
  ),
  "1final-neg-credential-signature": oneFinalProfile(
    "1final-neg-credential-signature",
    "oid4vp-1final-verifier-invalid-credential-signature",
    "sd_jwt_vc",
    "reject"
  ),
  "1final-neg-iat-future": oneFinalProfile(
    "1final-neg-iat-future",
    "oid4vp-1final-verifier-kb-jwt-iat-in-future",
    "sd_jwt_vc",
    "reject",
    KB_JWT_IAT_KNOWN_DIVERGENCE
  ),
  "1final-neg-iat-past": oneFinalProfile(
    "1final-neg-iat-past",
    "oid4vp-1final-verifier-kb-jwt-iat-in-past",
    "sd_jwt_vc",
    "reject",
    KB_JWT_IAT_KNOWN_DIVERGENCE
  ),
};

export type ProfileName = keyof typeof PROFILE_REGISTRY;

export function resolveProfile(name: string): ProfileDescriptor {
  const descriptor = PROFILE_REGISTRY[name];
  if (!descriptor) {
    const valid = Object.keys(PROFILE_REGISTRY).sort().join(", ");
    throw new Error(`Unknown profile "${name}". Valid profiles: ${valid}`);
  }
  return descriptor;
}
