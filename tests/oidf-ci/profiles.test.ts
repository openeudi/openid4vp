import "reflect-metadata";
import { describe, expect, it } from "vitest";
import { generateFixtures } from "../../scripts/oidf-ci/fixtures";
import { buildHappyFlowProfile } from "../../scripts/oidf-ci/profiles/happy-flow";
import { buildFullPlanProfile } from "../../scripts/oidf-ci/profiles/full-plan";

describe("profiles", () => {
  it("happy-flow profile carries the validated nested client.client_id with x509_san_dns: prefix", async () => {
    const fx = await generateFixtures({ hostname: "host.docker.internal" });
    const p = buildHappyFlowProfile(fx);

    expect(p.planName).toBe("oid4vp-id3-verifier-test-plan");
    expect(p.moduleName).toBe("oid4vp-id3-verifier-happy-flow");
    expect(p.variant.credential_format).toBe("sd_jwt_vc");
    // Bare hostname; suite prepends x509_san_dns: scheme at runtime.
    expect((p.config as { client: { client_id: string } }).client.client_id).toBe("host.docker.internal");
  });

  it("full-plan profile uses the full-plan moduleName", async () => {
    const fx = await generateFixtures({ hostname: "host.docker.internal" });
    const p = buildFullPlanProfile(fx);
    expect(p.moduleName).toBe("oid4vp-id3-verifier-test-plan");
  });

  it("both profiles inject issuer signing JWK private half + verifier-trusted cert match", async () => {
    const fx = await generateFixtures({ hostname: "host.docker.internal" });
    const p = buildHappyFlowProfile(fx);
    const signingJwk = (p.config as { credential: { signing_jwk: JsonWebKey } }).credential.signing_jwk;
    expect(signingJwk.kty).toBe("EC");
    expect(typeof signingJwk.d).toBe("string");
  });
});
