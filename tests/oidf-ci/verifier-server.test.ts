import "reflect-metadata";
import { describe, expect, it, afterEach } from "vitest";
import { CompactEncrypt, SignJWT, exportJWK, generateKeyPair, importJWK } from "jose";
import { generateFixtures } from "../../scripts/oidf-ci/fixtures";
import { startVerifierServer, type VerifierServerHandle } from "../../scripts/oidf-ci/verifier-server";

describe("verifier-server", () => {
  let handle: VerifierServerHandle | undefined;

  afterEach(async () => {
    if (handle) {
      await handle.close();
      handle = undefined;
    }
  });

  it("listens on the requested port and reports its base URL", async () => {
    const fx = await generateFixtures({ hostname: "127.0.0.1" });
    handle = await startVerifierServer({ fixtures: fx, port: 0 });
    expect(handle.url).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/);
  });

  it("serves /request.jwt with the correct content-type and a JWS-shaped body", async () => {
    const fx = await generateFixtures({ hostname: "127.0.0.1" });
    handle = await startVerifierServer({ fixtures: fx, port: 0 });

    const res = await fetch(`${handle.url}/request.jwt`);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("application/oauth-authz-req+jwt");
    const body = await res.text();
    expect(body.split(".")).toHaveLength(3);
  });

  it("rebuilds the JAR fresh on each fetch (different iat per request)", async () => {
    const fx = await generateFixtures({ hostname: "127.0.0.1" });
    handle = await startVerifierServer({ fixtures: fx, port: 0 });

    const a = await (await fetch(`${handle.url}/request.jwt`)).text();
    await new Promise((r) => setTimeout(r, 1100));
    const b = await (await fetch(`${handle.url}/request.jwt`)).text();

    expect(a).not.toBe(b);
  });

  it("returns 404 for unknown paths", async () => {
    const fx = await generateFixtures({ hostname: "127.0.0.1" });
    handle = await startVerifierServer({ fixtures: fx, port: 0 });
    const res = await fetch(`${handle.url}/nope`);
    expect(res.status).toBe(404);
  });

  it("records ok:false when the library returns result.valid:false (wrong issuer signature)", async () => {
    // Regression test: verifyAuthorizationResponse signals signature failures via
    // result.valid:false rather than throwing. The verifier-server must treat that
    // as a blocking failure, not silently record ok:true.
    const fx = await generateFixtures({ hostname: "127.0.0.1" });
    handle = await startVerifierServer({ fixtures: fx, port: 0 });

    // Build an SD-JWT issuer JWT signed by an ATTACKER key (not our trusted issuer)
    // but using the same kid the trusted JWK carries — library imports the trusted
    // JWK, jwtVerify fails, parse result is invalid.
    const attacker = await generateKeyPair("ES256");
    const attackerJwk = await exportJWK(attacker.publicKey);
    const fakeIssuerJwt = await new SignJWT({ vct: "urn:eudi:pid:1", iss: "attacker", given_name: "Mallory" })
      .setProtectedHeader({ alg: "ES256", typ: "vc+sd-jwt", kid: fx.issuerSigningJwkPublic.kid })
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(attacker.privateKey);
    const fakeSdJwt = `${fakeIssuerJwt}~`;
    void attackerJwk;

    // Encrypt the inner envelope to the verifier's public JWK so the server can decrypt.
    const encPub = await importJWK(fx.encryptionPublicJwk, "ECDH-ES");
    const inner = JSON.stringify({ vp_token: { pid: [fakeSdJwt] }, state: handle.state });
    const jwe = await new CompactEncrypt(new TextEncoder().encode(inner))
      .setProtectedHeader({ alg: "ECDH-ES", enc: "A128GCM" })
      .encrypt(encPub);

    const res = await fetch(`${handle.url}/response`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ response: jwe }).toString(),
    });
    expect(res.status).toBe(500);

    const drained = handle.drainResponses();
    expect(drained).toHaveLength(1);
    expect(drained[0].ok).toBe(false);
    // Either the library threw inside verify (invalidResult turns into result.valid=false
    // → our handler throws) or it threw earlier; both must be captured as ok:false.
    expect(drained[0].error?.message ?? "").toMatch(/library rejected|result\.valid|Issuer JWT/i);
  });
});
