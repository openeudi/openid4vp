import "reflect-metadata";
import { describe, expect, it, afterEach } from "vitest";
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
});
