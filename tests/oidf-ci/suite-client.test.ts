import { describe, expect, it, vi, beforeEach } from "vitest";
import { createSuiteClient, SuiteApiError } from "../../scripts/oidf-ci/suite-client";

describe("suite-client", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("createPlan POSTs JSON to /api/plan with planName + variant query params", async () => {
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(new Response(JSON.stringify({ id: "plan-id-1" }), { status: 201 }));
    const client = createSuiteClient({ baseUrl: "http://suite:8443" });

    const res = await client.createPlan("oid4vp-id3-verifier-test-plan", { foo: "bar" }, { client_id: "x" });

    expect(res).toEqual({ planId: "plan-id-1" });
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const [url, init] = fetchSpy.mock.calls[0];
    expect(String(url)).toContain("/api/plan");
    expect(String(url)).toContain("planName=oid4vp-id3-verifier-test-plan");
    expect(String(url)).toContain("variant=%7B%22foo%22%3A%22bar%22%7D");
    expect(init?.method).toBe("POST");
    expect(init?.headers).toMatchObject({ "content-type": "application/json" });
    expect(JSON.parse(init?.body as string)).toEqual({ client_id: "x" });
  });

  it("startTest POSTs to /api/runner with test name + plan id", async () => {
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(new Response(JSON.stringify({ id: "test-id-7" }), { status: 201 }));
    const client = createSuiteClient({ baseUrl: "http://suite:8443" });

    const res = await client.startTest("plan-id-1", "oid4vp-id3-verifier-happy-flow");

    expect(res).toEqual({ testId: "test-id-7" });
    const [url] = fetchSpy.mock.calls[0];
    expect(String(url)).toContain("/api/runner");
    expect(String(url)).toContain("test=oid4vp-id3-verifier-happy-flow");
    expect(String(url)).toContain("plan=plan-id-1");
  });

  it("getTestStatus GETs /api/info/<testId>", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ status: "WAITING", exposed: { authorization_endpoint: "http://x" } }), {
        status: 200,
      })
    );
    const client = createSuiteClient({ baseUrl: "http://suite:8443" });

    const res = await client.getTestStatus("test-id-7");
    expect(res.status).toBe("WAITING");
    expect(res.exposed.authorization_endpoint).toBe("http://x");
  });

  it("getTestLog GETs /api/log/<testId> and returns the entries array", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify([{ result: "SUCCESS", src: "CheckA" }]), { status: 200 })
    );
    const client = createSuiteClient({ baseUrl: "http://suite:8443" });

    const log = await client.getTestLog("test-id-7");
    expect(log).toEqual([{ result: "SUCCESS", src: "CheckA" }]);
  });

  it("throws SuiteApiError with status + body on non-2xx", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("boom", { status: 502 }));
    const client = createSuiteClient({ baseUrl: "http://suite:8443" });

    await expect(client.getTestLog("x")).rejects.toMatchObject({
      name: "SuiteApiError",
      status: 502,
    });
  });
});
