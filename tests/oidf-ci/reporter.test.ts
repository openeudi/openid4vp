import { describe, expect, it } from "vitest";
import { renderResult } from "../../scripts/oidf-ci/reporter";
import type { CategorisedResult } from "../../scripts/oidf-ci/categorise";

const passingResult: CategorisedResult = {
  tally: { success: 3, failure: 0, warning: 1, review: 0, info: 5, interrupted: 0 },
  blocking: [],
  allowlisted: [],
  pass: true,
};

const failingResult: CategorisedResult = {
  tally: { success: 1, failure: 2, warning: 0, review: 0, info: 0, interrupted: 0 },
  blocking: [{ src: "CheckBlocker", msg: "wire format wrong", raw: { result: "FAILURE", src: "CheckBlocker" } }],
  allowlisted: [
    {
      src: "CheckSpecDrift",
      msg: "unknown parameter",
      raw: { result: "FAILURE", src: "CheckSpecDrift" },
      allowlistEntry: {
        id: "CheckSpecDrift",
        category: "spec-drift",
        justification: "expected divergence",
        reference: "https://example.com",
      },
    },
  ],
  pass: false,
};

describe("reporter", () => {
  it("JSON output contains tally + pass + profile + per-failure detail", () => {
    const out = renderResult(failingResult, { profile: "happy-flow", planId: "p-1", testId: "t-1" });
    const parsed = JSON.parse(out.json);

    expect(parsed.profile).toBe("happy-flow");
    expect(parsed.planId).toBe("p-1");
    expect(parsed.testId).toBe("t-1");
    expect(parsed.pass).toBe(false);
    expect(parsed.tally).toEqual(failingResult.tally);
    expect(parsed.blocking).toHaveLength(1);
    expect(parsed.allowlisted).toHaveLength(1);
    expect(parsed.allowlisted[0].justification).toBe("expected divergence");
  });

  it("markdown output renders a tally table", () => {
    const out = renderResult(passingResult, { profile: "happy-flow", planId: "p-2", testId: "t-2" });

    expect(out.summary).toContain("# OIDF Conformance — happy-flow");
    expect(out.summary).toContain("| SUCCESS |");
    expect(out.summary).toContain("| WARNING |");
    expect(out.summary).toContain("Pass: ✅");
    expect(out.summary).toContain("p-2");
  });

  it("markdown output for failing run lists blocking failures", () => {
    const out = renderResult(failingResult, { profile: "full", planId: "p-3", testId: "t-3" });

    expect(out.summary).toContain("Pass: ❌");
    expect(out.summary).toContain("CheckBlocker");
    expect(out.summary).toContain("wire format wrong");
    expect(out.summary).toContain("Allow-listed (informational)");
    expect(out.summary).toContain("CheckSpecDrift");
  });
});
