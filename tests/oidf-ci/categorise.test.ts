import { describe, expect, it } from "vitest";
import { categorise, MalformedSuiteLogError, type Allowlist } from "../../scripts/oidf-ci/categorise";
import type { SuiteLogEntry } from "../../scripts/oidf-ci/suite-client";

const emptyAllowlist: Allowlist = { version: 1, checks: [] };

describe("categorise", () => {
  it("empty log → pass true, all tallies zero", () => {
    const r = categorise([], emptyAllowlist);
    expect(r.pass).toBe(true);
    expect(r.tally).toEqual({ success: 0, failure: 0, warning: 0, review: 0, info: 0, interrupted: 0, finished: 0 });
    expect(r.blocking).toEqual([]);
    expect(r.allowlisted).toEqual([]);
  });

  it("all SUCCESS → pass true", () => {
    const log: SuiteLogEntry[] = [
      { result: "SUCCESS", src: "A" },
      { result: "SUCCESS", src: "B" },
    ];
    const r = categorise(log, emptyAllowlist);
    expect(r.pass).toBe(true);
    expect(r.tally.success).toBe(2);
  });

  it("one FAILURE not in allow-list → pass false, blocking contains it", () => {
    const log: SuiteLogEntry[] = [{ result: "FAILURE", src: "CheckX", msg: "boom" }];
    const r = categorise(log, emptyAllowlist);
    expect(r.pass).toBe(false);
    expect(r.blocking).toHaveLength(1);
    expect(r.blocking[0].src).toBe("CheckX");
    expect(r.allowlisted).toEqual([]);
  });

  it("one FAILURE in allow-list → pass true, allowlisted contains it", () => {
    const log: SuiteLogEntry[] = [{ result: "FAILURE", src: "CheckSpecDrift" }];
    const allowlist: Allowlist = {
      version: 1,
      checks: [{ id: "CheckSpecDrift", category: "spec-drift", justification: "j", reference: "r" }],
    };
    const r = categorise(log, allowlist);
    expect(r.pass).toBe(true);
    expect(r.allowlisted).toHaveLength(1);
    expect(r.blocking).toEqual([]);
  });

  it("mixed FAILUREs (one allowlisted + one not) → pass false", () => {
    const log: SuiteLogEntry[] = [
      { result: "FAILURE", src: "CheckSpecDrift" },
      { result: "FAILURE", src: "CheckRegression" },
    ];
    const allowlist: Allowlist = {
      version: 1,
      checks: [{ id: "CheckSpecDrift", category: "spec-drift", justification: "j", reference: "r" }],
    };
    const r = categorise(log, allowlist);
    expect(r.pass).toBe(false);
    expect(r.blocking).toHaveLength(1);
    expect(r.blocking[0].src).toBe("CheckRegression");
    expect(r.allowlisted).toHaveLength(1);
  });

  it("WARNING entries surface in tally but never fail", () => {
    const log: SuiteLogEntry[] = [{ result: "WARNING", src: "W1" }];
    const r = categorise(log, emptyAllowlist);
    expect(r.pass).toBe(true);
    expect(r.tally.warning).toBe(1);
  });

  it("REVIEW + INFO entries surface in tally but never fail", () => {
    const log: SuiteLogEntry[] = [
      { result: "REVIEW", src: "R1" },
      { result: "INFO", src: "I1" },
    ];
    const r = categorise(log, emptyAllowlist);
    expect(r.pass).toBe(true);
    expect(r.tally.review).toBe(1);
    expect(r.tally.info).toBe(1);
  });

  it("INTERRUPTED test-runner markers tally separately and never fail on their own", () => {
    // Test-runner emits an INTERRUPTED entry when a callAndStopOnFailure stops
    // execution. The actual cause is a separate FAILURE entry; the marker itself
    // doesn't block.
    const log: SuiteLogEntry[] = [
      { result: "INTERRUPTED", src: "oid4vp-id3-verifier-happy-flow", msg: "Test was interrupted" },
    ];
    const r = categorise(log, emptyAllowlist);
    expect(r.pass).toBe(true);
    expect(r.tally.interrupted).toBe(1);
    expect(r.blocking).toEqual([]);
  });

  it("allow-list entry referencing a check not in log → not an error", () => {
    const allowlist: Allowlist = {
      version: 1,
      checks: [{ id: "CheckAbsent", category: "spec-drift", justification: "j", reference: "r" }],
    };
    const r = categorise([{ result: "SUCCESS", src: "A" }], allowlist);
    expect(r.pass).toBe(true);
  });

  it("multiple FAILUREs of same check ID with one allow-list entry → all instances allowlisted", () => {
    const log: SuiteLogEntry[] = [
      { result: "FAILURE", src: "CheckSame" },
      { result: "FAILURE", src: "CheckSame" },
    ];
    const allowlist: Allowlist = {
      version: 1,
      checks: [{ id: "CheckSame", category: "spec-drift", justification: "j", reference: "r" }],
    };
    const r = categorise(log, allowlist);
    expect(r.pass).toBe(true);
    expect(r.allowlisted).toHaveLength(2);
    expect(r.blocking).toEqual([]);
  });

  it("informational log entries without result field → skipped, not throw", () => {
    // Suite emits these for block markers, server-config dumps, etc.
    const log = [{ src: "InfoOnly", msg: "block start" } as unknown as SuiteLogEntry];
    const r = categorise(log, emptyAllowlist);
    expect(r.pass).toBe(true);
    expect(r.tally).toEqual({ success: 0, failure: 0, warning: 0, review: 0, info: 0, interrupted: 0, finished: 0 });
  });

  it("log entry with INVALID result value (not in known set) → throws MalformedSuiteLogError", () => {
    const badLog = [{ result: "BOGUS", src: "A" } as unknown as SuiteLogEntry];
    expect(() => categorise(badLog, emptyAllowlist)).toThrow(MalformedSuiteLogError);
  });

  it("allow-list with duplicate IDs → throws at validation", () => {
    const allowlist: Allowlist = {
      version: 1,
      checks: [
        { id: "X", category: "spec-drift", justification: "j", reference: "r" },
        { id: "X", category: "spec-drift", justification: "j2", reference: "r2" },
      ],
    };
    expect(() => categorise([], allowlist)).toThrow(/duplicate/i);
  });
});
