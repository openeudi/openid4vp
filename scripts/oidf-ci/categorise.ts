import type { SuiteLogEntry, SuiteLogResult } from "./suite-client";

export interface AllowlistEntry {
  id: string;
  /**
   * Reason this failure is permitted to slip past the merge gate. Per
   * docs/superpowers/specs/2026-04-25-openid4vp-d-oidf-conformance-ci-design.md:
   * - `library-known-divergence` — library knowingly diverges from the suite's
   *   expectation, tracked as a CHANGELOG known-limitation.
   * - `spec-drift` — OIDF ID3 expects an older shape than the library's 1.0
   *   Final emit (warnings / known parameter naming differences).
   * - `harness` — our test infrastructure can't satisfy the check (e.g. local
   *   verifier on plain HTTP can't satisfy `EnsureRequestUriIsHttps`).
   * - `upstream-bug` — confirmed bug in the conformance suite itself.
   */
  category: "spec-drift" | "library-known-divergence" | "harness" | "upstream-bug";
  justification: string;
  reference: string;
}

export interface Allowlist {
  version: 1;
  checks: AllowlistEntry[];
}

export interface CategorisedFailure {
  src: string;
  msg: string;
  raw: SuiteLogEntry;
  allowlistEntry?: AllowlistEntry;
}

export interface CategorisedResult {
  tally: {
    success: number;
    failure: number;
    warning: number;
    review: number;
    info: number;
    interrupted: number;
    finished: number;
  };
  blocking: CategorisedFailure[];
  allowlisted: CategorisedFailure[];
  pass: boolean;
}

export class MalformedSuiteLogError extends Error {
  override readonly name = "MalformedSuiteLogError";
}

const KNOWN_RESULTS: Set<SuiteLogResult> = new Set([
  "SUCCESS",
  "FAILURE",
  "WARNING",
  "REVIEW",
  "INFO",
  "INTERRUPTED",
  "FINISHED",
]);

export function categorise(log: SuiteLogEntry[], allowlist: Allowlist): CategorisedResult {
  validateAllowlist(allowlist);
  const allowlistById = new Map(allowlist.checks.map((c) => [c.id, c] as const));

  const tally = { success: 0, failure: 0, warning: 0, review: 0, info: 0, interrupted: 0, finished: 0 };
  const blocking: CategorisedFailure[] = [];
  const allowlisted: CategorisedFailure[] = [];

  for (const entry of log) {
    if (!entry) {
      throw new MalformedSuiteLogError(`Suite log entry is null/undefined`);
    }
    // Suite emits informational entries WITHOUT a result field (block markers,
    // server-config dumps, etc.). Skip these — they don't count toward tally.
    if (entry.result === undefined || entry.result === null) {
      continue;
    }
    if (typeof entry.result !== "string" || !KNOWN_RESULTS.has(entry.result)) {
      throw new MalformedSuiteLogError(`Suite log entry has invalid 'result' field: ${JSON.stringify(entry).slice(0, 200)}`);
    }

    switch (entry.result) {
      case "SUCCESS":
        tally.success++;
        break;
      case "WARNING":
        tally.warning++;
        break;
      case "REVIEW":
        tally.review++;
        break;
      case "INFO":
        tally.info++;
        break;
      case "INTERRUPTED":
        // Test-runner-level marker: test stopped at a callAndStopOnFailure
        // failure. Doesn't itself indicate a check failure; the actual FAILURE
        // entry that caused it is handled separately.
        tally.interrupted++;
        break;
      case "FINISHED":
        // Test-runner-level marker emitted on normal completion. Tracked for
        // visibility; doesn't affect pass/fail.
        tally.finished++;
        break;
      case "FAILURE": {
        tally.failure++;
        const found = allowlistById.get(entry.src);
        const failure: CategorisedFailure = {
          src: entry.src,
          msg: entry.msg ?? "",
          raw: entry,
          ...(found ? { allowlistEntry: found } : {}),
        };
        if (found) allowlisted.push(failure);
        else blocking.push(failure);
        break;
      }
    }
  }

  return { tally, blocking, allowlisted, pass: blocking.length === 0 };
}

function validateAllowlist(allowlist: Allowlist): void {
  const seen = new Set<string>();
  for (const c of allowlist.checks) {
    if (seen.has(c.id)) throw new Error(`Allow-list contains duplicate id: ${c.id}`);
    seen.add(c.id);
  }
}
