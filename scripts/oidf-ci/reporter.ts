import type { CategorisedResult } from "./categorise";

export interface VerifierExceptionRecord {
  name: string;
  message: string;
}

export interface RenderInput {
  /** Any registered profile name (see `profiles/registry.ts`). */
  profile: string;
  planId: string;
  testId: string;
  suiteRef?: string;
  /** What the profile expects the verifier to do with the response (see `ProfileDescriptor.expect`). */
  expect?: "accept" | "reject";
  verifierAccepts?: number;
  verifierRejects?: number;
  /**
   * Detail records for `verifierRejects`. For `expect: "accept"` profiles these are
   * blocking exceptions (the verifier wrongly rejected a valid presentation). For
   * `expect: "reject"` profiles these are the expected rejection evidence, not errors.
   */
  verifierExceptions?: VerifierExceptionRecord[];
  /**
   * Distinct labels for the orchestrator's final verdict so a non-blocking known
   * divergence (see `ProfileDescriptor.knownDivergence`) is never conflated with a
   * normal `"pass"` — both exit 0, but they mean different things and must render
   * differently. `"divergence-closed"` means a `knownDivergence` profile rejected as
   * the suite expects this run (the documented gap didn't reproduce).
   */
  outcome?: "pass" | "fail" | "known-divergence" | "divergence-closed";
  /** Present when `outcome` is `"known-divergence"` or `"divergence-closed"`. */
  divergence?: { reason: string };
}

export interface RenderOutput {
  json: string;
  summary: string;
}

export function renderResult(result: CategorisedResult, input: RenderInput): RenderOutput {
  const json = JSON.stringify(
    {
      profile: input.profile,
      planId: input.planId,
      testId: input.testId,
      suiteRef: input.suiteRef,
      pass: result.pass,
      outcome: input.outcome,
      divergence: input.divergence,
      tally: result.tally,
      verifier: {
        expect: input.expect,
        accepts: input.verifierAccepts ?? 0,
        rejects: input.verifierRejects ?? 0,
        exceptions: input.verifierExceptions ?? [],
      },
      blocking: result.blocking.map((f) => ({ src: f.src, msg: f.msg })),
      allowlisted: result.allowlisted.map((f) => ({
        src: f.src,
        msg: f.msg,
        category: f.allowlistEntry?.category,
        justification: f.allowlistEntry?.justification,
        reference: f.allowlistEntry?.reference,
      })),
    },
    null,
    2
  );

  const lines: string[] = [];
  lines.push(`# OIDF Conformance — ${input.profile}`);
  lines.push("");
  // A known-divergence run reports `result.pass: false` (see orchestrator's
  // `jsonPass`) even though the process exits 0 — never render that as a bare
  // "Pass ❌" (reads as a hard failure) or let a stale caller assume "Pass ✅" means
  // clean. Label it explicitly instead; the Outcome line below adds the reason.
  const passLine = input.outcome === "known-divergence" ? "⚠️ Known divergence (non-blocking, exit 0)" : result.pass ? "✅" : "❌";
  lines.push(`Pass: ${passLine}`);
  lines.push(`Plan ID: \`${input.planId}\``);
  lines.push(`Test ID: \`${input.testId}\``);
  if (input.suiteRef) lines.push(`Suite ref: \`${input.suiteRef}\``);
  if (input.expect) lines.push(`Expected outcome: \`${input.expect}\``);
  if (input.outcome === "known-divergence" || input.outcome === "divergence-closed") {
    const label = input.outcome === "known-divergence" ? "⚠️ KNOWN DIVERGENCE (non-blocking)" : "ℹ️ Divergence closed";
    lines.push(`Outcome: ${label}`);
    if (input.divergence?.reason) lines.push(`  - ${input.divergence.reason}`);
  } else if (input.outcome) {
    lines.push(`Outcome: \`${input.outcome}\``);
  }
  lines.push("");
  lines.push("| Result | Count |");
  lines.push("|---|---|");
  lines.push(`| SUCCESS | ${result.tally.success} |`);
  lines.push(`| FAILURE | ${result.tally.failure} |`);
  lines.push(`| WARNING | ${result.tally.warning} |`);
  lines.push(`| REVIEW | ${result.tally.review} |`);
  lines.push(`| INFO | ${result.tally.info} |`);

  if (input.verifierAccepts !== undefined || input.verifierRejects !== undefined) {
    lines.push("");
    lines.push(`Verifier responses — accepted: ${input.verifierAccepts ?? 0} | rejected: ${input.verifierRejects ?? 0}`);
    if (input.verifierExceptions?.length) {
      const label = input.expect === "reject" ? "Rejection detail" : "Blocking exceptions";
      lines.push(`${label}:`);
      for (const e of input.verifierExceptions) lines.push(`  - **${e.name}** — ${e.message}`);
    }
  }

  if (result.blocking.length) {
    lines.push("");
    lines.push("## Blocking failures");
    for (const f of result.blocking) {
      lines.push(`- **${f.src}** — ${f.msg}`);
    }
  }

  if (result.allowlisted.length) {
    lines.push("");
    lines.push("## Allow-listed (informational)");
    for (const f of result.allowlisted) {
      lines.push(`- **${f.src}** (${f.allowlistEntry?.category}) — ${f.msg}`);
      if (f.allowlistEntry?.justification) lines.push(`  - ${f.allowlistEntry.justification}`);
      if (f.allowlistEntry?.reference) lines.push(`  - Ref: ${f.allowlistEntry.reference}`);
    }
  }

  return { json, summary: lines.join("\n") + "\n" };
}
