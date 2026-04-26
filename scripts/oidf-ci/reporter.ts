import type { CategorisedResult } from "./categorise";

export interface RenderInput {
  profile: "happy-flow" | "full";
  planId: string;
  testId: string;
  suiteRef?: string;
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
      tally: result.tally,
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
  lines.push(`Pass: ${result.pass ? "✅" : "❌"}`);
  lines.push(`Plan ID: \`${input.planId}\``);
  lines.push(`Test ID: \`${input.testId}\``);
  if (input.suiteRef) lines.push(`Suite ref: \`${input.suiteRef}\``);
  lines.push("");
  lines.push("| Result | Count |");
  lines.push("|---|---|");
  lines.push(`| SUCCESS | ${result.tally.success} |`);
  lines.push(`| FAILURE | ${result.tally.failure} |`);
  lines.push(`| WARNING | ${result.tally.warning} |`);
  lines.push(`| REVIEW | ${result.tally.review} |`);
  lines.push(`| INFO | ${result.tally.info} |`);

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
