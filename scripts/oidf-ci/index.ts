import "reflect-metadata";
import { runProfile, type Profile } from "./orchestrator";

interface ParsedArgs {
  profile: Profile;
  suiteBase: string;
  outputDir: string;
}

function parseArgs(argv: string[]): ParsedArgs {
  const map = new Map<string, string>();
  for (const arg of argv.slice(2)) {
    const m = arg.match(/^--([^=]+)=(.*)$/);
    if (m) map.set(m[1], m[2]);
  }
  const profile = map.get("profile");
  const suiteBase = map.get("suite-base") ?? "https://localhost:8443";
  const outputDir = map.get("output-dir") ?? "./oidf-result";
  if (profile !== "happy-flow" && profile !== "full") {
    console.error("Usage: oidf-ci-run --profile=happy-flow|full [--suite-base=URL] [--output-dir=PATH]");
    process.exit(2);
  }
  return { profile: profile as Profile, suiteBase, outputDir };
}

async function main() {
  const args = parseArgs(process.argv);

  // The self-hosted OIDF suite uses an nginx-terminated self-signed TLS cert on :8443.
  // When the orchestrator targets a localhost suite, disable TLS verification so
  // built-in fetch() succeeds against the self-signed cert. Process-wide effect; only
  // applies when the operator explicitly points at a localhost URL.
  const targetUrl = new URL(args.suiteBase);
  if (
    (targetUrl.protocol === "https:" || targetUrl.protocol === "wss:") &&
    (targetUrl.hostname === "localhost" || targetUrl.hostname === "127.0.0.1")
  ) {
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
  }

  const { exitCode } = await runProfile({
    profile: args.profile,
    suiteBaseUrl: args.suiteBase,
    outputDir: args.outputDir,
  });
  process.exit(exitCode);
}

main().catch((err) => {
  console.error("[oidf-ci] uncaught error:", err);
  process.exit(2);
});
