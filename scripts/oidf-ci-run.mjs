#!/usr/bin/env node
// Thin shim: tsx-loads the TS entry. Allows `npm run oidf:ci` to invoke without
// requiring tsx in the npm script command directly.
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const tsxBin = join(here, "..", "node_modules", ".bin", "tsx");
const tsEntry = join(here, "oidf-ci", "index.ts");

const child = spawn(tsxBin, [tsEntry, ...process.argv.slice(2)], { stdio: "inherit" });
child.on("exit", (code) => process.exit(code ?? 1));
