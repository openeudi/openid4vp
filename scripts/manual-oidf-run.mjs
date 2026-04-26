#!/usr/bin/env node
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const tsxBin = join(here, "..", "node_modules", ".bin", "tsx");
const tsEntry = join(here, "manual-oidf-run.ts");

const child = spawn(tsxBin, [tsEntry, ...process.argv.slice(2)], { stdio: "inherit" });
child.on("exit", (code) => process.exit(code ?? 1));
