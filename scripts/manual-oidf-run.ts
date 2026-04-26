import "reflect-metadata";
import { generateFixtures } from "./oidf-ci/fixtures";
import { startVerifierServer } from "./oidf-ci/verifier-server";

const PUBLIC_BASE = process.env.PUBLIC_BASE;
if (!PUBLIC_BASE) {
  console.error("Set PUBLIC_BASE to the https URL of your tunnel (e.g. https://abcd.ngrok.app).");
  process.exit(1);
}

const hostname = new URL(PUBLIC_BASE).hostname;

const fixtures = await generateFixtures({ hostname });

// externalBaseUrl publishes the tunnel URL in the JAR's request_uri/response_uri,
// while the server binds locally for the tunnel to forward to.
const verifier = await startVerifierServer({
  fixtures,
  port: 8080,
  externalBaseUrl: PUBLIC_BASE,
});

console.log("\n--- Configure the OIDF demo test plan with these values ---");
console.log("client_id:    ", `x509_san_dns:${hostname}`);
console.log("request_uri:  ", `${PUBLIC_BASE}/request.jwt`);
console.log("response_uri: ", `${PUBLIC_BASE}/response`);
console.log("\nLocal verifier listening (bound on 0.0.0.0:8080) — tunnel must forward", PUBLIC_BASE, "→ http://localhost:8080\n");

// Keep the process alive; Ctrl+C to exit.
process.on("SIGINT", async () => {
  await verifier.close();
  process.exit(0);
});
