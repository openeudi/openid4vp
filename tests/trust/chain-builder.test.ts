import { describe, expect, it } from "vitest";
import { ChainBuilder } from "../../src/trust/ChainBuilder.js";
import { CertificateChainError } from "../../src/errors.js";
import { createCa, createIntermediate, createLeaf } from "./helpers/synthetic-ca.js";

describe("ChainBuilder — signature verification", () => {
  it("builds a valid leaf → root chain", async () => {
    const root = await createCa();
    const leaf = await createLeaf(root);
    const builder = new ChainBuilder();
    const chain = await builder.build(leaf.certificate, [root.certificate]);
    expect(chain).toHaveLength(2);
    expect(chain[0].subject).toBe(leaf.certificate.subject);
    expect(chain[chain.length - 1].subject).toBe(root.certificate.subject);
  });

  it("builds a valid leaf → intermediate → root chain", async () => {
    const root = await createCa();
    const intermediate = await createIntermediate(root);
    const leaf = await createLeaf(intermediate);
    const builder = new ChainBuilder();
    const chain = await builder.build(leaf.certificate, [root.certificate], [intermediate.certificate]);
    expect(chain).toHaveLength(3);
  });

  it("rejects a leaf signed by a different root", async () => {
    const realRoot = await createCa();
    const attackerRoot = await createCa();
    const leaf = await createLeaf(attackerRoot);
    const builder = new ChainBuilder();
    // Both CAs share DN `CN=Test Root CA` by default, so the DN climb selects
    // realRoot as the anchor; the AKI/SKI check rejects before we even reach
    // signature verification, with a more-specific reason.
    await expect(builder.build(leaf.certificate, [realRoot.certificate])).rejects.toMatchObject({
      code: "chain_invalid",
      reason: "aki_ski_mismatch",
    });
    await expect(builder.build(leaf.certificate, [realRoot.certificate])).rejects.toBeInstanceOf(CertificateChainError);
  });
});

describe("ChainBuilder — validity period", () => {
  it("rejects an expired leaf", async () => {
    const root = await createCa();
    const past = new Date("2020-01-01T00:00:00Z");
    const leaf = await createLeaf(root, {
      notBefore: new Date("2019-06-01T00:00:00Z"),
      notAfter: past,
    });
    const builder = new ChainBuilder();
    await expect(builder.build(leaf.certificate, [root.certificate])).rejects.toMatchObject({
      code: "chain_invalid",
      reason: "validity",
    });
  });

  it("rejects a not-yet-valid leaf", async () => {
    const root = await createCa();
    const future = new Date("2099-01-01T00:00:00Z");
    const leaf = await createLeaf(root, {
      notBefore: future,
      notAfter: new Date("2099-06-01T00:00:00Z"),
    });
    const builder = new ChainBuilder();
    await expect(builder.build(leaf.certificate, [root.certificate])).rejects.toMatchObject({
      code: "chain_invalid",
      reason: "validity",
    });
  });

  it("accepts a leaf expired within clockSkewTolerance", async () => {
    const root = await createCa({
      notBefore: new Date("2026-03-01T00:00:00Z"),
      notAfter: new Date("2027-04-01T00:00:00Z"),
    });
    const now = new Date("2026-04-22T12:00:00Z");
    const justExpired = new Date(now.getTime() - 30_000); // 30s ago
    const leaf = await createLeaf(root, {
      notBefore: new Date("2026-04-01T00:00:00Z"),
      notAfter: justExpired,
    });
    const builder = new ChainBuilder({
      clockSkewTolerance: 60,
      now: () => now,
    });
    await expect(builder.build(leaf.certificate, [root.certificate])).resolves.toHaveLength(2);
  });

  it("rejects a leaf expired beyond clockSkewTolerance", async () => {
    const root = await createCa({
      notBefore: new Date("2026-03-01T00:00:00Z"),
      notAfter: new Date("2027-04-01T00:00:00Z"),
    });
    const now = new Date("2026-04-22T12:00:00Z");
    const wayExpired = new Date(now.getTime() - 120_000); // 2min ago
    const leaf = await createLeaf(root, {
      notBefore: new Date("2026-04-01T00:00:00Z"),
      notAfter: wayExpired,
    });
    const builder = new ChainBuilder({
      clockSkewTolerance: 60,
      now: () => now,
    });
    await expect(builder.build(leaf.certificate, [root.certificate])).rejects.toMatchObject({ reason: "validity" });
  });
});

describe("ChainBuilder — algorithm allowlist", () => {
  it("accepts ES256 by default", async () => {
    const root = await createCa();
    const leaf = await createLeaf(root);
    const builder = new ChainBuilder();
    await expect(builder.build(leaf.certificate, [root.certificate])).resolves.toHaveLength(2);
  });

  it("rejects a cert whose signature algorithm is not in the allowlist", async () => {
    const root = await createCa();
    const leaf = await createLeaf(root);
    const builder = new ChainBuilder({ allowedAlgorithms: ["PS256"] });
    await expect(builder.build(leaf.certificate, [root.certificate])).rejects.toMatchObject({
      code: "chain_invalid",
      reason: "algorithm_disallowed",
    });
  });
});

describe("ChainBuilder — AKI/SKI matching", () => {
  it("rejects when child AKI does not match issuer SKI", async () => {
    // Build a leaf signed by parentA but craft an AKI that points at parentB's SKI.
    // The helpers don't support AKI injection directly, so we simulate this by
    // using two CAs with the same subject DN but different keys: the chain will
    // build by DN but fail on AKI comparison.
    const parentA = await createCa({ name: "CN=Same DN CA" });
    const parentB = await createCa({ name: "CN=Same DN CA" });
    const leaf = await createLeaf(parentA); // AKI points at parentA's SKI
    // parentB has the same subject but a different SKI.
    const builder = new ChainBuilder();
    // When anchors = [parentB], the DN climb will select parentB but the AKI
    // check should reject it. When anchors = [parentA], the chain builds.
    await expect(builder.build(leaf.certificate, [parentB.certificate])).rejects.toMatchObject({
      code: "chain_invalid",
      reason: "aki_ski_mismatch",
    });
    await expect(builder.build(leaf.certificate, [parentA.certificate])).resolves.toHaveLength(2);
  });
});
