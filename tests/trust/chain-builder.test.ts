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
    await expect(builder.build(leaf.certificate, [realRoot.certificate])).rejects.toMatchObject({
      code: "chain_invalid",
      reason: "signature",
    });
    await expect(builder.build(leaf.certificate, [realRoot.certificate])).rejects.toBeInstanceOf(CertificateChainError);
  });
});
