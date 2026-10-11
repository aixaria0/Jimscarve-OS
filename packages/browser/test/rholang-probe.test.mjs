// rholang-probe.test.mjs — pure tier-2 rnode cross-checking (#138)
//
// No live node is needed: this tests the decision boundary before transport,
// dyncap verification and /probe trust-weighting are wired around it.

import { build } from "esbuild";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const bundle = await build({
  absWorkingDir: here,
  entryPoints: [join(here, "..", "src", "rholang-probe.ts")],
  bundle: true, format: "esm", platform: "node", write: false,
});
const { assessRnodeAttestations } =
  await import("data:text/javascript;base64," + Buffer.from(bundle.outputFiles[0].text).toString("base64"));

let failed = 0;
const check = (label, cond, detail = "") => {
  if (cond) console.log(`  ok   ${label}`);
  else { failed++; console.log(`  FAIL ${label}  (${detail})`); }
};

const row = (peer, overrides = {}) => ({
  peer,
  program: "new x in { x!(1) }",
  preStateHash: "pre-A",
  postStateHash: "post-A",
  result: "1",
  ...overrides,
});

{
  const a = assessRnodeAttestations([row("node-a")]);
  check("one rnode is inconclusive, never silently trusted",
    a.status === "INCONCLUSIVE" && /at least 2/.test(a.blockers.join(" ")),
    JSON.stringify(a));
}

{
  const a = assessRnodeAttestations([row("node-a"), row("node-b")]);
  check("two matching independent perspectives form bounded agreement",
    a.status === "AGREEMENT"
      && a.perspectives === 2
      && a.postStateHash === "post-A"
      && a.result === "1",
    JSON.stringify(a));
}

{
  const a = assessRnodeAttestations([
    row("node-a"),
    row("node-b", { postStateHash: "post-B" }),
  ]);
  check("same input + different post-state is a decidable falsifier",
    a.status === "FALSIFIED"
      && a.falsifiers.some((f) => f.kind === "post-state-divergence"),
    JSON.stringify(a));
}

{
  const a = assessRnodeAttestations([
    row("node-a"),
    row("node-b", { result: "2" }),
  ]);
  check("same input + different result is surfaced",
    a.status === "FALSIFIED"
      && a.falsifiers.some((f) => f.kind === "result-divergence"),
    JSON.stringify(a));
}

{
  const a = assessRnodeAttestations([
    row("node-a"),
    row("node-b", { preStateHash: "pre-B" }),
  ]);
  check("different pre-states are not falsely called divergence",
    a.status === "INCONCLUSIVE"
      && a.falsifiers.length === 0
      && a.blockers.some((b) => b.includes("pre-state")),
    JSON.stringify(a));
}

{
  const duplicate = row("node-a");
  const a = assessRnodeAttestations([duplicate, { ...duplicate }]);
  check("duplicate delivery from one peer cannot manufacture quorum",
    a.status === "INCONCLUSIVE" && a.perspectives === 1,
    JSON.stringify(a));
}

{
  const duplicate = row("node-a");
  const a = assessRnodeAttestations([duplicate, { ...duplicate }, row("node-b")]);
  check("perspectives count distinct peers rather than rows",
    a.status === "AGREEMENT" && a.perspectives === 2,
    JSON.stringify(a));
}

{
  const a = assessRnodeAttestations([
    row("node-a"),
    row("node-a", { postStateHash: "post-B" }),
  ]);
  check("one peer equivocating is itself explicit falsifier evidence",
    a.status === "FALSIFIED"
      && a.falsifiers.some((f) => f.kind === "peer-equivocation"),
    JSON.stringify(a));
}

{
  const a = assessRnodeAttestations([
    row("node-a"),
    row("node-a", { preStateHash: "pre-B" }),
  ]);
  check("one peer reporting different inputs is not mislabeled equivocation",
    a.status === "INCONCLUSIVE"
      && a.falsifiers.length === 0
      && a.blockers.some((b) => b.includes("pre-state")),
    JSON.stringify(a));
}

{
  const a = assessRnodeAttestations([
    row("node-a"),
    row("node-b", { preStateHash: "" }),
  ]);
  check("malformed evidence fails closed",
    a.status === "INCONCLUSIVE"
      && a.perspectives === 1
      && a.blockers.some((b) => b.includes("malformed")),
    JSON.stringify(a));
}

{
  const a = assessRnodeAttestations([null, row("node-a"), row("node-b")]);
  check("non-object attestation is omitted instead of throwing",
    a.status === "INCONCLUSIVE"
      && a.blockers.some((b) => b.includes("malformed")),
    JSON.stringify(a));
}

{
  const a = assessRnodeAttestations([
    row("node-a"),
    row("node-b", { postStateHash: "post-B" }),
    null,
  ]);
  check("valid divergence dominates one malformed attestation",
    a.status === "FALSIFIED"
      && a.falsifiers.some((f) => f.kind === "post-state-divergence")
      && a.blockers.some((b) => b.includes("malformed")),
    JSON.stringify(a));
}

{
  const a = assessRnodeAttestations([
    row("node-a"),
    row("node-b", { postStateHash: "post-B" }),
    row("node-c", { preStateHash: "pre-B", postStateHash: "post-C" }),
  ]);
  check("divergence in one input cohort survives an unrelated cohort",
    a.status === "FALSIFIED"
      && a.preStateHash === "pre-A"
      && a.perspectives === 2
      && a.falsifiers.some((f) => f.kind === "post-state-divergence")
      && a.blockers.some((b) => b.includes("pre-state")),
    JSON.stringify(a));
}

{
  const a = assessRnodeAttestations([
    row("node-a"),
    row("node-a", { result: "2" }),
    null,
  ]);
  check("peer equivocation dominates unrelated malformed evidence",
    a.status === "FALSIFIED"
      && a.falsifiers.some((f) => f.kind === "peer-equivocation")
      && a.blockers.some((b) => b.includes("malformed")),
    JSON.stringify(a));
}

{
  const a = assessRnodeAttestations([
    row("node-a"),
    row("node-b", { postStateHash: "post-B" }),
    row("node-c"),
    row("node-d", { preStateHash: "pre-B", postStateHash: "post-D" }),
  ]);
  check("fourth-peer off-input injection cannot hide honest divergence",
    a.status === "FALSIFIED"
      && a.preStateHash === "pre-A"
      && a.perspectives === 3
      && a.falsifiers.some((f) => f.kind === "post-state-divergence"),
    JSON.stringify(a));
}

{
  const a = assessRnodeAttestations([
    null,
    { peer: "node-a", program: "", preStateHash: "", postStateHash: "", result: "" },
  ]);
  check("malformed-only evidence remains inconclusive",
    a.status === "INCONCLUSIVE"
      && a.falsifiers.length === 0
      && a.blockers.some((b) => b.includes("malformed")),
    JSON.stringify(a));
}

{
  const a = assessRnodeAttestations([
    row("node-a"),
    row("node-b"),
    row("node-c", { preStateHash: "pre-B", postStateHash: "post-B" }),
    row("node-d", { preStateHash: "pre-B", postStateHash: "post-B" }),
  ]);
  check("separate agreeing input cohorts remain inconclusive overall",
    a.status === "INCONCLUSIVE"
      && a.falsifiers.length === 0
      && a.blockers.some((b) => b.includes("pre-state")),
    JSON.stringify(a));
}

{
  const a = assessRnodeAttestations([row("node-a"), row("node-b")], 1);
  check("invalid minimum perspective configuration blocks agreement",
    a.status === "INCONCLUSIVE"
      && a.blockers.some((b) => b.includes("minPerspectives")),
    JSON.stringify(a));
}

{
  const a = assessRnodeAttestations([
    row("node-a"),
    row("node-b", { postStateHash: "post-B" }),
  ], 1);
  check("invalid minimum perspective configuration cannot suppress falsifier",
    a.status === "FALSIFIED"
      && a.falsifiers.some((f) => f.kind === "post-state-divergence")
      && a.blockers.some((b) => b.includes("minPerspectives")),
    JSON.stringify(a));
}

console.log(`\n${failed === 0 ? "PASS" : "FAIL"}: rholang-probe.test.mjs (${failed} failure${failed === 1 ? "" : "s"})`);
process.exit(failed === 0 ? 0 : 1);
