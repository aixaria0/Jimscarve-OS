/// Pure tier-2 cross-checking for rnode room members (#138).
///
/// The transport/authentication layer is deliberately outside this module:
/// callers only pass attestations after the room has accepted the envelope
/// identity (for example through dyncap). This function answers a narrower
/// question: given distinct peer perspectives, did deterministic rholang
/// execution agree for the same program and pre-state?
///
/// A single rnode never becomes proof. Different programs or pre-states are
/// not comparable and therefore stay INCONCLUSIVE. Only same-input divergence
/// is a decidable falsifier.

export interface RnodeAttestation {
  peer: string;
  program: string;
  preStateHash: string;
  postStateHash: string;
  result: string;
}

export type RholangProbeStatus = "AGREEMENT" | "FALSIFIED" | "INCONCLUSIVE";

export interface ValueBucket {
  value: string;
  peers: string[];
}

export interface RholangFalsifier {
  kind: "peer-equivocation" | "post-state-divergence" | "result-divergence";
  program?: string;
  preStateHash?: string;
  peer?: string;
  observations?: RnodeAttestation[];
  values?: ValueBucket[];
}

export interface RholangProbeAssessment {
  status: RholangProbeStatus;
  perspectives: number;
  peers: string[];
  program: string | null;
  preStateHash: string | null;
  postStateHash?: string;
  result?: string;
  blockers: string[];
  falsifiers: RholangFalsifier[];
}

interface ComparableCohort {
  key: string;
  program: string;
  preStateHash: string;
  rows: RnodeAttestation[];
  peers: string[];
}

function complete(a: unknown): a is RnodeAttestation {
  if (typeof a !== "object" || a === null) return false;
  const candidate = a as Partial<RnodeAttestation>;
  return [candidate.peer, candidate.program, candidate.preStateHash, candidate.postStateHash]
    .every((v) => typeof v === "string" && v.length > 0)
    && typeof candidate.result === "string";
}

function sameAttestation(a: RnodeAttestation, b: RnodeAttestation): boolean {
  return a.peer === b.peer
    && a.program === b.program
    && a.preStateHash === b.preStateHash
    && a.postStateHash === b.postStateHash
    && a.result === b.result;
}

function buckets(rows: RnodeAttestation[], pick: (a: RnodeAttestation) => string): ValueBucket[] {
  const grouped = new Map<string, string[]>();
  for (const row of rows) {
    const value = pick(row);
    const peers = grouped.get(value) ?? [];
    if (!peers.includes(row.peer)) peers.push(row.peer);
    grouped.set(value, peers);
  }
  return [...grouped.entries()].map(([value, peers]) => ({ value, peers }));
}

function cohortKey(program: string, preStateHash: string): string {
  return JSON.stringify([program, preStateHash]);
}

export function assessRnodeAttestations(
  input: RnodeAttestation[],
  minPerspectives = 2,
): RholangProbeAssessment {
  const blockers: string[] = [];
  const falsifiers: RholangFalsifier[] = [];

  const validMinPerspectives = Number.isInteger(minPerspectives) && minPerspectives >= 2;
  if (!validMinPerspectives) {
    blockers.push("minPerspectives must be an integer >= 2");
  }

  const malformed = input.filter((a) => !complete(a));
  if (malformed.length > 0) {
    blockers.push(`${malformed.length} malformed attestation(s) omitted`);
  }

  const rows: RnodeAttestation[] = [];
  for (const a of input.filter(complete)) {
    if (!rows.some((existing) => sameAttestation(existing, a))) rows.push(a);
  }

  const allPeers = [...new Set(rows.map((a) => a.peer))];
  const programs = [...new Set(rows.map((a) => a.program))];
  const preStates = [...new Set(rows.map((a) => a.preStateHash))];

  if (programs.length > 1) {
    blockers.push("attestations do not describe the same program");
  }
  if (preStates.length > 1) {
    blockers.push("attestations do not share the same pre-state");
  }

  const grouped = new Map<string, RnodeAttestation[]>();
  for (const row of rows) {
    const key = cohortKey(row.program, row.preStateHash);
    const cohortRows = grouped.get(key) ?? [];
    cohortRows.push(row);
    grouped.set(key, cohortRows);
  }

  const cohorts: ComparableCohort[] = [...grouped.entries()].map(([key, cohortRows]) => ({
    key,
    program: cohortRows[0].program,
    preStateHash: cohortRows[0].preStateHash,
    rows: cohortRows,
    peers: [...new Set(cohortRows.map((row) => row.peer))],
  }));

  const falsifiedCohorts: ComparableCohort[] = [];

  for (const cohort of cohorts) {
    const before = falsifiers.length;
    const byPeer = new Map<string, RnodeAttestation[]>();

    for (const row of cohort.rows) {
      const peerRows = byPeer.get(row.peer) ?? [];
      peerRows.push(row);
      byPeer.set(row.peer, peerRows);
    }

    for (const [peer, peerRows] of byPeer) {
      if (peerRows.length > 1) {
        falsifiers.push({
          kind: "peer-equivocation",
          program: cohort.program,
          preStateHash: cohort.preStateHash,
          peer,
          observations: peerRows,
        });
      }
    }

    // Cross-peer divergence is evaluated only across peers that supplied one
    // unambiguous attestation in this comparable input context. Equivocating
    // peers are already explicit falsifiers and cannot steer the buckets.
    const stableRows = [...byPeer.values()]
      .filter((peerRows) => peerRows.length === 1)
      .map((peerRows) => peerRows[0]);

    const postStates = buckets(stableRows, (a) => a.postStateHash);
    const results = buckets(stableRows, (a) => a.result);

    if (postStates.length > 1) {
      falsifiers.push({
        kind: "post-state-divergence",
        program: cohort.program,
        preStateHash: cohort.preStateHash,
        values: postStates,
      });
    }
    if (results.length > 1) {
      falsifiers.push({
        kind: "result-divergence",
        program: cohort.program,
        preStateHash: cohort.preStateHash,
        values: results,
      });
    }

    if (falsifiers.length > before) falsifiedCohorts.push(cohort);
  }

  // Explicit same-input contradiction dominates unrelated malformed or
  // non-comparable evidence. Those observations remain visible in blockers,
  // but cannot dilute a valid falsifier into INCONCLUSIVE.
  if (falsifiers.length > 0) {
    const context = falsifiedCohorts.length === 1 ? falsifiedCohorts[0] : null;
    const peers = context?.peers ?? allPeers;
    return {
      status: "FALSIFIED",
      perspectives: peers.length,
      peers,
      program: context?.program ?? null,
      preStateHash: context?.preStateHash ?? null,
      blockers,
      falsifiers,
    };
  }

  if (cohorts.length === 0) {
    if (validMinPerspectives) {
      blockers.push(`need at least ${minPerspectives} distinct rnode perspectives; got 0`);
    }
    return {
      status: "INCONCLUSIVE",
      perspectives: 0,
      peers: [],
      program: null,
      preStateHash: null,
      blockers,
      falsifiers,
    };
  }

  // Malformed evidence, invalid configuration, or multiple input contexts may
  // block bounded agreement, but only after all comparable cohorts have been
  // checked for stronger falsifier evidence above.
  if (blockers.length > 0 || cohorts.length !== 1) {
    return {
      status: "INCONCLUSIVE",
      perspectives: allPeers.length,
      peers: allPeers,
      program: programs.length === 1 ? programs[0] : null,
      preStateHash: preStates.length === 1 ? preStates[0] : null,
      blockers,
      falsifiers,
    };
  }

  const cohort = cohorts[0];
  if (cohort.peers.length < minPerspectives) {
    blockers.push(
      `need at least ${minPerspectives} distinct rnode perspectives; got ${cohort.peers.length}`,
    );
    return {
      status: "INCONCLUSIVE",
      perspectives: cohort.peers.length,
      peers: cohort.peers,
      program: cohort.program,
      preStateHash: cohort.preStateHash,
      blockers,
      falsifiers,
    };
  }

  const byPeer = new Map<string, RnodeAttestation>();
  for (const row of cohort.rows) byPeer.set(row.peer, row);
  const onePerPeer = [...byPeer.values()];
  const postStates = buckets(onePerPeer, (a) => a.postStateHash);
  const results = buckets(onePerPeer, (a) => a.result);

  return {
    status: "AGREEMENT",
    perspectives: cohort.peers.length,
    peers: cohort.peers,
    program: cohort.program,
    preStateHash: cohort.preStateHash,
    postStateHash: postStates[0].value,
    result: results[0].value,
    blockers,
    falsifiers,
  };
}
