# mih — Roadmap

> Working title: `mih` (MPC-in-the-Head). Rename before the first public commit.

## Thesis

MPC-in-the-Head turns a passively-secure multi-party protocol into a zero-knowledge
proof: the prover simulates all parties "in its head", commits to every party's view,
and the verifier opens a subset. Soundness comes from the fact that a cheating prover
must produce at least one inconsistent view; zero-knowledge comes from the privacy
threshold of the underlying protocol.

The engineering thesis of this project is that **the privacy property of a
decomposition should be a static property, not a proof obligation carried in prose**.
By Phase 5 it must be impossible to express a leaky gate decomposition in the frontend
DSL: a rule whose opened views are not simulatable from the shares alone is a compile
error, not a subtle bug found by a reviewer.

## Ground rules

- Language: Rust. Established crypto crates are used for primitives and plumbing:
  hashing (`sha2`, `blake3`), randomness (`rand`, `rand_chacha`), constant-time helpers
  (`subtle`), serialization, and zeroization. There is no reason to reimplement SHA-256
  in software here; the interesting work is above that layer.
- The line: anything that is *the object of study* is built here. Circuit
  representations, the decompositions, the sharing schemes, the commitment structure of
  the proof, seed trees, Fiat-Shamir, the parameter derivation, and the whole prover and
  verifier are written from scratch. No existing MPCitH, ZK, or signature library is
  pulled in, not even for comparison inside the code.
- Every dependency is justified in one line in `DESIGN_DECISIONS.md` at the point it is
  added. If the justification is hard to write, that is a signal the crate is doing
  something the project should be doing itself.
- Dev dependencies (criterion, proptest, hex) are unrestricted.
- Every phase ends with a reproducible artifact: a committed benchmark, a table, or a
  failing-by-design test. "It works on my machine" does not close a phase.
- Every phase has a `CHECKPOINT.md` entry: what was built, what was measured, what was
  deliberately left out.
- This is a learning implementation. It is not constant-time-audited and must carry a
  "do not use in production" notice in the README from the first commit.

## Repository layout (target)

```
mih/
  crates/
    mih-sym/        SHA-256 and LowMC as circuits, GF(2) matrices
    mih-circuit/    boolean circuit IR, builder, evaluator, statistics
    mih-core/       transcript, commitments, PRG, Fiat-Shamir, serialization
    mih-zkboo/      Phase 1-2: (2,3)-decomposition, ZKBoo / ZKB++
    mih-kkw/        Phase 3: preprocessing model, N-party, cut-and-choose
    mih-sig/        Phase 4: Picnic-style signature scheme
    mih-lang/       Phase 5: typed frontend for decompositions
  docs/
    README.md
    ROADMAP.md
    CHECKPOINT.md
    DESIGN_DECISIONS.md
  benches/
```

---

## Phase 0 — Groundwork and the proof-size wall

**Goal.** Build everything the proof system will sit on, and establish the baseline
problem that the rest of the project exists to attack.

**Scope.**
- Boolean circuit IR: `Xor`, `And`, `Not`, input/output wires, topological ordering.
- Circuit builder plus a plain evaluator, with gate statistics (AND count is the cost
  metric that matters for every later phase).
- SHA-256 expressed as a boolean circuit. No crate provides this, so the gate-level
  construction is hand-built; the `sha2` crate serves as the reference oracle that the
  circuit evaluator is differentially tested against.
- LowMC as a circuit, parameterized over (n, k, m, r); it is the Phase 4 one-way function
  and has a deliberately low AND count. The S-box layer and the linear layers are built
  here, with the matrix generation seeded and reproducible.
- `mih-core`: a domain-separated transcript, hash-based commitments, a PRG for
  randomness tapes, and a canonical byte serialization with round-trip tests. The hash
  and stream cipher underneath come from crates; the domain separation, the commitment
  structure, and the encoding are the project's own and are specified in writing.

**Deliverable — the wall.** A benchmark that computes, for SHA-256 and for LowMC, the
proof size of a naive MPCitH construction: all three views stored in full, repeated
often enough for 128-bit soundness. Print the number in megabytes. Every later phase
reports its size against this baseline.

**Done when.**
- The SHA-256 circuit agrees with `sha2` on the NIST vectors plus a randomized
  differential test over many inputs, run under proptest.
- AND-gate counts for both circuits are stable and recorded in `CHECKPOINT.md`.
- `cargo bench` prints the naive-size table and it is committed.

**Non-goals.** No proving yet. No arithmetic circuits. No optimization of the circuits.

---

## Phase 1 — ZKBoo: the (2,3)-decomposition

**Goal.** A working interactive zero-knowledge proof of knowledge for
"I know `x` such that `SHA256(x) = y`".

**Scope.**
- Replicated 3-party sharing over GF(2): `x = x_0 xor x_1 xor x_2`.
- Linear gates computed locally; the AND-gate rule consuming one bit of randomness tape
  per party per gate.
- Per-party views: input share, randomness tape seed, and the broadcast bits.
- Commit to all three views, verifier challenge `e` in {1, 2, 3}, open two views.
- Repetition: soundness error 2/3 per run, so tau = ceil(lambda / log2(3/2)),
  which is 219 repetitions for lambda = 128. Derive this in code, do not hardcode it.
- A simulator, implemented as a test: produce two views without the witness and assert
  the verifier accepts, which is the zero-knowledge property made executable.

**Done when.**
- Honest prover/verifier roundtrip succeeds for SHA-256 preimage knowledge.
- Negative tests: flipping one bit in one opened view, one broadcast value, or one
  commitment causes rejection.
- The simulator test passes and is documented as the ZK argument.
- Soundness parameter derivation has a unit test against hand-computed values.

**Reading.** Giacomelli, Madsen, Orlandi, "ZKBoo: Faster Zero-Knowledge for Boolean
Circuits" (USENIX Security 2016); Ishai, Kushilevitz, Ostrovsky, Sahai (STOC 2007) for
the original paradigm.

---

## Phase 2 — ZKB++ and non-interactivity

**Goal.** Cut the proof down to what is actually necessary and remove the verifier from
the loop.

**Scope.**
- Fiat-Shamir over the Phase 0 transcript, with the statement and all commitments bound
  in before the challenge is derived.
- Drop everything the verifier can recompute: derive input shares and tapes from seeds,
  send only the third input share and the unavoidable broadcast bits.
- Seed trees so that opening `tau` runs reveals a logarithmic number of seed nodes.
- A per-component proof-size accounting function: commitments, seeds, broadcasts,
  auxiliary share, each reported separately.

**Deliverable.** A size table comparing Phase 0 naive, Phase 1 ZKBoo, and Phase 2 ZKB++
for the same circuit and the same security level.

**Done when.**
- The NIZK verifies, and a proof for a different statement or a tampered transcript fails.
- The size reduction versus Phase 1 is in the same order of magnitude as the published
  ZKB++ figures for a comparable circuit; deviations are explained in `DESIGN_DECISIONS.md`.
- A written note on why Fiat-Shamir in the ROM is used here and what the Unruh transform
  would buy in the QROM.

---

## Phase 3 — KKW and the preprocessing model

**Goal.** The second big idea of the field: move the expensive part into a preprocessing
phase that is checked by cut-and-choose, and run the online phase with many parties.

**Scope.**
- N-party protocol (N = 16, 64, 128) in the preprocessing model, with multiplication
  triples and a broadcast-based online phase.
- Cut-and-choose over `M` preprocessing instances: open `M - tau` of them fully, run the
  online phase for the remaining `tau`, and open `N - 1` parties in each.
- A parameter search tool: given lambda, enumerate (N, M, tau) and report the size-optimal
  choice, together with the soundness expression it is derived from.

**Done when.**
- KKW proofs verify and are smaller than Phase 2 for the same circuit.
- The parameter tool reproduces the published KKW parameter sets when asked for their
  security levels.
- The size table now has four rows and is in the README.

**Reading.** Katz, Kolesnikov, Wang, "Improved Non-Interactive Zero Knowledge with
Applications to Post-Quantum Signatures" (CCS 2018).

---

## Phase 4 — A signature scheme

**Goal.** Turn the proof system into a Picnic-style post-quantum signature: the secret
key is a LowMC preimage, the signature is a NIZK of knowledge of it, with the message
bound into the challenge.

**Scope.**
- KeyGen, Sign, Verify over the Phase 3 prover.
- Message and a per-signature salt bound into the Fiat-Shamir transcript; document why
  the salt is there.
- A constant-time review pass over the secret-dependent code paths, with the findings
  written down rather than silently fixed.
- Known-answer tests, deterministic signing mode for reproducibility.

**Done when.**
- Sign/verify roundtrip over a corpus of messages, plus tamper tests on message,
  signature, and public key.
- An EUF-CMA argument written out in `DESIGN_DECISIONS.md`, stating explicitly which
  assumptions are inherited from the proof system.
- Signature sizes and sign/verify timings benchmarked and recorded.

---

## Phase 5 — The thesis: a typed frontend for decompositions

**Goal.** This is the phase that makes the project an argument rather than a
reimplementation. Everything before it is the substrate.

**Scope.**
- A small DSL in `mih-lang` for expressing a function once, from which the decomposition
  is derived, instead of hand-writing party-local code.
- A leakage type system over the shares. Each wire value carries which party's view it
  may enter. The typing rules enforce the simulation property directly: for every gate,
  the values appearing in any opened pair of views must be derivable from those parties'
  own shares and tapes. A rule that would place a value dependent on the third share
  into an opened view does not type.
- A companion type-level soundness budget: parameter choices carry the security level
  they achieve, and a configuration that cannot statically prove at least lambda bits
  does not compile. This is the direct analogue of the noise budget in `nsc`.
- Retarget the Phase 3 prover to consume DSL output.

**Done when.**
- A `tests/compile-fail/` suite where each file is a deliberately leaky or
  underparameterized decomposition, and each fails to compile with a specific,
  readable error naming the violated property.
- The SHA-256 and LowMC circuits go through the typed frontend and produce a prover that
  is byte-identical in output to the hand-written Phase 3 one.
- A written statement of exactly what the type system does and does not prove. Being
  precise about the gap between "well-typed" and "secure" is part of the deliverable.

---

## Phase 6 — The modern frontier, and the writeup

**Goal.** Reach the line of current work, then close the project properly.

**Scope.**
- Implement one modern variant and benchmark it against Phases 2 to 4. Candidates:
  - **VOLE-in-the-Head**, the FAEST approach, proving AES constraints via QuickSilver.
    The strongest choice if the aim is to touch what is actually being standardized.
  - **TCitH** (threshold computation in the head), which underpins MQOM and gives
    sublinear opening costs.
  - **SDitH**, MPCitH applied to syndrome decoding, if the goal is to leave the
    symmetric-primitive world and work over larger fields.
- Context worth writing down: as of 14 May 2026, NIST moved nine schemes into round 3 of
  its Additional Digital Signatures process, of which FAEST, MQOM and SDitH are the
  MPCitH-family candidates. The paradigm this project implements is a live
  standardization track, not a historical curiosity.
- Final documentation pass: README, CHECKPOINT, ROADMAP, DESIGN_DECISIONS.
- An English blog post: the arc from the Phase 0 proof-size wall to the typed frontend,
  with the size table as the spine of the argument.

**Done when.**
- The final size and timing table covers every phase and is reproducible from
  `cargo bench` on a clean checkout.
- The documentation set is complete and a reader can rebuild the project's reasoning
  from it without reading the code.
- The blog post is drafted.

---

## Sequencing notes

- Phases 1 to 3 are the ones with real conceptual mass; expect them to dominate the
  calendar. Phase 0 is larger than it looks because SHA-256 as a circuit is fiddly.
- Phase 5 depends on Phase 3 being stable, since the typed frontend must reproduce it
  exactly. Do not start the DSL while the prover is still moving.
- Phase 6 is optional in the sense that Phases 0 to 5 already form a complete story. If
  the project needs to stop early, stop after Phase 5 and write it up.

## Reading list

- Ishai, Kushilevitz, Ostrovsky, Sahai — Zero-knowledge from secure multiparty
  computation (STOC 2007). The origin.
- Giacomelli, Madsen, Orlandi — ZKBoo (USENIX Security 2016).
- Chase et al. — Post-quantum zero-knowledge and signatures from symmetric-key
  primitives (CCS 2017). ZKB++ and Picnic.
- Katz, Kolesnikov, Wang — KKW (CCS 2018).
- Baum, Malozemoff, Rosen, Scholl — Mac'n'Cheese, and Yang et al. — QuickSilver, for the
  VOLE line leading into FAEST.
- Feneuil, Rivain — Threshold computation in the head.
- The FAEST, MQOM and SDitH NIST submission specifications.
