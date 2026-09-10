# mih

From-scratch MPC-in-the-Head zero-knowledge proofs in Rust: ZKBoo, ZKB++ and KKW,
plus a typed frontend where a leaky decomposition does not compile.

> **This is a learning implementation.** It is not audited, not constant-time
> outside the few places that say so, and not interoperable with any deployed
> scheme. Do not use it for anything real.

## Status

Phase 0 of seven is complete. See [`docs/ROADMAP.md`](docs/ROADMAP.md) for the
plan and [`docs/CHECKPOINT.md`](docs/CHECKPOINT.md) for what each finished phase
actually delivered.

| Phase | Contents | State |
| ----- | -------- | ----- |
| 0 | Circuit IR, SHA-256 and LowMC as circuits, transcript, commitments, PRG, encoding, baseline size model | done |
| 1 | ZKBoo: the (2,3)-decomposition, interactive | not started |
| 2 | ZKB++: Fiat-Shamir, seed trees, size reduction | not started |
| 3 | KKW: preprocessing model, cut-and-choose | not started |
| 4 | Picnic-style signature scheme | not started |
| 5 | Typed frontend: leakage types and a soundness budget | not started |
| 6 | A modern variant (VOLEitH / TCitH / SDitH), writeup | not started |

## What MPC-in-the-Head is

Take a multi-party protocol that computes some function and is private against a
minority of corrupted parties. A prover who knows a witness can simulate all the
parties by itself, commit to each party's view of the execution, and let the
verifier open a subset. Soundness comes from the fact that a false statement
forces at least one pair of views to be inconsistent; zero-knowledge comes from
the privacy of the underlying protocol, since the opened views are simulatable
without the witness.

The paradigm is from Ishai, Kushilevitz, Ostrovsky and Sahai (2007). It became
practical with ZKBoo in 2016, and it is now one of the main routes to
post-quantum signatures: of the nine schemes NIST advanced to round 3 of its
Additional Digital Signatures process in May 2026, three (FAEST, MQOM, SDitH)
are built this way.

## The Phase 0 baseline

The starting point is a number, produced by `cargo bench -p mih-wall`:

```
circuit                 AND gates  total gates  AND depth    view bits    naive proof
--------------------------------------------------------------------------------------
SHA-256, one block          22296       134671       1604        45104       2.38 MiB
LowMC 128/128/10/20           600       336072         20         1328       91.5 KiB
LowMC 256/256/10/38          1140      2523089         38         2536      156.1 KiB
```

That last column is the size of a proof of preimage knowledge under the most
literal reading of the paradigm: three parties, all views stored in full, two
opened per repetition, 219 repetitions for 128-bit soundness. Two and a half
megabytes to prove knowledge of a SHA-256 preimage.

Two things fall out of the table immediately, and they set up everything that
follows:

**Proof size is linear in AND gates, and in nothing else.** SHA-256 has 134,671
gates but only 22,296 of them are AND gates, and only those cost anything. LowMC
has more than twice as many gates in total and produces a proof 27 times smaller,
because it was designed for exactly this cost model. This is why Phase 4 will
build its signature scheme on LowMC and not on a standard hash.

**The factor of 219 is the real enemy.** A single run of the naive protocol
catches a cheating prover with probability only 1/3, so soundness is bought by
repetition, and everything else in the proof gets multiplied by it. Phase 2
attacks the per-repetition cost by re-deriving views from seeds; Phase 3 changes
the protocol so that the per-run soundness error is much smaller to begin with.

## Layout

```
crates/mih-circuit   boolean circuit IR, builder, evaluator, cost statistics
crates/mih-core      transcript, commitments, PRG, canonical encoding
crates/mih-sym       SHA-256 and LowMC as circuits, GF(2) matrices
crates/mih-wall      the baseline proof-size model and its benchmark
```

`mih-circuit` has no dependencies at all, cryptographic or otherwise. The IR is
the one thing every later phase has to agree on, and it is arithmetic and data
structures, so it should stay free of everything else.

## Building

```sh
cargo test                 # the full suite, including the differential tests
cargo bench -p mih-wall    # prints the baseline table above
```

Requires a stable Rust toolchain; developed against 1.75.

## Dependencies

Primitives and plumbing come from established crates. Anything that is the object
of study is written here. See
[`docs/DESIGN_DECISIONS.md`](docs/DESIGN_DECISIONS.md) for the line and for the
justification of each dependency.

| Crate | Why |
| ----- | --- |
| `sha2` | SHA-256 for the transcript and commitments, and the reference oracle the SHA-256 circuit is tested against |
| `rand_chacha` | deterministic seed expansion for randomness tapes and instance generation |
| `rand_core` | the RNG traits those two agree on |
| `subtle` | constant-time comparison of commitments |

## References

- Ishai, Kushilevitz, Ostrovsky, Sahai, *Zero-knowledge from secure multiparty computation*, STOC 2007
- Giacomelli, Madsen, Orlandi, *ZKBoo: Faster Zero-Knowledge for Boolean Circuits*, USENIX Security 2016
- Chase et al., *Post-Quantum Zero-Knowledge and Signatures from Symmetric-Key Primitives*, CCS 2017
- Katz, Kolesnikov, Wang, *Improved Non-Interactive Zero Knowledge with Applications to Post-Quantum Signatures*, CCS 2018
- Albrecht, Rechberger, Schneider, Tiessen, Zohner, *Ciphers for MPC and FHE*, EUROCRYPT 2015 (LowMC)

## License

MIT or Apache-2.0, at your option.
