# Checkpoints

One entry per completed phase: what was built, what was measured, and what was
deliberately left out. The last section matters most. A phase that claims to be
finished without a list of what it does not do is a phase whose boundaries were
never thought about.

---

## Phase 0 — Groundwork and the proof-size wall

### Built

**`mih-circuit`** — the boolean circuit IR. A circuit is a flat, topologically
ordered gate list, where wire `i` is by definition the output of gate `i`, so
every operand index is strictly smaller than the gate's own. The builder is the
only way to construct one, which makes that invariant free; `validate()` exists
for later phases, which will build circuits from deserialized data and from the
Phase 5 frontend. Gates are `Input`, `Const`, `Xor`, `And`, `Not`. Constant
folding is eager and local. `evaluate_with_and_trace` returns one bit per AND
gate in gate order, which is the trace Phase 1 needs. Statistics carry gate
counts by kind and multiplicative depth. No dependencies.

**`mih-core`** — transcript, commitments, PRG, encoding. The transcript is a
32-byte state, updated by hashing a tag byte, the old state and length-prefixed
arguments; challenges ratchet the state so the same label cannot yield the same
challenge twice. Commitments are salted SHA-256 with the repetition index and
party index bound in, so a commitment cannot be moved between slots, and are
compared in constant time. The PRG is seeded ChaCha20. The encoder is strict and
canonical: explicit length prefixes, rejection of trailing bytes, rejection of
non-zero padding bits in bit strings.

**`mih-sym`** — SHA-256 and LowMC as circuits, plus GF(2) matrices. SHA-256
covers one compression against the standard IV; additions are ripple-carry at 31
AND gates each, `Ch` and `Maj` are one AND per bit via the standard rewrites, and
rotations and shifts are pure rewiring. LowMC is parameterized over `(n, k, m, r)`
with instances derived reproducibly from a seed, and ships with a native
reference implementation that the circuit is differentially tested against.

**`mih-wall`** — the baseline size model, as arithmetic on circuit statistics
with its own tests.

### Measured

```
circuit                 AND gates  total gates  AND depth    view bits    naive proof
--------------------------------------------------------------------------------------
SHA-256, one block          22296       134671       1604        45104       2.38 MiB
LowMC 128/128/10/20           600       336072         20         1328       91.5 KiB
LowMC 256/256/10/38          1140      2523089         38         2536      156.1 KiB
```

At 128-bit soundness the naive protocol needs 219 repetitions, and a view holds
the witness share plus two bits per AND gate (tape and broadcast). Reproduce with
`cargo bench -p mih-wall`.

The AND counts are pinned as constants and asserted by tests. They should never
move silently: every proof size in this project is linear in them.

Two observations to carry forward. SHA-256 costs 27 times what LowMC L1 costs
despite having *fewer* total gates, because only AND gates are charged. And the
repetition count, not the circuit, is what makes the naive number embarrassing:
219 multiplies everything.

### Verified

- The SHA-256 circuit agrees with `sha2` on the published vectors, on every
  message length from 0 to 55 bytes, and on 200 random messages.
- The LowMC circuit agrees with the native reference at a small parameter set and
  at Picnic L1; the OWF circuit at a fixed plaintext agrees with the full cipher.
- LowMC AND counts are exactly `3 * m * r` and multiplicative depth is exactly
  `r`, at all three parameter sets.
- The transcript resists concatenation ambiguity: absorbing `("ab", "c")` and
  `("a", "bc")` give different challenges. Challenge indices over `{0,1,2}` are
  uniform to within a few percent over 3000 draws.
- Commitments break under a change to any bound field: opening, payload,
  repetition index, party index.
- The encoder round-trips every field kind; the decoder rejects trailing bytes,
  truncated input, oversized length prefixes, and non-canonical bit padding.

### Deliberately not done

- **No proving.** No sharing, no decomposition, no views. That is Phase 1.
- **No seed trees.** They only pay off once there are many repetitions to open
  across, which is Phase 2.
- **No multi-block SHA-256.** One padded block covers messages up to 55 bytes,
  which is enough for a preimage statement. Chaining is gates nobody needs yet.
- **No circuit optimization.** Constant folding is as far as it goes. No common
  subexpression elimination, no AND-count minimization. The IR is a faithful
  representation, not a synthesis tool.
- **No interoperable LowMC instances.** Matrices come from a seeded ChaCha20
  stream rather than the specified Grain LFSR, so instances here do not match
  Picnic or the LowMC reference code.
- **No constant-time guarantees** beyond commitment comparison. Circuit
  evaluation branches on data. It becomes a real concern in Phase 4 and gets a
  review pass there.
- **No criterion.** The Phase 0 deliverable is a size, which is exact. Timings
  are printed as rough single samples and labelled as such.

### Notes for Phase 1

- `evaluate_with_and_trace` already fixes the ordering convention the prover
  needs: AND gates are indexed in gate order, and the tape is indexed the same
  way. Do not invent a second ordering.
- `Transcript::challenge_index` does rejection sampling over `{0, 1, 2}`, which
  is exactly the ZKBoo challenge. It is already tested for uniformity.
- `commit::Position` exists so that the repetition and party index are bound into
  every commitment from the first proof onward, rather than being retrofitted
  after someone notices a view can be relocated.
- The 219 repetitions should be derived in code from the soundness expression,
  not hardcoded. `mih_wall::repetitions` does this and its test checks
  minimality, not just the formula.
