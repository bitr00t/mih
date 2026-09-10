# Design decisions

Decisions that were not forced, with the reasoning at the time. Entries are
appended, not rewritten: if a decision is reversed later, the reversal gets its
own entry and the original stays.

---

## Phase 0

### The dependency line

Primitives and plumbing come from crates. Anything that is the object of study is
written here.

Reimplementing SHA-256 in software would teach nothing this project is about, and
a hand-rolled version would be slower and more likely to be wrong. But the
circuit form of SHA-256, the decompositions, the commitment structure, the
transcript framing and the proof systems are the subject matter, and taking those
from a library would hollow the project out.

Each dependency, justified:

- `sha2` — SHA-256 for the transcript and the commitment scheme, and the
  reference oracle for the SHA-256 circuit. Having an independent implementation
  to differentially test against is strictly better than self-consistency.
- `rand_chacha` — deterministic, reproducible seed expansion. Randomness tapes
  must be identical for prover and verifier from the same seed, on any machine.
- `rand_core` — the trait both of the above agree on.
- `subtle` — constant-time equality for commitment comparison.

Not taken: any MPCitH, ZK or signature library, not even for comparison inside
the code. Comparisons against published figures happen in prose, in the
checkpoint.

`mih-circuit` has no dependencies at all. The IR is what every later phase agrees
on; it is data structures and arithmetic and should stay that way.

### `Not` as its own gate

It could be desugared to `Xor(x, Const(true))`. Keeping it explicit costs a
variant and makes the statistics honest: a reader looking at the gate counts sees
2,553 negations in SHA-256 rather than 2,553 XOR gates that are not really XORs.
It is free in every decomposition, exactly like XOR, so nothing downstream cares.

### Eager constant folding, and nothing more

The word-level helpers generate constants constantly: shifts feed in zeros, round
constants get added, the OWF circuit hardwires a plaintext. Without folding the
circuit fills with gates whose value is known at build time, and the AND count
stops meaning anything.

Folding is local and syntactic: constant operands, `x XOR x`, `x AND x`, double
negation. No common subexpression elimination, no rewriting, no AND-count
minimization. Those are synthesis, they would make the IR's output depend on an
optimizer's mood, and Phase 5 needs an IR whose output is predictable.

Consequence worth stating: the SHA-256 AND count of 22,296 is slightly below the
figure usually quoted for a naive gate-level SHA-256, because folding removes
gates around the round constants. It is not comparable to published numbers to
the last digit, and it is not meant to be.

### The PRG lives in `mih-core`, not `mih-sym`

The roadmap put seed expansion in `mih-sym` alongside the primitives. It ended up
in `mih-core` instead, because it is used by the proof machinery rather than by
the circuits, and `mih-sym` should be about circuit constructions only. Seed
trees will follow it into `mih-core` in Phase 2.

### Randomness tapes as `Vec<bool>`

One byte per bit, eight times the memory of a packed representation. Accepted for
now: tapes are tens of kilobytes, and the prover's access pattern is gate-indexed,
which is far easier to get right against a flat slice than against packed words.
Revisit if Phase 3, where the party count grows, makes it hurt.

### Position binding in commitments

The repetition index and party index are hashed into every commitment. Without
it, a commitment valid in one slot is valid in every slot, and a prover gains a
small amount of freedom to relocate views after seeing the challenge. Each such
freedom is a hole in soundness, and retrofitting this after the proof format
exists means changing the format.

### A strict, hand-written encoder rather than serde

Proofs get hashed, so the encoding must be canonical: one value, one byte string.
A derived encoding hides exactly the decisions that matter — field order, length
framing, how a bit string's padding is handled. The decoder therefore rejects
trailing bytes, oversized length prefixes, and non-zero padding bits in bit
strings, since each of those would give a second encoding of the same proof and
hence malleability.

Every `read_bytes` takes an explicit limit. A decoder that allocates whatever a
length prefix asks for is a denial-of-service primitive.

### Transcript framing

The state update hashes a tag byte, the previous state, and every argument with
an explicit length prefix. The length prefixes are the point: without them,
absorbing `("ab", "c")` and `("a", "bc")` produce the same state, which is the
most common way transcript constructions break. There is a test for exactly that.

Challenges ratchet the state, so drawing twice with the same label gives
different values. This makes accidental randomness reuse impossible rather than
merely discouraged.

Challenge indices use rejection sampling rather than `x % 3`. The bias of modular
reduction is small here, but it is real, and there is no reason to accept it.

### LowMC instance generation departs from the specification

The reference derives matrices and round constants from a Grain LFSR. This uses a
seeded ChaCha20 stream instead: simpler, reproducible, and adequate, since the
instance is public and only has to match between prover and verifier.

The cost is that instances here are not interoperable with Picnic or the LowMC
reference code. That is acceptable while nothing external needs to verify a
proof. If Phase 4 ever wants interoperability, `LowMcInstance::generate` is the
single function to replace.

Linear layers are drawn by rejection until invertible. A random binary matrix is
invertible with probability around 0.289, so this terminates quickly; the loop is
bounded at 256 attempts anyway, because an unbounded retry in instance generation
is how a test suite hangs at three in the morning.

### The S-box sits on the lowest `3m` bits

The reference places it differently. Since instances are generated here anyway,
the choice is free; it is recorded so that a future attempt at interoperability
knows to check it.

### No criterion

The Phase 0 deliverable is a proof size, which is exact arithmetic on circuit
statistics. A statistical benchmarking framework would add a dependency tree and
noise to a number that has neither. Timings are printed as single rough samples
and labelled as such. Criterion arrives when there is something worth
micro-benchmarking, which is Phase 1 at the earliest.

### The wall model is generous to the naive construction

It assumes perfect bit packing, charges nothing for framing or length prefixes,
and ignores the challenge. The real thing would be larger. This is deliberate:
the baseline should be a lower bound on a bad idea, so that later improvements
cannot be accused of beating a strawman.
