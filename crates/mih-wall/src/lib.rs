//! The proof-size wall: the baseline problem the rest of the project attacks.
//!
//! Take MPC-in-the-Head in its most literal form. Secret-share the witness among
//! three parties, have each party evaluate the circuit on shares, commit to all
//! three views, let the verifier pick two and check them against each other. A
//! cheating prover must produce at least one inconsistent pair, and the verifier
//! opens one of three pairs, so a single run catches cheating with probability
//! at least 1/3. Repeat until the soundness error is negligible.
//!
//! Now count the bytes. A view contains the party's input share, its randomness
//! tape, and the value it broadcast at every AND gate. Two of those are sent per
//! repetition, and there are a couple of hundred repetitions. For SHA-256 the
//! result is measured in megabytes.
//!
//! That number is the wall. Phase 2 knocks most of it down by observing that
//! nearly everything in a view can be recomputed from a seed; Phase 3 changes
//! the protocol so that far less has to be opened at all. Every later phase
//! reports its size against this baseline, which is why the model lives in its
//! own crate and is covered by tests rather than being a number in a README.
//!
//! The model is deliberately generous to the naive construction: it assumes
//! perfect packing, ignores framing and length prefixes, and charges nothing for
//! the challenge. The real thing is larger. It is a lower bound on a bad idea.

use mih_circuit::Circuit;

/// Bytes in a commitment, matching `mih_core::COMMITMENT_LEN`.
///
/// Duplicated rather than imported so that the size model has no dependency on
/// the cryptographic crates; it is arithmetic, and it should stay that way.
pub const COMMITMENT_BYTES: usize = 32;

/// Parties in the ZKBoo decomposition.
pub const PARTIES: usize = 3;
/// Views opened per repetition.
pub const OPENED_VIEWS: usize = 2;

/// Repetitions needed for `lambda` bits of soundness.
///
/// A single run has soundness error 2/3, so `(2/3)^tau <= 2^-lambda`, giving
/// `tau >= lambda / log2(3/2)`. At the 128-bit level this is 219, and that
/// factor of two hundred is the reason naive MPC-in-the-Head proofs are so
/// large: everything below gets multiplied by it.
pub fn repetitions(lambda: u32) -> u32 {
    let per_repetition = (3.0f64 / 2.0).log2();
    (f64::from(lambda) / per_repetition).ceil() as u32
}

/// A costed naive proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WallEstimate {
    pub lambda: u32,
    pub repetitions: u32,
    pub input_bits: u32,
    pub and_gates: u32,
    /// Bits in one full party view.
    pub view_bits: u64,
    /// Bytes transmitted per repetition.
    pub bytes_per_repetition: u64,
    /// Total proof size in bytes.
    pub total_bytes: u64,
}

impl WallEstimate {
    pub fn total_kib(&self) -> f64 {
        self.total_bytes as f64 / 1024.0
    }

    pub fn total_mib(&self) -> f64 {
        self.total_bytes as f64 / (1024.0 * 1024.0)
    }
}

/// Cost a naive proof for a circuit of the given shape.
///
/// A view holds three things:
///
/// - the party's share of the witness, one bit per input bit;
/// - its randomness tape, one bit per AND gate, since the (2,3)-decomposition
///   consumes one random bit per party per AND gate;
/// - its broadcast values, again one bit per AND gate.
///
/// Hence `input_bits + 2 * and_gates` bits per view.
pub fn estimate(input_bits: u32, and_gates: u32, lambda: u32) -> WallEstimate {
    let repetitions = repetitions(lambda);
    let view_bits = u64::from(input_bits) + 2 * u64::from(and_gates);
    let view_bytes = (view_bits + 7) / 8;
    let bytes_per_repetition =
        OPENED_VIEWS as u64 * view_bytes + PARTIES as u64 * COMMITMENT_BYTES as u64;
    WallEstimate {
        lambda,
        repetitions,
        input_bits,
        and_gates,
        view_bits,
        bytes_per_repetition,
        total_bytes: bytes_per_repetition * u64::from(repetitions),
    }
}

/// Cost a naive proof of knowledge of a satisfying input to `circuit`.
pub fn estimate_circuit(circuit: &Circuit, lambda: u32) -> WallEstimate {
    estimate(circuit.arity(), circuit.and_gates(), lambda)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repetition_counts_match_the_soundness_bound() {
        assert_eq!(repetitions(128), 219);
        assert_eq!(repetitions(256), 438);
        // The defining property, checked directly rather than by restating the
        // formula: tau repetitions suffice and tau - 1 do not.
        for lambda in [40u32, 64, 80, 128, 192, 256] {
            let tau = repetitions(lambda);
            let error = |n: u32| (2.0f64 / 3.0).powi(n as i32);
            let target = 2.0f64.powi(-(lambda as i32));
            assert!(error(tau) <= target, "tau too small at lambda={lambda}");
            assert!(error(tau - 1) > target, "tau not minimal at lambda={lambda}");
        }
    }

    #[test]
    fn a_view_is_the_witness_share_plus_two_bits_per_and_gate() {
        let e = estimate(512, 1000, 128);
        assert_eq!(e.view_bits, 512 + 2000);
    }

    #[test]
    fn size_is_linear_in_the_and_count() {
        // The claim the whole project rests on: halve the AND gates, halve the
        // proof. Not exactly, because each repetition also carries three
        // commitments and the witness share, and that overhead does not scale
        // with the circuit. Hence the tolerance rather than an equality.
        let small = estimate(128, 100_000, 128);
        let large = estimate(128, 200_000, 128);
        let ratio = large.total_bytes as f64 / small.total_bytes as f64;
        assert!((ratio - 2.0).abs() < 0.01, "ratio was {ratio}");
    }

    #[test]
    fn commitments_are_charged_for_all_three_parties() {
        // Even a circuit with no gates at all is not free: three commitments per
        // repetition still have to be sent.
        let e = estimate(0, 0, 128);
        assert_eq!(e.bytes_per_repetition, 96);
        assert_eq!(e.total_bytes, 96 * 219);
    }

    #[test]
    fn higher_security_costs_proportionally_more() {
        let a = estimate(128, 10_000, 128);
        let b = estimate(128, 10_000, 256);
        assert_eq!(b.total_bytes, 2 * a.total_bytes);
    }
}
