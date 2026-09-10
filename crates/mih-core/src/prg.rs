//! Seed-expanding pseudorandom generator.
//!
//! Every simulated party in an MPC-in-the-Head proof gets a randomness tape: one
//! bit per AND gate in the ZKBoo decomposition of Phase 1, considerably more in
//! the preprocessing model of Phase 3. Tapes are never transmitted. They are
//! derived from a 32-byte seed, and the seed is what gets revealed when a view
//! is opened. That is the trick that keeps proofs from being enormous, and it is
//! why the expansion has to be deterministic and reproducible across machines.

use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// Length of a PRG seed in bytes.
pub const SEED_LEN: usize = 32;

/// A seed for [`Prg`].
pub type Seed = [u8; SEED_LEN];

/// Deterministic seed expansion.
#[derive(Clone, Debug)]
pub struct Prg {
    inner: ChaCha20Rng,
}

impl Prg {
    pub fn from_seed(seed: Seed) -> Self {
        Prg {
            inner: ChaCha20Rng::from_seed(seed),
        }
    }

    pub fn fill_bytes(&mut self, out: &mut [u8]) {
        self.inner.fill_bytes(out);
    }

    pub fn next_bytes<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        self.inner.fill_bytes(&mut out);
        out
    }

    pub fn next_seed(&mut self) -> Seed {
        self.next_bytes::<SEED_LEN>()
    }

    /// Produce `len` pseudorandom bits, unpacked one per `bool`.
    ///
    /// The unpacked representation costs eight times the memory of a packed one.
    /// That is accepted for now: tapes are on the order of tens of kilobytes,
    /// and the gate-indexed access pattern of the prover is much easier to get
    /// right against a flat slice. Revisit if Phase 3 makes it hurt.
    pub fn next_bits(&mut self, len: usize) -> Vec<bool> {
        let mut bytes = vec![0u8; (len + 7) / 8];
        self.inner.fill_bytes(&mut bytes);
        (0..len)
            .map(|i| (bytes[i / 8] >> (i % 8)) & 1 == 1)
            .collect()
    }

    /// A randomness tape with one bit per AND gate, which is what the
    /// (2,3)-decomposition of Phase 1 consumes.
    pub fn tape(&mut self, and_gates: usize) -> Vec<bool> {
        self.next_bits(and_gates)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expansion_is_deterministic() {
        let a = Prg::from_seed([42; SEED_LEN]).next_bits(1024);
        let b = Prg::from_seed([42; SEED_LEN]).next_bits(1024);
        assert_eq!(a, b);
    }

    #[test]
    fn different_seeds_diverge() {
        let a = Prg::from_seed([1; SEED_LEN]).next_bits(256);
        let b = Prg::from_seed([2; SEED_LEN]).next_bits(256);
        assert_ne!(a, b);
    }

    #[test]
    fn bit_expansion_is_a_prefix_of_itself() {
        // Requesting n bits and then more must not change the first n, otherwise
        // a verifier recomputing a shorter prefix would disagree with the prover.
        let short = Prg::from_seed([9; SEED_LEN]).next_bits(64);
        let long = Prg::from_seed([9; SEED_LEN]).next_bits(512);
        assert_eq!(short, long[..64]);
    }

    #[test]
    fn bits_are_roughly_balanced() {
        // Not a statistical test of ChaCha20, just a smoke test that the bit
        // unpacking is not dropping or duplicating bits.
        let bits = Prg::from_seed([0; SEED_LEN]).next_bits(100_000);
        let ones = bits.iter().filter(|b| **b).count();
        assert!((49_000..51_000).contains(&ones), "ones = {ones}");
    }
}
