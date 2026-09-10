//! LowMC as a boolean circuit, plus a native reference implementation.
//!
//! LowMC is the block cipher Picnic uses, and it is here for one reason: its AND
//! count. A SHA-256 block costs upwards of twenty thousand AND gates; a LowMC
//! instance at the same security level costs `3 * m * r`, which for the Picnic
//! L1 parameters is six hundred. Since proof size is linear in the AND count,
//! that is the difference between a proof of megabytes and a proof of kilobytes,
//! and it is why the Phase 4 signature scheme will use LowMC rather than a
//! standard hash as its one-way function.
//!
//! The design trade is deliberate and worth stating plainly: LowMC buys its low
//! AND count with very heavy, very wide linear layers, which are free in this
//! cost model and expensive everywhere else. It has also seen real cryptanalysis
//! over its lifetime, some of it damaging to specific parameter sets. Nothing
//! here should be taken as an endorsement of particular parameters.
//!
//! # Instance generation
//!
//! The matrices and round constants of a LowMC instance are public and must
//! match between prover and verifier. The reference specification derives them
//! from a Grain LFSR. This implementation instead derives them from a seeded
//! ChaCha20 stream, which is reproducible and adequate for a learning
//! implementation but means instances here are *not* interoperable with Picnic
//! or with the LowMC reference code. If Phase 4 ever wants interoperability,
//! this is the function to replace.

use mih_circuit::{Circuit, CircuitBuilder, WireId};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

use crate::gf2::BitMatrix;

/// LowMC parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LowMcParams {
    /// Block size in bits.
    pub n: usize,
    /// Key size in bits.
    pub k: usize,
    /// Number of 3-bit S-boxes per round.
    pub m: usize,
    /// Number of rounds.
    pub r: usize,
}

impl LowMcParams {
    /// Total AND gates: three per S-box, `m` S-boxes per round, `r` rounds.
    ///
    /// The linear layers and the key schedule are pure XOR and contribute
    /// nothing, which is the entire point of the design.
    pub const fn and_gates(&self) -> usize {
        3 * self.m * self.r
    }

    /// Width of the S-box layer in bits; the remaining `n - 3m` bits of the
    /// state pass through untouched.
    pub const fn sbox_bits(&self) -> usize {
        3 * self.m
    }
}

/// The Picnic L1 parameter set: 128-bit block and key, 10 S-boxes, 20 rounds.
pub const PICNIC_L1: LowMcParams = LowMcParams {
    n: 128,
    k: 128,
    m: 10,
    r: 20,
};

/// The Picnic L5 parameter set: 256-bit block and key, 10 S-boxes, 38 rounds.
pub const PICNIC_L5: LowMcParams = LowMcParams {
    n: 256,
    k: 256,
    m: 10,
    r: 38,
};

/// A concrete LowMC instance: the public matrices and constants.
#[derive(Clone, Debug)]
pub struct LowMcInstance {
    params: LowMcParams,
    /// `r + 1` matrices of shape `n x k`, index 0 being the whitening key.
    key_matrices: Vec<BitMatrix>,
    /// `r` invertible matrices of shape `n x n`.
    linear_layers: Vec<BitMatrix>,
    /// `r` round constants of `n` bits.
    round_constants: Vec<Vec<bool>>,
}

impl LowMcInstance {
    /// Derive an instance deterministically from a 32-byte seed.
    pub fn generate(params: LowMcParams, seed: [u8; 32]) -> Self {
        assert!(
            params.sbox_bits() <= params.n,
            "S-box layer is wider than the block"
        );
        let mut rng = ChaCha20Rng::from_seed(seed);
        let linear_layers = (0..params.r)
            .map(|_| BitMatrix::random_invertible(params.n, &mut rng))
            .collect();
        let key_matrices = (0..=params.r)
            .map(|_| BitMatrix::random(params.n, params.k, &mut rng))
            .collect();
        let round_constants = (0..params.r)
            .map(|_| {
                let m = BitMatrix::random(1, params.n, &mut rng);
                (0..params.n).map(|c| m.get(0, c)).collect()
            })
            .collect();
        LowMcInstance {
            params,
            key_matrices,
            linear_layers,
            round_constants,
        }
    }

    pub fn params(&self) -> LowMcParams {
        self.params
    }

    /// Native evaluation, used as the reference the circuit is tested against.
    ///
    /// The S-box is applied to the lowest `3m` bits of the state:
    /// `S(a, b, c) = (a ^ bc, a ^ b ^ ac, a ^ b ^ c ^ ab)`.
    pub fn encrypt(&self, plaintext: &[bool], key: &[bool]) -> Vec<bool> {
        assert_eq!(plaintext.len(), self.params.n, "plaintext width mismatch");
        assert_eq!(key.len(), self.params.k, "key width mismatch");

        let whitening = self.key_matrices[0].mul_vec(key);
        let mut state: Vec<bool> = plaintext
            .iter()
            .zip(&whitening)
            .map(|(p, w)| p ^ w)
            .collect();

        for round in 0..self.params.r {
            for s in 0..self.params.m {
                let (a, b, c) = (state[3 * s], state[3 * s + 1], state[3 * s + 2]);
                state[3 * s] = a ^ (b & c);
                state[3 * s + 1] = a ^ b ^ (a & c);
                state[3 * s + 2] = a ^ b ^ c ^ (a & b);
            }
            state = self.linear_layers[round].mul_vec(&state);
            let round_key = self.key_matrices[round + 1].mul_vec(key);
            for i in 0..self.params.n {
                state[i] ^= self.round_constants[round][i] ^ round_key[i];
            }
        }
        state
    }

    /// The circuit for the full cipher, with `n + k` input bits laid out as
    /// plaintext followed by key.
    pub fn circuit(&self) -> Circuit {
        let mut builder = CircuitBuilder::new();
        let plaintext = builder.input_bits(self.params.n);
        let key = builder.input_bits(self.params.k);
        let out = self.emit(&mut builder, &plaintext, &key);
        builder.output_bits(&out);
        builder.build()
    }

    /// The circuit for the one-way function used by a Picnic-style signature:
    /// the plaintext is a fixed public constant, the key is the secret input.
    ///
    /// This is the statement Phase 4 proves knowledge for, so it is the shape
    /// that actually matters, and it costs the same AND gates as the full
    /// cipher because the whitening and key schedule are linear either way.
    pub fn owf_circuit(&self, plaintext: &[bool]) -> Circuit {
        assert_eq!(plaintext.len(), self.params.n, "plaintext width mismatch");
        let mut builder = CircuitBuilder::new();
        let key = builder.input_bits(self.params.k);
        let pt: Vec<WireId> = plaintext
            .iter()
            .map(|&bit| builder.constant(bit))
            .collect();
        let out = self.emit(&mut builder, &pt, &key);
        builder.output_bits(&out);
        builder.build()
    }

    /// Emit the cipher into an existing builder.
    fn emit(
        &self,
        builder: &mut CircuitBuilder,
        plaintext: &[WireId],
        key: &[WireId],
    ) -> Vec<WireId> {
        let mut state = self.apply_key_matrix(builder, 0, key);
        for i in 0..self.params.n {
            state[i] = builder.xor(plaintext[i], state[i]);
        }

        for round in 0..self.params.r {
            // Non-linear layer: three AND gates per S-box.
            for s in 0..self.params.m {
                let (a, b, c) = (state[3 * s], state[3 * s + 1], state[3 * s + 2]);
                let bc = builder.and(b, c);
                let ac = builder.and(a, c);
                let ab = builder.and(a, b);
                let ab_xor = builder.xor(a, b);
                let abc_xor = builder.xor(ab_xor, c);
                state[3 * s] = builder.xor(a, bc);
                state[3 * s + 1] = builder.xor(ab_xor, ac);
                state[3 * s + 2] = builder.xor(abc_xor, ab);
            }

            // Linear layer: an XOR tree per output bit, driven by the row support.
            let layer = &self.linear_layers[round];
            let mut next = Vec::with_capacity(self.params.n);
            for row in 0..self.params.n {
                let support: Vec<WireId> = layer
                    .row_support(row)
                    .into_iter()
                    .map(|c| state[c])
                    .collect();
                next.push(builder.xor_many(&support));
            }
            state = next;

            // Round constant and round key, both linear.
            let round_key = self.apply_key_matrix(builder, round + 1, key);
            for i in 0..self.params.n {
                let with_key = builder.xor(state[i], round_key[i]);
                state[i] = if self.round_constants[round][i] {
                    builder.not(with_key)
                } else {
                    with_key
                };
            }
        }
        state
    }

    fn apply_key_matrix(
        &self,
        builder: &mut CircuitBuilder,
        index: usize,
        key: &[WireId],
    ) -> Vec<WireId> {
        let matrix = &self.key_matrices[index];
        (0..self.params.n)
            .map(|row| {
                let support: Vec<WireId> = matrix
                    .row_support(row)
                    .into_iter()
                    .map(|c| key[c])
                    .collect();
                builder.xor_many(&support)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::rand_core::{RngCore, SeedableRng};

    fn random_bits(rng: &mut ChaCha20Rng, len: usize) -> Vec<bool> {
        let mut bytes = vec![0u8; (len + 7) / 8];
        rng.fill_bytes(&mut bytes);
        (0..len)
            .map(|i| (bytes[i / 8] >> (i % 8)) & 1 == 1)
            .collect()
    }

    /// The small parameter set used by the fast tests. The Picnic sets are
    /// exercised too, but their linear layers are large enough that building
    /// every circuit for every case is not worth the seconds.
    const TINY: LowMcParams = LowMcParams {
        n: 24,
        k: 24,
        m: 4,
        r: 5,
    };

    #[test]
    fn circuit_is_structurally_valid() {
        let instance = LowMcInstance::generate(TINY, [1; 32]);
        instance.circuit().validate().unwrap();
    }

    #[test]
    fn circuit_agrees_with_the_native_reference() {
        let instance = LowMcInstance::generate(TINY, [2; 32]);
        let circuit = instance.circuit();
        let mut rng = ChaCha20Rng::from_seed([3; 32]);
        for _ in 0..64 {
            let pt = random_bits(&mut rng, TINY.n);
            let key = random_bits(&mut rng, TINY.k);
            let mut input = pt.clone();
            input.extend_from_slice(&key);
            assert_eq!(circuit.evaluate(&input).unwrap(), instance.encrypt(&pt, &key));
        }
    }

    #[test]
    fn circuit_agrees_with_the_reference_at_picnic_l1() {
        let instance = LowMcInstance::generate(PICNIC_L1, [4; 32]);
        let circuit = instance.circuit();
        let mut rng = ChaCha20Rng::from_seed([5; 32]);
        for _ in 0..8 {
            let pt = random_bits(&mut rng, PICNIC_L1.n);
            let key = random_bits(&mut rng, PICNIC_L1.k);
            let mut input = pt.clone();
            input.extend_from_slice(&key);
            assert_eq!(circuit.evaluate(&input).unwrap(), instance.encrypt(&pt, &key));
        }
    }

    #[test]
    fn owf_circuit_matches_the_full_circuit_at_a_fixed_plaintext() {
        let instance = LowMcInstance::generate(PICNIC_L1, [6; 32]);
        let mut rng = ChaCha20Rng::from_seed([7; 32]);
        let pt = random_bits(&mut rng, PICNIC_L1.n);
        let owf = instance.owf_circuit(&pt);
        assert_eq!(owf.arity(), PICNIC_L1.k as u32);
        for _ in 0..8 {
            let key = random_bits(&mut rng, PICNIC_L1.k);
            assert_eq!(owf.evaluate(&key).unwrap(), instance.encrypt(&pt, &key));
        }
    }

    #[test]
    fn and_count_is_exactly_three_per_sbox_per_round() {
        for params in [TINY, PICNIC_L1, PICNIC_L5] {
            let instance = LowMcInstance::generate(params, [8; 32]);
            let circuit = instance.circuit();
            assert_eq!(
                circuit.and_gates() as usize,
                params.and_gates(),
                "unexpected AND count for {params:?}"
            );
        }
    }

    #[test]
    fn and_depth_is_one_per_round() {
        // The S-box has depth one and the linear layers are free, so the
        // multiplicative depth of the whole cipher is the number of rounds.
        let instance = LowMcInstance::generate(PICNIC_L1, [9; 32]);
        assert_eq!(instance.circuit().stats().and_depth, PICNIC_L1.r as u32);
    }

    #[test]
    fn instances_are_reproducible_and_seed_dependent() {
        let a = LowMcInstance::generate(TINY, [10; 32]);
        let b = LowMcInstance::generate(TINY, [10; 32]);
        let c = LowMcInstance::generate(TINY, [11; 32]);
        let mut rng = ChaCha20Rng::from_seed([12; 32]);
        let pt = random_bits(&mut rng, TINY.n);
        let key = random_bits(&mut rng, TINY.k);
        assert_eq!(a.encrypt(&pt, &key), b.encrypt(&pt, &key));
        assert_ne!(a.encrypt(&pt, &key), c.encrypt(&pt, &key));
    }

    #[test]
    fn linear_layers_are_invertible() {
        let instance = LowMcInstance::generate(TINY, [13; 32]);
        for layer in &instance.linear_layers {
            assert!(layer.is_invertible());
        }
    }

    #[test]
    fn distinct_keys_give_distinct_ciphertexts() {
        let instance = LowMcInstance::generate(PICNIC_L1, [14; 32]);
        let mut rng = ChaCha20Rng::from_seed([15; 32]);
        let pt = random_bits(&mut rng, PICNIC_L1.n);
        let k1 = random_bits(&mut rng, PICNIC_L1.k);
        let mut k2 = k1.clone();
        k2[0] = !k2[0];
        assert_ne!(instance.encrypt(&pt, &k1), instance.encrypt(&pt, &k2));
    }
}
