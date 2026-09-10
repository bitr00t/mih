//! SHA-256 as a boolean circuit.
//!
//! No crate provides this, and none can: what is needed is not a fast software
//! hash but the gate-level structure of the compression function, because that
//! structure is what the simulated parties evaluate on shares. So it is built
//! here, and the `sha2` crate is used in the tests as the reference oracle the
//! circuit is differentially tested against.
//!
//! The circuit covers one compression of a single 512-bit block against the
//! standard IV. That is enough for the canonical MPC-in-the-Head statement, "I
//! know a preimage of this digest", as long as the preimage fits in one padded
//! block. Multi-block chaining is a Phase 1 concern at the earliest and is not
//! worth the gates until something needs it.
//!
//! Where the AND gates go, for a 512-bit block:
//!
//! - Each 32-bit addition is a ripple-carry adder, one AND per carry, so 31.
//! - `Ch` and `Maj` are one AND per bit, so 32 each.
//! - Rotations and shifts are pure wire relabelling and cost nothing.
//! - XOR costs nothing.
//!
//! The message schedule contributes 48 iterations of three additions, and each
//! of the 64 rounds contributes five additions plus a `Ch` and a `Maj`.

use mih_circuit::{Circuit, CircuitBuilder, WireId};

/// A 32-bit word as wires, index 0 being the most significant bit.
///
/// Big-endian indexing matches the way the SHA-256 specification talks about
/// words and, more importantly, matches the byte order of the block and digest,
/// which keeps the conversion helpers free of surprises.
pub type Word = [WireId; 32];

/// Number of input bits of the block circuit.
pub const BLOCK_BITS: usize = 512;
/// Number of output bits of the block circuit.
pub const DIGEST_BITS: usize = 256;
/// Largest message that fits in a single padded block.
pub const MAX_ONE_BLOCK_MESSAGE: usize = 55;

const IV: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

const K: [u32; 64] = [
    0x428a_2f98, 0x7137_4491, 0xb5c0_fbcf, 0xe9b5_dba5, 0x3956_c25b, 0x59f1_11f1, 0x923f_82a4,
    0xab1c_5ed5, 0xd807_aa98, 0x1283_5b01, 0x2431_85be, 0x550c_7dc3, 0x72be_5d74, 0x80de_b1fe,
    0x9bdc_06a7, 0xc19b_f174, 0xe49b_69c1, 0xefbe_4786, 0x0fc1_9dc6, 0x240c_a1cc, 0x2de9_2c6f,
    0x4a74_84aa, 0x5cb0_a9dc, 0x76f9_88da, 0x983e_5152, 0xa831_c66d, 0xb003_27c8, 0xbf59_7fc7,
    0xc6e0_0bf3, 0xd5a7_9147, 0x06ca_6351, 0x1429_2967, 0x27b7_0a85, 0x2e1b_2138, 0x4d2c_6dfc,
    0x5338_0d13, 0x650a_7354, 0x766a_0abb, 0x81c2_c92e, 0x9272_2c85, 0xa2bf_e8a1, 0xa81a_664b,
    0xc24b_8b70, 0xc76c_51a3, 0xd192_e819, 0xd699_0624, 0xf40e_3585, 0x106a_a070, 0x19a4_c116,
    0x1e37_6c08, 0x2748_774c, 0x34b0_bcb5, 0x391c_0cb3, 0x4ed8_aa4a, 0x5b9c_ca4f, 0x682e_6ff3,
    0x748f_82ee, 0x78a5_636f, 0x84c8_7814, 0x8cc7_0208, 0x90be_fffa, 0xa450_6ceb, 0xbef9_a3f7,
    0xc671_78f2,
];

fn const_word(builder: &mut CircuitBuilder, value: u32) -> Word {
    let mut word = [0u32; 32];
    for (i, slot) in word.iter_mut().enumerate() {
        // Index 0 is the most significant bit.
        let bit = (value >> (31 - i)) & 1 == 1;
        *slot = builder.constant(bit);
    }
    word
}

fn xor_word(builder: &mut CircuitBuilder, a: &Word, b: &Word) -> Word {
    let mut out = [0u32; 32];
    for i in 0..32 {
        out[i] = builder.xor(a[i], b[i]);
    }
    out
}

/// Rotate right by `n`. Pure rewiring, no gates.
fn rotr(a: &Word, n: usize) -> Word {
    let mut out = [0u32; 32];
    for i in 0..32 {
        out[i] = a[(i + 32 - n) % 32];
    }
    out
}

/// Shift right by `n`, feeding in constant zero. No gates beyond the shared
/// zero constant.
fn shr(builder: &mut CircuitBuilder, a: &Word, n: usize) -> Word {
    let zero = builder.constant(false);
    let mut out = [zero; 32];
    for i in n..32 {
        out[i] = a[i - n];
    }
    out
}

/// Ripple-carry addition modulo 2^32. Costs 31 AND gates: the least significant
/// bit has no incoming carry, and the carry out of the most significant bit is
/// discarded, which is exactly the modular reduction.
fn add_word(builder: &mut CircuitBuilder, a: &Word, b: &Word) -> Word {
    let mut out = [0u32; 32];
    // Index 31 is the least significant bit.
    out[31] = builder.xor(a[31], b[31]);
    let mut carry = builder.and(a[31], b[31]);
    for i in (0..31).rev() {
        let partial = builder.xor(a[i], b[i]);
        out[i] = builder.xor(partial, carry);
        if i > 0 {
            carry = builder.majority(a[i], b[i], carry);
        }
    }
    out
}

fn add_words(builder: &mut CircuitBuilder, terms: &[Word]) -> Word {
    let mut acc = terms[0];
    for term in &terms[1..] {
        acc = add_word(builder, &acc, term);
    }
    acc
}

fn ch(builder: &mut CircuitBuilder, x: &Word, y: &Word, z: &Word) -> Word {
    let mut out = [0u32; 32];
    for i in 0..32 {
        out[i] = builder.choose(x[i], y[i], z[i]);
    }
    out
}

fn maj(builder: &mut CircuitBuilder, x: &Word, y: &Word, z: &Word) -> Word {
    let mut out = [0u32; 32];
    for i in 0..32 {
        out[i] = builder.majority(x[i], y[i], z[i]);
    }
    out
}

fn big_sigma0(builder: &mut CircuitBuilder, x: &Word) -> Word {
    let a = rotr(x, 2);
    let b = rotr(x, 13);
    let c = rotr(x, 22);
    let ab = xor_word(builder, &a, &b);
    xor_word(builder, &ab, &c)
}

fn big_sigma1(builder: &mut CircuitBuilder, x: &Word) -> Word {
    let a = rotr(x, 6);
    let b = rotr(x, 11);
    let c = rotr(x, 25);
    let ab = xor_word(builder, &a, &b);
    xor_word(builder, &ab, &c)
}

fn small_sigma0(builder: &mut CircuitBuilder, x: &Word) -> Word {
    let a = rotr(x, 7);
    let b = rotr(x, 18);
    let c = shr(builder, x, 3);
    let ab = xor_word(builder, &a, &b);
    xor_word(builder, &ab, &c)
}

fn small_sigma1(builder: &mut CircuitBuilder, x: &Word) -> Word {
    let a = rotr(x, 17);
    let b = rotr(x, 19);
    let c = shr(builder, x, 10);
    let ab = xor_word(builder, &a, &b);
    xor_word(builder, &ab, &c)
}

/// Emit the compression of one 512-bit block against a starting state.
///
/// Exposed separately from [`sha256_block_circuit`] so that a later phase can
/// chain blocks without touching the internals.
pub fn compress(builder: &mut CircuitBuilder, state: &[Word; 8], block: &[WireId]) -> [Word; 8] {
    assert_eq!(block.len(), BLOCK_BITS);

    // Message schedule.
    let mut w: Vec<Word> = Vec::with_capacity(64);
    for t in 0..16 {
        let mut word = [0u32; 32];
        word.copy_from_slice(&block[t * 32..(t + 1) * 32]);
        w.push(word);
    }
    for t in 16..64 {
        let s1 = small_sigma1(builder, &w[t - 2]);
        let s0 = small_sigma0(builder, &w[t - 15]);
        let next = add_words(builder, &[s1, w[t - 7], s0, w[t - 16]]);
        w.push(next);
    }

    // Rounds.
    let mut v = *state;
    for t in 0..64 {
        let k = const_word(builder, K[t]);
        let s1 = big_sigma1(builder, &v[4]);
        let choice = ch(builder, &v[4], &v[5], &v[6]);
        let t1 = add_words(builder, &[v[7], s1, choice, k, w[t]]);
        let s0 = big_sigma0(builder, &v[0]);
        let majority = maj(builder, &v[0], &v[1], &v[2]);
        let t2 = add_word(builder, &s0, &majority);

        v[7] = v[6];
        v[6] = v[5];
        v[5] = v[4];
        v[4] = add_word(builder, &v[3], &t1);
        v[3] = v[2];
        v[2] = v[1];
        v[1] = v[0];
        v[0] = add_word(builder, &t1, &t2);
    }

    // Feed-forward.
    let mut out = [[0u32; 32]; 8];
    for i in 0..8 {
        out[i] = add_word(builder, &state[i], &v[i]);
    }
    out
}

/// The circuit for one SHA-256 block: 512 input bits in, 256 output bits out.
///
/// The caller supplies an already-padded block. Padding is deterministic and
/// public, so there is nothing to be gained from proving it inside the circuit;
/// see [`pad_message`].
pub fn sha256_block_circuit() -> Circuit {
    let mut builder = CircuitBuilder::new();
    let block = builder.input_bits(BLOCK_BITS);
    let state: [Word; 8] = {
        let mut s = [[0u32; 32]; 8];
        for i in 0..8 {
            s[i] = const_word(&mut builder, IV[i]);
        }
        s
    };
    let out = compress(&mut builder, &state, &block);
    for word in &out {
        builder.output_bits(word);
    }
    builder.build()
}

/// Pad a message of at most 55 bytes into a single 512-bit block, big-endian
/// bit order, most significant bit of each byte first.
pub fn pad_message(message: &[u8]) -> Vec<bool> {
    assert!(
        message.len() <= MAX_ONE_BLOCK_MESSAGE,
        "message must fit in one padded block"
    );
    let mut block = [0u8; 64];
    block[..message.len()].copy_from_slice(message);
    block[message.len()] = 0x80;
    let bit_length = (message.len() as u64) * 8;
    block[56..64].copy_from_slice(&bit_length.to_be_bytes());
    bytes_to_bits(&block)
}

/// Big-endian bit expansion: byte 0 bit 7 first.
pub fn bytes_to_bits(bytes: &[u8]) -> Vec<bool> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    for byte in bytes {
        for i in (0..8).rev() {
            bits.push((byte >> i) & 1 == 1);
        }
    }
    bits
}

/// Inverse of [`bytes_to_bits`]; the length must be a multiple of eight.
pub fn bits_to_bytes(bits: &[bool]) -> Vec<u8> {
    assert!(bits.len() % 8 == 0, "bit length must be a multiple of eight");
    bits.chunks(8)
        .map(|chunk| {
            chunk
                .iter()
                .fold(0u8, |acc, &bit| (acc << 1) | u8::from(bit))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::rand_core::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use sha2::{Digest, Sha256};

    fn circuit_hash(circuit: &Circuit, message: &[u8]) -> [u8; 32] {
        let bits = circuit.evaluate(&pad_message(message)).unwrap();
        let bytes = bits_to_bytes(&bits);
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        out
    }

    fn reference_hash(message: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(message);
        hasher.finalize().into()
    }

    #[test]
    fn circuit_is_structurally_valid() {
        sha256_block_circuit().validate().unwrap();
    }

    #[test]
    fn matches_the_published_test_vectors() {
        let circuit = sha256_block_circuit();

        assert_eq!(
            hex::encode(circuit_hash(&circuit, b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex::encode(circuit_hash(&circuit, b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let long: &[u8] = &b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"[..55];
        assert_eq!(circuit_hash(&circuit, long), reference_hash(long));
    }

    #[test]
    fn agrees_with_sha2_at_every_admissible_length() {
        let circuit = sha256_block_circuit();
        let mut rng = ChaCha20Rng::from_seed([17; 32]);
        for len in 0..=MAX_ONE_BLOCK_MESSAGE {
            let mut message = vec![0u8; len];
            rng.fill_bytes(&mut message);
            assert_eq!(
                circuit_hash(&circuit, &message),
                reference_hash(&message),
                "mismatch at length {len}"
            );
        }
    }

    #[test]
    fn differential_test_against_sha2_on_random_messages() {
        let circuit = sha256_block_circuit();
        let mut rng = ChaCha20Rng::from_seed([99; 32]);
        for _ in 0..200 {
            let mut len_bytes = [0u8; 1];
            rng.fill_bytes(&mut len_bytes);
            let len = (len_bytes[0] as usize) % (MAX_ONE_BLOCK_MESSAGE + 1);
            let mut message = vec![0u8; len];
            rng.fill_bytes(&mut message);
            assert_eq!(circuit_hash(&circuit, &message), reference_hash(&message));
        }
    }

    #[test]
    fn the_and_trace_has_one_bit_per_and_gate() {
        let circuit = sha256_block_circuit();
        let (_, trace) = circuit
            .evaluate_with_and_trace(&pad_message(b"abc"))
            .unwrap();
        assert_eq!(trace.len(), circuit.and_gates() as usize);
    }

    #[test]
    fn byte_and_bit_conversion_round_trips() {
        let bytes: Vec<u8> = (0..64u16).map(|i| i as u8).collect();
        assert_eq!(bits_to_bytes(&bytes_to_bits(&bytes)), bytes);
    }

    /// Locked-in cost. If a change to the builder or to these constructions
    /// moves the AND count, that is a real event: every proof size in the
    /// project is linear in this number, so it should never move silently.
    #[test]
    fn and_gate_count_is_stable() {
        let stats = sha256_block_circuit().stats();
        assert_eq!(stats.and_gates, EXPECTED_AND_GATES);
        assert_eq!(stats.and_depth, EXPECTED_AND_DEPTH);
    }

    const EXPECTED_AND_GATES: u32 = crate::SHA256_AND_GATES;
    const EXPECTED_AND_DEPTH: u32 = crate::SHA256_AND_DEPTH;
}
