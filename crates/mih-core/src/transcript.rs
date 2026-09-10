//! A domain-separated transcript.
//!
//! Phase 1 uses this to bind the statement and the commitments before the
//! verifier's challenge is drawn; Phase 2 replaces the interactive verifier with
//! it entirely via Fiat-Shamir. Getting the framing right now is cheap, and
//! getting it wrong later is the classic way these schemes break.
//!
//! The construction is deliberately boring. The state is a 32-byte value; every
//! operation replaces it with a hash of a tag, the old state, and
//! length-prefixed arguments. Because every field is length-prefixed and every
//! operation carries a distinct tag byte, no sequence of absorbs can be made to
//! produce the same state as a different sequence.

use sha2::{Digest, Sha256};

const TAG_INIT: u8 = 0x00;
const TAG_ABSORB: u8 = 0x01;
const TAG_CHALLENGE: u8 = 0x02;
const TAG_SQUEEZE: u8 = 0x03;

/// A running transcript state.
#[derive(Clone, Debug)]
pub struct Transcript {
    state: [u8; 32],
}

fn absorb_framed(hasher: &mut Sha256, data: &[u8]) {
    hasher.update((data.len() as u64).to_le_bytes());
    hasher.update(data);
}

impl Transcript {
    /// Start a transcript for a named protocol. Two protocols with different
    /// names can never produce the same challenges from the same inputs.
    pub fn new(protocol: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update([TAG_INIT]);
        absorb_framed(&mut hasher, protocol.as_bytes());
        Transcript {
            state: hasher.finalize().into(),
        }
    }

    /// Bind a labelled byte string into the transcript.
    pub fn absorb(&mut self, label: &str, data: &[u8]) {
        let mut hasher = Sha256::new();
        hasher.update([TAG_ABSORB]);
        hasher.update(self.state);
        absorb_framed(&mut hasher, label.as_bytes());
        absorb_framed(&mut hasher, data);
        self.state = hasher.finalize().into();
    }

    pub fn absorb_u64(&mut self, label: &str, value: u64) {
        self.absorb(label, &value.to_le_bytes());
    }

    /// Bind a bit string, packed LSB-first with an explicit length.
    pub fn absorb_bits(&mut self, label: &str, bits: &[bool]) {
        let mut packed = Vec::with_capacity(8 + (bits.len() + 7) / 8);
        packed.extend_from_slice(&(bits.len() as u64).to_le_bytes());
        packed.extend_from_slice(&pack_bits(bits));
        self.absorb(label, &packed);
    }

    /// Derive challenge bytes and ratchet the state forward.
    ///
    /// Ratcheting means a challenge can never be drawn twice from the same
    /// state, so a caller cannot accidentally reuse randomness by calling this
    /// twice with the same label.
    pub fn challenge_bytes(&mut self, label: &str, out: &mut [u8]) {
        let mut hasher = Sha256::new();
        hasher.update([TAG_CHALLENGE]);
        hasher.update(self.state);
        absorb_framed(&mut hasher, label.as_bytes());
        self.state = hasher.finalize().into();

        let mut counter: u64 = 0;
        for chunk in out.chunks_mut(32) {
            let mut hasher = Sha256::new();
            hasher.update([TAG_SQUEEZE]);
            hasher.update(self.state);
            hasher.update(counter.to_le_bytes());
            let block: [u8; 32] = hasher.finalize().into();
            chunk.copy_from_slice(&block[..chunk.len()]);
            counter += 1;
        }
    }

    pub fn challenge_array<const N: usize>(&mut self, label: &str) -> [u8; N] {
        let mut out = [0u8; N];
        self.challenge_bytes(label, &mut out);
        out
    }

    /// Draw a uniform index in `0..modulus` by rejection sampling.
    ///
    /// Phase 1 draws exactly this: one index in `{0, 1, 2}` per repetition,
    /// selecting which pair of views is opened. Rejection sampling rather than
    /// reduction because the bias of `x % 3` is small but real, and there is no
    /// reason to accept it.
    pub fn challenge_index(&mut self, label: &str, modulus: u32) -> u32 {
        assert!(modulus > 0, "modulus must be positive");
        if modulus == 1 {
            return 0;
        }
        let limit = u32::MAX - (u32::MAX % modulus);
        let mut attempt: u64 = 0;
        loop {
            let mut buf = [0u8; 4];
            self.challenge_bytes(label, &mut buf);
            let value = u32::from_le_bytes(buf);
            if value < limit {
                return value % modulus;
            }
            attempt += 1;
            assert!(attempt < 128, "rejection sampling failed to terminate");
        }
    }

    /// Draw `count` independent indices in `0..modulus`.
    pub fn challenge_indices(&mut self, label: &str, modulus: u32, count: usize) -> Vec<u32> {
        (0..count)
            .map(|_| self.challenge_index(label, modulus))
            .collect()
    }

    /// The current state, for debugging and for test vectors.
    pub fn state(&self) -> [u8; 32] {
        self.state
    }
}

/// Pack bits LSB-first into bytes. The length is not encoded; callers that need
/// canonicity encode it themselves.
pub fn pack_bits(bits: &[bool]) -> Vec<u8> {
    let mut out = vec![0u8; (bits.len() + 7) / 8];
    for (i, &bit) in bits.iter().enumerate() {
        if bit {
            out[i / 8] |= 1 << (i % 8);
        }
    }
    out
}

/// Inverse of [`pack_bits`] for a known bit length.
pub fn unpack_bits(bytes: &[u8], len: usize) -> Vec<bool> {
    (0..len)
        .map(|i| (bytes[i / 8] >> (i % 8)) & 1 == 1)
        .collect()
}
