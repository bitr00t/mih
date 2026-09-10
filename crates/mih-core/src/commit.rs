//! Hash-based commitments.
//!
//! Phase 1 commits to three party views per repetition and opens two. The
//! commitment must be binding, so that a prover cannot swap a view after seeing
//! the challenge, and hiding, so that the unopened view leaks nothing. A salted
//! hash gives both in the random oracle model, which is the model the rest of
//! the project works in anyway.
//!
//! The position of a commitment inside the proof is bound in explicitly. Without
//! it, a prover could move a valid commitment from one repetition or one party
//! slot to another, and each such freedom is a small hole in soundness.

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Length of a commitment in bytes.
pub const COMMITMENT_LEN: usize = 32;
/// Length of the per-view opening randomness in bytes.
pub const OPENING_LEN: usize = 32;

const TAG_COMMIT: u8 = 0x10;

/// A commitment to a party view.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Commitment(pub [u8; COMMITMENT_LEN]);

impl Commitment {
    pub fn as_bytes(&self) -> &[u8; COMMITMENT_LEN] {
        &self.0
    }
}

/// Where a commitment sits in the proof. Bound into the hash so commitments are
/// not interchangeable between slots.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Position {
    /// Which repetition of the protocol.
    pub repetition: u32,
    /// Which simulated party.
    pub party: u32,
}

/// Commit to `data` at `position`, using `opening` as the hiding randomness.
///
/// The opening is per-view and is revealed together with the view. It must come
/// from the PRG, never from a fixed value: it is the only thing hiding a view
/// whose content an adversary may be able to guess.
pub fn commit(opening: &[u8; OPENING_LEN], position: Position, data: &[u8]) -> Commitment {
    let mut hasher = Sha256::new();
    hasher.update([TAG_COMMIT]);
    hasher.update(opening);
    hasher.update(position.repetition.to_le_bytes());
    hasher.update(position.party.to_le_bytes());
    hasher.update((data.len() as u64).to_le_bytes());
    hasher.update(data);
    Commitment(hasher.finalize().into())
}

/// Recompute a commitment and compare it in constant time.
pub fn verify(
    commitment: &Commitment,
    opening: &[u8; OPENING_LEN],
    position: Position,
    data: &[u8],
) -> bool {
    let recomputed = commit(opening, position, data);
    recomputed.0.ct_eq(&commitment.0).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    const POS: Position = Position {
        repetition: 3,
        party: 1,
    };

    fn opening(byte: u8) -> [u8; OPENING_LEN] {
        [byte; OPENING_LEN]
    }

    #[test]
    fn commitment_verifies_against_itself() {
        let c = commit(&opening(7), POS, b"view bytes");
        assert!(verify(&c, &opening(7), POS, b"view bytes"));
    }

    #[test]
    fn changing_any_bound_field_breaks_verification() {
        let c = commit(&opening(7), POS, b"view bytes");
        assert!(!verify(&c, &opening(8), POS, b"view bytes"));
        assert!(!verify(&c, &opening(7), POS, b"other bytes"));
        assert!(!verify(
            &c,
            &opening(7),
            Position {
                repetition: 4,
                party: 1
            },
            b"view bytes"
        ));
        assert!(!verify(
            &c,
            &opening(7),
            Position {
                repetition: 3,
                party: 2
            },
            b"view bytes"
        ));
    }

    #[test]
    fn length_prefix_prevents_splitting_ambiguity() {
        // Without the length prefix on the payload these two would be at risk of
        // colliding through the concatenation, since the position fields are
        // fixed width but the payload is not.
        let a = commit(&opening(1), POS, b"abcd");
        let b = commit(&opening(1), POS, b"abc");
        assert_ne!(a, b);
    }
}
