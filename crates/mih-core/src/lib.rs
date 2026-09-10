//! Shared cryptographic plumbing for MPC-in-the-Head.
//!
//! Nothing here is novel and nothing here is meant to be. The transcript, the
//! commitment scheme, the seed expansion and the encoding are the machinery that
//! the proof systems in later phases are built on top of, and the reason they
//! live in Phase 0 is that getting their framing and domain separation right is
//! much easier before there is a protocol depending on them.
//!
//! Primitives come from crates. The structure around them - what gets bound into
//! what, in which order, with which tags - is the project's own, because that
//! structure is where these schemes actually break.

pub mod transcript;

pub use transcript::{pack_bits, unpack_bits, Transcript};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transcript_is_deterministic() {
        let mut a = Transcript::new("mih/test");
        let mut b = Transcript::new("mih/test");
        a.absorb("statement", b"y");
        b.absorb("statement", b"y");
        assert_eq!(a.challenge_array::<32>("e"), b.challenge_array::<32>("e"));
    }

    #[test]
    fn protocol_label_separates_transcripts() {
        let mut a = Transcript::new("mih/zkboo");
        let mut b = Transcript::new("mih/kkw");
        a.absorb("statement", b"y");
        b.absorb("statement", b"y");
        assert_ne!(a.challenge_array::<32>("e"), b.challenge_array::<32>("e"));
    }

    #[test]
    fn absorbed_data_changes_the_challenge() {
        let mut a = Transcript::new("mih/test");
        let mut b = Transcript::new("mih/test");
        a.absorb("commitments", b"aaa");
        b.absorb("commitments", b"aab");
        assert_ne!(a.challenge_array::<32>("e"), b.challenge_array::<32>("e"));
    }

    #[test]
    fn labels_are_separated() {
        let mut a = Transcript::new("mih/test");
        let mut b = Transcript::new("mih/test");
        a.absorb("x", b"same");
        b.absorb("y", b"same");
        assert_ne!(a.challenge_array::<32>("e"), b.challenge_array::<32>("e"));
    }

    #[test]
    fn framing_prevents_concatenation_collisions() {
        // Without length prefixes, ("ab", "c") and ("a", "bc") would hash the
        // same way. This is the single most common transcript bug.
        let mut a = Transcript::new("mih/test");
        let mut b = Transcript::new("mih/test");
        a.absorb("f", b"ab");
        a.absorb("f", b"c");
        b.absorb("f", b"a");
        b.absorb("f", b"bc");
        assert_ne!(a.challenge_array::<32>("e"), b.challenge_array::<32>("e"));
    }

    #[test]
    fn challenges_ratchet() {
        let mut t = Transcript::new("mih/test");
        t.absorb("statement", b"y");
        let first = t.challenge_array::<32>("e");
        let second = t.challenge_array::<32>("e");
        assert_ne!(first, second, "same label must not yield the same challenge twice");
    }

    #[test]
    fn challenge_indices_are_in_range_and_cover_the_domain() {
        // Phase 1 draws one index in {0, 1, 2} per repetition. Check both that
        // the range holds and that no value is systematically missing.
        let mut t = Transcript::new("mih/test");
        t.absorb("statement", b"y");
        let indices = t.challenge_indices("e", 3, 3000);
        assert!(indices.iter().all(|&i| i < 3));
        for value in 0..3u32 {
            let count = indices.iter().filter(|&&i| i == value).count();
            assert!((800..1200).contains(&count), "value {value} appeared {count} times");
        }
    }

    #[test]
    fn bit_packing_round_trips_at_every_length() {
        for len in 0..40usize {
            let bits: Vec<bool> = (0..len).map(|i| i % 3 == 0).collect();
            let packed = pack_bits(&bits);
            assert_eq!(packed.len(), (len + 7) / 8);
            assert_eq!(unpack_bits(&packed, len), bits);
        }
    }
}
