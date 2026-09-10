//! Boolean circuit IR for MPC-in-the-Head.
//!
//! Everything in this project is ultimately a boolean circuit that some set of
//! simulated parties evaluates on shares. This crate defines what a circuit is,
//! how to build one, and what its cost is. It has no dependencies, cryptographic
//! or otherwise, on purpose: the IR is the one thing every later phase agrees on.
//!
//! The cost model is the whole point. XOR, NOT and constants are linear and are
//! computed locally by each party without communication. AND gates are the only
//! non-linear operation, they consume randomness and produce broadcast traffic,
//! and so the AND count is what a proof's size is proportional to. Every
//! construction in `mih-sym` is written to keep that number down.

mod builder;
mod circuit;

pub use builder::CircuitBuilder;
pub use circuit::{Circuit, CircuitError, CircuitStats, Gate, WireId};

#[cfg(test)]
mod tests {
    use super::*;

    /// Exhaustively check a 2-input circuit against a reference function.
    fn check_binary<F: Fn(bool, bool) -> bool>(circuit: &Circuit, reference: F) {
        for a in [false, true] {
            for b in [false, true] {
                let got = circuit.evaluate(&[a, b]).unwrap();
                assert_eq!(got, vec![reference(a, b)], "mismatch on ({a}, {b})");
            }
        }
    }

    #[test]
    fn and_xor_not_have_the_expected_semantics() {
        let mut b = CircuitBuilder::new();
        let x = b.input();
        let y = b.input();
        let w = b.and(x, y);
        b.output(w);
        let c = b.build();
        c.validate().unwrap();
        check_binary(&c, |a, b| a & b);

        let mut b = CircuitBuilder::new();
        let x = b.input();
        let y = b.input();
        let w = b.xor(x, y);
        b.output(w);
        check_binary(&b.build(), |a, b| a ^ b);

        let mut b = CircuitBuilder::new();
        let x = b.input();
        let _ = b.input();
        let w = b.not(x);
        b.output(w);
        check_binary(&b.build(), |a, _| !a);
    }

    #[test]
    fn or_and_mux_are_correct_and_cost_one_and_gate() {
        let mut b = CircuitBuilder::new();
        let x = b.input();
        let y = b.input();
        let w = b.or(x, y);
        b.output(w);
        let c = b.build();
        check_binary(&c, |a, b| a | b);
        assert_eq!(c.and_gates(), 1);

        let mut b = CircuitBuilder::new();
        let s = b.input();
        let f = b.input();
        let t = b.input();
        let w = b.mux(s, f, t);
        b.output(w);
        let c = b.build();
        assert_eq!(c.and_gates(), 1);
        for sel in [false, true] {
            for lo in [false, true] {
                for hi in [false, true] {
                    let expected = if sel { hi } else { lo };
                    assert_eq!(c.evaluate(&[sel, lo, hi]).unwrap(), vec![expected]);
                }
            }
        }
    }

    #[test]
    fn majority_and_choose_are_correct_and_cost_one_and_gate() {
        for which in 0..2 {
            let mut b = CircuitBuilder::new();
            let x = b.input();
            let y = b.input();
            let z = b.input();
            let w = if which == 0 {
                b.majority(x, y, z)
            } else {
                b.choose(x, y, z)
            };
            b.output(w);
            let c = b.build();
            assert_eq!(c.and_gates(), 1, "expected exactly one AND gate");
            for a in [false, true] {
                for bb in [false, true] {
                    for cc in [false, true] {
                        let expected = if which == 0 {
                            (a & bb) | (a & cc) | (bb & cc)
                        } else {
                            (a & bb) ^ (!a & cc)
                        };
                        assert_eq!(
                            c.evaluate(&[a, bb, cc]).unwrap(),
                            vec![expected],
                            "mismatch on ({a}, {bb}, {cc})"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn constants_are_folded_and_cached() {
        let mut b = CircuitBuilder::new();
        let x = b.input();
        let zero = b.constant(false);
        let one = b.constant(true);
        // Folding: none of these may emit a gate.
        let a = b.xor(x, zero);
        assert_eq!(a, x);
        let a = b.and(x, one);
        assert_eq!(a, x);
        let a = b.and(x, zero);
        assert_eq!(b.constant(false), a);
        let a = b.xor(x, x);
        assert_eq!(b.constant(false), a);
        // Constant wires are cached.
        assert_eq!(b.constant(false), zero);
        assert_eq!(b.constant(true), one);
        let c = b.build();
        assert_eq!(c.and_gates(), 0);
        assert_eq!(c.stats().xor_gates, 0);
        assert_eq!(c.stats().const_gates, 2);
    }

    #[test]
    fn double_negation_collapses() {
        let mut b = CircuitBuilder::new();
        let x = b.input();
        let n = b.not(x);
        let nn = b.not(n);
        assert_eq!(nn, x);
        b.output(nn);
        assert_eq!(b.build().stats().not_gates, 1);
    }

    #[test]
    fn and_depth_counts_multiplicative_layers() {
        let mut b = CircuitBuilder::new();
        let x = b.input();
        let y = b.input();
        let l1 = b.and(x, y);
        let lin = b.xor(l1, x);
        let l2 = b.and(lin, y);
        b.output(l2);
        let c = b.build();
        assert_eq!(c.stats().and_depth, 2, "XOR must not increase AND depth");
        assert_eq!(c.and_gates(), 2);
    }

    #[test]
    fn and_trace_matches_gate_order_and_length() {
        let mut b = CircuitBuilder::new();
        let x = b.input();
        let y = b.input();
        let g1 = b.and(x, y);
        let g2 = b.and(g1, y);
        b.output(g2);
        let c = b.build();
        let (out, trace) = c.evaluate_with_and_trace(&[true, true]).unwrap();
        assert_eq!(out, vec![true]);
        assert_eq!(trace, vec![true, true]);
        let (out, trace) = c.evaluate_with_and_trace(&[true, false]).unwrap();
        assert_eq!(out, vec![false]);
        assert_eq!(trace.len(), c.and_gates() as usize);
        assert_eq!(trace, vec![false, false]);
    }

    #[test]
    fn wrong_input_length_is_rejected() {
        let mut b = CircuitBuilder::new();
        let x = b.input();
        b.output(x);
        let c = b.build();
        assert_eq!(
            c.evaluate(&[]),
            Err(CircuitError::InputLengthMismatch {
                expected: 1,
                got: 0
            })
        );
    }

    #[test]
    fn validation_catches_a_forward_reference() {
        let mut b = CircuitBuilder::new();
        let x = b.input();
        let y = b.input();
        let w = b.and(x, y);
        b.output(w);
        let good = b.build();
        good.validate().unwrap();

        // Hand-assemble a circuit the builder could never produce.
        let broken = Circuit::from_parts(
            vec![Gate::Input(0), Gate::Xor(0, 5)],
            1,
            vec![1],
            CircuitStats::default(),
        );
        assert_eq!(
            broken.validate(),
            Err(CircuitError::NotTopological {
                gate: 1,
                operand: 5
            })
        );
    }
}
