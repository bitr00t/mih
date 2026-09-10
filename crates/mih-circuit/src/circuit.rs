//! The circuit IR.
//!
//! A circuit is a flat, topologically ordered list of gates. Wire `i` is by
//! definition the output of `gates[i]`, so every operand index of a gate is
//! strictly smaller than the gate's own index. This makes evaluation a single
//! forward pass and makes topological validity a local, checkable property.

use core::fmt;

/// Index of a wire, equivalently the index of the gate that produces it.
pub type WireId = u32;

/// A single gate.
///
/// `Not` is kept as its own node rather than being desugared to `Xor(x, 1)`
/// because it carries no cost in any MPC-in-the-Head decomposition and keeping
/// it explicit makes the gate statistics honest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gate {
    /// The `n`-th bit of the circuit input.
    Input(u32),
    /// A hardwired constant.
    Const(bool),
    /// XOR: linear, free in every decomposition used later.
    Xor(WireId, WireId),
    /// AND: the only non-linear gate, and therefore the only cost that matters.
    And(WireId, WireId),
    /// Negation: linear.
    Not(WireId),
}

/// Why a circuit failed validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CircuitError {
    /// A gate referenced a wire at or after its own position.
    NotTopological { gate: WireId, operand: WireId },
    /// An `Input(i)` gate referenced an input index outside the declared arity.
    InputOutOfRange { gate: WireId, index: u32, arity: u32 },
    /// An output referenced a wire that does not exist.
    OutputOutOfRange { output: usize, wire: WireId },
    /// The evaluator was handed the wrong number of input bits.
    InputLengthMismatch { expected: u32, got: usize },
}

impl fmt::Display for CircuitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CircuitError::NotTopological { gate, operand } => write!(
                f,
                "gate {gate} references wire {operand}, which is not strictly earlier"
            ),
            CircuitError::InputOutOfRange { gate, index, arity } => write!(
                f,
                "gate {gate} reads input {index}, but the circuit has arity {arity}"
            ),
            CircuitError::OutputOutOfRange { output, wire } => {
                write!(f, "output {output} references non-existent wire {wire}")
            }
            CircuitError::InputLengthMismatch { expected, got } => {
                write!(f, "circuit expects {expected} input bits, got {got}")
            }
        }
    }
}

/// Structural statistics of a circuit.
///
/// `and_gates` is the cost metric that drives everything downstream: view size,
/// tape length and ultimately proof size are all linear in it. `and_depth` is
/// the multiplicative depth, which matters for the round structure of the
/// protocols in later phases.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CircuitStats {
    pub inputs: u32,
    pub outputs: u32,
    pub wires: u32,
    pub and_gates: u32,
    pub xor_gates: u32,
    pub not_gates: u32,
    pub const_gates: u32,
    pub and_depth: u32,
}

impl fmt::Display for CircuitStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "inputs={} outputs={} wires={} AND={} XOR={} NOT={} CONST={} and_depth={}",
            self.inputs,
            self.outputs,
            self.wires,
            self.and_gates,
            self.xor_gates,
            self.not_gates,
            self.const_gates,
            self.and_depth
        )
    }
}

/// A finished, immutable circuit.
#[derive(Clone, Debug)]
pub struct Circuit {
    gates: Vec<Gate>,
    arity: u32,
    outputs: Vec<WireId>,
    stats: CircuitStats,
}

impl Circuit {
    pub(crate) fn from_parts(
        gates: Vec<Gate>,
        arity: u32,
        outputs: Vec<WireId>,
        stats: CircuitStats,
    ) -> Self {
        Circuit {
            gates,
            arity,
            outputs,
            stats,
        }
    }

    pub fn gates(&self) -> &[Gate] {
        &self.gates
    }

    pub fn outputs(&self) -> &[WireId] {
        &self.outputs
    }

    /// Number of input bits the circuit expects.
    pub fn arity(&self) -> u32 {
        self.arity
    }

    pub fn stats(&self) -> CircuitStats {
        self.stats
    }

    pub fn and_gates(&self) -> u32 {
        self.stats.and_gates
    }

    /// Check the invariants that the builder is supposed to maintain.
    ///
    /// Nothing in this crate can currently produce an invalid circuit, which is
    /// exactly why this exists: later phases will construct circuits from
    /// deserialized data and from the Phase 5 frontend, and this is the gate
    /// they have to pass.
    pub fn validate(&self) -> Result<(), CircuitError> {
        for (idx, gate) in self.gates.iter().enumerate() {
            let idx = idx as WireId;
            let check = |operand: WireId| -> Result<(), CircuitError> {
                if operand >= idx {
                    Err(CircuitError::NotTopological {
                        gate: idx,
                        operand,
                    })
                } else {
                    Ok(())
                }
            };
            match *gate {
                Gate::Input(index) => {
                    if index >= self.arity {
                        return Err(CircuitError::InputOutOfRange {
                            gate: idx,
                            index,
                            arity: self.arity,
                        });
                    }
                }
                Gate::Const(_) => {}
                Gate::Not(a) => check(a)?,
                Gate::Xor(a, b) | Gate::And(a, b) => {
                    check(a)?;
                    check(b)?;
                }
            }
        }
        for (position, &wire) in self.outputs.iter().enumerate() {
            if wire as usize >= self.gates.len() {
                return Err(CircuitError::OutputOutOfRange {
                    output: position,
                    wire,
                });
            }
        }
        Ok(())
    }

    /// Evaluate the circuit in the clear.
    ///
    /// This is the reference semantics that every decomposition in later phases
    /// must reproduce: whatever the parties compute on shares, recombining their
    /// outputs has to equal this.
    pub fn evaluate(&self, inputs: &[bool]) -> Result<Vec<bool>, CircuitError> {
        if inputs.len() != self.arity as usize {
            return Err(CircuitError::InputLengthMismatch {
                expected: self.arity,
                got: inputs.len(),
            });
        }
        let mut wires = vec![false; self.gates.len()];
        for (idx, gate) in self.gates.iter().enumerate() {
            wires[idx] = match *gate {
                Gate::Input(i) => inputs[i as usize],
                Gate::Const(b) => b,
                Gate::Xor(a, b) => wires[a as usize] ^ wires[b as usize],
                Gate::And(a, b) => wires[a as usize] & wires[b as usize],
                Gate::Not(a) => !wires[a as usize],
            };
        }
        Ok(self
            .outputs
            .iter()
            .map(|&w| wires[w as usize])
            .collect())
    }

    /// Evaluate and additionally return the output bit of every AND gate, in
    /// gate order.
    ///
    /// Phase 1 needs exactly this trace: in the (2,3)-decomposition, one bit per
    /// AND gate per party is broadcast, and the tape consumption is indexed the
    /// same way. Having it here keeps the prover from re-deriving the ordering.
    pub fn evaluate_with_and_trace(
        &self,
        inputs: &[bool],
    ) -> Result<(Vec<bool>, Vec<bool>), CircuitError> {
        if inputs.len() != self.arity as usize {
            return Err(CircuitError::InputLengthMismatch {
                expected: self.arity,
                got: inputs.len(),
            });
        }
        let mut wires = vec![false; self.gates.len()];
        let mut trace = Vec::with_capacity(self.stats.and_gates as usize);
        for (idx, gate) in self.gates.iter().enumerate() {
            let value = match *gate {
                Gate::Input(i) => inputs[i as usize],
                Gate::Const(b) => b,
                Gate::Xor(a, b) => wires[a as usize] ^ wires[b as usize],
                Gate::And(a, b) => {
                    let v = wires[a as usize] & wires[b as usize];
                    trace.push(v);
                    v
                }
                Gate::Not(a) => !wires[a as usize],
            };
            wires[idx] = value;
        }
        let outputs = self.outputs.iter().map(|&w| wires[w as usize]).collect();
        Ok((outputs, trace))
    }
}
