//! Incremental construction of circuits.
//!
//! The builder is the only way to produce a [`Circuit`], which is what makes the
//! topological invariant free: a gate can only reference wires that were handed
//! out before it.

use crate::circuit::{Circuit, CircuitStats, Gate, WireId};

/// Builds a circuit gate by gate.
///
/// Constant folding is performed eagerly and locally. It is not an optimizer;
/// it exists so that generic word-level helpers (shifts that feed in zeros,
/// additions against round constants) do not litter the circuit with gates whose
/// value is already known. Anything beyond that is deliberately left undone:
/// this crate is a faithful IR, not a synthesis tool.
pub struct CircuitBuilder {
    gates: Vec<Gate>,
    /// Multiplicative depth of each wire.
    depth: Vec<u32>,
    arity: u32,
    outputs: Vec<WireId>,
    zero: Option<WireId>,
    one: Option<WireId>,
    stats: CircuitStats,
}

impl Default for CircuitBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl CircuitBuilder {
    pub fn new() -> Self {
        CircuitBuilder {
            gates: Vec::new(),
            depth: Vec::new(),
            arity: 0,
            outputs: Vec::new(),
            zero: None,
            one: None,
            stats: CircuitStats::default(),
        }
    }

    fn push(&mut self, gate: Gate, depth: u32) -> WireId {
        let id = self.gates.len() as WireId;
        self.gates.push(gate);
        self.depth.push(depth);
        if depth > self.stats.and_depth {
            self.stats.and_depth = depth;
        }
        id
    }

    fn depth_of(&self, w: WireId) -> u32 {
        self.depth[w as usize]
    }

    /// Return `Some(value)` if the wire is a hardwired constant.
    fn as_const(&self, w: WireId) -> Option<bool> {
        match self.gates[w as usize] {
            Gate::Const(b) => Some(b),
            _ => None,
        }
    }

    /// Allocate one fresh input bit.
    pub fn input(&mut self) -> WireId {
        let index = self.arity;
        self.arity += 1;
        self.stats.inputs += 1;
        self.push(Gate::Input(index), 0)
    }

    /// Allocate `n` fresh input bits.
    pub fn input_bits(&mut self, n: usize) -> Vec<WireId> {
        (0..n).map(|_| self.input()).collect()
    }

    /// A hardwired constant. The two constant wires are cached, so a circuit
    /// contains at most one `Const(false)` and one `Const(true)`.
    pub fn constant(&mut self, value: bool) -> WireId {
        let cached = if value { self.one } else { self.zero };
        if let Some(w) = cached {
            return w;
        }
        self.stats.const_gates += 1;
        let w = self.push(Gate::Const(value), 0);
        if value {
            self.one = Some(w);
        } else {
            self.zero = Some(w);
        }
        w
    }

    pub fn xor(&mut self, a: WireId, b: WireId) -> WireId {
        match (self.as_const(a), self.as_const(b)) {
            (Some(x), Some(y)) => return self.constant(x ^ y),
            (Some(false), None) => return b,
            (None, Some(false)) => return a,
            (Some(true), None) => return self.not(b),
            (None, Some(true)) => return self.not(a),
            _ => {}
        }
        if a == b {
            return self.constant(false);
        }
        let depth = self.depth_of(a).max(self.depth_of(b));
        self.stats.xor_gates += 1;
        self.push(Gate::Xor(a, b), depth)
    }

    pub fn and(&mut self, a: WireId, b: WireId) -> WireId {
        match (self.as_const(a), self.as_const(b)) {
            (Some(x), Some(y)) => return self.constant(x & y),
            (Some(false), _) | (_, Some(false)) => return self.constant(false),
            (Some(true), None) => return b,
            (None, Some(true)) => return a,
            _ => {}
        }
        if a == b {
            return a;
        }
        let depth = self.depth_of(a).max(self.depth_of(b)) + 1;
        self.stats.and_gates += 1;
        self.push(Gate::And(a, b), depth)
    }

    pub fn not(&mut self, a: WireId) -> WireId {
        if let Some(x) = self.as_const(a) {
            return self.constant(!x);
        }
        if let Gate::Not(inner) = self.gates[a as usize] {
            return inner;
        }
        let depth = self.depth_of(a);
        self.stats.not_gates += 1;
        self.push(Gate::Not(a), depth)
    }

    /// `a OR b`, expressed as `a XOR b XOR (a AND b)`. Costs one AND gate.
    pub fn or(&mut self, a: WireId, b: WireId) -> WireId {
        let and = self.and(a, b);
        let xor = self.xor(a, b);
        self.xor(xor, and)
    }

    /// `if selector { on_true } else { on_false }`, one AND gate.
    pub fn mux(&mut self, selector: WireId, on_false: WireId, on_true: WireId) -> WireId {
        let diff = self.xor(on_false, on_true);
        let masked = self.and(selector, diff);
        self.xor(on_false, masked)
    }

    /// XOR of an arbitrary number of wires; the empty fold is the zero constant.
    pub fn xor_many(&mut self, wires: &[WireId]) -> WireId {
        let mut acc = self.constant(false);
        for &w in wires {
            acc = self.xor(acc, w);
        }
        acc
    }

    /// The 3-input majority function, in one AND gate:
    /// `maj(a, b, c) = ((a XOR c) AND (b XOR c)) XOR c`.
    ///
    /// This is the carry rule of the ripple-carry adder and the `Maj` function
    /// of SHA-256, and it is the reason both cost one AND per bit.
    pub fn majority(&mut self, a: WireId, b: WireId, c: WireId) -> WireId {
        let ac = self.xor(a, c);
        let bc = self.xor(b, c);
        let and = self.and(ac, bc);
        self.xor(and, c)
    }

    /// The choice function `ch(x, y, z) = (x AND y) XOR (NOT x AND z)`,
    /// rewritten as `((y XOR z) AND x) XOR z` for one AND gate.
    pub fn choose(&mut self, x: WireId, y: WireId, z: WireId) -> WireId {
        let yz = self.xor(y, z);
        let and = self.and(yz, x);
        self.xor(and, z)
    }

    pub fn output(&mut self, wire: WireId) {
        self.outputs.push(wire);
        self.stats.outputs += 1;
    }

    pub fn output_bits(&mut self, wires: &[WireId]) {
        for &w in wires {
            self.output(w);
        }
    }

    /// Number of AND gates emitted so far. Useful for attributing cost to
    /// sub-constructions while building.
    pub fn and_gates_so_far(&self) -> u32 {
        self.stats.and_gates
    }

    pub fn build(mut self) -> Circuit {
        self.stats.wires = self.gates.len() as u32;
        Circuit::from_parts(self.gates, self.arity, self.outputs, self.stats)
    }
}
