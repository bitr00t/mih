//! Symmetric primitives expressed as boolean circuits.
//!
//! The proof systems of later phases prove statements about circuits, so a
//! primitive is only usable here once it exists in gate form. Two are provided,
//! and they are chosen to sit at opposite ends of the cost spectrum:
//!
//! - SHA-256, standard and interoperable, and expensive: over twenty thousand
//!   AND gates for a single block.
//! - LowMC, non-standard and designed for exactly this setting, and cheap: six
//!   hundred AND gates at the Picnic L1 parameters.
//!
//! Having both from the start means every later phase can be measured against a
//! circuit nobody chose to be convenient and against one that was.

pub mod gf2;

pub use gf2::BitMatrix;
