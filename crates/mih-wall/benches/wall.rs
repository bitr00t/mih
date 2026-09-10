//! Prints the Phase 0 baseline table.
//!
//! Run with `cargo bench -p mih-wall`. There is no criterion harness here: what
//! this measures is proof size, which is exact arithmetic on circuit statistics
//! rather than a timing, so a statistical benchmarking framework would only add
//! noise and dependencies. Circuit build and evaluation times are printed too,
//! but as rough figures, clearly labelled as such.

use std::time::Instant;

use mih_sym::lowmc::{LowMcInstance, PICNIC_L1, PICNIC_L5};
use mih_sym::sha256::{pad_message, sha256_block_circuit};
use mih_wall::{estimate_circuit, repetitions};

const LAMBDA: u32 = 128;

fn main() {
    println!();
    println!("MPC-in-the-Head, Phase 0 baseline");
    println!("Security level: {LAMBDA} bits");
    println!(
        "Repetitions of the naive (2,3) protocol: {}",
        repetitions(LAMBDA)
    );
    println!();

    let mut rows = Vec::new();

    let start = Instant::now();
    let sha = sha256_block_circuit();
    let sha_build = start.elapsed();
    rows.push(("SHA-256, one block", sha.stats(), estimate_circuit(&sha, LAMBDA)));

    let l1 = LowMcInstance::generate(PICNIC_L1, [0x11; 32]);
    let l1_pt = vec![false; PICNIC_L1.n];
    let start = Instant::now();
    let l1_circuit = l1.owf_circuit(&l1_pt);
    let l1_build = start.elapsed();
    rows.push((
        "LowMC 128/128/10/20",
        l1_circuit.stats(),
        estimate_circuit(&l1_circuit, LAMBDA),
    ));

    let l5 = LowMcInstance::generate(PICNIC_L5, [0x55; 32]);
    let l5_pt = vec![false; PICNIC_L5.n];
    let l5_circuit = l5.owf_circuit(&l5_pt);
    rows.push((
        "LowMC 256/256/10/38",
        l5_circuit.stats(),
        estimate_circuit(&l5_circuit, LAMBDA),
    ));

    println!(
        "{:<22} {:>10} {:>12} {:>10} {:>12} {:>14}",
        "circuit", "AND gates", "total gates", "AND depth", "view bits", "naive proof"
    );
    println!("{}", "-".repeat(86));
    for (name, stats, estimate) in &rows {
        let size = if estimate.total_mib() >= 1.0 {
            format!("{:.2} MiB", estimate.total_mib())
        } else {
            format!("{:.1} KiB", estimate.total_kib())
        };
        println!(
            "{:<22} {:>10} {:>12} {:>10} {:>12} {:>14}",
            name, stats.and_gates, stats.wires, stats.and_depth, estimate.view_bits, size
        );
    }
    println!();

    let (sha_name, _, sha_estimate) = &rows[0];
    let (l1_name, _, l1_estimate) = &rows[1];
    println!(
        "{sha_name} costs {:.0}x the proof size of {l1_name}.",
        sha_estimate.total_bytes as f64 / l1_estimate.total_bytes as f64
    );
    println!(
        "Per repetition: {} bytes for SHA-256, {} bytes for LowMC L1.",
        sha_estimate.bytes_per_repetition, l1_estimate.bytes_per_repetition
    );
    println!();

    let input = pad_message(b"abc");
    let start = Instant::now();
    let iterations = 20;
    for _ in 0..iterations {
        let _ = sha.evaluate(&input).unwrap();
    }
    let per_eval = start.elapsed() / iterations;
    println!("Rough timings (single sample, unoptimised build settings apply):");
    println!("  SHA-256 circuit build:      {sha_build:?}");
    println!("  SHA-256 circuit evaluation: {per_eval:?}");
    println!("  LowMC L1 circuit build:     {l1_build:?}");
    println!();
    println!("This is the number Phase 2 and Phase 3 have to beat.");
    println!();
}
