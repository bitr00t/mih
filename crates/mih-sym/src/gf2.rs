//! Dense binary matrices.
//!
//! LowMC needs a lot of these: one `n x n` invertible linear layer per round and
//! one `n x k` key-schedule matrix per round plus one for the whitening. They
//! are generated once per instance, are public, and are the same for prover and
//! verifier, so the only real requirements are reproducibility and, for the
//! linear layers, invertibility.

use rand_chacha::rand_core::RngCore;

/// A dense matrix over GF(2), stored row-major as bit-packed words.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BitMatrix {
    rows: usize,
    cols: usize,
    /// One bitset per row; bit `c` of row `r` is entry `(r, c)`.
    data: Vec<Vec<u64>>,
}

fn words_for(bits: usize) -> usize {
    (bits + 63) / 64
}

impl BitMatrix {
    pub fn zero(rows: usize, cols: usize) -> Self {
        BitMatrix {
            rows,
            cols,
            data: vec![vec![0u64; words_for(cols)]; rows],
        }
    }

    pub fn identity(n: usize) -> Self {
        let mut m = Self::zero(n, n);
        for i in 0..n {
            m.set(i, i, true);
        }
        m
    }

    /// Fill with bits drawn from `rng`.
    pub fn random<R: RngCore>(rows: usize, cols: usize, rng: &mut R) -> Self {
        let mut m = Self::zero(rows, cols);
        let mut bytes = vec![0u8; (cols + 7) / 8];
        for r in 0..rows {
            rng.fill_bytes(&mut bytes);
            for c in 0..cols {
                if (bytes[c / 8] >> (c % 8)) & 1 == 1 {
                    m.set(r, c, true);
                }
            }
        }
        m
    }

    /// Draw random `n x n` matrices until one is invertible.
    ///
    /// A random binary matrix is invertible with probability around 0.289 for
    /// any appreciable `n`, so this terminates quickly. It is bounded anyway,
    /// because an unbounded retry loop in instance generation is the kind of
    /// thing that hangs a test suite at three in the morning.
    pub fn random_invertible<R: RngCore>(n: usize, rng: &mut R) -> Self {
        for _ in 0..256 {
            let candidate = Self::random(n, n, rng);
            if candidate.rank() == n {
                return candidate;
            }
        }
        panic!("failed to draw an invertible {n}x{n} matrix in 256 attempts");
    }

    pub fn rows(&self) -> usize {
        self.rows
    }

    pub fn cols(&self) -> usize {
        self.cols
    }

    pub fn get(&self, row: usize, col: usize) -> bool {
        (self.data[row][col / 64] >> (col % 64)) & 1 == 1
    }

    pub fn set(&mut self, row: usize, col: usize, value: bool) {
        let word = &mut self.data[row][col / 64];
        let mask = 1u64 << (col % 64);
        if value {
            *word |= mask;
        } else {
            *word &= !mask;
        }
    }

    /// Indices of the set entries in a row, which is the list of vector
    /// components that feed into that output bit.
    pub fn row_support(&self, row: usize) -> Vec<usize> {
        (0..self.cols).filter(|&c| self.get(row, c)).collect()
    }

    /// Matrix-vector product over GF(2).
    pub fn mul_vec(&self, v: &[bool]) -> Vec<bool> {
        assert_eq!(v.len(), self.cols, "dimension mismatch");
        (0..self.rows)
            .map(|r| {
                (0..self.cols)
                    .filter(|&c| self.get(r, c))
                    .fold(false, |acc, c| acc ^ v[c])
            })
            .collect()
    }

    /// Rank over GF(2) by Gaussian elimination on a copy.
    pub fn rank(&self) -> usize {
        let mut rows = self.data.clone();
        let width = words_for(self.cols);
        let mut rank = 0usize;
        for col in 0..self.cols {
            let word = col / 64;
            let mask = 1u64 << (col % 64);
            let pivot = (rank..self.rows).find(|&r| rows[r][word] & mask != 0);
            let Some(pivot) = pivot else { continue };
            rows.swap(rank, pivot);
            for r in 0..self.rows {
                if r != rank && rows[r][word] & mask != 0 {
                    for w in 0..width {
                        rows[r][w] ^= rows[rank][w];
                    }
                }
            }
            rank += 1;
            if rank == self.rows {
                break;
            }
        }
        rank
    }

    pub fn is_invertible(&self) -> bool {
        self.rows == self.cols && self.rank() == self.rows
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn identity_has_full_rank_and_acts_as_identity() {
        let m = BitMatrix::identity(64);
        assert_eq!(m.rank(), 64);
        assert!(m.is_invertible());
        let v: Vec<bool> = (0..64).map(|i| i % 5 == 0).collect();
        assert_eq!(m.mul_vec(&v), v);
    }

    #[test]
    fn zero_matrix_has_rank_zero() {
        assert_eq!(BitMatrix::zero(32, 32).rank(), 0);
    }

    #[test]
    fn a_repeated_row_reduces_the_rank() {
        let mut m = BitMatrix::identity(8);
        // Make row 3 equal to row 2.
        m.set(3, 3, false);
        m.set(3, 2, true);
        assert_eq!(m.rank(), 7);
        assert!(!m.is_invertible());
    }

    #[test]
    fn generation_is_reproducible_from_a_seed() {
        let a = BitMatrix::random_invertible(128, &mut ChaCha20Rng::from_seed([5; 32]));
        let b = BitMatrix::random_invertible(128, &mut ChaCha20Rng::from_seed([5; 32]));
        assert_eq!(a, b);
    }

    #[test]
    fn random_invertible_matrices_really_are_invertible() {
        let mut rng = ChaCha20Rng::from_seed([11; 32]);
        for n in [8usize, 32, 128] {
            for _ in 0..4 {
                assert!(BitMatrix::random_invertible(n, &mut rng).is_invertible());
            }
        }
    }

    #[test]
    fn mul_vec_is_linear() {
        let mut rng = ChaCha20Rng::from_seed([13; 32]);
        let m = BitMatrix::random(37, 53, &mut rng);
        let x: Vec<bool> = (0..53).map(|i| i % 3 == 0).collect();
        let y: Vec<bool> = (0..53).map(|i| i % 7 < 3).collect();
        let sum: Vec<bool> = x.iter().zip(&y).map(|(a, b)| a ^ b).collect();
        let expected: Vec<bool> = m
            .mul_vec(&x)
            .iter()
            .zip(m.mul_vec(&y))
            .map(|(a, b)| a ^ b)
            .collect();
        assert_eq!(m.mul_vec(&sum), expected);
    }

    #[test]
    fn row_support_agrees_with_get() {
        let mut rng = ChaCha20Rng::from_seed([23; 32]);
        let m = BitMatrix::random(16, 100, &mut rng);
        for r in 0..16 {
            let support = m.row_support(r);
            for c in 0..100 {
                assert_eq!(support.contains(&c), m.get(r, c));
            }
        }
    }
}
