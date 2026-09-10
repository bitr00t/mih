//! Canonical byte encoding.
//!
//! Proofs get hashed. That means the encoding has to be canonical: one value,
//! one byte string, no exceptions. If two encodings of the same proof exist, the
//! Fiat-Shamir challenge is no longer a function of the proof, and malleability
//! follows. So the decoder is strict by construction, rejects trailing bytes,
//! and every variable-length field carries an explicit length.
//!
//! This is deliberately not serde. Deriving an encoding hides exactly the
//! decisions that matter here, and a proof format is small enough to write out
//! by hand.

use core::fmt;

/// Why decoding failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodecError {
    /// The input ended before the requested field did.
    UnexpectedEnd { needed: usize, available: usize },
    /// A length prefix exceeded the caller-supplied bound.
    LengthLimitExceeded { limit: usize, got: usize },
    /// Decoding finished with bytes left over.
    TrailingBytes { remaining: usize },
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CodecError::UnexpectedEnd { needed, available } => {
                write!(f, "unexpected end of input: needed {needed}, had {available}")
            }
            CodecError::LengthLimitExceeded { limit, got } => {
                write!(f, "length {got} exceeds the limit of {limit}")
            }
            CodecError::TrailingBytes { remaining } => {
                write!(f, "{remaining} trailing bytes after decoding")
            }
        }
    }
}

/// Append-only byte encoder. All integers are little-endian.
#[derive(Clone, Debug, Default)]
pub struct Encoder {
    buf: Vec<u8>,
}

impl Encoder {
    pub fn new() -> Self {
        Encoder { buf: Vec::new() }
    }

    pub fn write_u8(&mut self, value: u8) {
        self.buf.push(value);
    }

    pub fn write_u32(&mut self, value: u32) {
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    pub fn write_u64(&mut self, value: u64) {
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    /// A fixed-length field. The length is part of the format, not the data, so
    /// nothing is prefixed.
    pub fn write_fixed(&mut self, value: &[u8]) {
        self.buf.extend_from_slice(value);
    }

    /// A variable-length byte string, length-prefixed.
    pub fn write_bytes(&mut self, value: &[u8]) {
        self.write_u64(value.len() as u64);
        self.buf.extend_from_slice(value);
    }

    /// A bit string, length-prefixed in bits and packed LSB-first.
    ///
    /// Padding bits in the final byte are written as zero. The decoder checks
    /// this: a non-zero pad would give a second encoding of the same value.
    pub fn write_bits(&mut self, bits: &[bool]) {
        self.write_u64(bits.len() as u64);
        self.buf.extend_from_slice(&crate::transcript::pack_bits(bits));
    }

    pub fn finish(self) -> Vec<u8> {
        self.buf
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

/// Strict decoder over a byte slice.
#[derive(Clone, Debug)]
pub struct Decoder<'a> {
    buf: &'a [u8],
    position: usize,
}

impl<'a> Decoder<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Decoder { buf, position: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], CodecError> {
        let available = self.buf.len() - self.position;
        if available < n {
            return Err(CodecError::UnexpectedEnd {
                needed: n,
                available,
            });
        }
        let slice = &self.buf[self.position..self.position + n];
        self.position += n;
        Ok(slice)
    }

    pub fn read_u8(&mut self) -> Result<u8, CodecError> {
        Ok(self.take(1)?[0])
    }

    pub fn read_u32(&mut self) -> Result<u32, CodecError> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub fn read_u64(&mut self) -> Result<u64, CodecError> {
        let bytes = self.take(8)?;
        let mut array = [0u8; 8];
        array.copy_from_slice(bytes);
        Ok(u64::from_le_bytes(array))
    }

    pub fn read_fixed<const N: usize>(&mut self) -> Result<[u8; N], CodecError> {
        let bytes = self.take(N)?;
        let mut array = [0u8; N];
        array.copy_from_slice(bytes);
        Ok(array)
    }

    /// Read a length-prefixed byte string, refusing anything above `limit`.
    ///
    /// The limit is not optional. A decoder that allocates whatever a length
    /// prefix asks for is a denial-of-service primitive, and proof formats have
    /// known bounds anyway.
    pub fn read_bytes(&mut self, limit: usize) -> Result<&'a [u8], CodecError> {
        let len = self.read_u64()? as usize;
        if len > limit {
            return Err(CodecError::LengthLimitExceeded { limit, got: len });
        }
        self.take(len)
    }

    /// Read a length-prefixed bit string, rejecting non-zero padding bits.
    pub fn read_bits(&mut self, limit: usize) -> Result<Vec<bool>, CodecError> {
        let len = self.read_u64()? as usize;
        if len > limit {
            return Err(CodecError::LengthLimitExceeded { limit, got: len });
        }
        let bytes = self.take((len + 7) / 8)?;
        if len % 8 != 0 {
            let pad_mask = 0xffu8 << (len % 8);
            if bytes[bytes.len() - 1] & pad_mask != 0 {
                // Non-canonical: two byte strings would decode to one value.
                return Err(CodecError::TrailingBytes { remaining: 1 });
            }
        }
        Ok(crate::transcript::unpack_bits(bytes, len))
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.position
    }

    /// Assert that the input has been fully consumed.
    pub fn finish(self) -> Result<(), CodecError> {
        if self.remaining() != 0 {
            Err(CodecError::TrailingBytes {
                remaining: self.remaining(),
            })
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_of_every_field_kind() {
        let bits = vec![true, false, true, true, false, false, false, true, true];
        let mut enc = Encoder::new();
        enc.write_u8(0xab);
        enc.write_u32(0xdead_beef);
        enc.write_u64(u64::MAX - 1);
        enc.write_fixed(&[9u8; 32]);
        enc.write_bytes(b"a view");
        enc.write_bits(&bits);
        let encoded = enc.finish();

        let mut dec = Decoder::new(&encoded);
        assert_eq!(dec.read_u8().unwrap(), 0xab);
        assert_eq!(dec.read_u32().unwrap(), 0xdead_beef);
        assert_eq!(dec.read_u64().unwrap(), u64::MAX - 1);
        assert_eq!(dec.read_fixed::<32>().unwrap(), [9u8; 32]);
        assert_eq!(dec.read_bytes(1024).unwrap(), b"a view");
        assert_eq!(dec.read_bits(1024).unwrap(), bits);
        dec.finish().unwrap();
    }

    #[test]
    fn empty_bit_string_round_trips() {
        let mut enc = Encoder::new();
        enc.write_bits(&[]);
        let encoded = enc.finish();
        let mut dec = Decoder::new(&encoded);
        assert_eq!(dec.read_bits(16).unwrap(), Vec::<bool>::new());
        dec.finish().unwrap();
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut enc = Encoder::new();
        enc.write_u32(7);
        let mut encoded = enc.finish();
        encoded.push(0);
        let mut dec = Decoder::new(&encoded);
        assert_eq!(dec.read_u32().unwrap(), 7);
        assert_eq!(dec.finish(), Err(CodecError::TrailingBytes { remaining: 1 }));
    }

    #[test]
    fn truncated_input_is_rejected() {
        let mut enc = Encoder::new();
        enc.write_bytes(b"12345678");
        let encoded = enc.finish();
        let mut dec = Decoder::new(&encoded[..encoded.len() - 3]);
        assert!(matches!(
            dec.read_bytes(1024),
            Err(CodecError::UnexpectedEnd { .. })
        ));
    }

    #[test]
    fn oversized_length_prefix_is_rejected_before_allocating() {
        let mut enc = Encoder::new();
        enc.write_u64(u64::MAX);
        let encoded = enc.finish();
        let mut dec = Decoder::new(&encoded);
        assert!(matches!(
            dec.read_bytes(64),
            Err(CodecError::LengthLimitExceeded { limit: 64, .. })
        ));
    }

    #[test]
    fn non_canonical_bit_padding_is_rejected() {
        let mut enc = Encoder::new();
        enc.write_bits(&[true, false, true]);
        let mut encoded = enc.finish();
        // Flip a padding bit: same three data bits, different bytes.
        let last = encoded.len() - 1;
        encoded[last] |= 0b1000_0000;
        let mut dec = Decoder::new(&encoded);
        assert!(dec.read_bits(64).is_err());
    }
}
