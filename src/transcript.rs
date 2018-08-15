//! Defines a `TranscriptProtocol` trait for using a Merlin transcript.

use byteorder::{ByteOrder, LittleEndian};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

pub trait TranscriptProtocol {
    fn commit_u64(&mut self, value: u64);
    fn commit_scalar(&mut self, scalar: &Scalar);
    fn commit_point(&mut self, point: &CompressedRistretto);
    fn challenge_scalar(&mut self) -> Scalar;
}

impl TranscriptProtocol for Transcript {
    fn commit_u64(&mut self, value: u64) {
        let mut value_bytes = [0u8; 8];
        LittleEndian::write_u64(&mut value_bytes, value);
        self.commit(b"u64", &value_bytes);
    }

    fn commit_scalar(&mut self, scalar: &Scalar) {
        self.commit(b"sc", scalar.as_bytes());
    }

    fn commit_point(&mut self, point: &CompressedRistretto) {
        self.commit(b"pt", point.as_bytes());
    }

    fn challenge_scalar(&mut self) -> Scalar {
        let mut buf = [0u8; 64];
        self.challenge(b"sc", &mut buf);

        Scalar::from_bytes_mod_order_wide(&buf)
    }
}
