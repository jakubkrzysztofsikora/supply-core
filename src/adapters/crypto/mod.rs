use crate::ports::Hasher;
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use sha2::{Digest, Sha512};
use std::io::{self, Read};

pub struct ShaHasher;

struct NpmIntegrityReader {
    reader: Box<dyn Read + Send>,
    expected: [u8; 64],
    hasher: Sha512,
    finished: bool,
}

impl Read for NpmIntegrityReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.finished || buffer.is_empty() {
            return Ok(0);
        }
        let count = self.reader.read(buffer)?;
        if count != 0 {
            self.hasher.update(&buffer[..count]);
            return Ok(count);
        }
        self.finished = true;
        if self.hasher.clone().finalize()[..] != self.expected[..] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "npm integrity mismatch",
            ));
        }
        Ok(0)
    }
}

impl Hasher for ShaHasher {
    fn verified_npm_reader(
        &self,
        reader: Box<dyn Read + Send>,
        integrity: &str,
    ) -> Result<Box<dyn Read + Send>> {
        let encoded = integrity
            .strip_prefix("sha512-")
            .ok_or_else(|| anyhow!("unsupported npm integrity algorithm"))?;
        let expected: [u8; 64] = STANDARD
            .decode(encoded)?
            .try_into()
            .map_err(|_| anyhow!("invalid npm integrity digest"))?;
        Ok(Box::new(NpmIntegrityReader {
            reader,
            expected,
            hasher: Sha512::new(),
            finished: false,
        }))
    }
}
