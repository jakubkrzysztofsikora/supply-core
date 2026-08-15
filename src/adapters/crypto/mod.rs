use crate::ports::Hasher;
use base64::{engine::general_purpose::STANDARD, Engine};
use sha2::{Digest, Sha256, Sha512};
pub struct ShaHasher;
impl Hasher for ShaHasher {
    fn sha256(&self, bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }
    fn verify_npm_integrity(&self, bytes: &[u8], integrity: &str) -> bool {
        if let Some(b64) = integrity.strip_prefix("sha512-") {
            STANDARD
                .decode(b64)
                .map(|e| e == Sha512::digest(bytes).as_slice())
                .unwrap_or(false)
        } else {
            false
        }
    }
}
