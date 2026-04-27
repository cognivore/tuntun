//! Secret value type. Wraps bytes with `Zeroize` and a redacted `Debug` impl.

use std::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Opaque secret bytes. `Debug` redacts; `Drop` zeroizes.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretValue {
    inner: Vec<u8>,
}

impl SecretValue {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { inner: bytes }
    }

    pub fn from_string(s: String) -> Self {
        Self {
            inner: s.into_bytes(),
        }
    }

    pub fn expose_bytes(&self) -> &[u8] {
        &self.inner
    }

    pub fn expose_str(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.inner)
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretValue(<redacted, {} bytes>)", self.inner.len())
    }
}

impl PartialEq for SecretValue {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.inner.ct_eq(&other.inner).into()
    }
}

impl Eq for SecretValue {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts() {
        let s = SecretValue::from_string("super-secret".to_string());
        let dbg = format!("{s:?}");
        assert!(!dbg.contains("super-secret"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn equality_constant_time() {
        let a = SecretValue::from_bytes(vec![1, 2, 3]);
        let b = SecretValue::from_bytes(vec![1, 2, 3]);
        let c = SecretValue::from_bytes(vec![1, 2, 4]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
