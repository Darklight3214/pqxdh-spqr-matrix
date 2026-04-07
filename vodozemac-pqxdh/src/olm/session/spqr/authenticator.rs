// Copyright 2024 PQXDH Contributors
// MAC-based authenticator for ML-KEM Braid protocol messages.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//! Authenticator for ML-KEM Braid protocol messages.
//!
//! Provides MAC-based authentication on:
//! - Encapsulation key (EK/header) messages
//! - Ciphertext (CT) messages
//!
//! The authenticator key evolves each epoch by incorporating the epoch
//! secret, providing forward secrecy for authentication.
//!
//! Matches Signal's `authenticator.rs` construction.

use hmac::{Hmac, Mac as HmacMac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

type HmacSha256 = Hmac<Sha256>;

/// Size of MAC output in bytes.
#[allow(dead_code)]
pub const MAC_SIZE: usize = 32;

/// A MAC tag.
#[allow(dead_code)]
pub type MacTag = Vec<u8>;

/// Error type for authentication failures.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// MAC verification failed.
    #[error("MAC verification failed")]
    InvalidMac,
}

/// Authenticator with evolving key for Braid protocol messages.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Authenticator {
    /// Current authentication key (evolves each epoch).
    #[serde(with = "serde_bytes")]
    key: Vec<u8>,
}

impl Authenticator {
    /// Create a new Authenticator with an initial key.
    /// The initial key is derived from the PQXDH session setup.
    pub fn new() -> Self {
        // Initial key is all zeros until the first epoch update.
        Self {
            key: vec![0u8; 32],
        }
    }

    /// Create an authenticator with a specific initial key.
    #[allow(dead_code)]
    pub fn with_key(key: &[u8]) -> Self {
        Self {
            key: key.to_vec(),
        }
    }

    /// Update the authenticator key with the new epoch secret.
    ///
    /// ```text
    /// new_key = HMAC-SHA256(old_key, epoch_be || secret || "SPQR_AUTH_UPDATE")
    /// ```
    pub fn update(&mut self, epoch: u64, secret: &[u8]) {
        let mut mac = HmacSha256::new_from_slice(&self.key)
            .expect("HMAC key can be any size");
        mac.update(&epoch.to_be_bytes());
        mac.update(secret);
        mac.update(b"SPQR_AUTH_UPDATE");
        let result = mac.finalize();
        self.key = result.into_bytes().to_vec();
    }

    /// Compute MAC over an encapsulation key (EK/header) message.
    ///
    /// ```text
    /// mac = HMAC-SHA256(auth_key, epoch_be || "EK" || ek_bytes)
    /// ```
    pub fn mac_ek(&self, epoch: u64, ek_bytes: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(&self.key)
            .expect("HMAC key can be any size");
        mac.update(&epoch.to_be_bytes());
        mac.update(b"EK");
        mac.update(ek_bytes);
        mac.finalize().into_bytes().to_vec()
    }

    /// Verify MAC on an encapsulation key (EK/header) message.
    pub fn verify_ek(&self, epoch: u64, ek_bytes: &[u8], mac_bytes: &[u8]) -> Result<(), AuthError> {
        let expected = self.mac_ek(epoch, ek_bytes);
        if constant_time_eq(&expected, mac_bytes) {
            Ok(())
        } else {
            Err(AuthError::InvalidMac)
        }
    }

    /// Compute MAC over a ciphertext (CT) message.
    ///
    /// ```text
    /// mac = HMAC-SHA256(auth_key, epoch_be || "CT" || ct_bytes)
    /// ```
    pub fn mac_ct(&self, epoch: u64, ct_bytes: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(&self.key)
            .expect("HMAC key can be any size");
        mac.update(&epoch.to_be_bytes());
        mac.update(b"CT");
        mac.update(ct_bytes);
        mac.finalize().into_bytes().to_vec()
    }

    /// Verify MAC on a ciphertext (CT) message.
    pub fn verify_ct(&self, epoch: u64, ct_bytes: &[u8], mac_bytes: &[u8]) -> Result<(), AuthError> {
        let expected = self.mac_ct(epoch, ct_bytes);
        if constant_time_eq(&expected, mac_bytes) {
            Ok(())
        } else {
            Err(AuthError::InvalidMac)
        }
    }
}

/// Constant-time comparison to avoid timing attacks.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn mac_ek_roundtrip() {
        let auth = Authenticator::with_key(&[1u8; 32]);
        let ek = vec![2u8; 1184];
        let mac = auth.mac_ek(1, &ek);
        assert!(auth.verify_ek(1, &ek, &mac).is_ok());
    }

    #[test]
    fn mac_ct_roundtrip() {
        let auth = Authenticator::with_key(&[1u8; 32]);
        let ct = vec![3u8; 1088];
        let mac = auth.mac_ct(1, &ct);
        assert!(auth.verify_ct(1, &ct, &mac).is_ok());
    }

    #[test]
    fn mac_fails_with_wrong_data() {
        let auth = Authenticator::with_key(&[1u8; 32]);
        let ek = vec![2u8; 1184];
        let mac = auth.mac_ek(1, &ek);
        // Change one byte
        let mut bad_ek = ek.clone();
        bad_ek[0] = 0xFF;
        assert!(auth.verify_ek(1, &bad_ek, &mac).is_err());
    }

    #[test]
    fn mac_fails_with_wrong_epoch() {
        let auth = Authenticator::with_key(&[1u8; 32]);
        let ek = vec![2u8; 1184];
        let mac = auth.mac_ek(1, &ek);
        assert!(auth.verify_ek(2, &ek, &mac).is_err());
    }

    #[test]
    fn key_evolves_after_update() {
        let mut auth = Authenticator::with_key(&[1u8; 32]);
        let ek = vec![2u8; 1184];
        let mac_before = auth.mac_ek(1, &ek);
        auth.update(1, &[42u8; 32]);
        let mac_after = auth.mac_ek(1, &ek);
        assert_ne!(mac_before, mac_after);
    }
}
