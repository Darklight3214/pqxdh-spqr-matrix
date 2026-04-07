// Copyright 2024 PQXDH Contributors
// Signal-compatible Sparse Post-Quantum Ratchet (SPQR) for Matrix
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//! Sparse Post-Quantum Ratchet (SPQR) module.
//!
//! Implements a Signal-compatible post-quantum ratchet that runs in parallel
//! with the classical DH Double Ratchet, forming a "Triple Ratchet."
//!
//! This module uses the same cryptographic patterns as Signal's SPQR
//! (ML-KEM Braid with incremental ML-KEM-768, epoch-based symmetric chain,
//! MAC authentication) but transports its protocol messages over Matrix events.
//!
//! ## Architecture
//!
//! The SPQR operates as a parallel ratchet alongside the DH Double Ratchet:
//!
//! ```text
//! final_message_key = KDF(dr_message_key || spqr_message_key)
//! ```
//!
//! Both ratchets must be compromised to break message encryption.

#![allow(unreachable_pub)]

pub mod authenticator;
pub mod braid;
pub mod chain;
pub mod incremental_mlkem768;

use serde::{Deserialize, Serialize};

pub use braid::{BraidMessage, BraidRole, BraidState, EpochSecret};
pub use chain::{Chain, ChainError};

/// SPQR configuration parameters.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SpqrConfig {
    /// Maximum out-of-order keys to store per epoch direction.
    pub max_ooo_keys: u32,
    /// Maximum forward jump in message counter.
    pub max_jump: u32,
}

impl Default for SpqrConfig {
    fn default() -> Self {
        Self {
            max_ooo_keys: 2000,
            max_jump: 25000,
        }
    }
}

/// The top-level SPQR state held by a Session.
///
/// Manages the ML-KEM Braid key exchange and the symmetric chain
/// for deriving per-message encryption keys.
#[derive(Clone, Serialize, Deserialize)]
pub struct SpqrState {
    /// The ML-KEM Braid state machine for PQ key exchange.
    pub braid: BraidState,
    /// The symmetric chain for deriving message keys from epoch secrets.
    pub chain: Chain,
    /// Configuration parameters.
    pub config: SpqrConfig,
    /// Whether SPQR has been initialized (first epoch completed on both sides).
    pub initialized: bool,
    /// Epoch secret from CT-sender's send_ct1(), held until send_ct2() confirms
    /// that the peer can also derive the secret. Stored as (epoch, secret_bytes).
    #[serde(default)]
    pending_epoch_secret: Option<(u64, Vec<u8>)>,
}

impl SpqrState {
    /// Create a new SPQR state. `role` determines who sends the first
    /// key exchange: the session initiator (Alice) sends EK first.
    pub fn new(role: BraidRole, auth_key: &[u8], config: SpqrConfig) -> Self {
        let braid = BraidState::new(role);
        let chain = Chain::new(auth_key, role.into(), config);

        Self {
            braid,
            chain,
            config,
            initialized: false,
            pending_epoch_secret: None,
        }
    }

    /// Called when a new epoch secret is produced by the ML-KEM Braid.
    /// Feeds the secret into the symmetric chain.
    pub fn add_epoch(&mut self, epoch_secret: &EpochSecret) {
        self.chain.add_epoch(epoch_secret);
        self.initialized = true;
    }

    /// Get the current epoch number.
    pub fn current_epoch(&self) -> u64 {
        self.chain.current_epoch()
    }

    /// Get a send key for the current epoch.
    pub fn send_key(&mut self) -> Option<(u64, u32, Vec<u8>)> {
        if !self.initialized {
            return None;
        }
        let epoch = self.chain.current_epoch();
        self.chain.send_key(epoch).ok().map(|(idx, key)| (epoch, idx, key))
    }

    /// Get a receive key for the given epoch and index.
    pub fn recv_key(&mut self, epoch: u64, index: u32) -> Result<Vec<u8>, ChainError> {
        self.chain.recv_key(epoch, index)
    }

    /// Store an epoch secret from CT-sender's send_ct1() without activating it.
    /// It will be activated when confirm_pending_epoch() is called after send_ct2().
    pub fn defer_epoch(&mut self, epoch_secret: &EpochSecret) {
        self.pending_epoch_secret = Some((epoch_secret.epoch, epoch_secret.secret.clone()));
    }

    /// Activate the pending epoch secret (called after send_ct2 completes).
    /// This is the point at which the peer is also guaranteed to be able to
    /// derive the same epoch secret (via recv_ct2).
    pub fn confirm_pending_epoch(&mut self) {
        if let Some((epoch, secret)) = self.pending_epoch_secret.take() {
            let es = EpochSecret { epoch, secret };
            self.add_epoch(&es);
        }
    }
}

/// Combine a DH ratchet message key with an SPQR message key
/// to produce the final message encryption key.
///
/// ```text
/// final_key = HKDF(salt=spqr_key, ikm=dr_key, info="SPQR_COMBINE") → 32 bytes
/// ```
pub fn combine_keys(dr_key: &[u8; 32], spqr_key: &[u8]) -> Box<[u8; 32]> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let hkdf: Hkdf<Sha256> = Hkdf::new(Some(spqr_key), dr_key);
    let mut combined = Box::new([0u8; 32]);

    #[allow(clippy::expect_used)]
    hkdf.expand(b"SPQR_COMBINE", combined.as_mut())
        .expect("HKDF expand failed");

    combined
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn combine_keys_deterministic() {
        let dr_key = [1u8; 32];
        let spqr_key = [2u8; 32];
        let k1 = combine_keys(&dr_key, &spqr_key);
        let k2 = combine_keys(&dr_key, &spqr_key);
        assert_eq!(k1, k2);
    }

    #[test]
    fn combine_keys_differs_with_different_inputs() {
        let dr_key = [1u8; 32];
        let spqr_key_a = [2u8; 32];
        let spqr_key_b = [3u8; 32];
        let k1 = combine_keys(&dr_key, &spqr_key_a);
        let k2 = combine_keys(&dr_key, &spqr_key_b);
        assert_ne!(k1, k2);
    }

    #[test]
    fn spqr_state_new() {
        let state = SpqrState::new(BraidRole::Initiator, &[0u8; 32], SpqrConfig::default());
        assert!(!state.initialized);
        assert_eq!(state.current_epoch(), 0);
    }
}
