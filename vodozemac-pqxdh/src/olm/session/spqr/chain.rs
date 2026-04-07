// Copyright 2024 PQXDH Contributors
// Epoch-based symmetric chain — matching Signal's chain.rs
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//! Epoch-based symmetric chain for SPQR.
//!
//! Each epoch (produced by an ML-KEM Braid round) creates send/recv
//! chain directions. Per-message keys are derived from the chain state
//! using labeled HKDF, matching Signal's construction:
//!
//! ```text
//! Chain Start:   HKDF(salt=[0;32], ikm=initial_key, info="Signal PQ Ratchet V1 Chain  Start") → 96 bytes
//!   [0..32]  = next_root
//!   [32..64] = A2B chain key
//!   [64..96] = B2A chain key
//!
//! Chain Next:    HKDF(salt=[0;32], ikm=chain_state, info=ctr_be||"Signal PQ Ratchet V1 Chain Next") → 64 bytes
//!   [0..32]  = next chain state
//!   [32..64] = message key
//!
//! Add Epoch:     HKDF(salt=next_root, ikm=epoch_secret, info="Signal PQ Ratchet V1 Chain Add Epoch") → 96 bytes
//! ```

use std::collections::HashMap;

use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroize;

use super::braid::EpochSecret;
use super::SpqrConfig;

/// Direction of communication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    /// Alice-to-Bob
    A2B,
    /// Bob-to-Alice
    B2A,
}

impl Direction {
    fn switch(self) -> Self {
        match self {
            Direction::A2B => Direction::B2A,
            Direction::B2A => Direction::A2B,
        }
    }
}

impl From<super::braid::BraidRole> for Direction {
    fn from(role: super::braid::BraidRole) -> Self {
        match role {
            super::braid::BraidRole::Initiator => Direction::A2B,
            super::braid::BraidRole::Responder => Direction::B2A,
        }
    }
}

/// Per-epoch per-direction chain state.
#[derive(Clone, Serialize, Deserialize)]
struct ChainEpochDirection {
    /// Message counter for this direction in this epoch.
    ctr: u32,
    /// Current chain state (consumed to derive next key).
    #[serde(with = "serde_bytes")]
    next: Vec<u8>,
    /// Stored out-of-order keys: (index → key).
    stored_keys: HashMap<u32, Vec<u8>>,
}

impl ChainEpochDirection {
    fn new(key: &[u8]) -> Self {
        Self {
            ctr: 0,
            next: key.to_vec(),
            stored_keys: HashMap::new(),
        }
    }

    /// Derive the next message key, advancing the chain.
    fn next_key(&mut self) -> (u32, Vec<u8>) {
        self.ctr += 1;
        let mut genr8r = [0u8; 64];
        let info = [
            self.ctr.to_be_bytes().as_slice(),
            b"Signal PQ Ratchet V1 Chain Next",
        ]
        .concat();
        hkdf_expand(&[0u8; 32], &self.next, &info, &mut genr8r);
        self.next = genr8r[..32].to_vec();
        let key = genr8r[32..64].to_vec();
        genr8r.zeroize();
        (self.ctr, key)
    }

    /// Get a key at a specific index.
    /// If it's the next key, derive it.
    /// If it's a past key, look it up in storage.
    /// If it's a future key, fast-forward and store skipped keys.
    fn key_at(
        &mut self,
        at: u32,
        config: &SpqrConfig,
    ) -> Result<Vec<u8>, ChainError> {
        if at < self.ctr {
            // Past key — look up in stored keys
            self.stored_keys
                .remove(&at)
                .ok_or(ChainError::KeyAlreadyUsed(at))
        } else if at == self.ctr {
            // Current counter — already consumed this key
            Err(ChainError::KeyAlreadyUsed(at))
        } else {
            // Future key — fast-forward
            if at - self.ctr > config.max_jump {
                return Err(ChainError::JumpTooLarge {
                    from: self.ctr,
                    to: at,
                    max: config.max_jump,
                });
            }

            // Store intermediate keys (up to max_ooo_keys)
            while self.ctr + 1 < at {
                let (idx, key) = self.next_key();
                if self.stored_keys.len() < config.max_ooo_keys as usize {
                    self.stored_keys.insert(idx, key);
                }
                // GC: remove keys that are too old
                if self.stored_keys.len() > config.max_ooo_keys as usize {
                    let oldest = *self.stored_keys.keys().min().unwrap_or(&0);
                    self.stored_keys.remove(&oldest);
                }
            }

            // Now derive the target key
            let (_, key) = self.next_key();
            Ok(key)
        }
    }
}

/// A single epoch in the chain, with send and receive directions.
#[derive(Clone, Serialize, Deserialize)]
struct ChainEpoch {
    send: ChainEpochDirection,
    recv: ChainEpochDirection,
}

/// The symmetric chain for SPQR.
///
/// Manages epoch-based key derivation for message encryption/decryption.
#[derive(Clone, Serialize, Deserialize)]
pub struct Chain {
    /// Our direction (A2B or B2A).
    dir: Direction,
    /// Current epoch number (0 = initial, first real epoch = 1).
    current_epoch: u64,
    /// Epoch at which we last sent a message.
    send_epoch: u64,
    /// The chain epochs (recent history).
    epochs: Vec<ChainEpoch>,
    /// Root key for deriving next epoch's chain keys.
    #[serde(with = "serde_bytes")]
    next_root: Vec<u8>,
    /// Configuration parameters.
    config: SpqrConfig,
}

impl Chain {
    /// Create a new chain from an initial key.
    pub fn new(initial_key: &[u8], dir: Direction, config: SpqrConfig) -> Self {
        let mut genr8r = [0u8; 96];
        hkdf_expand(
            &[0u8; 32],
            initial_key,
            b"Signal PQ Ratchet V1 Chain  Start",
            &mut genr8r,
        );

        let epoch = ChainEpoch {
            send: Self::ced_for_direction(&genr8r, &dir),
            recv: Self::ced_for_direction(&genr8r, &dir.switch()),
        };

        let next_root = genr8r[0..32].to_vec();
        genr8r.zeroize();

        Self {
            dir,
            current_epoch: 0,
            send_epoch: 0,
            epochs: vec![epoch],
            next_root,
            config,
        }
    }

    fn ced_for_direction(genr8r: &[u8], dir: &Direction) -> ChainEpochDirection {
        ChainEpochDirection::new(match dir {
            Direction::A2B => &genr8r[32..64],
            Direction::B2A => &genr8r[64..96],
        })
    }

    /// Add a new epoch from a Braid round's epoch secret.
    pub fn add_epoch(&mut self, epoch_secret: &EpochSecret) {
        assert!(epoch_secret.epoch == self.current_epoch + 1);

        let mut genr8r = [0u8; 96];
        hkdf_expand(
            &self.next_root,
            &epoch_secret.secret,
            b"Signal PQ Ratchet V1 Chain Add Epoch",
            &mut genr8r,
        );

        self.current_epoch = epoch_secret.epoch;
        self.next_root = genr8r[0..32].to_vec();
        self.epochs.push(ChainEpoch {
            send: Self::ced_for_direction(&genr8r, &self.dir),
            recv: Self::ced_for_direction(&genr8r, &self.dir.switch()),
        });

        genr8r.zeroize();

        // GC: keep at most 5 old epochs
        const MAX_EPOCHS: usize = 5;
        while self.epochs.len() > MAX_EPOCHS {
            self.epochs.remove(0);
        }
    }

    /// Get the current epoch number.
    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    /// Resolve epoch index in the epochs vector.
    fn epoch_idx(&self, epoch: u64) -> Result<usize, ChainError> {
        if epoch > self.current_epoch {
            return Err(ChainError::EpochOutOfRange(epoch));
        }
        let back = (self.current_epoch - epoch) as usize;
        if back >= self.epochs.len() {
            return Err(ChainError::EpochOutOfRange(epoch));
        }
        Ok(self.epochs.len() - 1 - back)
    }

    /// Get a send key for the given epoch.
    ///
    /// Returns `(message_index, message_key)`.
    pub fn send_key(&mut self, epoch: u64) -> Result<(u32, Vec<u8>), ChainError> {
        let idx = self.epoch_idx(epoch)?;
        if epoch > self.send_epoch {
            self.send_epoch = epoch;
        }
        Ok(self.epochs[idx].send.next_key())
    }

    /// Get a receive key for the given epoch and message index.
    pub fn recv_key(&mut self, epoch: u64, index: u32) -> Result<Vec<u8>, ChainError> {
        let idx = self.epoch_idx(epoch)?;
        self.epochs[idx].recv.key_at(index, &self.config)
    }
}

/// HKDF-SHA256 expand helper.
fn hkdf_expand(salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) {
    let hkdf: Hkdf<Sha256> = Hkdf::new(Some(salt), ikm);
    #[allow(clippy::expect_used)]
    hkdf.expand(info, out).expect("HKDF expand failed");
}

/// Errors from the symmetric chain.
#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    /// Epoch is out of range (too old or too new).
    #[error("Epoch {0} is out of range")]
    EpochOutOfRange(u64),

    /// Key at this index was already used or discarded.
    #[error("Key at index {0} already used or discarded")]
    KeyAlreadyUsed(u32),

    /// Forward jump too large.
    #[error("Jump from {from} to {to} exceeds max {max}")]
    JumpTooLarge { from: u32, to: u32, max: u32 },
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn chain_send_recv_keys_match() {
        let initial_key = [42u8; 32];
        let mut alice_chain = Chain::new(&initial_key, Direction::A2B, SpqrConfig::default());
        let mut bob_chain = Chain::new(&initial_key, Direction::B2A, SpqrConfig::default());

        // Alice sends, Bob receives (epoch 0)
        let (idx, send_key) = alice_chain.send_key(0).unwrap();
        let recv_key = bob_chain.recv_key(0, idx).unwrap();
        assert_eq!(send_key, recv_key);

        // Bob sends, Alice receives (epoch 0)
        let (idx2, send_key2) = bob_chain.send_key(0).unwrap();
        let recv_key2 = alice_chain.recv_key(0, idx2).unwrap();
        assert_eq!(send_key2, recv_key2);

        // Keys should differ
        assert_ne!(send_key, send_key2);
    }

    #[test]
    fn chain_epoch_advance() {
        let initial_key = [42u8; 32];
        let mut chain = Chain::new(&initial_key, Direction::A2B, SpqrConfig::default());

        let epoch_secret = EpochSecret {
            epoch: 1,
            secret: vec![99u8; 32],
        };
        chain.add_epoch(&epoch_secret);
        assert_eq!(chain.current_epoch(), 1);

        let (idx, key1) = chain.send_key(1).unwrap();
        assert_eq!(idx, 1);
        assert_eq!(key1.len(), 32);
    }

    #[test]
    fn chain_out_of_order_keys() {
        let initial_key = [42u8; 32];
        let mut chain = Chain::new(&initial_key, Direction::A2B, SpqrConfig::default());

        // Skip ahead to index 3
        let key3 = chain.recv_key(0, 3).unwrap();
        // Now get key 1 (stored as out-of-order)
        let key1 = chain.recv_key(0, 1).unwrap();
        // Key 2 should also be available
        let key2 = chain.recv_key(0, 2).unwrap();

        // All should be different
        assert_ne!(key1, key2);
        assert_ne!(key2, key3);

        // Key 1 should not be available again
        assert!(chain.recv_key(0, 1).is_err());
    }

    #[test]
    fn chain_jump_too_large() {
        let initial_key = [42u8; 32];
        let config = SpqrConfig {
            max_ooo_keys: 10,
            max_jump: 100,
        };
        let mut chain = Chain::new(&initial_key, Direction::A2B, config);

        // Jump beyond max_jump
        assert!(chain.recv_key(0, 200).is_err());
    }
}
