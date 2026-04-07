// Copyright 2024 PQXDH Contributors
// ML-KEM Braid Protocol — Signal-compatible with incremental ML-KEM-768
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

#![allow(unreachable_pub, missing_docs)]

//! ML-KEM Braid: 2-round interactive key exchange using incremental ML-KEM-768.
//!
//! Matches Signal's architecture exactly:
//!
//! ```text
//! Alice (send_ek side)                    Bob (send_ct side)
//! ─────────────────────                   ────────────────────
//! KeysUnsampled
//!   ↓ generate ML-KEM-768 keypair
//!   ↓ send header(hdr[64], mac) ───────→  NoHeaderReceived
//!                                           ↓ recv_header(hdr, mac)
//! HeaderSent                              HeaderReceived
//!   ↓ send_ek(ek[1152]) ──────────────→    ↓ send_ct1(ct1[960]) + derive secret
//! EkSent                                  Ct1Sent
//!   ↓ recv_ct1(ct1)                        ↓ recv_ek(ek)
//! EkSentCt1Received                       Ct1SentEkReceived
//!   ↓ recv_ct2(ct2[128], mac)              ↓ send_ct2(ct2[128], mac)
//!     + derive secret
//!   → NoHeaderReceived (next epoch)       Ct2Sent
//!                                           → KeysUnsampled (next epoch)
//! ```
//!
//! Each completed round produces an `EpochSecret` fed into the symmetric chain.

use rand::{Rng, rngs::OsRng};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::authenticator::{AuthError, Authenticator};
use super::incremental_mlkem768::{self, CIPHERTEXT1_SIZE, CIPHERTEXT2_SIZE, HEADER_SIZE};

/// Epoch counter type.
pub type Epoch = u64;

/// Which role this side plays in the Braid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BraidRole {
    /// Session initiator — starts as EK sender (KeysUnsampled)
    Initiator,
    /// Session responder — starts as CT sender (NoHeaderReceived)
    Responder,
}

/// The epoch secret produced by a successful ML-KEM Braid round.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EpochSecret {
    /// The epoch number this secret belongs to.
    #[zeroize(skip)]
    pub epoch: Epoch,
    /// The 32-byte shared secret derived from KEM + HKDF.
    pub secret: Vec<u8>,
}

/// Outbound protocol messages carried within Matrix events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BraidMessage {
    /// Header message: first part of public key (64 bytes) + MAC.
    Header {
        epoch: Epoch,
        hdr: Vec<u8>,
        mac: Vec<u8>,
    },
    /// Encapsulation key: second part of public key (1152 bytes).
    EncapsulationKey {
        epoch: Epoch,
        ek: Vec<u8>,
    },
    /// First ciphertext part (960 bytes).
    Ciphertext1 {
        epoch: Epoch,
        ct1: Vec<u8>,
    },
    /// Second ciphertext part (128 bytes) + MAC authenticating ct1||ct2.
    Ciphertext2 {
        epoch: Epoch,
        ct2: Vec<u8>,
        mac: Vec<u8>,
    },
}

// ────────────────────────────────────────────────────────────────────────
// EK-sender side states (Alice on odd epochs, Bob on even epochs)
// ────────────────────────────────────────────────────────────────────────

/// Initial state: ready to generate a fresh keypair.
#[derive(Clone, Serialize, Deserialize)]
pub struct KeysUnsampled {
    pub epoch: Epoch,
    auth: Authenticator,
}

/// Header has been sent; waiting to send EK.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct HeaderSent {
    epoch: Epoch,
    auth: Authenticator,
    #[serde(with = "serde_bytes")]
    ek: Vec<u8>,  // 1152 bytes
    #[serde(with = "serde_bytes")]
    dk: Vec<u8>,  // 2400 bytes
}

/// EK has been sent; waiting for CT1 from peer.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct EkSent {
    epoch: Epoch,
    auth: Authenticator,
    #[serde(with = "serde_bytes")]
    dk: Vec<u8>,  // 2400 bytes
}

/// EK sent and CT1 received; waiting for CT2 from peer.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct EkSentCt1Received {
    epoch: Epoch,
    auth: Authenticator,
    #[serde(with = "serde_bytes")]
    dk: Vec<u8>,   // 2400 bytes
    #[serde(with = "serde_bytes")]
    ct1: Vec<u8>,  // 960 bytes
}

// ────────────────────────────────────────────────────────────────────────
// CT-sender side states (Bob on odd epochs, Alice on even epochs)
// ────────────────────────────────────────────────────────────────────────

/// Initial state: waiting for a header from the peer.
#[derive(Clone, Serialize, Deserialize)]
pub struct NoHeaderReceived {
    pub epoch: Epoch,
    auth: Authenticator,
}

/// Header received; ready to produce CT1.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct HeaderReceived {
    epoch: Epoch,
    auth: Authenticator,
    #[serde(with = "serde_bytes")]
    hdr: Vec<u8>,  // 64 bytes
}

/// CT1 has been sent; waiting for EK from peer.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Ct1Sent {
    epoch: Epoch,
    auth: Authenticator,
    #[serde(with = "serde_bytes")]
    hdr: Vec<u8>,   // 64 bytes
    #[serde(with = "serde_bytes")]
    es: Vec<u8>,    // 2080 bytes (encapsulation state)
    #[serde(with = "serde_bytes")]
    ct1: Vec<u8>,   // 960 bytes
}

/// CT1 sent and EK received; ready to produce CT2.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Ct1SentEkReceived {
    epoch: Epoch,
    auth: Authenticator,
    #[serde(with = "serde_bytes")]
    es: Vec<u8>,   // 2080 bytes
    #[serde(with = "serde_bytes")]
    ek: Vec<u8>,   // 1152 bytes
    #[serde(with = "serde_bytes")]
    ct1: Vec<u8>,  // 960 bytes
}

/// CT2 has been sent; round complete.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Ct2Sent {
    epoch: Epoch,
    auth: Authenticator,
}

// ────────────────────────────────────────────────────────────────────────
// The unified BraidState enum (serializable)
// ────────────────────────────────────────────────────────────────────────

/// The full Braid state machine, encompassing all possible states.
#[derive(Clone, Serialize, Deserialize)]
#[allow(unreachable_pub)]
pub enum BraidState {
    // EK-sender side
    KeysUnsampled(KeysUnsampled),
    HeaderSent(HeaderSent),
    EkSent(EkSent),
    EkSentCt1Received(EkSentCt1Received),

    // CT-sender side
    NoHeaderReceived(NoHeaderReceived),
    HeaderReceived(HeaderReceived),
    Ct1Sent(Ct1Sent),
    Ct1SentEkReceived(Ct1SentEkReceived),
    Ct2Sent(Ct2Sent),
}

impl BraidState {
    /// Create a new Braid. Initiator starts as EK sender; responder waits for header.
    pub fn new(role: BraidRole) -> Self {
        let auth = Authenticator::new();
        match role {
            BraidRole::Initiator => BraidState::KeysUnsampled(KeysUnsampled { epoch: 1, auth }),
            BraidRole::Responder => BraidState::NoHeaderReceived(NoHeaderReceived { epoch: 1, auth }),
        }
    }

    /// Get the current epoch.
    pub fn epoch(&self) -> Epoch {
        match self {
            BraidState::KeysUnsampled(s) => s.epoch,
            BraidState::HeaderSent(s) => s.epoch,
            BraidState::EkSent(s) => s.epoch,
            BraidState::EkSentCt1Received(s) => s.epoch,
            BraidState::NoHeaderReceived(s) => s.epoch,
            BraidState::HeaderReceived(s) => s.epoch,
            BraidState::Ct1Sent(s) => s.epoch,
            BraidState::Ct1SentEkReceived(s) => s.epoch,
            BraidState::Ct2Sent(s) => s.epoch,
        }
    }

    // ──────────── EK-sender side transitions ────────────

    /// [KeysUnsampled → HeaderSent] Generate keypair and send header.
    pub fn send_header(&mut self) -> Result<BraidMessage, BraidError> {
        let state = match self {
            BraidState::KeysUnsampled(s) => s.clone(),
            _ => return Err(BraidError::WrongState("send_header requires KeysUnsampled")),
        };

        let mut rng = OsRng;
        let keys = incremental_mlkem768::generate(&mut rng);

        let mac = state.auth.mac_ek(state.epoch, &keys.hdr);

        let msg = BraidMessage::Header {
            epoch: state.epoch,
            hdr: keys.hdr.clone(),
            mac: mac.clone(),
        };

        *self = BraidState::HeaderSent(HeaderSent {
            epoch: state.epoch,
            auth: state.auth,
            ek: keys.ek,
            dk: keys.dk,
        });

        Ok(msg)
    }

    /// [HeaderSent → EkSent] Send the encapsulation key.
    pub fn send_ek(&mut self) -> Result<BraidMessage, BraidError> {
        let state = match self {
            BraidState::HeaderSent(s) => s.clone(),
            _ => return Err(BraidError::WrongState("send_ek requires HeaderSent")),
        };

        let msg = BraidMessage::EncapsulationKey {
            epoch: state.epoch,
            ek: state.ek.clone(),
        };

        *self = BraidState::EkSent(EkSent {
            epoch: state.epoch,
            auth: state.auth,
            dk: state.dk,
        });

        Ok(msg)
    }

    /// [EkSent → EkSentCt1Received] Receive CT1 from peer.
    pub fn recv_ct1(&mut self, epoch: Epoch, ct1: Vec<u8>) -> Result<(), BraidError> {
        let state = match self {
            BraidState::EkSent(s) => s.clone(),
            _ => return Err(BraidError::WrongState("recv_ct1 requires EkSent")),
        };

        if epoch != state.epoch {
            return Err(BraidError::EpochMismatch { expected: state.epoch, got: epoch });
        }
        if ct1.len() != CIPHERTEXT1_SIZE {
            return Err(BraidError::InvalidData("CT1 wrong size"));
        }

        *self = BraidState::EkSentCt1Received(EkSentCt1Received {
            epoch: state.epoch,
            auth: state.auth,
            dk: state.dk,
            ct1,
        });

        Ok(())
    }

    /// [EkSentCt1Received → NoHeaderReceived] Receive CT2 + MAC, decapsulate.
    ///
    /// Returns the epoch secret on success.
    pub fn recv_ct2(
        &mut self,
        epoch: Epoch,
        ct2: Vec<u8>,
        mac: &[u8],
    ) -> Result<EpochSecret, BraidError> {
        let state = match self {
            BraidState::EkSentCt1Received(s) => s.clone(),
            _ => return Err(BraidError::WrongState("recv_ct2 requires EkSentCt1Received")),
        };

        if epoch != state.epoch {
            return Err(BraidError::EpochMismatch { expected: state.epoch, got: epoch });
        }
        if ct2.len() != CIPHERTEXT2_SIZE {
            return Err(BraidError::InvalidData("CT2 wrong size"));
        }

        // Decapsulate
        let ss = incremental_mlkem768::decaps(&state.dk, &state.ct1, &ct2);

        // Derive epoch secret
        let epoch_secret = derive_epoch_secret(state.epoch, &ss);

        // Update authenticator
        let mut auth = state.auth;
        auth.update(state.epoch, &epoch_secret.secret);

        // Verify MAC on ct1||ct2
        let mut full_ct = state.ct1.clone();
        full_ct.extend_from_slice(&ct2);
        auth.verify_ct(state.epoch, &full_ct, mac)?;

        // Transition to NoHeaderReceived for next epoch (role swap)
        *self = BraidState::NoHeaderReceived(NoHeaderReceived {
            epoch: state.epoch + 1,
            auth,
        });

        Ok(epoch_secret)
    }

    // ──────────── CT-sender side transitions ────────────

    /// [NoHeaderReceived → HeaderReceived] Receive header from peer.
    pub fn recv_header(
        &mut self,
        epoch: Epoch,
        hdr: Vec<u8>,
        mac: &[u8],
    ) -> Result<(), BraidError> {
        let state = match self {
            BraidState::NoHeaderReceived(s) => s.clone(),
            _ => return Err(BraidError::WrongState("recv_header requires NoHeaderReceived")),
        };

        if epoch != state.epoch {
            return Err(BraidError::EpochMismatch { expected: state.epoch, got: epoch });
        }
        if hdr.len() != HEADER_SIZE {
            return Err(BraidError::InvalidData("Header wrong size"));
        }

        // Verify MAC on header
        state.auth.verify_ek(epoch, &hdr, mac)?;

        *self = BraidState::HeaderReceived(HeaderReceived {
            epoch: state.epoch,
            auth: state.auth,
            hdr,
        });

        Ok(())
    }

    /// [HeaderReceived → Ct1Sent] Encapsulate phase 1 and send CT1.
    ///
    /// Returns (BraidMessage::Ciphertext1, EpochSecret).
    pub fn send_ct1(&mut self) -> Result<(BraidMessage, EpochSecret), BraidError> {
        let state = match self {
            BraidState::HeaderReceived(s) => s.clone(),
            _ => return Err(BraidError::WrongState("send_ct1 requires HeaderReceived")),
        };

        let mut rng = OsRng;
        let (ct1, es, ss) = incremental_mlkem768::encaps1(&state.hdr, &mut rng);

        // Derive epoch secret
        let epoch_secret = derive_epoch_secret(state.epoch, &ss);

        // Update authenticator
        let mut auth = state.auth;
        auth.update(state.epoch, &epoch_secret.secret);

        let msg = BraidMessage::Ciphertext1 {
            epoch: state.epoch,
            ct1: ct1.clone(),
        };

        *self = BraidState::Ct1Sent(Ct1Sent {
            epoch: state.epoch,
            auth,
            hdr: state.hdr,
            es,
            ct1,
        });

        Ok((msg, epoch_secret))
    }

    /// [Ct1Sent → Ct1SentEkReceived] Receive EK from peer.
    pub fn recv_ek(&mut self, epoch: Epoch, ek: Vec<u8>) -> Result<(), BraidError> {
        let state = match self {
            BraidState::Ct1Sent(s) => s.clone(),
            _ => return Err(BraidError::WrongState("recv_ek requires Ct1Sent")),
        };

        if epoch != state.epoch {
            return Err(BraidError::EpochMismatch { expected: state.epoch, got: epoch });
        }

        // Verify EK matches header
        if !incremental_mlkem768::ek_matches_header(&ek, &state.hdr) {
            return Err(BraidError::InvalidData("EK doesn't match header"));
        }

        *self = BraidState::Ct1SentEkReceived(Ct1SentEkReceived {
            epoch: state.epoch,
            auth: state.auth,
            es: state.es,
            ek,
            ct1: state.ct1,
        });

        Ok(())
    }

    /// [Ct1SentEkReceived → Ct2Sent → KeysUnsampled] Complete encapsulation, send CT2 + MAC.
    pub fn send_ct2(&mut self) -> Result<BraidMessage, BraidError> {
        let state = match self {
            BraidState::Ct1SentEkReceived(s) => s.clone(),
            _ => return Err(BraidError::WrongState("send_ct2 requires Ct1SentEkReceived")),
        };

        let ct2 = incremental_mlkem768::encaps2(&state.ek, &state.es);

        // MAC over ct1||ct2
        let mut full_ct = state.ct1;
        full_ct.extend_from_slice(&ct2);
        let mac = state.auth.mac_ct(state.epoch, &full_ct);

        let msg = BraidMessage::Ciphertext2 {
            epoch: state.epoch,
            ct2,
            mac,
        };

        // Transition to KeysUnsampled for next epoch (role swap)
        *self = BraidState::KeysUnsampled(KeysUnsampled {
            epoch: state.epoch + 1,
            auth: state.auth,
        });

        Ok(msg)
    }
}

/// Derive an epoch secret from raw KEM shared secret using labeled HKDF.
///
/// Matches Signal's construction exactly:
/// ```text
/// HKDF(salt=[0;32], ikm=ss, info="Signal_PQCKA_V1_MLKEM768:SCKA Key" || epoch_be) → 32 bytes
/// ```
fn derive_epoch_secret(epoch: Epoch, kem_ss: &[u8]) -> EpochSecret {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let info = [
        b"Signal_PQCKA_V1_MLKEM768:SCKA Key".as_slice(),
        &epoch.to_be_bytes(),
    ]
    .concat();

    let hkdf: Hkdf<Sha256> = Hkdf::new(Some(&[0u8; 32]), kem_ss);
    let mut secret = vec![0u8; 32];

    #[allow(clippy::expect_used)]
    hkdf.expand(&info, &mut secret)
        .expect("HKDF expand failed");

    EpochSecret { epoch, secret }
}

/// Errors from the Braid protocol.
#[derive(Debug, thiserror::Error)]
pub enum BraidError {
    /// State machine is in the wrong state for this operation.
    #[error("Wrong state: {0}")]
    WrongState(&'static str),

    /// Epoch number doesn't match expected.
    #[error("Epoch mismatch: expected {expected}, got {got}")]
    EpochMismatch { expected: Epoch, got: Epoch },

    /// Invalid data received.
    #[error("Invalid data: {0}")]
    InvalidData(&'static str),

    /// MAC verification failed.
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(#[from] AuthError),
}

#[cfg(test)]
mod test {
    use super::*;

    /// Full 2-round Braid cycle: Alice (Initiator) ↔ Bob (Responder).
    #[test]
    fn braid_full_epoch_with_split_ct() {
        let mut alice = BraidState::new(BraidRole::Initiator);
        let mut bob = BraidState::new(BraidRole::Responder);

        // ── Epoch 1: Alice sends EK, Bob encapsulates ──

        // Alice: KeysUnsampled → HeaderSent
        let hdr_msg = alice.send_header().unwrap();
        let (epoch, hdr, mac) = match hdr_msg {
            BraidMessage::Header { epoch, hdr, mac } => (epoch, hdr, mac),
            _ => panic!("Expected Header"),
        };
        assert_eq!(epoch, 1);

        // Bob: NoHeaderReceived → HeaderReceived
        bob.recv_header(epoch, hdr, &mac).unwrap();

        // Alice: HeaderSent → EkSent (send EK)
        let ek_msg = alice.send_ek().unwrap();
        let (ek_epoch, ek) = match ek_msg {
            BraidMessage::EncapsulationKey { epoch, ek } => (epoch, ek),
            _ => panic!("Expected EncapsulationKey"),
        };

        // Bob: HeaderReceived → Ct1Sent (send CT1 + derive secret)
        let (ct1_msg, bob_secret) = bob.send_ct1().unwrap();
        let (ct1_epoch, ct1) = match ct1_msg {
            BraidMessage::Ciphertext1 { epoch, ct1 } => (epoch, ct1),
            _ => panic!("Expected Ciphertext1"),
        };
        assert_eq!(bob_secret.epoch, 1);

        // Alice: EkSent → EkSentCt1Received (receive CT1)
        alice.recv_ct1(ct1_epoch, ct1).unwrap();

        // Bob: Ct1Sent → Ct1SentEkReceived (receive EK)
        bob.recv_ek(ek_epoch, ek).unwrap();

        // Bob: Ct1SentEkReceived → KeysUnsampled (send CT2 + MAC)
        let ct2_msg = bob.send_ct2().unwrap();
        let (ct2_epoch, ct2, ct2_mac) = match ct2_msg {
            BraidMessage::Ciphertext2 { epoch, ct2, mac } => (epoch, ct2, mac),
            _ => panic!("Expected Ciphertext2"),
        };

        // Alice: EkSentCt1Received → NoHeaderReceived (recv CT2 + derive secret)
        let alice_secret = alice.recv_ct2(ct2_epoch, ct2, &ct2_mac).unwrap();

        // Both sides derive the same epoch secret
        assert_eq!(alice_secret.secret, bob_secret.secret);
        assert_eq!(alice_secret.epoch, 1);

        // ── Epoch 2: Roles swap — Bob sends EK, Alice encapsulates ──
        // After epoch 1: Alice is NoHeaderReceived, Bob is KeysUnsampled
        assert!(matches!(alice, BraidState::NoHeaderReceived(_)));
        assert!(matches!(bob, BraidState::KeysUnsampled(_)));

        // Bob: KeysUnsampled → HeaderSent
        let hdr_msg2 = bob.send_header().unwrap();
        let (epoch2, hdr2, mac2) = match hdr_msg2 {
            BraidMessage::Header { epoch, hdr, mac } => (epoch, hdr, mac),
            _ => panic!("Expected Header"),
        };
        assert_eq!(epoch2, 2);

        // Alice: NoHeaderReceived → HeaderReceived
        alice.recv_header(epoch2, hdr2, &mac2).unwrap();

        // Bob: HeaderSent → EkSent
        let ek_msg2 = bob.send_ek().unwrap();
        let (ek_epoch2, ek2) = match ek_msg2 {
            BraidMessage::EncapsulationKey { epoch, ek } => (epoch, ek),
            _ => panic!("Expected EncapsulationKey"),
        };

        // Alice: HeaderReceived → Ct1Sent
        let (ct1_msg2, alice_secret2) = alice.send_ct1().unwrap();
        let (ct1_epoch2, ct1_2) = match ct1_msg2 {
            BraidMessage::Ciphertext1 { epoch, ct1 } => (epoch, ct1),
            _ => panic!("Expected Ciphertext1"),
        };

        // Bob: EkSent → EkSentCt1Received
        bob.recv_ct1(ct1_epoch2, ct1_2).unwrap();

        // Alice: Ct1Sent → Ct1SentEkReceived
        alice.recv_ek(ek_epoch2, ek2).unwrap();

        // Alice: send CT2
        let ct2_msg2 = alice.send_ct2().unwrap();
        let (ct2_epoch2, ct2_2, ct2_mac2) = match ct2_msg2 {
            BraidMessage::Ciphertext2 { epoch, ct2, mac } => (epoch, ct2, mac),
            _ => panic!("Expected Ciphertext2"),
        };

        // Bob: recv CT2 + derive secret
        let bob_secret2 = bob.recv_ct2(ct2_epoch2, ct2_2, &ct2_mac2).unwrap();

        assert_eq!(alice_secret2.secret, bob_secret2.secret);
        assert_eq!(alice_secret2.epoch, 2);

        // Epoch 1 and 2 secrets differ
        assert_ne!(alice_secret.secret, alice_secret2.secret);
    }

    #[test]
    fn wrong_state_is_rejected() {
        let mut alice = BraidState::new(BraidRole::Initiator);
        // Alice is KeysUnsampled — can't recv_header
        assert!(alice.recv_header(1, vec![0; 64], &[0; 32]).is_err());
        // Can't send_ct1
        assert!(alice.send_ct1().is_err());
    }

    #[test]
    fn epoch_mismatch_rejected() {
        let mut bob = BraidState::new(BraidRole::Responder);
        // Bob expects epoch 1, send epoch 99
        assert!(bob.recv_header(99, vec![0; 64], &[0; 32]).is_err());
    }
}
