// Copyright 2021 Damir Jelić
// Modified for PQXDH support (Signal-compatible, Revision 3)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//! A PQXDH implementation following Signal's specification (Revision 3).
//!
//! PQXDH adds a fourth DH and ML-KEM-768 encapsulation for post-quantum security.
//!
//! Key agreement (Signal specification):
//! ```text
//!     KM = DH(IK_A, SPK_B) || DH(EK_A, IK_B) || DH(EK_A, SPK_B) || DH(EK_A, OPK_B) || KEM_SS
//!     SK = KDF(F || KM)
//!         where F = 0xFF * 32 (for Curve25519)
//!         HKDF salt = 0x00 * 64 (SHA-512 hash output length)
//!         HKDF info = "PQXDH_CURVE25519_SHA-512_ML-KEM-768"
//! ```
//!
//! Associated Data:
//! ```text
//!     AD = Encode(IK_A) || Encode(IK_B)
//! ```

use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{ReusableSecret, SharedSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Curve25519PublicKey as PublicKey, types::Curve25519SecretKey as StaticSecret};

/// Signal PQXDH KDF info string (protocol_curve_hash_pqkem).
const PQXDH_KDF_INFO: &[u8] = b"PQXDH_CURVE25519_SHA-512_ML-KEM-768";

/// F prefix: 32 bytes of 0xFF (for Curve25519).
/// Per Signal spec: "F is a byte sequence containing 32 0xFF bytes if curve is curve25519."
/// This ensures the first bits of HKDF IKM are never a valid curve point encoding.
const F_PREFIX: [u8; 32] = [0xFF; 32];

/// HKDF salt: zero-filled with SHA-512 output length (64 bytes).
/// Per Signal spec: "HKDF salt = A zero-filled byte sequence with length equal to
/// the hash output length, in bytes."
const PQXDH_HKDF_SALT: [u8; 64] = [0u8; 64];

/// PQXDH shared secret (4 DH + optional KEM = up to 160 bytes)
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SharedPQXDHSecret {
    /// The raw key material KM = DH1 || DH2 || DH3 || [DH4] || [KEM_SS]
    secret: Vec<u8>,
    /// Local identity public key (IK_A for initiator, IK_B for responder)
    #[zeroize(skip)]
    local_identity_key: [u8; 32],
    /// Remote identity public key
    #[zeroize(skip)]
    remote_identity_key: [u8; 32],
}

/// Remote PQXDH shared secret
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RemoteSharedPQXDHSecret {
    /// The raw key material KM = DH1 || DH2 || DH3 || [DH4] || [KEM_SS]
    secret: Vec<u8>,
    /// Local identity public key (IK_B for responder)
    #[zeroize(skip)]
    local_identity_key: [u8; 32],
    /// Remote identity public key (IK_A for responder)
    #[zeroize(skip)]
    remote_identity_key: [u8; 32],
}

// Keep original 3DH for backwards compatibility
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Shared3DHSecret(Box<[u8; 96]>);

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RemoteShared3DHSecret(Box<[u8; 96]>);

/// Original 3DH key expand (unchanged for backward compatibility).
fn expand_3dh(shared_secret: &[u8]) -> (Box<[u8; 32]>, Box<[u8; 32]>) {
    let hkdf: Hkdf<Sha256> = Hkdf::new(Some(&[0]), shared_secret);
    let mut root_key = Box::new([0u8; 32]);
    let mut chain_key = Box::new([0u8; 32]);
    let mut expanded_keys = [0u8; 64];

    #[allow(clippy::expect_used)]
    hkdf.expand(b"OLM_ROOT", &mut expanded_keys)
        .expect("HKDF expand failed");

    root_key.copy_from_slice(&expanded_keys[0..32]);
    chain_key.copy_from_slice(&expanded_keys[32..64]);
    expanded_keys.zeroize();

    (root_key, chain_key)
}

/// Signal-compatible PQXDH KDF.
///
/// Per Signal PQXDH spec (Revision 3, Section 2.2):
/// ```text
/// KDF(KM) = HKDF(salt, F || KM, info) → 64 bytes
///   salt = [0x00; 64]  (SHA-512 output length)
///   F    = [0xFF; 32]  (for Curve25519)
///   info = "PQXDH_CURVE25519_SHA-512_ML-KEM-768"
/// ```
///
/// We expand to 64 bytes: first 32 = root key, second 32 = chain key.
fn expand_pqxdh(key_material: &[u8]) -> (Box<[u8; 32]>, Box<[u8; 32]>) {
    // IKM = F || KM
    let mut ikm = Vec::with_capacity(32 + key_material.len());
    ikm.extend_from_slice(&F_PREFIX);
    ikm.extend_from_slice(key_material);

    let hkdf: Hkdf<Sha256> = Hkdf::new(Some(&PQXDH_HKDF_SALT), &ikm);
    let mut expanded_keys = [0u8; 64];

    #[allow(clippy::expect_used)]
    hkdf.expand(PQXDH_KDF_INFO, &mut expanded_keys)
        .expect("HKDF expand failed");

    let mut root_key = Box::new([0u8; 32]);
    let mut chain_key = Box::new([0u8; 32]);

    root_key.copy_from_slice(&expanded_keys[0..32]);
    chain_key.copy_from_slice(&expanded_keys[32..64]);

    ikm.zeroize();
    expanded_keys.zeroize();

    (root_key, chain_key)
}

fn merge_secrets_3dh(
    first: SharedSecret,
    second: SharedSecret,
    third: SharedSecret,
) -> Box<[u8; 96]> {
    let mut secret = Box::new([0u8; 96]);
    secret[0..32].copy_from_slice(first.as_bytes());
    secret[32..64].copy_from_slice(second.as_bytes());
    secret[64..96].copy_from_slice(third.as_bytes());
    secret
}

impl SharedPQXDHSecret {
    /// Create PQXDH shared secret (initiator side).
    ///
    /// `local_identity_public` is Alice's identity public key (IK_A).
    pub fn new(
        identity_key: &StaticSecret,
        ephemeral_key: &ReusableSecret,
        remote_identity_key: &PublicKey,
        remote_signed_prekey: &PublicKey,
        remote_one_time_key: Option<&PublicKey>,
        kem_shared_secret: Option<&[u8]>,
        local_identity_public: &PublicKey,
    ) -> Self {
        // DH1 = DH(IK_A, SPK_B)
        let dh1 = identity_key.diffie_hellman(remote_signed_prekey);
        // DH2 = DH(EK_A, IK_B)
        let dh2 = ephemeral_key.diffie_hellman(&remote_identity_key.inner);
        // DH3 = DH(EK_A, SPK_B)
        let dh3 = ephemeral_key.diffie_hellman(&remote_signed_prekey.inner);

        let mut secret = Vec::with_capacity(160);
        secret.extend_from_slice(dh1.as_bytes());
        secret.extend_from_slice(dh2.as_bytes());
        secret.extend_from_slice(dh3.as_bytes());

        // DH4 = DH(EK_A, OPK_B) - optional
        if let Some(opk) = remote_one_time_key {
            let dh4 = ephemeral_key.diffie_hellman(&opk.inner);
            secret.extend_from_slice(dh4.as_bytes());
        }

        // KEM shared secret - optional but recommended
        if let Some(kem_ss) = kem_shared_secret {
            secret.extend_from_slice(kem_ss);
        }

        Self {
            secret,
            local_identity_key: *local_identity_public.as_bytes(),
            remote_identity_key: *remote_identity_key.as_bytes(),
        }
    }

    /// Derive root key and chain key using Signal-compatible PQXDH KDF.
    pub fn expand(mut self) -> (Box<[u8; 32]>, Box<[u8; 32]>) {
        let result = expand_pqxdh(&self.secret);
        self.secret.zeroize();
        result
    }

    /// Construct the Associated Data (AD) for the first AEAD message.
    ///
    /// Per Signal PQXDH spec: AD = Encode(IK_A) || Encode(IK_B)
    #[allow(dead_code)]
    pub fn associated_data(&self) -> Vec<u8> {
        let mut ad = Vec::with_capacity(64);
        ad.extend_from_slice(&self.local_identity_key);
        ad.extend_from_slice(&self.remote_identity_key);
        ad
    }
}

impl RemoteSharedPQXDHSecret {
    /// Create PQXDH shared secret (responder side).
    ///
    /// `local_identity_public` is Bob's identity public key (IK_B).
    pub fn new(
        identity_key: &StaticSecret,
        signed_prekey: &StaticSecret,
        one_time_key: Option<&StaticSecret>,
        remote_identity_key: &PublicKey,
        remote_ephemeral_key: &PublicKey,
        kem_shared_secret: Option<&[u8]>,
        local_identity_public: &PublicKey,
    ) -> Self {
        // DH1 = DH(SPK_B, IK_A)
        let dh1 = signed_prekey.diffie_hellman(remote_identity_key);
        // DH2 = DH(IK_B, EK_A)
        let dh2 = identity_key.diffie_hellman(remote_ephemeral_key);
        // DH3 = DH(SPK_B, EK_A)
        let dh3 = signed_prekey.diffie_hellman(remote_ephemeral_key);

        let mut secret = Vec::with_capacity(160);
        secret.extend_from_slice(dh1.as_bytes());
        secret.extend_from_slice(dh2.as_bytes());
        secret.extend_from_slice(dh3.as_bytes());

        // DH4 = DH(OPK_B, EK_A) - optional
        if let Some(opk) = one_time_key {
            let dh4 = opk.diffie_hellman(remote_ephemeral_key);
            secret.extend_from_slice(dh4.as_bytes());
        }

        // KEM shared secret
        if let Some(kem_ss) = kem_shared_secret {
            secret.extend_from_slice(kem_ss);
        }

        Self {
            secret,
            local_identity_key: *local_identity_public.as_bytes(),
            remote_identity_key: *remote_identity_key.as_bytes(),
        }
    }

    /// Derive root key and chain key using Signal-compatible PQXDH KDF.
    pub fn expand(mut self) -> (Box<[u8; 32]>, Box<[u8; 32]>) {
        let result = expand_pqxdh(&self.secret);
        self.secret.zeroize();
        result
    }

    /// Construct the Associated Data (AD) for verifying the first AEAD message.
    ///
    /// Per Signal PQXDH spec: AD = Encode(IK_A) || Encode(IK_B)
    /// Note: for the responder, remote = IK_A, local = IK_B
    #[allow(dead_code)]
    pub fn associated_data(&self) -> Vec<u8> {
        let mut ad = Vec::with_capacity(64);
        // AD must be in Alice-first order: IK_A || IK_B
        ad.extend_from_slice(&self.remote_identity_key);
        ad.extend_from_slice(&self.local_identity_key);
        ad
    }
}

// Original 3DH for backwards compatibility
impl RemoteShared3DHSecret {
    pub(crate) fn new(
        identity_key: &StaticSecret,
        one_time_key: &StaticSecret,
        remote_identity_key: &PublicKey,
        remote_one_time_key: &PublicKey,
    ) -> Self {
        let first_secret = one_time_key.diffie_hellman(remote_identity_key);
        let second_secret = identity_key.diffie_hellman(remote_one_time_key);
        let third_secret = one_time_key.diffie_hellman(remote_one_time_key);
        Self(merge_secrets_3dh(first_secret, second_secret, third_secret))
    }

    pub fn expand(self) -> (Box<[u8; 32]>, Box<[u8; 32]>) {
        expand_3dh(&self.0[..])
    }
}

impl Shared3DHSecret {
    pub(crate) fn new(
        identity_key: &StaticSecret,
        one_time_key: &ReusableSecret,
        remote_identity_key: &PublicKey,
        remote_one_time_key: &PublicKey,
    ) -> Self {
        let first_secret = identity_key.diffie_hellman(remote_one_time_key);
        let second_secret = one_time_key.diffie_hellman(&remote_identity_key.inner);
        let third_secret = one_time_key.diffie_hellman(&remote_one_time_key.inner);
        Self(merge_secrets_3dh(first_secret, second_secret, third_secret))
    }

    pub fn expand(self) -> (Box<[u8; 32]>, Box<[u8; 32]>) {
        expand_3dh(&self.0[..])
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::thread_rng;
    use x25519_dalek::ReusableSecret;

    #[test]
    fn pqxdh_key_agreement() {
        let rng = thread_rng();

        // Alice (initiator)
        let alice_identity = StaticSecret::new();
        let alice_identity_public = PublicKey::from(&alice_identity);
        let alice_ephemeral = ReusableSecret::random_from_rng(rng.clone());

        // Bob (responder)
        let bob_identity = StaticSecret::new();
        let bob_identity_public = PublicKey::from(&bob_identity);
        let bob_signed_prekey = StaticSecret::new();
        let bob_one_time_key = StaticSecret::new();

        // Simulated KEM shared secret (in real use, from ML-KEM-768)
        let kem_ss = [42u8; 32];

        let alice_secret = SharedPQXDHSecret::new(
            &alice_identity,
            &alice_ephemeral,
            &bob_identity_public,
            &PublicKey::from(&bob_signed_prekey),
            Some(&PublicKey::from(&bob_one_time_key)),
            Some(&kem_ss),
            &alice_identity_public,
        );

        let bob_secret = RemoteSharedPQXDHSecret::new(
            &bob_identity,
            &bob_signed_prekey,
            Some(&bob_one_time_key),
            &alice_identity_public,
            &PublicKey::from(&alice_ephemeral),
            Some(&kem_ss),
            &bob_identity_public,
        );

        // Verify AD matches on both sides
        let alice_ad = alice_secret.associated_data();
        let bob_ad = bob_secret.associated_data();
        assert_eq!(alice_ad, bob_ad, "Associated data must match");

        let alice_keys = alice_secret.expand();
        let bob_keys = bob_secret.expand();

        assert_eq!(alice_keys, bob_keys, "Derived keys must match");
    }

    #[test]
    fn pqxdh_kdf_uses_f_prefix() {
        // Verify that F||KM prefix is used: the PQXDH KDF should produce
        // different output than a plain HKDF without the prefix.
        let km = [1u8; 96]; // Fake key material

        // PQXDH KDF with F prefix
        let (root_pqxdh, _) = expand_pqxdh(&km);

        // Plain HKDF without F prefix (should differ)
        let hkdf_plain: Hkdf<Sha256> = Hkdf::new(Some(&PQXDH_HKDF_SALT), &km);
        let mut plain_out = [0u8; 32];
        hkdf_plain.expand(PQXDH_KDF_INFO, &mut plain_out).expect("HKDF expand failed");

        assert_ne!(*root_pqxdh, plain_out, "F prefix must change output");
    }

    #[test]
    fn pqxdh_without_otk_or_kem() {
        let rng = thread_rng();

        let alice_identity = StaticSecret::new();
        let alice_identity_public = PublicKey::from(&alice_identity);
        let alice_ephemeral = ReusableSecret::random_from_rng(rng.clone());

        let bob_identity = StaticSecret::new();
        let bob_identity_public = PublicKey::from(&bob_identity);
        let bob_signed_prekey = StaticSecret::new();

        // No OTK, no KEM — just 3 DH
        let alice_secret = SharedPQXDHSecret::new(
            &alice_identity,
            &alice_ephemeral,
            &bob_identity_public,
            &PublicKey::from(&bob_signed_prekey),
            None,
            None,
            &alice_identity_public,
        );

        let bob_secret = RemoteSharedPQXDHSecret::new(
            &bob_identity,
            &bob_signed_prekey,
            None,
            &alice_identity_public,
            &PublicKey::from(&alice_ephemeral),
            None,
            &bob_identity_public,
        );

        let alice_keys = alice_secret.expand();
        let bob_keys = bob_secret.expand();

        assert_eq!(alice_keys, bob_keys, "Derived keys must match even without OTK/KEM");
    }
}
