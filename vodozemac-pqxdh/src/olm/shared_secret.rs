// Copyright 2021 Damir Jelić
// Modified for PQXDH support
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//! A PQXDH implementation extending Olm's 3DH.
//!
//! PQXDH adds a fourth DH and ML-KEM-768 encapsulation for post-quantum security.
//!
//! ```text
//!     S = ECDH(Ia, SPKb) || ECDH(Ea, Ib) || ECDH(Ea, SPKb) || ECDH(Ea, OPKb) || KEM_SS
//!     R0, C0,0 = HKDF(0, S, "OLM_ROOT", 64)
//! ```

use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{ReusableSecret, SharedSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Curve25519PublicKey as PublicKey, types::Curve25519SecretKey as StaticSecret};

/// PQXDH shared secret (4 DH + optional KEM = up to 160 bytes)
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SharedPQXDHSecret {
    secret: Vec<u8>,
}

/// Remote PQXDH shared secret
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RemoteSharedPQXDHSecret {
    secret: Vec<u8>,
}

// Keep original 3DH for backwards compatibility
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Shared3DHSecret(Box<[u8; 96]>);

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RemoteShared3DHSecret(Box<[u8; 96]>);

fn expand(shared_secret: &[u8]) -> (Box<[u8; 32]>, Box<[u8; 32]>) {
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
    /// Create PQXDH shared secret (initiator side)
    pub fn new(
        identity_key: &StaticSecret,
        ephemeral_key: &ReusableSecret,
        remote_identity_key: &PublicKey,
        remote_signed_prekey: &PublicKey,
        remote_one_time_key: Option<&PublicKey>,
        kem_shared_secret: Option<&[u8]>,
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

        Self { secret }
    }

    pub fn expand(mut self) -> (Box<[u8; 32]>, Box<[u8; 32]>) {
        let result = expand(&self.secret);
        self.secret.zeroize();
        result
    }
}

impl RemoteSharedPQXDHSecret {
    /// Create PQXDH shared secret (responder side)
    pub fn new(
        identity_key: &StaticSecret,
        signed_prekey: &StaticSecret,
        one_time_key: Option<&StaticSecret>,
        remote_identity_key: &PublicKey,
        remote_ephemeral_key: &PublicKey,
        kem_shared_secret: Option<&[u8]>,
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

        Self { secret }
    }

    pub fn expand(mut self) -> (Box<[u8; 32]>, Box<[u8; 32]>) {
        let result = expand(&self.secret);
        self.secret.zeroize();
        result
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
        expand(&self.0[..])
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
        expand(&self.0[..])
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
        let alice_ephemeral = ReusableSecret::random_from_rng(rng.clone());

        // Bob (responder)
        let bob_identity = StaticSecret::new();
        let bob_signed_prekey = StaticSecret::new();
        let bob_one_time_key = StaticSecret::new();

        // Simulated KEM shared secret (in real use, from ML-KEM-768)
        let kem_ss = [42u8; 32];

        let alice_secret = SharedPQXDHSecret::new(
            &alice_identity,
            &alice_ephemeral,
            &PublicKey::from(&bob_identity),
            &PublicKey::from(&bob_signed_prekey),
            Some(&PublicKey::from(&bob_one_time_key)),
            Some(&kem_ss),
        );

        let bob_secret = RemoteSharedPQXDHSecret::new(
            &bob_identity,
            &bob_signed_prekey,
            Some(&bob_one_time_key),
            &PublicKey::from(&alice_identity),
            &PublicKey::from(&alice_ephemeral),
            Some(&kem_ss),
        );

        let alice_keys = alice_secret.expand();
        let bob_keys = bob_secret.expand();

        assert_eq!(alice_keys, bob_keys);
    }
}
