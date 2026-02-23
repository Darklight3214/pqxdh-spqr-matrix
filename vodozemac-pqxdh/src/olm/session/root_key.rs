// Copyright 2021 Damir Jelić
// Modified for SPQR support
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{
    chain_key::{ChainKey, RemoteChainKey},
    ratchet::{RatchetKey, RemoteRatchetKey},
};

const ADVANCEMENT_SEED: &[u8; 11] = b"OLM_RATCHET";
const PQ_SEED: &[u8; 9] = b"SPQR_ROOT";

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
pub(crate) struct RootKey {
    pub key: Box<[u8; 32]>,
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub(crate) struct RemoteRootKey {
    pub key: Box<[u8; 32]>,
}

fn kdf(
    root_key: &[u8; 32],
    ratchet_key: &RatchetKey,
    remote_ratchet_key: &RemoteRatchetKey,
) -> Box<[u8; 64]> {
    let shared_secret = ratchet_key.diffie_hellman(remote_ratchet_key);
    let hkdf: Hkdf<Sha256> = Hkdf::new(Some(root_key.as_ref()), shared_secret.as_bytes());
    let mut output = Box::new([0u8; 64]);

    #[allow(clippy::expect_used)]
    hkdf.expand(ADVANCEMENT_SEED, output.as_mut_slice())
        .expect("HKDF expand failed");

    output
}

/// Mix SPQR post-quantum secret into root key
fn mix_pq_secret(root_key: &[u8; 32], pq_secret: &[u8]) -> Box<[u8; 32]> {
    let mut ikm = Vec::with_capacity(32 + pq_secret.len());
    ikm.extend_from_slice(root_key);
    ikm.extend_from_slice(pq_secret);

    let hkdf: Hkdf<Sha256> = Hkdf::new(None, &ikm);
    let mut new_root = Box::new([0u8; 32]);

    #[allow(clippy::expect_used)]
    hkdf.expand(PQ_SEED, new_root.as_mut_slice())
        .expect("HKDF expand failed");

    new_root
}

impl RemoteRootKey {
    pub(super) const fn new(bytes: Box<[u8; 32]>) -> Self {
        Self { key: bytes }
    }

    /// Mix SPQR secret into this root key
    pub(super) fn mix_pq(&mut self, pq_secret: &[u8]) {
        self.key = mix_pq_secret(&self.key, pq_secret);
    }

    pub(super) fn advance(
        &self,
        remote_ratchet_key: &RemoteRatchetKey,
    ) -> (RootKey, ChainKey, RatchetKey) {
        let ratchet_key = RatchetKey::new();
        let output = kdf(&self.key, &ratchet_key, remote_ratchet_key);

        let mut chain_key = Box::new([0u8; 32]);
        let mut root_key = Box::new([0u8; 32]);

        chain_key.copy_from_slice(&output[32..]);
        root_key.copy_from_slice(&output[..32]);

        let chain_key = ChainKey::new(chain_key);
        let root_key = RootKey::new(root_key);

        (root_key, chain_key, ratchet_key)
    }

    /// Advance with optional SPQR secret
    pub(super) fn advance_with_pq(
        &self,
        remote_ratchet_key: &RemoteRatchetKey,
        pq_secret: Option<&[u8]>,
    ) -> (RootKey, ChainKey, RatchetKey) {
        let effective_root = match pq_secret {
            Some(secret) => mix_pq_secret(&self.key, secret),
            None => self.key.clone(),
        };

        let ratchet_key = RatchetKey::new();
        let output = kdf(&effective_root, &ratchet_key, remote_ratchet_key);

        let mut chain_key = Box::new([0u8; 32]);
        let mut root_key = Box::new([0u8; 32]);

        chain_key.copy_from_slice(&output[32..]);
        root_key.copy_from_slice(&output[..32]);

        (RootKey::new(root_key), ChainKey::new(chain_key), ratchet_key)
    }
}

impl RootKey {
    pub(super) const fn new(bytes: Box<[u8; 32]>) -> Self {
        Self { key: bytes }
    }

    /// Mix SPQR secret into this root key
    pub(super) fn mix_pq(&mut self, pq_secret: &[u8]) {
        self.key = mix_pq_secret(&self.key, pq_secret);
    }

    pub(super) fn advance(
        &self,
        old_ratchet_key: &RatchetKey,
        remote_ratchet_key: &RemoteRatchetKey,
    ) -> (RemoteRootKey, RemoteChainKey) {
        let output = kdf(&self.key, old_ratchet_key, remote_ratchet_key);

        let mut chain_key = Box::new([0u8; 32]);
        let mut root_key = Box::new([0u8; 32]);

        root_key.copy_from_slice(&output[..32]);
        chain_key.copy_from_slice(&output[32..]);

        (RemoteRootKey::new(root_key), RemoteChainKey::new(chain_key))
    }

    /// Advance with optional SPQR secret
    pub(super) fn advance_with_pq(
        &self,
        old_ratchet_key: &RatchetKey,
        remote_ratchet_key: &RemoteRatchetKey,
        pq_secret: Option<&[u8]>,
    ) -> (RemoteRootKey, RemoteChainKey) {
        let effective_root = match pq_secret {
            Some(secret) => mix_pq_secret(&self.key, secret),
            None => self.key.clone(),
        };

        let output = kdf(&effective_root, old_ratchet_key, remote_ratchet_key);

        let mut chain_key = Box::new([0u8; 32]);
        let mut root_key = Box::new([0u8; 32]);

        root_key.copy_from_slice(&output[..32]);
        chain_key.copy_from_slice(&output[32..]);

        (RemoteRootKey::new(root_key), RemoteChainKey::new(chain_key))
    }
}
