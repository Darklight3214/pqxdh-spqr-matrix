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

impl RemoteRootKey {
    pub(super) const fn new(bytes: Box<[u8; 32]>) -> Self {
        Self { key: bytes }
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
}

impl RootKey {
    pub(super) const fn new(bytes: Box<[u8; 32]>) -> Self {
        Self { key: bytes }
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
}
