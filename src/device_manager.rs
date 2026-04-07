// ========== DEVICE MANAGER ==========
// Device discovery, Olm session cache, and key distribution for group members.

use std::collections::HashMap;

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use serde_json::json;
use vodozemac::olm::{Account, OlmMessage, Session, SessionConfig};
use vodozemac::Curve25519PublicKey;

use crate::CONDUIT;

/// Information about a peer's device
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub user_id: String,
    pub device_id: String,
    pub identity_key: String,   // Curve25519 base64
    pub signing_key: String,    // Ed25519 base64
    pub kem_key: String,        // ML-KEM-768 base64
    pub spk: String,            // Signed prekey (Curve25519 base64)
}

/// Cached Olm sessions for (user_id, device_id) pairs
pub struct OlmSessionCache {
    /// (user_id, device_id) -> Olm Session
    sessions: HashMap<String, Session>,
}

impl OlmSessionCache {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    fn cache_key(user_id: &str, device_id: &str) -> String {
        format!("{}|{}", user_id, device_id)
    }

    pub fn get(&self, user_id: &str, device_id: &str) -> Option<&Session> {
        self.sessions.get(&Self::cache_key(user_id, device_id))
    }

    pub fn get_mut(&mut self, user_id: &str, device_id: &str) -> Option<&mut Session> {
        self.sessions.get_mut(&Self::cache_key(user_id, device_id))
    }

    pub fn insert(&mut self, user_id: &str, device_id: &str, session: Session) {
        self.sessions.insert(Self::cache_key(user_id, device_id), session);
    }

    pub fn has(&self, user_id: &str, device_id: &str) -> bool {
        self.sessions.contains_key(&Self::cache_key(user_id, device_id))
    }
}

/// Query the Matrix server for all members of a room
pub fn query_room_members(
    http: &reqwest::blocking::Client,
    tok: &str,
    room_id: &str,
) -> Vec<String> {
    let url = format!(
        "{CONDUIT}/_matrix/client/v3/rooms/{}/members?membership=join",
        room_id
    );
    let resp: serde_json::Value = match http.get(&url).bearer_auth(tok).send() {
        Ok(r) => r.json().unwrap_or_default(),
        Err(e) => {
            println!("[error] Failed to query room members: {}", e);
            return Vec::new();
        }
    };

    let mut members = Vec::new();
    if let Some(chunks) = resp["chunk"].as_array() {
        for evt in chunks {
            if let Some(uid) = evt["state_key"].as_str() {
                members.push(uid.to_string());
            }
        }
    }
    members
}

/// Query the Matrix server for a user's devices and their keys
pub fn query_member_devices(
    http: &reqwest::blocking::Client,
    tok: &str,
    user_id: &str,
) -> Vec<DeviceInfo> {
    let body = json!({
        "device_keys": {
            user_id: []
        }
    });

    let resp: serde_json::Value = match http
        .post(format!("{CONDUIT}/_matrix/client/v3/keys/query"))
        .bearer_auth(tok)
        .json(&body)
        .send()
    {
        Ok(r) => r.json().unwrap_or_default(),
        Err(e) => {
            println!("[error] Failed to query keys for {}: {}", user_id, e);
            return Vec::new();
        }
    };

    let mut devices = Vec::new();
    if let Some(user_devices) = resp["device_keys"][user_id].as_object() {
        for (device_id, dev_data) in user_devices {
            let keys = &dev_data["keys"];

            let ik_key = format!("curve25519:{}", device_id);
            let sk_key = format!("ed25519:{}", device_id);
            let kem_key_name = format!("kem:{}", device_id);
            let spk_key_name = format!("spk:{}", device_id);

            let identity_key = keys[&ik_key].as_str().unwrap_or("").to_string();
            let signing_key = keys[&sk_key].as_str().unwrap_or("").to_string();
            let kem_key = keys.get(&kem_key_name)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let spk = keys.get(&spk_key_name)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            if identity_key.is_empty() || signing_key.is_empty() {
                continue;
            }

            devices.push(DeviceInfo {
                user_id: user_id.to_string(),
                device_id: device_id.clone(),
                identity_key,
                signing_key,
                kem_key,
                spk,
            });
        }
    }
    devices
}

/// Claim a one-time key for a specific user/device
pub fn claim_otk_for_device(
    http: &reqwest::blocking::Client,
    tok: &str,
    user_id: &str,
    device_id: &str,
) -> Option<String> {
    let body = json!({
        "one_time_keys": {
            user_id: {
                device_id: "curve25519"
            }
        }
    });

    let resp: serde_json::Value = http
        .post(format!("{CONDUIT}/_matrix/client/v3/keys/claim"))
        .bearer_auth(tok)
        .json(&body)
        .send()
        .ok()?
        .json()
        .ok()?;

    let otks = resp["one_time_keys"][user_id][device_id].as_object()?;
    for (_key_id, key_data) in otks {
        if let Some(key) = key_data["key"].as_str() {
            return Some(key.to_string());
        }
        if let Some(key) = key_data.as_str() {
            return Some(key.to_string());
        }
    }
    None
}

/// Establish PQXDH Olm sessions with all devices in a room that we don't already have sessions with.
/// Returns the KEM ciphertexts for devices that need them.
pub fn ensure_olm_sessions(
    http: &reqwest::blocking::Client,
    tok: &str,
    own_uid: &str,
    own_device_id: &str,
    account: &mut Account,
    members: &[String],
    cache: &mut OlmSessionCache,
) -> Vec<(String, String, Vec<u8>)> {
    // Returns: Vec<(user_id, device_id, kem_ciphertext)>
    let mut new_sessions = Vec::new();

    for member_uid in members {
        if member_uid == own_uid {
            continue;
        }

        let devices = query_member_devices(http, tok, member_uid);
        for dev in &devices {
            if dev.device_id == own_device_id {
                continue;
            }
            if cache.has(&dev.user_id, &dev.device_id) {
                continue;
            }

            // Establish an Olm session with this device via PQXDH
            let peer_ik = match Curve25519PublicKey::from_base64(&dev.identity_key) {
                Ok(k) => k,
                Err(_) => {
                    println!(
                        "[warn] Bad identity key for {}:{}, skipping",
                        dev.user_id, dev.device_id
                    );
                    continue;
                }
            };

            // Use the real signed prekey from the device's uploaded keys
            let peer_spk = if !dev.spk.is_empty() {
                match Curve25519PublicKey::from_base64(&dev.spk) {
                    Ok(k) => k,
                    Err(_) => {
                        println!(
                            "[warn] Bad SPK for {}:{}, skipping",
                            dev.user_id, dev.device_id
                        );
                        continue;
                    }
                }
            } else {
                println!(
                    "[warn] No SPK for {}:{}, falling back to identity key",
                    dev.user_id, dev.device_id
                );
                peer_ik
            };

            // Claim OTK
            let otk_b64 = match claim_otk_for_device(http, tok, &dev.user_id, &dev.device_id) {
                Some(k) => k,
                None => {
                    println!(
                        "[warn] No OTK available for {}:{}, skipping",
                        dev.user_id, dev.device_id
                    );
                    continue;
                }
            };
            let peer_otk = match Curve25519PublicKey::from_base64(&otk_b64) {
                Ok(k) => k,
                Err(_) => continue,
            };

            // Decode KEM public key if available
            let kem_pk_bytes = if !dev.kem_key.is_empty() {
                match B64.decode(&dev.kem_key) {
                    Ok(b) => b,
                    Err(_) => {
                        println!(
                            "[warn] Bad KEM key for {}:{}, skipping",
                            dev.user_id, dev.device_id
                        );
                        continue;
                    }
                }
            } else {
                println!(
                    "[warn] No KEM key for {}:{}, skipping",
                    dev.user_id, dev.device_id
                );
                continue;
            };

            let (session, kem_ct) = account.create_outbound_session_pqxdh(
                SessionConfig::version_2(),
                peer_ik,
                peer_spk,
                Some(peer_otk),
                &kem_pk_bytes,
            );

            println!(
                "[olm] Established PQXDH session with {}:{}",
                dev.user_id, dev.device_id
            );

            cache.insert(&dev.user_id, &dev.device_id, session);
            new_sessions.push((
                dev.user_id.clone(),
                dev.device_id.clone(),
                kem_ct,
            ));
        }
    }

    new_sessions
}

/// Send an encrypted to-device event (m.room_key) to a specific user/device
/// using the cached Olm session
pub fn send_room_key_to_device(
    http: &reqwest::blocking::Client,
    tok: &str,
    sender_key: &str,
    target_user: &str,
    target_device: &str,
    room_id: &str,
    session_id: &str,
    session_key_b64: &str,
    olm_session: &mut Session,
    kem_ct: Option<&[u8]>,
) {
    // Build the m.room_key payload
    let room_key_content = json!({
        "algorithm": "m.megolm.v1.aes-sha2",
        "room_id": room_id,
        "session_id": session_id,
        "session_key": session_key_b64,
    });

    let plaintext = serde_json::to_string(&room_key_content).unwrap();

    // Encrypt with Olm
    let wire = olm_session.encrypt_pq(&plaintext);
    let (msg_type, ct_bytes) = match &wire.message {
        OlmMessage::PreKey(m) => (0u8, m.to_bytes()),
        OlmMessage::Normal(m) => (1u8, m.to_bytes()),
    };

    let mut payload = json!({
        "algorithm": "m.olm.pqxdh.v1",
        "sender_key": sender_key,
        "ciphertext": B64.encode(&ct_bytes),
        "type": msg_type,
    });

    if let Some(ct) = kem_ct {
        payload["kem_ciphertext"] = json!(B64.encode(ct));
    }

    if let Some(ref meta) = wire.spqr_meta {
        payload["spqr_meta"] = serde_json::to_value(meta).unwrap_or_default();
    }

    if !wire.braid_msgs.is_empty() {
        payload["braid_msgs"] = serde_json::to_value(&wire.braid_msgs).unwrap_or_default();
    }

    // Send as to-device event
    let txn_id = crate::txn_id();
    let body = json!({
        "messages": {
            target_user: {
                target_device: payload,
            }
        }
    });

    match http
        .put(format!(
            "{CONDUIT}/_matrix/client/v3/sendToDevice/m.room.encrypted/{}",
            txn_id
        ))
        .bearer_auth(tok)
        .json(&body)
        .send()
    {
        Ok(resp) => {
            if resp.status().is_success() {
                println!(
                    "[megolm] Sent room key to {}:{}",
                    target_user, target_device
                );
            } else {
                println!(
                    "[error] Failed to send room key to {}:{}: {}",
                    target_user,
                    target_device,
                    resp.status()
                );
            }
        }
        Err(e) => {
            println!(
                "[error] Failed to send room key to {}:{}: {}",
                target_user, target_device, e
            );
        }
    }
}
