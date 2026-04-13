// ========== GROUP CHAT ==========
// Megolm-based encrypted group chat with PQXDH key distribution.

use std::collections::HashSet;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use serde_json::json;
use vodozemac::megolm::{
    GroupSession, InboundGroupSession, MegolmMessage, SessionConfig, SessionKey,
};
use vodozemac::olm::{Account, OlmMessage};

use crate::device_manager::{
    self, OlmSessionCache, ensure_olm_sessions, query_room_members,
    send_room_key_to_device,
};
use crate::megolm_store::MegolmStore;
use crate::{
    CONDUIT, append_history, clear_history, prompt, show_history, sync, txn_id,
};

/// Create a group room and invite multiple users
pub fn create_group_room(
    http: &reqwest::blocking::Client,
    tok: &str,
    invitees: &[String],
    room_name: &str,
) -> String {
    // Per Matrix spec: set initial_state with m.room.encryption to enable E2EE
    let body = json!({
        "preset": "private_chat",
        "name": room_name,
        "invite": invitees,
        "is_direct": false,
        "initial_state": [
            {
                "type": "m.room.encryption",
                "state_key": "",
                "content": {
                    "algorithm": "m.megolm.v1.aes-sha2",
                    "rotation_period_ms": 604800000,
                    "rotation_period_msgs": 100
                }
            }
        ]
    });

    let resp: serde_json::Value = http
        .post(format!("{CONDUIT}/_matrix/client/v3/createRoom"))
        .bearer_auth(tok)
        .json(&body)
        .send()
        .expect("Failed to create room")
        .json()
        .unwrap_or_default();

    let room_id = resp["room_id"]
        .as_str()
        .expect("No room_id in createRoom response")
        .to_string();

    println!("[room] Created group room: {}", room_id);
    for invitee in invitees {
        println!("[room] Invited: {}", invitee);
    }

    room_id
}

/// Join an existing room by room ID
pub fn join_room(
    http: &reqwest::blocking::Client,
    tok: &str,
    room_id: &str,
) -> bool {
    let resp = http
        .post(format!("{CONDUIT}/_matrix/client/v3/join/{}", room_id))
        .bearer_auth(tok)
        .json(&json!({}))
        .send();

    match resp {
        Ok(r) if r.status().is_success() => {
            println!("[room] Joined group room: {}", room_id);
            true
        }
        Ok(r) => {
            println!("[error] Failed to join room: {}", r.status());
            false
        }
        Err(e) => {
            println!("[error] Failed to join room: {}", e);
            false
        }
    }
}

/// Distribute the Megolm session key to all members of a room via PQXDH Olm channels
pub fn distribute_megolm_key(
    http: &reqwest::blocking::Client,
    tok: &str,
    own_uid: &str,
    own_device_id: &str,
    sender_key: &str,
    account: &mut Account,
    room_id: &str,
    megolm_session: &GroupSession,
    store: &mut MegolmStore,
    cache: &mut OlmSessionCache,
    pickle_key: &[u8; 32],
) {
    let members = query_room_members(http, tok, room_id);
    println!("[megolm] Room has {} member(s)", members.len());

    // Ensure Olm sessions exist with all member devices
    let new_sessions = ensure_olm_sessions(
        http, tok, own_uid, own_device_id, account, &members, cache,
    );

    // Get the Megolm session key
    let session_key = megolm_session.session_key();
    let session_key_b64 = session_key.to_base64();
    let session_id = megolm_session.session_id();

    // Already shared set
    let already_shared = store.shared_with(room_id);

    // Send session key to each member's device via Olm
    for member_uid in &members {
        if member_uid == own_uid {
            continue;
        }
        let devices = device_manager::query_member_devices(http, tok, member_uid);
        for dev in &devices {
            if dev.device_id == own_device_id {
                continue;
            }

            // Check if already shared
            let pair = (dev.user_id.clone(), dev.device_id.clone());
            if already_shared.contains(&pair) {
                continue;
            }

            // Get the Olm session from cache
            if let Some(olm_session) = cache.get_mut(&dev.user_id, &dev.device_id) {
                // Find matching KEM ciphertext from new sessions
                let kem_ct = new_sessions
                    .iter()
                    .find(|(u, d, _)| u == &dev.user_id && d == &dev.device_id)
                    .map(|(_, _, ct)| ct.as_slice());

                send_room_key_to_device(
                    http,
                    tok,
                    sender_key,
                    &dev.user_id,
                    &dev.device_id,
                    room_id,
                    &session_id,
                    &session_key_b64,
                    olm_session,
                    kem_ct,
                );

                store.mark_shared(room_id, &dev.user_id, &dev.device_id);
            } else {
                println!(
                    "[warn] No Olm session for {}:{}, cannot share key",
                    dev.user_id, dev.device_id
                );
            }
        }
    }

    store.save(&format!("group"), pickle_key);
    println!("[megolm] Session key distributed (session_id: {})", &session_id[..8]);
}

/// Send a Megolm-encrypted message to a group room.
/// Per Matrix spec, the plaintext passed to Megolm encrypt is a JSON event envelope:
/// {"type":"m.room.message","content":{"msgtype":"m.text","body":"..."},"room_id":"..."}
pub fn send_group_encrypted(
    http: &reqwest::blocking::Client,
    tok: &str,
    room_id: &str,
    session: &mut GroupSession,
    plaintext: &str,
    sender_key: &str,
    device_id: &str,
) {
    // Build the event JSON that gets encrypted (per Matrix spec §11.12.2)
    let event_json = json!({
        "type": "m.room.message",
        "content": {
            "msgtype": "m.text",
            "body": plaintext
        },
        "room_id": room_id
    });
    let event_bytes = serde_json::to_string(&event_json)
        .expect("Failed to serialize event JSON");

    let message = session.encrypt(event_bytes.as_bytes());

    // The m.room.encrypted content sent to the room
    let payload = json!({
        "algorithm": "m.megolm.v1.aes-sha2",
        "sender_key": sender_key,
        "session_id": session.session_id(),
        "ciphertext": message.to_base64(),
        "device_id": device_id,
    });

    if let Err(e) = http
        .put(format!(
            "{CONDUIT}/_matrix/client/v3/rooms/{}/send/m.room.encrypted/{}",
            room_id,
            txn_id()
        ))
        .bearer_auth(tok)
        .json(&payload)
        .send()
    {
        println!("[error] Send failed: {}", e);
    }
}

/// Try to decrypt a Megolm-encrypted event.
/// Per Matrix spec, the decrypted bytes are a JSON event envelope:
///   {"type":"m.room.message","content":{"msgtype":"m.text","body":"..."},"room_id":"..."}
/// We parse the envelope and extract the inner `body` field.
fn try_decrypt_megolm_event(
    evt: &serde_json::Value,
    store: &mut MegolmStore,
    pickle_key: &[u8; 32],
) -> Option<(String, String, u32)> {
    // Returns: (sender, plaintext_body, message_index)
    let content = &evt["content"];

    let algorithm = content["algorithm"].as_str().unwrap_or("");
    if algorithm != "m.megolm.v1.aes-sha2" {
        return None;
    }

    let session_id = content["session_id"].as_str()?;
    let ciphertext_b64 = content["ciphertext"].as_str()?;
    let sender = evt["sender"].as_str()?;

    // Look up the room_id from the event
    let room_id = evt["room_id"].as_str().unwrap_or("");

    let mut inbound = store.get_inbound_session(room_id, session_id, pickle_key)?;

    let message = match MegolmMessage::from_base64(ciphertext_b64) {
        Ok(m) => m,
        Err(e) => {
            println!("[error] Bad Megolm message: {}", e);
            return None;
        }
    };

    match inbound.decrypt(&message) {
        Ok(decrypted) => {
            let raw = String::from_utf8_lossy(&decrypted.plaintext).to_string();

            // Parse the JSON event envelope per Matrix spec
            let plaintext = match serde_json::from_str::<serde_json::Value>(&raw) {
                Ok(envelope) => {
                    // Verify room_id matches to prevent cross-room key reuse attacks
                    if let Some(env_room_id) = envelope["room_id"].as_str() {
                        if !room_id.is_empty() && env_room_id != room_id {
                            println!("[error] Megolm room_id mismatch: envelope says {} but event is in {}", env_room_id, room_id);
                            return None;
                        }
                    }

                    // Extract the body from the content per spec
                    envelope["content"]["body"]
                        .as_str()
                        .unwrap_or(&raw)
                        .to_string()
                }
                Err(_) => {
                    // Fallback: treat as raw text (backward compat with non-spec senders)
                    raw
                }
            };

            // Update the inbound session state after decryption
            store.update_inbound_session(room_id, session_id, &inbound, pickle_key);

            Some((sender.to_string(), plaintext, decrypted.message_index))
        }
        Err(e) => {
            println!("[error] Megolm decrypt failed: {:?}", e);
            None
        }
    }
}

/// Process to-device events to extract m.room_key events
pub fn process_to_device_events(
    sync_response: &serde_json::Value,
    own_uid: &str,
    account: &mut Account,
    kem_sk: &[u8],
    store: &mut MegolmStore,
    pickle_key: &[u8; 32],
) {
    let events = match sync_response["to_device"]["events"].as_array() {
        Some(e) => e,
        None => return,
    };

    for evt in events {
        let evt_type = evt["type"].as_str().unwrap_or("");
        let sender = evt["sender"].as_str().unwrap_or("");
        let content = &evt["content"];

        // These are Olm-encrypted to-device messages containing room keys
        if evt_type == "m.room.encrypted" {
            let algorithm = content["algorithm"].as_str().unwrap_or("");
            if algorithm != "m.olm.pqxdh.v1" {
                continue;
            }

            let ct_b64 = content["ciphertext"].as_str().unwrap_or("");
            let kem_ct_b64 = content["kem_ciphertext"].as_str().unwrap_or("");
            let msg_type = content["type"].as_u64().unwrap_or(1) as usize;

            if ct_b64.is_empty() {
                continue;
            }

            let ct = match B64.decode(ct_b64) {
                Ok(b) => b,
                Err(_) => continue,
            };

            let olm = match OlmMessage::from_parts(msg_type, &ct) {
                Ok(m) => m,
                Err(_) => continue,
            };

            // Try to decrypt as a PreKey message (new session)
            if let OlmMessage::PreKey(ref pkm) = olm {
                let kem_ct = if !kem_ct_b64.is_empty() {
                    B64.decode(kem_ct_b64).ok()
                } else {
                    None
                };

                let kem_ct_ref = kem_ct.as_deref().unwrap_or(&[]);

                match account.create_inbound_session_pqxdh(
                    pkm.identity_key(),
                    pkm,
                    kem_ct_ref,
                    kem_sk,
                ) {
                    Ok(result) => {
                        let plaintext_str = String::from_utf8_lossy(&result.plaintext);

                        // Parse as a room key event
                        if let Ok(room_key) =
                            serde_json::from_str::<serde_json::Value>(&plaintext_str)
                        {
                            let rk_algorithm =
                                room_key["algorithm"].as_str().unwrap_or("");
                            if rk_algorithm == "m.megolm.v1.aes-sha2" {
                                let room_id =
                                    room_key["room_id"].as_str().unwrap_or("");
                                let session_id =
                                    room_key["session_id"].as_str().unwrap_or("");
                                let session_key_b64 =
                                    room_key["session_key"].as_str().unwrap_or("");
                                let sender_key_val =
                                    content["sender_key"].as_str().unwrap_or("");

                                if !room_id.is_empty()
                                    && !session_id.is_empty()
                                    && !session_key_b64.is_empty()
                                {
                                    match SessionKey::from_base64(session_key_b64) {
                                        Ok(sk) => {
                                            let inbound = InboundGroupSession::new(
                                                &sk,
                                                SessionConfig::version_2(),
                                            );
                                            store.add_inbound_session(
                                                room_id,
                                                session_id,
                                                sender,
                                                sender_key_val,
                                                &inbound,
                                                pickle_key,
                                            );
                                            println!(
                                                "[megolm] Received room key from {} for room {} (session: {})",
                                                sender,
                                                room_id,
                                                &session_id[..8.min(session_id.len())]
                                            );
                                        }
                                        Err(e) => {
                                            println!(
                                                "[error] Bad session key from {}: {}",
                                                sender, e
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        println!("[warn] Failed to decrypt to-device event from {}: {:?}", sender, e);
                    }
                }
            }
        }
    }
}

enum GroupResult {
    Back,
    Logout,
    Exit,
}

/// The main group chat loop
pub fn group_chat_loop(
    http: &reqwest::blocking::Client,
    tok: &str,
    uid: &str,
    device_id: &str,
    sender_key: &str,
    room_id: &str,
    account: Arc<Mutex<Account>>,
    kem_sk: Arc<Vec<u8>>,
    megolm_session: Arc<Mutex<GroupSession>>,
    store: Arc<Mutex<MegolmStore>>,
    olm_cache: Arc<Mutex<OlmSessionCache>>,
    username: &str,
    pickle_key: [u8; 32],
) -> GroupResult {
    let members = query_room_members(http, tok, room_id);
    let member_names: Vec<String> = members
        .iter()
        .filter(|m| m.as_str() != uid)
        .cloned()
        .collect();

    println!("\n========================================");
    println!("  PQXDH Group Chat (Megolm)");
    println!("  Post-quantum key distribution: ACTIVE");
    println!("  Room: {}", room_id);
    println!("  Members: {} + you", member_names.len());
    for m in &member_names {
        println!("    - {}", m);
    }
    println!("  /logout  - switch account");
    println!("  /exit    - quit program");
    println!("  /back    - return to group menu");
    println!("  /members - show room members");
    println!("  /rotate  - force key rotation");
    println!("  /clear   - clear chat history");
    println!("========================================\n");

    let history_key = format!("group-{}", &room_id[..12.min(room_id.len())]);
    show_history(&history_key);

    // Initial sync to get next_batch token
    let initial = sync(http, tok, None, 500);
    let since = Arc::new(Mutex::new(
        initial["next_batch"].as_str().map(|s| s.to_string()),
    ));

    // Process any to-device events from initial sync
    {
        let mut acct = account.lock().unwrap();
        let mut st = store.lock().unwrap();
        process_to_device_events(&initial, uid, &mut acct, &kem_sk, &mut st, &pickle_key);
    }

    let mut scanned_messages: HashSet<String> = HashSet::new();

    // Backfill missed messages — collect events first, then decrypt
    {
        let mut events_to_decrypt: Vec<(String, serde_json::Value)> = Vec::new();
        if let Some(rooms) = initial["rooms"]["join"].as_object() {
            if let Some(rd) = rooms.get(room_id) {
                if let Some(evts) = rd["timeline"]["events"].as_array() {
                    for evt in evts {
                        let event_id = evt["event_id"].as_str().unwrap_or("");
                        if !event_id.is_empty() {
                            if scanned_messages.contains(event_id) {
                                continue;
                            }
                            scanned_messages.insert(event_id.to_string());
                        }

                        let sender = evt["sender"].as_str().unwrap_or("");
                        if sender == uid {
                            continue;
                        }
                        if evt["type"].as_str() != Some("m.room.encrypted") {
                            continue;
                        }

                        let mut evt_with_room = evt.clone();
                        evt_with_room["room_id"] = serde_json::Value::String(room_id.to_string());
                        events_to_decrypt.push((sender.to_string(), evt_with_room));
                    }
                }
            }
        }

        let mut missed = 0;
        for (sender, evt) in &events_to_decrypt {
            let mut st = store.lock().unwrap();
            if let Some((_, text, _)) = try_decrypt_megolm_event(evt, &mut st, &pickle_key) {
                println!("[missed] {}: {}", sender, text);
                append_history(&history_key, sender, &text);
                missed += 1;
            }
        }
        if missed > 0 {
            println!("[backfill] {} missed message(s)\n", missed);
        }
    }

    let running = Arc::new(Mutex::new(true));
    let running_clone = running.clone();
    let scanned_arc = Arc::new(Mutex::new(scanned_messages));
    let scanned_clone = scanned_arc.clone();

    let recv_tok = tok.to_string();
    let recv_uid = uid.to_string();
    let recv_room_id = room_id.to_string();
    let recv_since = since.clone();
    let recv_history_key = history_key.clone();
    let recv_store = store.clone();
    let recv_account = account.clone();
    let recv_kem_sk = kem_sk.clone();

    // Background sync thread for receiving messages
    let handle = std::thread::spawn(move || {
        let http = reqwest::blocking::Client::new();
        while *running_clone.lock().unwrap() {
            let since_val = recv_since.lock().unwrap().clone();
            let r = sync(&http, &recv_tok, since_val.as_deref(), 5000);
            *recv_since.lock().unwrap() = r["next_batch"].as_str().map(|s| s.to_string());

            // Process to-device events (room key delivery)
            {
                let mut acct = recv_account.lock().unwrap();
                let mut st = recv_store.lock().unwrap();
                process_to_device_events(
                    &r,
                    &recv_uid,
                    &mut acct,
                    &recv_kem_sk,
                    &mut st,
                    &pickle_key,
                );
            }

            // Process room timeline events
            if let Some(rooms) = r["rooms"]["join"].as_object() {
                for (rid, rd) in rooms {
                    if rid != &recv_room_id {
                        continue;
                    }
                    if let Some(evts) = rd["timeline"]["events"].as_array() {
                        for evt in evts {
                            let event_id = evt["event_id"].as_str().unwrap_or("");
                            if !event_id.is_empty() {
                                let mut scanned = scanned_clone.lock().unwrap();
                                if scanned.contains(event_id) {
                                    continue;
                                }
                                scanned.insert(event_id.to_string());
                            }

                            let sender = evt["sender"].as_str().unwrap_or("");
                            if sender == recv_uid {
                                continue;
                            }
                            if evt["type"].as_str() != Some("m.room.encrypted") {
                                continue;
                            }

                            // Inject room_id for decryption lookup
                            let mut evt_with_room = evt.clone();
                            evt_with_room["room_id"] =
                                serde_json::Value::String(recv_room_id.clone());

                            let mut st = recv_store.lock().unwrap();
                            if let Some((_, text, _)) =
                                try_decrypt_megolm_event(&evt_with_room, &mut st, &pickle_key)
                            {
                                println!("\r{}: {}", sender, text);
                                append_history(&recv_history_key, sender, &text);
                                print!("> ");
                                io::stdout().flush().ok();
                            } else {
                                println!("\r[warn] Could not decrypt message from {} (no session key yet)", sender);
                                print!("> ");
                                io::stdout().flush().ok();
                            }
                        }
                    }

                    // Handle new member joins: membership state events
                    if let Some(state_evts) = rd["state"]["events"].as_array() {
                        for evt in state_evts {
                            if evt["type"].as_str() == Some("m.room.member") {
                                let membership = evt["content"]["membership"].as_str().unwrap_or("");
                                let who = evt["state_key"].as_str().unwrap_or("");
                                if membership == "join" && who != recv_uid {
                                    println!("\r[room] {} joined the room", who);
                                    print!("> ");
                                    io::stdout().flush().ok();
                                } else if membership == "leave" {
                                    println!("\r[room] {} left the room — key rotation needed", who);
                                    // Invalidate outbound session to force rotation
                                    let mut st = recv_store.lock().unwrap();
                                    st.invalidate_outbound(&recv_room_id);
                                    print!("> ");
                                    io::stdout().flush().ok();
                                }
                            }
                        }
                    }
                }
            }
        }
    });

    // Main input loop
    let room_id_owned = room_id.to_string();
    let sender_key_owned = sender_key.to_string();
    let device_id_owned = device_id.to_string();
    let uid_owned = uid.to_string();

    let result = loop {
        print!("> ");
        io::stdout().flush().unwrap();

        let mut line = String::new();
        io::stdin().read_line(&mut line).unwrap();
        let line = line.trim();

        if line == "/logout" {
            break GroupResult::Logout;
        }
        if line == "/exit" {
            break GroupResult::Exit;
        }
        if line == "/back" {
            // Signal to return to group menu
            *running.lock().unwrap() = false;
            let _ = handle.join();
            let st = store.lock().unwrap();
            st.save(&format!("group"), &pickle_key);
            return GroupResult::Back;
        }
        if line == "/clear" {
            clear_history(&history_key);
            continue;
        }
        if line == "/members" {
            let members = query_room_members(http, tok, room_id);
            println!("\n--- Room Members ---");
            for m in &members {
                println!("  {}", m);
            }
            println!("--------------------\n");
            continue;
        }
        if line == "/rotate" {
            println!("[megolm] Forcing key rotation...");
            let mut st = store.lock().unwrap();
            st.invalidate_outbound(&room_id_owned);
            let new_session = st.create_outbound_session(&room_id_owned, &pickle_key);
            *megolm_session.lock().unwrap() = new_session;

            // Redistribute key
            let ms = megolm_session.lock().unwrap();
            let mut acct = account.lock().unwrap();
            let mut oc = olm_cache.lock().unwrap();
            distribute_megolm_key(
                http,
                tok,
                &uid_owned,
                &device_id_owned,
                &sender_key_owned,
                &mut acct,
                &room_id_owned,
                &ms,
                &mut st,
                &mut oc,
                &pickle_key,
            );
            println!("[megolm] Key rotation complete");
            continue;
        }

        if line.is_empty() {
            continue;
        }

        // Check if we need key rotation
        {
            let mut st = store.lock().unwrap();
            if st.needs_rotation(&room_id_owned) {
                println!("[megolm] Rotating session key...");
                let new_session = st.create_outbound_session(&room_id_owned, &pickle_key);
                *megolm_session.lock().unwrap() = new_session;

                let ms = megolm_session.lock().unwrap();
                let mut acct = account.lock().unwrap();
                let mut oc = olm_cache.lock().unwrap();
                distribute_megolm_key(
                    http,
                    tok,
                    &uid_owned,
                    &device_id_owned,
                    &sender_key_owned,
                    &mut acct,
                    &room_id_owned,
                    &ms,
                    &mut st,
                    &mut oc,
                    &pickle_key,
                );
            }
        }

        // Encrypt and send with Megolm
        {
            let mut ms = megolm_session.lock().unwrap();
            send_group_encrypted(
                http,
                tok,
                &room_id_owned,
                &mut ms,
                line,
                &sender_key_owned,
                &device_id_owned,
            );

            // Update store
            let mut st = store.lock().unwrap();
            st.update_outbound_session(&room_id_owned, &ms, 1, &pickle_key);
            st.save(&format!("group"), &pickle_key);
        }

        append_history(&history_key, &uid_owned, line);
    };

    *running.lock().unwrap() = false;
    let _ = handle.join();

    // Save final store state
    {
        let st = store.lock().unwrap();
        st.save(&format!("group"), &pickle_key);
    }

    result
}

/// Query the server for pending group room invites
fn list_pending_invites(
    http: &reqwest::blocking::Client,
    tok: &str,
) -> Vec<(String, String)> {
    // Returns: Vec<(room_id, inviter)>
    let r = sync(http, tok, None, 500);
    let mut invites = Vec::new();

    if let Some(rooms) = r["rooms"]["invite"].as_object() {
        for (room_id, room_data) in rooms {
            let mut inviter = String::from("unknown");
            if let Some(evts) = room_data["invite_state"]["events"].as_array() {
                for evt in evts {
                    if evt["type"].as_str() == Some("m.room.member") {
                        if let Some(sender) = evt["sender"].as_str() {
                            inviter = sender.to_string();
                        }
                    }
                }
            }
            invites.push((room_id.clone(), inviter));
        }
    }
    invites
}

/// Entry point for group chat flow (called from main)
/// Loops so user can manage multiple groups without re-logging in
pub fn run_group_chat(
    http: &reqwest::blocking::Client,
    tok: &str,
    uid: &str,
    device_id: &str,
    sender_key: &str,
    account: &mut Account,
    kem_sk_bytes: &[u8],
    username: &str,
    pickle_key: [u8; 32],
) -> bool {
    loop {
        println!("\n[group] Group Chat Mode (Megolm + PQXDH)");

        // Show pending invites
        let invites = list_pending_invites(http, tok);
        if !invites.is_empty() {
            println!("\n  Pending invites:");
            for (i, (room_id, inviter)) in invites.iter().enumerate() {
                println!("    [{}] {} (from {})", i + 1, room_id, inviter);
            }
        }

        println!("\n  [c] Create new group room");
        println!("  [j] Join room by ID");
        if !invites.is_empty() {
            println!("  [1-{}] Accept invite", invites.len());
        }
        println!("  [q] Back to main menu");
        let choice = prompt("Choice: ");

        // Check if it's a number (accept invite)
        if let Ok(num) = choice.trim().parse::<usize>() {
            if num >= 1 && num <= invites.len() {
                let room_id = invites[num - 1].0.clone();
                println!("[room] Accepting invite to {}...", room_id);
                if !join_room(http, tok, &room_id) {
                    continue;
                }
                // Enter that room's chat
                let result = enter_group_room(
                    http, tok, uid, device_id, sender_key,
                    account, kem_sk_bytes, username, pickle_key,
                    &room_id,
                );
                match result {
                    GroupResult::Back => continue,
                    GroupResult::Logout => return true,
                    GroupResult::Exit => return false,
                }
            } else {
                println!("[error] Invalid invite number");
                continue;
            }
        }

        match choice.to_lowercase().trim() {
            "c" => {
                let room_name = prompt("Room name: ");
                let peers_input = prompt("Invite users (comma-separated usernames): ");
                let invitees: Vec<String> = peers_input
                    .split(',')
                    .map(|s| {
                        let s = s.trim();
                        if s.starts_with('@') {
                            s.to_string()
                        } else {
                            format!("@{}:matrix.local", s)
                        }
                    })
                    .collect();

                let room_id = create_group_room(http, tok, &invitees, &room_name);

                let result = enter_group_room(
                    http, tok, uid, device_id, sender_key,
                    account, kem_sk_bytes, username, pickle_key,
                    &room_id,
                );
                match result {
                    GroupResult::Back => continue,
                    GroupResult::Logout => return true,
                    GroupResult::Exit => return false,
                }
            }
            "j" => {
                let room_id = prompt("Room ID: ");
                let room_id = room_id.trim().to_string();
                if !join_room(http, tok, &room_id) {
                    continue;
                }

                let result = enter_group_room(
                    http, tok, uid, device_id, sender_key,
                    account, kem_sk_bytes, username, pickle_key,
                    &room_id,
                );
                match result {
                    GroupResult::Back => continue,
                    GroupResult::Logout => return true,
                    GroupResult::Exit => return false,
                }
            }
            "q" => return true,
            _ => {
                println!("[error] Invalid choice");
            }
        }
    }
}


/// Set up Megolm session for a room and enter the chat loop
fn enter_group_room(
    http: &reqwest::blocking::Client,
    tok: &str,
    uid: &str,
    device_id: &str,
    sender_key: &str,
    account: &mut Account,
    kem_sk_bytes: &[u8],
    username: &str,
    pickle_key: [u8; 32],
    room_id: &str,
) -> GroupResult {
    // Wait a moment for invites to be processed
    std::thread::sleep(std::time::Duration::from_millis(1000));

    // Initialize Megolm store
    let mut store = MegolmStore::load("group", &pickle_key);

    // Create or restore outbound Megolm session
    let megolm_session = if store.needs_rotation(room_id) {
        let session = store.create_outbound_session(room_id, &pickle_key);
        println!("[megolm] New outbound session: {}", &session.session_id()[..8]);
        session
    } else {
        match store.get_outbound_session(room_id, &pickle_key) {
            Some(s) => {
                println!("[megolm] Restored outbound session: {}", &s.session_id()[..8]);
                s
            }
            None => {
                let session = store.create_outbound_session(room_id, &pickle_key);
                println!("[megolm] New outbound session: {}", &session.session_id()[..8]);
                session
            }
        }
    };

    // Initialize Olm session cache and distribute keys
    let mut olm_cache = OlmSessionCache::new();

    distribute_megolm_key(
        http,
        tok,
        uid,
        device_id,
        sender_key,
        account,
        room_id,
        &megolm_session,
        &mut store,
        &mut olm_cache,
        &pickle_key,
    );

    store.save("group", &pickle_key);

    // Wrap shared state in arcs — duplicate the Account via pickle round-trip
    let pickle_key_arr: [u8; 32] = pickle_key;
    let acct_pickle = account.pickle().encrypt(&pickle_key_arr);
    let acct_copy: Account = vodozemac::olm::AccountPickle::from_encrypted(
        &acct_pickle, &pickle_key_arr
    ).expect("Account pickle round-trip failed").into();
    let account_arc = Arc::new(Mutex::new(acct_copy));
    let kem_sk_arc = Arc::new(kem_sk_bytes.to_vec());
    let megolm_arc = Arc::new(Mutex::new(megolm_session));
    let store_arc = Arc::new(Mutex::new(store));
    let olm_cache_arc = Arc::new(Mutex::new(olm_cache));

    group_chat_loop(
        http,
        tok,
        uid,
        device_id,
        sender_key,
        room_id,
        account_arc,
        kem_sk_arc,
        megolm_arc,
        store_arc,
        olm_cache_arc,
        username,
        pickle_key,
    )
}
