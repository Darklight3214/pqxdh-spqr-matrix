// ========== MEGOLM SESSION STORE ==========
// Persistent storage for Megolm group sessions (outbound + inbound).

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use vodozemac::megolm::{
    GroupSession, GroupSessionPickle, InboundGroupSession, InboundGroupSessionPickle,
    SessionConfig, SessionKey,
};

use crate::current_timestamp;

/// Key rotation policy constants
const MAX_MESSAGES_PER_SESSION: u32 = 100;
const MAX_SESSION_AGE_SECS: u64 = 7 * 24 * 3600; // 7 days

/// Metadata for an outbound Megolm session
#[derive(Serialize, Deserialize, Clone)]
pub struct OutboundSessionInfo {
    /// Encrypted pickle of the GroupSession
    pub pickle: String,
    /// Room ID this session belongs to
    pub room_id: String,
    /// Session ID for identification
    pub session_id: String,
    /// Number of messages encrypted with this session
    pub message_count: u32,
    /// Timestamp when this session was created
    pub created_at: u64,
    /// Set of (user_id, device_id) pairs that have received this session key
    pub shared_with: Vec<(String, String)>,
}

/// Metadata for an inbound Megolm session
#[derive(Serialize, Deserialize, Clone)]
pub struct InboundSessionInfo {
    /// Encrypted pickle of the InboundGroupSession
    pub pickle: String,
    /// Room ID
    pub room_id: String,
    /// Session ID
    pub session_id: String,
    /// Sender's user ID
    pub sender_user_id: String,
    /// Sender's Curve25519 identity key
    pub sender_key: String,
}

/// The persistent Megolm session store
#[derive(Serialize, Deserialize, Default)]
pub struct MegolmStore {
    /// Outbound sessions: room_id -> session info
    pub outbound: HashMap<String, OutboundSessionInfo>,
    /// Inbound sessions: (room_id, session_id) -> session info
    pub inbound: HashMap<String, InboundSessionInfo>,
}

impl MegolmStore {
    /// Load the store from disk, or create a new empty one
    pub fn load(username: &str, pickle_key: &[u8; 32]) -> Self {
        let path = format!(".pqxdh-{}.megolm", username);
        if !Path::new(&path).exists() {
            return Self::default();
        }
        match fs::read_to_string(&path) {
            Ok(raw) => serde_json::from_str(&raw).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    /// Persist the store to disk
    pub fn save(&self, username: &str, _pickle_key: &[u8; 32]) {
        let path = format!(".pqxdh-{}.megolm", username);
        if let Ok(json) = serde_json::to_string_pretty(self) {
            let _ = fs::write(&path, json);
        }
    }

    /// Create a new outbound Megolm session for a room
    pub fn create_outbound_session(
        &mut self,
        room_id: &str,
        pickle_key: &[u8; 32],
    ) -> GroupSession {
        let session = GroupSession::new(SessionConfig::version_2());
        let session_id = session.session_id();
        let pickle = session.pickle().encrypt(pickle_key);

        let info = OutboundSessionInfo {
            pickle,
            room_id: room_id.to_string(),
            session_id,
            message_count: 0,
            created_at: current_timestamp(),
            shared_with: Vec::new(),
        };

        self.outbound.insert(room_id.to_string(), info);
        session
    }

    /// Get (and unpickle) the outbound session for a room, if one exists
    pub fn get_outbound_session(
        &self,
        room_id: &str,
        pickle_key: &[u8; 32],
    ) -> Option<GroupSession> {
        let info = self.outbound.get(room_id)?;
        let pickle = GroupSessionPickle::from_encrypted(&info.pickle, pickle_key).ok()?;
        Some(GroupSession::from_pickle(pickle))
    }

    /// Update the outbound session pickle after encrypting messages
    pub fn update_outbound_session(
        &mut self,
        room_id: &str,
        session: &GroupSession,
        messages_sent: u32,
        pickle_key: &[u8; 32],
    ) {
        if let Some(info) = self.outbound.get_mut(room_id) {
            info.pickle = session.pickle().encrypt(pickle_key);
            info.message_count += messages_sent;
            info.session_id = session.session_id();
        }
    }

    /// Mark that a session key has been shared with a (user, device)
    pub fn mark_shared(&mut self, room_id: &str, user_id: &str, device_id: &str) {
        if let Some(info) = self.outbound.get_mut(room_id) {
            let pair = (user_id.to_string(), device_id.to_string());
            if !info.shared_with.contains(&pair) {
                info.shared_with.push(pair);
            }
        }
    }

    /// Check if the outbound session for a room needs rotation
    pub fn needs_rotation(&self, room_id: &str) -> bool {
        match self.outbound.get(room_id) {
            None => true, // No session means we need a new one
            Some(info) => {
                if info.message_count >= MAX_MESSAGES_PER_SESSION {
                    println!(
                        "[megolm] Session rotation: {} messages sent (max {})",
                        info.message_count, MAX_MESSAGES_PER_SESSION
                    );
                    return true;
                }
                let age = current_timestamp().saturating_sub(info.created_at);
                if age >= MAX_SESSION_AGE_SECS {
                    println!(
                        "[megolm] Session rotation: age {} secs (max {})",
                        age, MAX_SESSION_AGE_SECS
                    );
                    return true;
                }
                false
            }
        }
    }

    /// Force rotation: remove the outbound session for a room
    pub fn invalidate_outbound(&mut self, room_id: &str) {
        self.outbound.remove(room_id);
    }

    /// Store an inbound Megolm session (received via m.room_key)
    pub fn add_inbound_session(
        &mut self,
        room_id: &str,
        session_id: &str,
        sender_user_id: &str,
        sender_key: &str,
        session: &InboundGroupSession,
        pickle_key: &[u8; 32],
    ) {
        let pickle = session.pickle().encrypt(pickle_key);
        let key = format!("{}|{}", room_id, session_id);

        let info = InboundSessionInfo {
            pickle,
            room_id: room_id.to_string(),
            session_id: session_id.to_string(),
            sender_user_id: sender_user_id.to_string(),
            sender_key: sender_key.to_string(),
        };

        self.inbound.insert(key, info);
    }

    /// Retrieve an inbound session by room_id and session_id
    pub fn get_inbound_session(
        &self,
        room_id: &str,
        session_id: &str,
        pickle_key: &[u8; 32],
    ) -> Option<InboundGroupSession> {
        let key = format!("{}|{}", room_id, session_id);
        let info = self.inbound.get(&key)?;
        let pickle = InboundGroupSessionPickle::from_encrypted(&info.pickle, pickle_key).ok()?;
        Some(InboundGroupSession::from_pickle(pickle))
    }

    /// Update an inbound session's pickle (after decrypting messages, the ratchet advances)
    pub fn update_inbound_session(
        &mut self,
        room_id: &str,
        session_id: &str,
        session: &InboundGroupSession,
        pickle_key: &[u8; 32],
    ) {
        let key = format!("{}|{}", room_id, session_id);
        if let Some(info) = self.inbound.get_mut(&key) {
            info.pickle = session.pickle().encrypt(pickle_key);
        }
    }

    /// Get the list of (user_id, device_id) pairs that already have the current session key
    pub fn shared_with(&self, room_id: &str) -> Vec<(String, String)> {
        self.outbound
            .get(room_id)
            .map(|info| info.shared_with.clone())
            .unwrap_or_default()
    }

    /// Get the outbound session ID for a room
    pub fn outbound_session_id(&self, room_id: &str) -> Option<String> {
        self.outbound.get(room_id).map(|info| info.session_id.clone())
    }
}
