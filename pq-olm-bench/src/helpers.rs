use vodozemac::olm::{Account, Session, SessionConfig, OlmMessage};
use oqs::kem::{Kem, Algorithm};

/// Create a classical X3DH session pair (Alice outbound, Bob inbound).
/// Returns (alice_session, bob_session).
pub fn create_classical_session_pair() -> (Account, Account, Session, Session) {
    let alice = Account::new();
    let mut bob = Account::new();
    bob.generate_one_time_keys(1);

    let otk = *bob.one_time_keys().values().next().expect("No OTK generated");

    let mut alice_session = alice.create_outbound_session(
        SessionConfig::version_2(),
        bob.curve25519_key(),
        otk,
    );

    // Alice encrypts an initial message to produce a PreKeyMessage
    let msg = alice_session.encrypt("bench_init");

    match &msg {
        OlmMessage::PreKey(pkm) => {
            let result = bob.create_inbound_session(
                alice.curve25519_key(),
                pkm,
            ).expect("Classical inbound session failed");
            (alice, bob, alice_session, result.session)
        }
        _ => panic!("Expected PreKeyMessage from first encrypt"),
    }
}

/// Create a PQXDH session pair (Alice outbound, Bob inbound).
/// Returns (alice_account, bob_account, alice_session, bob_session, kem_pk, kem_sk).
pub fn create_pqxdh_session_pair() -> (Account, Account, Session, Session, Vec<u8>, Vec<u8>) {
    let alice = Account::new();
    let mut bob = Account::new();

    // Bob generates signed prekey and OTKs
    let (bob_spk, _sig) = bob.generate_signed_prekey();
    bob.generate_one_time_keys(1);
    let otk = *bob.one_time_keys().values().next().expect("No OTK generated");

    // Bob generates ML-KEM-768 keypair
    let kem = Kem::new(Algorithm::MlKem768).expect("ML-KEM-768 unavailable");
    let (kem_pk, kem_sk) = kem.keypair().expect("KEM keygen failed");
    let pk_bytes = kem_pk.as_ref().to_vec();
    let sk_bytes = kem_sk.as_ref().to_vec();

    // Alice creates outbound PQXDH session
    let (mut alice_session, kem_ct) = alice.create_outbound_session_pqxdh(
        SessionConfig::version_2(),
        bob.curve25519_key(),
        bob_spk,
        Some(otk),
        &pk_bytes,
    );

    // Alice encrypts initial message
    let msg = alice_session.encrypt("bench_init");

    match &msg {
        OlmMessage::PreKey(pkm) => {
            let result = bob.create_inbound_session_pqxdh(
                alice.curve25519_key(),
                pkm,
                &kem_ct,
                &sk_bytes,
            ).expect("PQXDH inbound session failed");
            (alice, bob, alice_session, result.session, pk_bytes, sk_bytes)
        }
        _ => panic!("Expected PreKeyMessage from first encrypt"),
    }
}

/// Generate a plaintext string of given byte length.
pub fn make_plaintext(size: usize) -> String {
    "A".repeat(size)
}

/// Get ciphertext byte length from an OlmMessage.
pub fn olm_message_bytes(msg: &OlmMessage) -> Vec<u8> {
    match msg {
        OlmMessage::PreKey(m) => m.to_bytes(),
        OlmMessage::Normal(m) => m.to_bytes(),
    }
}
