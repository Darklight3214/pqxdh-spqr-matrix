#![allow(missing_docs)]
use vodozemac::olm::{Account, SessionConfig};
use oqs::kem::{Kem, Algorithm};

#[test]
fn test_triple_ratchet_flow() {
    let mut alice = Account::new();
    let mut bob = Account::new();

    bob.generate_one_time_keys(1);
    let bob_ik = bob.identity_keys().curve25519.clone();
    let bob_otk = bob.one_time_keys().into_values().next().unwrap();
    let bob_spk = bob.generate_signed_prekey().0.clone();

    let kem_algo = Kem::new(Algorithm::MlKem768).unwrap();
    let (bob_kem_pk, bob_kem_sk) = kem_algo.keypair().unwrap();

    let (mut alice_session, kem_ct) = alice.create_outbound_session_pqxdh(
        SessionConfig::version_2(),
        bob_ik,
        bob_spk,
        Some(bob_otk),
        bob_kem_pk.as_ref(),
    );

    // Message 1: Alice -> Bob
    let m1_wire = alice_session.encrypt_pq("Message 1 From Alice");
    
    let bob_session_result = bob.create_inbound_session_pqxdh(
        alice.identity_keys().curve25519,
        match &m1_wire.message {
            vodozemac::olm::OlmMessage::PreKey(pk) => pk,
            _ => panic!("Expected PreKey message"),
        },
        &kem_ct,
        bob_kem_sk.as_ref()
    ).unwrap();
    
    let mut bob_session = bob_session_result.session;
    
    // Remember: create_inbound_session_pqxdh decrypted the PreKey (M1 payload), but Bob still needs to process M1's Braid messages!
    // Since create_inbound_session doesn't take braid_msgs, we simulate what pqxdh-node SHOULD be doing but isn't.
    // Wait, if we call `decrypt_pq` here, it will try to decrypt the message again! 
    // We can't call decrypt_pq because the classical message is already decrypted by create_inbound_session!
    // We MUST extract the SPQR Braid state advancement out of decrypt_pq, OR make create_inbound_session handle it!
    
    println!("Alice's M1 plaintext inside create_inbound_session: {}", String::from_utf8(bob_session_result.plaintext).unwrap());
    
    // Message 2: Bob -> Alice
    // Bob encrypts a reply. Bob's SpqrState is stuck on NoHeaderReceived.
    let mut m2_wire = bob_session.encrypt_pq("Message 2 From Bob");

    // Alice decrypts M2
    let (m2_pt, mut a_resp_1) = alice_session.decrypt_pq(
        &m2_wire.message,
        m2_wire.spqr_meta.as_ref(),
        &m2_wire.braid_msgs
    ).unwrap();
    println!("Alice decrypted M2: {}", String::from_utf8(m2_pt).unwrap());

    // Message 3: Alice -> Bob
    let mut m3_wire = alice_session.encrypt_pq("Message 3 From Alice");
    m3_wire.braid_msgs.append(&mut a_resp_1);

    // Bob decrypts M3
    let (m3_pt, _) = bob_session.decrypt_pq(
        &m3_wire.message,
        m3_wire.spqr_meta.as_ref(),
        &m3_wire.braid_msgs
    ).unwrap();
    println!("Bob decrypted M3: {}", String::from_utf8(m3_pt).unwrap());
}
