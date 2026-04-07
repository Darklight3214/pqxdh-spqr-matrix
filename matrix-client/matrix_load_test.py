#!/usr/bin/env python3
"""
Matrix PQXDH Integration with Load Testing

This implements PQXDH in a Matrix-like protocol flow:
1. Client stores PQXDH identity keys on server
2. Clients perform PQXDH handshake
3. Messages encrypted with session keys
4. Load testing with multiple clients
"""
import oqs
import time
import asyncio
import json
from concurrent.futures import ThreadPoolExecutor
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os


class PQXDHKeyBundle:
    """PQXDH identity and one-time keys (like Matrix prekeys)"""
    
    def __init__(self, user_id):
        self.user_id = user_id
        
        # Identity keys (long-term)
        self.x25519_identity_private = x25519.X25519PrivateKey.generate()
        self.x25519_identity_public = self.x25519_identity_private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        self.kyber_identity_kem = oqs.KeyEncapsulation("ML-KEM-768")
        self.kyber_identity_public = self.kyber_identity_kem.generate_keypair()
        
        # One-time keys (would generate multiple in production)
        self.x25519_onetime_private = x25519.X25519PrivateKey.generate()
        self.x25519_onetime_public = self.x25519_onetime_private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    
    def get_public_bundle(self):
        """Get public keys to upload to server"""
        return {
            'user_id': self.user_id,
            'x25519_identity': self.x25519_identity_public,
            'kyber_identity': self.kyber_identity_public,
            'x25519_onetime': self.x25519_onetime_public
        }


class MatrixPQXDHClient:
    """Matrix client with PQXDH encryption"""
    
    def __init__(self, user_id):
        self.user_id = user_id
        self.key_bundle = PQXDHKeyBundle(user_id)
        self.sessions = {}  # recipient_id -> session
        self.message_counter = 0
    
    def claim_keys(self, recipient_public_bundle):
        """
        Initiate PQXDH handshake (Bob claims Alice's keys)
        Returns handshake data to send to recipient
        """
        start = time.perf_counter()
        
        # Generate ephemeral keys
        ephemeral_private = x25519.X25519PrivateKey.generate()
        ephemeral_public = ephemeral_private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        # X25519 triple DH (like X3DH)
        alice_identity = x25519.X25519PublicKey.from_public_bytes(
            recipient_public_bundle['x25519_identity']
        )
        alice_onetime = x25519.X25519PublicKey.from_public_bytes(
            recipient_public_bundle['x25519_onetime']
        )
        
        dh1 = self.key_bundle.x25519_identity_private.exchange(alice_identity)
        dh2 = ephemeral_private.exchange(alice_identity)
        dh3 = ephemeral_private.exchange(alice_onetime)
        
        x25519_shared = dh1 + dh2 + dh3
        
        # ML-KEM-768 encapsulation
        bob_kem = oqs.KeyEncapsulation("ML-KEM-768")
        kyber_ciphertext, kyber_shared = bob_kem.encap_secret(
            recipient_public_bundle['kyber_identity']
        )
        
        # Combine and derive session key
        combined = x25519_shared + kyber_shared
        kdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'Matrix-PQXDH-v1')
        session_key = kdf.derive(combined)
        
        # Create session
        session = {
            'aes': AESGCM(session_key),
            'shared_secret': session_key,
            'created_at': time.time()
        }
        self.sessions[recipient_public_bundle['user_id']] = session
        
        handshake_time = (time.perf_counter() - start) * 1000
        
        return {
            'sender': self.user_id,
            'recipient': recipient_public_bundle['user_id'],
            'ephemeral_public': ephemeral_public,
            'kyber_ciphertext': kyber_ciphertext,
            'sender_identity_public': self.key_bundle.x25519_identity_public,
            'handshake_time_ms': handshake_time
        }
    
    def process_handshake(self, handshake_data):
        """
        Complete PQXDH handshake (Alice processes Bob's handshake)
        """
        start = time.perf_counter()
        
        # X25519 triple DH
        bob_identity = x25519.X25519PublicKey.from_public_bytes(
            handshake_data['sender_identity_public']
        )
        bob_ephemeral = x25519.X25519PublicKey.from_public_bytes(
            handshake_data['ephemeral_public']
        )
        
        dh1 = self.key_bundle.x25519_onetime_private.exchange(bob_ephemeral)
        dh2 = self.key_bundle.x25519_identity_private.exchange(bob_ephemeral)
        dh3 = self.key_bundle.x25519_identity_private.exchange(bob_identity)
        
        x25519_shared = dh3 + dh2 + dh1
        
        # ML-KEM-768 decapsulation
        kyber_shared = self.key_bundle.kyber_identity_kem.decap_secret(
            handshake_data['kyber_ciphertext']
        )
        
        # Combine and derive session key
        combined = x25519_shared + kyber_shared
        kdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'Matrix-PQXDH-v1')
        session_key = kdf.derive(combined)
        
        # Create session
        session = {
            'aes': AESGCM(session_key),
            'shared_secret': session_key,
            'created_at': time.time()
        }
        self.sessions[handshake_data['sender']] = session
        
        complete_time = (time.perf_counter() - start) * 1000
        
        return complete_time
    
    def encrypt_message(self, recipient_id, plaintext):
        """Encrypt message for recipient"""
        if recipient_id not in self.sessions:
            raise ValueError(f"No session with {recipient_id}")
        
        session = self.sessions[recipient_id]
        nonce = os.urandom(12)
        
        start = time.perf_counter()
        ciphertext = session['aes'].encrypt(nonce, plaintext, None)
        encrypt_time = (time.perf_counter() - start) * 1000
        
        self.message_counter += 1
        
        return {
            'sender': self.user_id,
            'recipient': recipient_id,
            'nonce': nonce,
            'ciphertext': ciphertext,
            'message_id': self.message_counter,
            'encrypt_time_ms': encrypt_time
        }
    
    def decrypt_message(self, encrypted_message):
        """Decrypt message from sender"""
        sender_id = encrypted_message['sender']
        
        if sender_id not in self.sessions:
            raise ValueError(f"No session with {sender_id}")
        
        session = self.sessions[sender_id]
        
        start = time.perf_counter()
        plaintext = session['aes'].decrypt(
            encrypted_message['nonce'],
            encrypted_message['ciphertext'],
            None
        )
        decrypt_time = (time.perf_counter() - start) * 1000
        
        return plaintext, decrypt_time


def simulate_matrix_conversation(num_messages=1000, message_size=1024):
    """Simulate a Matrix conversation with PQXDH encryption"""
    print(f"\nSimulating Matrix conversation: {num_messages} messages")
    
    # Create clients
    alice = MatrixPQXDHClient("@alice:matrix.local")
    bob = MatrixPQXDHClient("@bob:matrix.local")
    
    # Exchange public keys (simulating /keys/query)
    alice_public = alice.key_bundle.get_public_bundle()
    bob_public = bob.key_bundle.get_public_bundle()
    
    # Bob initiates encrypted session with Alice
    print("  Bob initiating PQXDH handshake...")
    handshake_data = bob.claim_keys(alice_public)
    print(f"  Handshake created: {handshake_data['handshake_time_ms']:.2f}ms")
    
    # Alice processes handshake
    print("  Alice processing handshake...")
    complete_time = alice.process_handshake(handshake_data)
    print(f"  Handshake completed: {complete_time:.2f}ms")
    
    # Verify session keys match
    if alice.sessions[bob.user_id]['shared_secret'] != bob.sessions[alice.user_id]['shared_secret']:
        raise ValueError("Session keys don't match!")
    
    print("  Session established successfully")
    
    # Simulate conversation
    messages = [os.urandom(message_size) for _ in range(num_messages)]
    
    print(f"  Sending {num_messages} encrypted messages...")
    
    encrypt_times = []
    decrypt_times = []
    encrypted_messages = []
    
    total_start = time.perf_counter()
    
    # Bob sends to Alice
    for msg in messages:
        encrypted = bob.encrypt_message(alice.user_id, msg)
        encrypted_messages.append(encrypted)
        encrypt_times.append(encrypted['encrypt_time_ms'])
    
    # Alice receives and decrypts
    for encrypted in encrypted_messages:
        plaintext, decrypt_time = alice.decrypt_message(encrypted)
        decrypt_times.append(decrypt_time)
    
    total_time = time.perf_counter() - total_start
    
    total_bytes = num_messages * message_size
    throughput_mbps = (total_bytes / total_time) / (1024 * 1024)
    
    print(f"\n  Results:")
    print(f"    Total time: {total_time:.3f}s")
    print(f"    Throughput: {throughput_mbps:.2f} MB/s")
    print(f"    Avg encrypt: {sum(encrypt_times)/len(encrypt_times):.3f}ms")
    print(f"    Avg decrypt: {sum(decrypt_times)/len(decrypt_times):.3f}ms")
    print(f"    Messages/sec: {num_messages/total_time:.0f}")
    
    return {
        'throughput_mbps': throughput_mbps,
        'total_time': total_time,
        'handshake_time_ms': handshake_data['handshake_time_ms'] + complete_time
    }


def simulate_multiple_rooms(num_rooms=10, messages_per_room=1000):
    """Simulate multiple Matrix rooms with concurrent encrypted conversations"""
    print(f"\nSimulating {num_rooms} Matrix rooms concurrently")
    
    def run_room_conversation(room_id):
        alice = MatrixPQXDHClient(f"@alice_room{room_id}:matrix.local")
        bob = MatrixPQXDHClient(f"@bob_room{room_id}:matrix.local")
        
        # Handshake
        alice_public = alice.key_bundle.get_public_bundle()
        handshake = bob.claim_keys(alice_public)
        alice.process_handshake(handshake)
        
        # Exchange messages
        messages = [os.urandom(1024) for _ in range(messages_per_room)]
        
        room_start = time.perf_counter()
        
        for msg in messages:
            encrypted = bob.encrypt_message(alice.user_id, msg)
            alice.decrypt_message(encrypted)
        
        room_time = time.perf_counter() - room_start
        
        return {
            'room_id': room_id,
            'time': room_time,
            'bytes': messages_per_room * 1024
        }
    
    total_start = time.perf_counter()
    
    with ThreadPoolExecutor(max_workers=min(num_rooms, 20)) as executor:
        futures = [executor.submit(run_room_conversation, i) for i in range(num_rooms)]
        results = [f.result() for f in futures]
    
    total_time = time.perf_counter() - total_start
    total_bytes = sum(r['bytes'] for r in results)
    throughput_mbps = (total_bytes / total_time) / (1024 * 1024)
    
    print(f"  Completed {num_rooms} rooms in {total_time:.2f}s")
    print(f"  Total throughput: {throughput_mbps:.2f} MB/s")
    print(f"  Rooms/second: {num_rooms/total_time:.2f}")


def main():
    print("="*100)
    print("MATRIX PQXDH INTEGRATION - LOAD TESTING")
    print("="*100)
    
    # Test 1: Single conversation
    print("\nTEST 1: Single encrypted conversation")
    print("-" * 100)
    simulate_matrix_conversation(num_messages=10000, message_size=1024)
    
    # Test 2: Multiple concurrent rooms
    print("\n\nTEST 2: Multiple concurrent rooms")
    print("-" * 100)
    simulate_multiple_rooms(num_rooms=50, messages_per_room=1000)
    
    # Test 3: High load
    print("\n\nTEST 3: High load simulation")
    print("-" * 100)
    simulate_multiple_rooms(num_rooms=100, messages_per_room=500)
    
    print("\n" + "="*100)
    print("TESTING COMPLETE")
    print("="*100)


if __name__ == "__main__":
    main()
