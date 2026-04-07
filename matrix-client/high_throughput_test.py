#!/usr/bin/env python3
"""
High-Throughput PQXDH Testing for 10GB/s Traffic Scenarios

Architecture:
1. PQXDH handshake establishes session keys
2. Symmetric encryption (AES-256-GCM) for message traffic
3. Concurrent sessions for parallelization
4. Throughput measurement under load
"""
import oqs
import time
import threading
import queue
import statistics
from concurrent.futures import ThreadPoolExecutor, as_completed
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os


class HybridPQXDHSession:
    """PQXDH session with symmetric message encryption"""
    
    def __init__(self):
        self.shared_secret = None
        self.aes_key = None
        self.nonce_counter = 0
    
    def perform_handshake_alice(self):
        """Alice generates keys (receiver)"""
        start = time.perf_counter()
        
        # X25519
        x25519_private = x25519.X25519PrivateKey.generate()
        x25519_public = x25519_private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        # ML-KEM-768
        alice_kem = oqs.KeyEncapsulation("ML-KEM-768")
        kyber_public = alice_kem.generate_keypair()
        
        handshake_time = (time.perf_counter() - start) * 1000
        
        return {
            'x25519_private': x25519_private,
            'kyber_kem': alice_kem,
            'public_keys': {
                'x25519': x25519_public,
                'kyber': kyber_public
            },
            'handshake_time_ms': handshake_time
        }
    
    def perform_handshake_bob(self, alice_public_keys):
        """Bob initiates handshake (sender)"""
        start = time.perf_counter()
        
        # X25519 DH
        ephemeral_private = x25519.X25519PrivateKey.generate()
        ephemeral_public = ephemeral_private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        alice_x25519_public = x25519.X25519PublicKey.from_public_bytes(
            alice_public_keys['x25519']
        )
        x25519_shared = ephemeral_private.exchange(alice_x25519_public)
        
        # ML-KEM-768 encapsulation
        bob_kem = oqs.KeyEncapsulation("ML-KEM-768")
        kyber_ciphertext, kyber_shared = bob_kem.encap_secret(
            alice_public_keys['kyber']
        )
        
        # Derive session key
        combined = x25519_shared + kyber_shared
        kdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'PQXDH-v1')
        session_key = kdf.derive(combined)
        
        handshake_time = (time.perf_counter() - start) * 1000
        
        # Initialize AES-GCM for message encryption
        self.shared_secret = session_key
        self.aes_key = AESGCM(session_key)
        
        return {
            'ephemeral_public': ephemeral_public,
            'kyber_ciphertext': kyber_ciphertext,
            'handshake_time_ms': handshake_time
        }
    
    def complete_handshake_alice(self, alice_keys, bob_handshake):
        """Alice completes handshake"""
        start = time.perf_counter()
        
        # X25519 DH
        bob_ephemeral = x25519.X25519PublicKey.from_public_bytes(
            bob_handshake['ephemeral_public']
        )
        x25519_shared = alice_keys['x25519_private'].exchange(bob_ephemeral)
        
        # ML-KEM-768 decapsulation
        kyber_shared = alice_keys['kyber_kem'].decap_secret(
            bob_handshake['kyber_ciphertext']
        )
        
        # Derive session key
        combined = x25519_shared + kyber_shared
        kdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'PQXDH-v1')
        session_key = kdf.derive(combined)
        
        handshake_time = (time.perf_counter() - start) * 1000
        
        # Initialize AES-GCM for message encryption
        self.shared_secret = session_key
        self.aes_key = AESGCM(session_key)
        
        return handshake_time
    
    def encrypt_message(self, plaintext):
        """Encrypt message using AES-256-GCM (symmetric)"""
        if not self.aes_key:
            raise ValueError("Session not established")
        
        # Generate nonce (96 bits for GCM)
        nonce = os.urandom(12)
        
        start = time.perf_counter()
        ciphertext = self.aes_key.encrypt(nonce, plaintext, None)
        encrypt_time = (time.perf_counter() - start) * 1000
        
        return nonce + ciphertext, encrypt_time
    
    def decrypt_message(self, encrypted_data):
        """Decrypt message using AES-256-GCM"""
        if not self.aes_key:
            raise ValueError("Session not established")
        
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        
        start = time.perf_counter()
        plaintext = self.aes_key.decrypt(nonce, ciphertext, None)
        decrypt_time = (time.perf_counter() - start) * 1000
        
        return plaintext, decrypt_time


def test_single_session_throughput(message_size=1024, num_messages=10000):
    """Test throughput of a single PQXDH session"""
    print(f"\nTesting single session: {num_messages} messages of {message_size} bytes")
    
    session_bob = HybridPQXDHSession()
    session_alice = HybridPQXDHSession()
    
    # Handshake
    print("  Performing handshake...")
    alice_keys = session_alice.perform_handshake_alice()
    bob_handshake = session_bob.perform_handshake_bob(alice_keys['public_keys'])
    alice_complete_time = session_alice.complete_handshake_alice(alice_keys, bob_handshake)
    
    # Verify shared secrets match
    if session_bob.shared_secret != session_alice.shared_secret:
        raise ValueError("Handshake failed: shared secrets don't match")
    
    print(f"  Handshake complete: Bob={bob_handshake['handshake_time_ms']:.2f}ms, Alice={alice_complete_time:.2f}ms")
    
    # Generate test messages
    messages = [os.urandom(message_size) for _ in range(num_messages)]
    
    # Encryption throughput
    print(f"  Encrypting {num_messages} messages...")
    encrypt_times = []
    encrypted_messages = []
    
    total_start = time.perf_counter()
    for msg in messages:
        encrypted, encrypt_time = session_bob.encrypt_message(msg)
        encrypted_messages.append(encrypted)
        encrypt_times.append(encrypt_time)
    total_encrypt_time = time.perf_counter() - total_start
    
    total_bytes_encrypted = num_messages * message_size
    encrypt_throughput_mbps = (total_bytes_encrypted / total_encrypt_time) / (1024 * 1024)
    
    print(f"  Encryption: {total_encrypt_time:.3f}s, {encrypt_throughput_mbps:.2f} MB/s")
    
    # Decryption throughput
    print(f"  Decrypting {num_messages} messages...")
    decrypt_times = []
    
    total_start = time.perf_counter()
    for encrypted in encrypted_messages:
        plaintext, decrypt_time = session_alice.decrypt_message(encrypted)
        decrypt_times.append(decrypt_time)
    total_decrypt_time = time.perf_counter() - total_start
    
    decrypt_throughput_mbps = (total_bytes_encrypted / total_decrypt_time) / (1024 * 1024)
    
    print(f"  Decryption: {total_decrypt_time:.3f}s, {decrypt_throughput_mbps:.2f} MB/s")
    
    return {
        'encrypt_throughput_mbps': encrypt_throughput_mbps,
        'decrypt_throughput_mbps': decrypt_throughput_mbps,
        'encrypt_time_total': total_encrypt_time,
        'decrypt_time_total': total_decrypt_time,
        'handshake_time_ms': bob_handshake['handshake_time_ms'] + alice_complete_time
    }


def test_concurrent_sessions(num_sessions=100, messages_per_session=1000, message_size=1024):
    """Test multiple concurrent PQXDH sessions"""
    print(f"\nTesting {num_sessions} concurrent sessions")
    print(f"  {messages_per_session} messages per session, {message_size} bytes each")
    
    def run_session(session_id):
        """Run a complete session"""
        session_bob = HybridPQXDHSession()
        session_alice = HybridPQXDHSession()
        
        # Handshake
        alice_keys = session_alice.perform_handshake_alice()
        bob_handshake = session_bob.perform_handshake_bob(alice_keys['public_keys'])
        alice_complete_time = session_alice.complete_handshake_alice(alice_keys, bob_handshake)
        
        # Verify
        if session_bob.shared_secret != session_alice.shared_secret:
            raise ValueError(f"Session {session_id}: handshake failed")
        
        # Generate and encrypt messages
        messages = [os.urandom(message_size) for _ in range(messages_per_session)]
        
        session_start = time.perf_counter()
        
        encrypted_messages = []
        for msg in messages:
            encrypted, _ = session_bob.encrypt_message(msg)
            encrypted_messages.append(encrypted)
        
        # Decrypt
        for encrypted in encrypted_messages:
            plaintext, _ = session_alice.decrypt_message(encrypted)
        
        session_time = time.perf_counter() - session_start
        
        return {
            'session_id': session_id,
            'handshake_time_ms': bob_handshake['handshake_time_ms'] + alice_complete_time,
            'session_time': session_time,
            'bytes_transferred': messages_per_session * message_size
        }
    
    # Run concurrent sessions
    print("  Starting concurrent sessions...")
    total_start = time.perf_counter()
    
    with ThreadPoolExecutor(max_workers=min(num_sessions, 50)) as executor:
        futures = [executor.submit(run_session, i) for i in range(num_sessions)]
        results = [future.result() for future in as_completed(futures)]
    
    total_time = time.perf_counter() - total_start
    
    # Calculate statistics
    total_bytes = sum(r['bytes_transferred'] for r in results)
    total_handshake_time_ms = sum(r['handshake_time_ms'] for r in results)
    
    throughput_mbps = (total_bytes / total_time) / (1024 * 1024)
    throughput_gbps = throughput_mbps / 1024
    
    print(f"\n  Completed {num_sessions} sessions in {total_time:.2f}s")
    print(f"  Total data transferred: {total_bytes / (1024*1024):.2f} MB")
    print(f"  Average throughput: {throughput_mbps:.2f} MB/s ({throughput_gbps:.3f} GB/s)")
    print(f"  Average handshake time: {total_handshake_time_ms/num_sessions:.2f}ms")
    print(f"  Sessions per second: {num_sessions/total_time:.2f}")
    
    return {
        'throughput_mbps': throughput_mbps,
        'throughput_gbps': throughput_gbps,
        'total_time': total_time,
        'avg_handshake_ms': total_handshake_time_ms/num_sessions
    }


def test_sustained_10gbps_simulation():
    """Simulate sustained 10GB/s traffic"""
    print("\n" + "="*100)
    print("SIMULATING SUSTAINED 10GB/s TRAFFIC")
    print("="*100)
    
    # To reach 10GB/s, we need massive parallelization
    # Test configuration for high throughput
    test_duration_seconds = 10
    target_throughput_gbps = 10
    
    # Calculate required parameters
    # At 10GB/s for 10 seconds = 100GB total
    # With 1KB messages = 100 million messages
    # Across 1000 concurrent sessions = 100,000 messages per session
    
    message_size = 1024  # 1KB
    num_sessions = 1000
    target_bytes = target_throughput_gbps * 1024 * 1024 * 1024 * test_duration_seconds
    messages_per_session = int(target_bytes / (num_sessions * message_size))
    
    print(f"\nTest Configuration:")
    print(f"  Target: {target_throughput_gbps} GB/s for {test_duration_seconds} seconds")
    print(f"  Concurrent sessions: {num_sessions}")
    print(f"  Message size: {message_size} bytes")
    print(f"  Messages per session: {messages_per_session}")
    print(f"  Total target data: {target_bytes / (1024**3):.2f} GB")
    
    print("\nWARNING: This will consume significant CPU and memory!")
    print("Starting test in 3 seconds...")
    time.sleep(3)
    
    results = test_concurrent_sessions(num_sessions, messages_per_session, message_size)
    
    print(f"\n" + "="*100)
    print("RESULTS:")
    print(f"  Achieved throughput: {results['throughput_gbps']:.3f} GB/s")
    print(f"  Target throughput: {target_throughput_gbps} GB/s")
    print(f"  Achievement rate: {(results['throughput_gbps']/target_throughput_gbps)*100:.1f}%")
    print("="*100)


def main():
    """Main high-throughput testing suite"""
    print("="*100)
    print("HIGH-THROUGHPUT PQXDH TESTING FOR 10GB/s SCENARIOS")
    print("="*100)
    
    # Test 1: Single session baseline
    print("\n" + "="*100)
    print("TEST 1: SINGLE SESSION THROUGHPUT BASELINE")
    print("="*100)
    single_results = test_single_session_throughput(message_size=1024, num_messages=10000)
    
    # Test 2: Moderate concurrency
    print("\n" + "="*100)
    print("TEST 2: MODERATE CONCURRENCY (100 sessions)")
    print("="*100)
    concurrent_results = test_concurrent_sessions(num_sessions=100, messages_per_session=1000, message_size=1024)
    
    # Test 3: High concurrency
    print("\n" + "="*100)
    print("TEST 3: HIGH CONCURRENCY (500 sessions)")
    print("="*100)
    high_concurrent = test_concurrent_sessions(num_sessions=500, messages_per_session=500, message_size=1024)
    
    # Test 4: 10GB/s simulation (optional - very resource intensive)
    response = input("\nRun 10GB/s sustained load test? (y/n): ")
    if response.lower() == 'y':
        test_sustained_10gbps_simulation()
    
    print("\n" + "="*100)
    print("HIGH-THROUGHPUT TESTING COMPLETE")
    print("="*100)


if __name__ == "__main__":
    main()
