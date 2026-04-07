#!/usr/bin/env python3
import oqs
import time

print("Testing ML-KEM-768 (Post-Quantum KEM)...\n")

# Initialize ML-KEM-768
kem = oqs.KeyEncapsulation("ML-KEM-768")

print(f"Algorithm: {kem.details['name']}")
print(f"Public key size: {kem.details['length_public_key']} bytes")
print(f"Secret key size: {kem.details['length_secret_key']} bytes")
print(f"Ciphertext size: {kem.details['length_ciphertext']} bytes")
print(f"Shared secret size: {kem.details['length_shared_secret']} bytes")
print()

# Benchmark key generation
start = time.perf_counter()
public_key = kem.generate_keypair()
keygen_time = (time.perf_counter() - start) * 1000
print(f" Key generation: {keygen_time:.2f} ms")

# Benchmark encapsulation (like Bob creating shared secret)
start = time.perf_counter()
ciphertext, shared_secret_bob = kem.encap_secret(public_key)
encap_time = (time.perf_counter() - start) * 1000
print(f" Encapsulation: {encap_time:.2f} ms")

# Benchmark decapsulation (like Alice recovering shared secret)
start = time.perf_counter()
shared_secret_alice = kem.decap_secret(ciphertext)
decap_time = (time.perf_counter() - start) * 1000
print(f" Decapsulation: {decap_time:.2f} ms")

# Verify shared secrets match
assert shared_secret_alice == shared_secret_bob
print(f"\n Shared secrets match! ({len(shared_secret_alice)} bytes)")
print(f"\n Total ML-KEM-768 handshake time: {keygen_time + encap_time + decap_time:.2f} ms")
