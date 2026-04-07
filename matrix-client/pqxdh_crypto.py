#!/usr/bin/env python3
"""
Test the exact pattern used in PQXDH:
- Alice creates KEM instance and generates keypair
- Bob creates separate KEM instance and encapsulates
- Alice uses her original KEM instance to decapsulate
"""
import oqs

print("Testing PQXDH KEM pattern (separate instances)...")
print()

# Step 1: Alice generates her keypair
print("Step 1: Alice generates keypair")
alice_kem = oqs.KeyEncapsulation("ML-KEM-768")
alice_public = alice_kem.generate_keypair()
print(f"  Alice's public key: {len(alice_public)} bytes")
print(f"  Alice's KEM instance ID: {id(alice_kem)}")
print()

# Step 2: Bob encapsulates using Alice's public key
print("Step 2: Bob encapsulates")
bob_kem = oqs.KeyEncapsulation("ML-KEM-768")
ciphertext, bob_shared = bob_kem.encap_secret(alice_public)
print(f"  Ciphertext: {len(ciphertext)} bytes")
print(f"  Bob's shared secret: {bob_shared.hex()[:32]}...")
print(f"  Bob's KEM instance ID: {id(bob_kem)}")
print()

# Step 3: Alice decapsulates using her original KEM instance
print("Step 3: Alice decapsulates")
print(f"  Using Alice's original KEM instance ID: {id(alice_kem)}")
try:
    alice_shared = alice_kem.decap_secret(ciphertext)
    print(f"  Alice's shared secret: {alice_shared.hex()[:32]}...")
    print()
    
    # Verify
    if alice_shared == bob_shared:
        print("SUCCESS: Shared secrets match!")
        print("The KEM instance DOES retain the secret key after generate_keypair()")
    else:
        print("FAILURE: Shared secrets don't match")
        print("Something is wrong with the crypto")
        
except Exception as e:
    print(f"ERROR: {e}")
    print("The KEM instance does NOT retain the secret key")
