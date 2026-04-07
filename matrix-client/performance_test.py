#!/usr/bin/env python3
"""
Comprehensive Performance Testing for Hybrid PQXDH
- Multiple iterations for statistical accuracy
- Comparison with classical X3DH
- Detailed metrics and analysis
"""
import oqs
import time
import statistics
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class HybridPQXDH:
    """Hybrid Post-Quantum X3DH implementation"""
    
    def __init__(self):
        """Initialize HybridPQXDH - each operation creates its own KEM instance"""
        pass
    
    def generate_identity_keypair(self):
        """Generate hybrid identity keys (X25519 + ML-KEM-768)"""
        start = time.perf_counter()
        
        # Classical X25519
        x25519_private = x25519.X25519PrivateKey.generate()
        x25519_public = x25519_private.public_key()
        
        # Post-quantum ML-KEM-768
        alice_kem = oqs.KeyEncapsulation("ML-KEM-768")
        kyber_public = alice_kem.generate_keypair()
        
        keygen_time = (time.perf_counter() - start) * 1000
        
        return {
            'private': {
                'x25519': x25519_private,
                'kyber_kem': alice_kem
            },
            'public': {
                'x25519': x25519_public.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                ),
                'kyber': kyber_public
            },
            'keygen_time_ms': keygen_time
        }
    
    def initiate_handshake(self, recipient_public_keys):
        """Initiator (Bob) creates hybrid shared secret"""
        start = time.perf_counter()
        
        # Classical X25519 DH
        ephemeral_private = x25519.X25519PrivateKey.generate()
        ephemeral_public = ephemeral_private.public_key()
        
        alice_x25519_public = x25519.X25519PublicKey.from_public_bytes(
            recipient_public_keys['x25519']
        )
        x25519_shared = ephemeral_private.exchange(alice_x25519_public)
        
        # Post-quantum ML-KEM-768 encapsulation
        bob_kem = oqs.KeyEncapsulation("ML-KEM-768")
        kyber_ciphertext, kyber_shared = bob_kem.encap_secret(
            recipient_public_keys['kyber']
        )
        
        # Combine both shared secrets with HKDF
        combined_secret = x25519_shared + kyber_shared
        
        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'PQXDH-v1'
        )
        final_shared_secret = kdf.derive(combined_secret)
        
        handshake_time = (time.perf_counter() - start) * 1000
        
        return {
            'shared_secret': final_shared_secret,
            'ephemeral_public': ephemeral_public.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            ),
            'kyber_ciphertext': kyber_ciphertext,
            'handshake_time_ms': handshake_time
        }
    
    def complete_handshake(self, identity_keys, handshake_data):
        """Responder (Alice) recovers hybrid shared secret"""
        start = time.perf_counter()
        
        # Classical X25519 DH
        bob_ephemeral_public = x25519.X25519PublicKey.from_public_bytes(
            handshake_data['ephemeral_public']
        )
        x25519_shared = identity_keys['private']['x25519'].exchange(
            bob_ephemeral_public
        )
        
        # Post-quantum ML-KEM-768 decapsulation
        alice_kem = identity_keys['private']['kyber_kem']
        kyber_shared = alice_kem.decap_secret(handshake_data['kyber_ciphertext'])
        
        # Combine both shared secrets with HKDF
        combined_secret = x25519_shared + kyber_shared
        
        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'PQXDH-v1'
        )
        final_shared_secret = kdf.derive(combined_secret)
        
        complete_time = (time.perf_counter() - start) * 1000
        
        return {
            'shared_secret': final_shared_secret,
            'complete_time_ms': complete_time
        }


class ClassicalX3DH:
    """Classical X3DH implementation (X25519 only) for comparison"""
    
    def __init__(self):
        pass
    
    def generate_identity_keypair(self):
        """Generate classical identity keys (X25519 only)"""
        start = time.perf_counter()
        
        x25519_private = x25519.X25519PrivateKey.generate()
        x25519_public = x25519_private.public_key()
        
        keygen_time = (time.perf_counter() - start) * 1000
        
        return {
            'private': {
                'x25519': x25519_private
            },
            'public': {
                'x25519': x25519_public.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
            },
            'keygen_time_ms': keygen_time
        }
    
    def initiate_handshake(self, recipient_public_keys):
        """Initiator creates classical shared secret"""
        start = time.perf_counter()
        
        # Classical X25519 DH
        ephemeral_private = x25519.X25519PrivateKey.generate()
        ephemeral_public = ephemeral_private.public_key()
        
        alice_x25519_public = x25519.X25519PublicKey.from_public_bytes(
            recipient_public_keys['x25519']
        )
        x25519_shared = ephemeral_private.exchange(alice_x25519_public)
        
        # Use HKDF
        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'X3DH-v1'
        )
        final_shared_secret = kdf.derive(x25519_shared)
        
        handshake_time = (time.perf_counter() - start) * 1000
        
        return {
            'shared_secret': final_shared_secret,
            'ephemeral_public': ephemeral_public.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            ),
            'handshake_time_ms': handshake_time
        }
    
    def complete_handshake(self, identity_keys, handshake_data):
        """Responder recovers classical shared secret"""
        start = time.perf_counter()
        
        # Classical X25519 DH
        bob_ephemeral_public = x25519.X25519PublicKey.from_public_bytes(
            handshake_data['ephemeral_public']
        )
        x25519_shared = identity_keys['private']['x25519'].exchange(
            bob_ephemeral_public
        )
        
        # Use HKDF
        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'X3DH-v1'
        )
        final_shared_secret = kdf.derive(x25519_shared)
        
        complete_time = (time.perf_counter() - start) * 1000
        
        return {
            'shared_secret': final_shared_secret,
            'complete_time_ms': complete_time
        }


def run_single_handshake(protocol):
    """Run a single complete handshake and return timing metrics"""
    # Alice generates keys
    alice_keys = protocol.generate_identity_keypair()
    
    # Bob initiates handshake
    handshake = protocol.initiate_handshake(alice_keys['public'])
    
    # Alice completes handshake
    completion = protocol.complete_handshake(alice_keys, handshake)
    
    # Verify
    if handshake['shared_secret'] != completion['shared_secret']:
        raise ValueError("Shared secrets don't match!")
    
    return {
        'keygen_ms': alice_keys['keygen_time_ms'],
        'initiate_ms': handshake['handshake_time_ms'],
        'complete_ms': completion['complete_time_ms'],
        'total_ms': alice_keys['keygen_time_ms'] + handshake['handshake_time_ms'] + completion['complete_time_ms']
    }


def run_performance_test(protocol_name, protocol_class, iterations=100):
    """Run multiple iterations and collect statistics"""
    print(f"\nRunning {protocol_name} performance test ({iterations} iterations)...")
    
    protocol = protocol_class()
    results = {
        'keygen_ms': [],
        'initiate_ms': [],
        'complete_ms': [],
        'total_ms': []
    }
    
    # Warmup
    for _ in range(5):
        run_single_handshake(protocol)
    
    # Actual test
    for i in range(iterations):
        if (i + 1) % 20 == 0:
            print(f"  Progress: {i + 1}/{iterations}")
        
        metrics = run_single_handshake(protocol)
        for key in results:
            results[key].append(metrics[key])
    
    # Calculate statistics
    stats = {}
    for key in results:
        stats[key] = {
            'mean': statistics.mean(results[key]),
            'median': statistics.median(results[key]),
            'stdev': statistics.stdev(results[key]) if len(results[key]) > 1 else 0,
            'min': min(results[key]),
            'max': max(results[key])
        }
    
    return stats


def print_statistics(name, stats):
    """Print performance statistics in a formatted table"""
    print(f"\n{name} PERFORMANCE STATISTICS")
    print("=" * 80)
    print(f"{'Metric':<20} {'Mean':>10} {'Median':>10} {'StdDev':>10} {'Min':>10} {'Max':>10}")
    print("-" * 80)
    
    metrics = [
        ('Key Generation', 'keygen_ms'),
        ('Initiate Handshake', 'initiate_ms'),
        ('Complete Handshake', 'complete_ms'),
        ('Total Handshake', 'total_ms')
    ]
    
    for label, key in metrics:
        s = stats[key]
        print(f"{label:<20} {s['mean']:>9.2f}ms {s['median']:>9.2f}ms "
              f"{s['stdev']:>9.2f}ms {s['min']:>9.2f}ms {s['max']:>9.2f}ms")
    
    print("=" * 80)


def print_comparison(x3dh_stats, pqxdh_stats):
    """Print side-by-side comparison"""
    print("\n" + "=" * 100)
    print("PERFORMANCE COMPARISON: X3DH vs PQXDH")
    print("=" * 100)
    print(f"{'Metric':<25} {'X3DH Mean':>12} {'PQXDH Mean':>12} {'Overhead':>12} {'Factor':>10}")
    print("-" * 100)
    
    metrics = [
        ('Key Generation', 'keygen_ms'),
        ('Initiate Handshake', 'initiate_ms'),
        ('Complete Handshake', 'complete_ms'),
        ('Total Handshake', 'total_ms')
    ]
    
    for label, key in metrics:
        x3dh_mean = x3dh_stats[key]['mean']
        pqxdh_mean = pqxdh_stats[key]['mean']
        overhead = pqxdh_mean - x3dh_mean
        factor = pqxdh_mean / x3dh_mean if x3dh_mean > 0 else 0
        
        print(f"{label:<25} {x3dh_mean:>11.2f}ms {pqxdh_mean:>11.2f}ms "
              f"{overhead:>11.2f}ms {factor:>9.1f}x")
    
    print("=" * 100)
    
    # Additional analysis
    print("\nKEY INSIGHTS:")
    total_overhead_ms = pqxdh_stats['total_ms']['mean'] - x3dh_stats['total_ms']['mean']
    total_overhead_percent = (total_overhead_ms / x3dh_stats['total_ms']['mean']) * 100
    
    print(f"  Total overhead: {total_overhead_ms:.2f} ms ({total_overhead_percent:.1f}%)")
    print(f"  X3DH throughput: ~{1000/x3dh_stats['total_ms']['mean']:.0f} handshakes/second")
    print(f"  PQXDH throughput: ~{1000/pqxdh_stats['total_ms']['mean']:.0f} handshakes/second")
    
    # Network impact
    print("\nNETWORK IMPACT:")
    print(f"  X3DH public key size: 32 bytes (X25519)")
    print(f"  PQXDH public key size: 1216 bytes (32 + 1184)")
    print(f"  Size increase: 38x")
    print(f"  X3DH handshake payload: 32 bytes")
    print(f"  PQXDH handshake payload: 1216 bytes (32 + 1184)")
    print(f"  Payload increase: 38x")
    print("=" * 100)


def save_results_to_file(x3dh_stats, pqxdh_stats, filename='performance_results.txt'):
    """Save results to a file"""
    with open(filename, 'w') as f:
        f.write("PQXDH PERFORMANCE TEST RESULTS\n")
        f.write("=" * 80 + "\n\n")
        
        f.write("X3DH STATISTICS\n")
        f.write("-" * 80 + "\n")
        for key in ['keygen_ms', 'initiate_ms', 'complete_ms', 'total_ms']:
            f.write(f"{key}: mean={x3dh_stats[key]['mean']:.2f}ms, "
                   f"median={x3dh_stats[key]['median']:.2f}ms, "
                   f"stdev={x3dh_stats[key]['stdev']:.2f}ms\n")
        
        f.write("\nPQXDH STATISTICS\n")
        f.write("-" * 80 + "\n")
        for key in ['keygen_ms', 'initiate_ms', 'complete_ms', 'total_ms']:
            f.write(f"{key}: mean={pqxdh_stats[key]['mean']:.2f}ms, "
                   f"median={pqxdh_stats[key]['median']:.2f}ms, "
                   f"stdev={pqxdh_stats[key]['stdev']:.2f}ms\n")
        
        f.write("\nCOMPARISON\n")
        f.write("-" * 80 + "\n")
        total_overhead = pqxdh_stats['total_ms']['mean'] - x3dh_stats['total_ms']['mean']
        f.write(f"Total overhead: {total_overhead:.2f} ms\n")
        f.write(f"Overhead factor: {pqxdh_stats['total_ms']['mean'] / x3dh_stats['total_ms']['mean']:.2f}x\n")
    
    print(f"\nResults saved to {filename}")


def main():
    """Main performance testing suite"""
    print("=" * 100)
    print("COMPREHENSIVE PERFORMANCE TESTING: X3DH vs PQXDH")
    print("=" * 100)
    
    iterations = 100
    
    # Test Classical X3DH
    x3dh_stats = run_performance_test("Classical X3DH", ClassicalX3DH, iterations)
    print_statistics("CLASSICAL X3DH", x3dh_stats)
    
    # Test Hybrid PQXDH
    pqxdh_stats = run_performance_test("Hybrid PQXDH", HybridPQXDH, iterations)
    print_statistics("HYBRID PQXDH", pqxdh_stats)
    
    # Comparison
    print_comparison(x3dh_stats, pqxdh_stats)
    
    # Save results
    save_results_to_file(x3dh_stats, pqxdh_stats)
    
    print("\nPerformance testing complete!")


if __name__ == "__main__":
    main()
