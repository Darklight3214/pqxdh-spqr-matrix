#!/usr/bin/env python3
"""
generate_charts.py — Publication-quality figures for pq-olm-bench results.

Reads from results/all_results.json and produces charts suitable for
an IEEE/ACM-style journal paper comparing X3DH+DR vs PQXDH+SPQR.

Graph types chosen for academic papers:
  - Grouped bar charts: side-by-side timing comparisons (Metrics 1, 2, 5, 7)
  - Stacked bar charts: bandwidth breakdown (Metric 9)
  - Table figures: security properties, key sizes (Metrics 4, 6)
  - Box plots: latency jitter distributions (Metric 10)
  - Line plots: message size scaling (Metric 3)

Usage:
  python3 generate_charts.py [--results results/all_results.json] [--outdir charts/]
"""
import json
import sys
import os
import argparse

try:
    import matplotlib
    matplotlib.use('Agg')  # Non-interactive backend
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    import numpy as np
except ImportError:
    print("ERROR: matplotlib and numpy are required.")
    print("  pip install matplotlib numpy")
    sys.exit(1)

# ─── Paper-quality style ───────────────────────────────────────
plt.rcParams.update({
    'figure.dpi': 300,
    'savefig.dpi': 300,
    'font.family': 'serif',
    'font.serif': ['Times New Roman', 'DejaVu Serif'],
    'font.size': 10,
    'axes.titlesize': 11,
    'axes.labelsize': 10,
    'xtick.labelsize': 9,
    'ytick.labelsize': 9,
    'legend.fontsize': 9,
    'figure.figsize': (6.5, 4),    # IEEE column width
    'axes.grid': True,
    'grid.alpha': 0.3,
    'grid.linestyle': '--',
})

COLOR_CLASSICAL = '#2E86AB'   # Blue
COLOR_PQ = '#E8430C'          # Red-orange
BAR_WIDTH = 0.35


def load_results(path):
    with open(path) as f:
        return json.load(f)


def safe_get(data, *keys, default=0.0):
    """Safely traverse nested dict."""
    d = data
    for k in keys:
        if isinstance(d, dict) and k in d:
            d = d[k]
        else:
            return default
    return d


def ns_to_us(ns):
    return ns / 1000.0


def ns_to_ms(ns):
    return ns / 1_000_000.0


# ═══════════════════════════════════════════════════════════════
#  Metric #1: Handshake Time — Grouped Bar Chart
# ═══════════════════════════════════════════════════════════════
def chart_handshake(data, outdir):
    d = data.get('01_handshake', {})
    if not d:
        return

    categories = ['Initiator', 'Responder', 'Roundtrip']
    keys = ['initiator', 'responder', 'roundtrip']

    c_means = [ns_to_us(safe_get(d, k, 'classical', 'summary', 'mean')) for k in keys]
    p_means = [ns_to_us(safe_get(d, k, 'pq', 'summary', 'mean')) for k in keys]
    c_stds = [ns_to_us(safe_get(d, k, 'classical', 'summary', 'std_dev')) for k in keys]
    p_stds = [ns_to_us(safe_get(d, k, 'pq', 'summary', 'std_dev')) for k in keys]

    x = np.arange(len(categories))
    fig, ax = plt.subplots()
    ax.bar(x - BAR_WIDTH/2, c_means, BAR_WIDTH, yerr=c_stds, label='X3DH + DR',
           color=COLOR_CLASSICAL, capsize=3, edgecolor='black', linewidth=0.5)
    ax.bar(x + BAR_WIDTH/2, p_means, BAR_WIDTH, yerr=p_stds, label='PQXDH + SPQR',
           color=COLOR_PQ, capsize=3, edgecolor='black', linewidth=0.5)

    # Overhead labels
    for i in range(len(categories)):
        if c_means[i] > 0:
            overhead = p_means[i] / c_means[i]
            ax.annotate(f'{overhead:.1f}×', xy=(x[i] + BAR_WIDTH/2, p_means[i] + p_stds[i]),
                        ha='center', va='bottom', fontsize=8, color=COLOR_PQ, fontweight='bold')

    ax.set_ylabel('Latency (µs)')
    ax.set_title('Metric #1: Session Handshake Time')
    ax.set_xticks(x)
    ax.set_xticklabels(categories)
    ax.legend()
    fig.tight_layout()
    fig.savefig(os.path.join(outdir, 'fig1_handshake.png'))
    fig.savefig(os.path.join(outdir, 'fig1_handshake.pdf'))
    plt.close(fig)
    print("  ✓ fig1_handshake")


# ═══════════════════════════════════════════════════════════════
#  Metric #2: Ratchet Step Time — Grouped Bar Chart
# ═══════════════════════════════════════════════════════════════
def chart_ratchet(data, outdir):
    d = data.get('02_ratchet', {})
    if not d:
        return

    categories = ['Ratchet Step\n(2 direction changes)']
    c_mean = [ns_to_us(safe_get(d, 'classical', 'summary', 'mean'))]
    p_mean = [ns_to_us(safe_get(d, 'pq', 'summary', 'mean'))]
    c_std = [ns_to_us(safe_get(d, 'classical', 'summary', 'std_dev'))]
    p_std = [ns_to_us(safe_get(d, 'pq', 'summary', 'std_dev'))]

    x = np.arange(len(categories))
    fig, ax = plt.subplots(figsize=(4, 4))
    ax.bar(x - BAR_WIDTH/2, c_mean, BAR_WIDTH, yerr=c_std, label='X3DH + DR',
           color=COLOR_CLASSICAL, capsize=3, edgecolor='black', linewidth=0.5)
    ax.bar(x + BAR_WIDTH/2, p_mean, BAR_WIDTH, yerr=p_std, label='PQXDH + SPQR',
           color=COLOR_PQ, capsize=3, edgecolor='black', linewidth=0.5)

    if c_mean[0] > 0:
        overhead = p_mean[0] / c_mean[0]
        ax.annotate(f'{overhead:.2f}×', xy=(x[0] + BAR_WIDTH/2, p_mean[0] + p_std[0]),
                    ha='center', va='bottom', fontsize=9, color=COLOR_PQ, fontweight='bold')

    ax.set_ylabel('Latency (µs)')
    ax.set_title('Metric #2: Ratchet Step Time')
    ax.set_xticks(x)
    ax.set_xticklabels(categories)
    ax.legend()
    fig.tight_layout()
    fig.savefig(os.path.join(outdir, 'fig2_ratchet.png'))
    fig.savefig(os.path.join(outdir, 'fig2_ratchet.pdf'))
    plt.close(fig)
    print("  ✓ fig2_ratchet")


# ═══════════════════════════════════════════════════════════════
#  Metric #3: Message Size — Line Chart
# ═══════════════════════════════════════════════════════════════
def chart_message_size(data, outdir):
    d = data.get('03_message_size', {})
    if not d or 'sizes' not in d:
        return

    sizes = d['sizes']
    pt = [s['plaintext_bytes'] for s in sizes]
    c_ct = [s['classical_ct_bytes'] for s in sizes]
    p_ct = [s['pq_ct_bytes'] for s in sizes]
    pq_extra = [s['pq_extra_vs_classical'] for s in sizes]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 4))

    # Left: Ciphertext sizes
    ax1.plot(pt, c_ct, 'o-', color=COLOR_CLASSICAL, label='X3DH + DR', linewidth=1.5, markersize=5)
    ax1.plot(pt, p_ct, 's-', color=COLOR_PQ, label='PQXDH + SPQR', linewidth=1.5, markersize=5)
    ax1.set_xlabel('Plaintext Size (bytes)')
    ax1.set_ylabel('Ciphertext Size (bytes)')
    ax1.set_title('Ciphertext Size vs Plaintext')
    ax1.legend()

    # Right: PQ Extra overhead
    ax2.bar(range(len(pt)), pq_extra, color=COLOR_PQ, edgecolor='black', linewidth=0.5)
    ax2.set_xticks(range(len(pt)))
    ax2.set_xticklabels([str(p) for p in pt])
    ax2.set_xlabel('Plaintext Size (bytes)')
    ax2.set_ylabel('PQ Extra Overhead (bytes)')
    ax2.set_title('PQXDH+SPQR Overhead vs X3DH+DR')

    fig.suptitle('Metric #3: Message Size on Wire', fontsize=11, fontweight='bold')
    fig.tight_layout()
    fig.savefig(os.path.join(outdir, 'fig3_message_size.png'))
    fig.savefig(os.path.join(outdir, 'fig3_message_size.pdf'))
    plt.close(fig)
    print("  ✓ fig3_message_size")


# ═══════════════════════════════════════════════════════════════
#  Metric #5: Encrypt/Decrypt Time — Grouped Bar Chart
# ═══════════════════════════════════════════════════════════════
def chart_encrypt_decrypt(data, outdir):
    d = data.get('05_encrypt_decrypt', {})
    if not d:
        return

    sizes = sorted([k for k in d.keys() if k.endswith('B')])
    if not sizes:
        return

    for direction in ['encrypt', 'decrypt']:
        categories = sizes
        c_means = [ns_to_us(safe_get(d, s, direction, 'classical', 'summary', 'mean')) for s in sizes]
        p_means = [ns_to_us(safe_get(d, s, direction, 'pq', 'summary', 'mean')) for s in sizes]
        c_stds = [ns_to_us(safe_get(d, s, direction, 'classical', 'summary', 'std_dev')) for s in sizes]
        p_stds = [ns_to_us(safe_get(d, s, direction, 'pq', 'summary', 'std_dev')) for s in sizes]

        x = np.arange(len(categories))
        fig, ax = plt.subplots()
        ax.bar(x - BAR_WIDTH/2, c_means, BAR_WIDTH, yerr=c_stds, label='X3DH + DR',
               color=COLOR_CLASSICAL, capsize=3, edgecolor='black', linewidth=0.5)
        ax.bar(x + BAR_WIDTH/2, p_means, BAR_WIDTH, yerr=p_stds, label='PQXDH + SPQR',
               color=COLOR_PQ, capsize=3, edgecolor='black', linewidth=0.5)

        for i in range(len(categories)):
            if c_means[i] > 0:
                overhead = p_means[i] / c_means[i]
                ax.annotate(f'{overhead:.2f}×', xy=(x[i] + BAR_WIDTH/2, p_means[i] + p_stds[i]),
                            ha='center', va='bottom', fontsize=8, color=COLOR_PQ, fontweight='bold')

        ax.set_ylabel('Latency (µs)')
        ax.set_title(f'Metric #5: Per-Message {direction.title()} Time')
        ax.set_xticks(x)
        ax.set_xticklabels(categories)
        ax.set_xlabel('Plaintext Size')
        ax.legend()
        fig.tight_layout()
        fig.savefig(os.path.join(outdir, f'fig5_{direction}.png'))
        fig.savefig(os.path.join(outdir, f'fig5_{direction}.pdf'))
        plt.close(fig)
        print(f"  ✓ fig5_{direction}")


# ═══════════════════════════════════════════════════════════════
#  Metric #6: Key & Bundle Sizes — Horizontal Bar Chart
# ═══════════════════════════════════════════════════════════════
def chart_key_sizes(data, outdir):
    d = data.get('06_key_sizes', {})
    if not d or 'bundles' not in d:
        return

    b = d['bundles']
    categories = ['Prekey Bundle']
    c_val = [b.get('x3dh_dr_bundle_bytes', b.get('classical_bundle_bytes', 0))]
    p_val = [b.get('pqxdh_spqr_bundle_bytes', b.get('pq_bundle_bytes', 0))]

    fig, ax = plt.subplots(figsize=(6, 3))
    y = np.arange(len(categories))
    ax.barh(y - 0.15, c_val, 0.3, label='X3DH + DR', color=COLOR_CLASSICAL,
            edgecolor='black', linewidth=0.5)
    ax.barh(y + 0.15, p_val, 0.3, label='PQXDH + SPQR', color=COLOR_PQ,
            edgecolor='black', linewidth=0.5)

    for i in range(len(categories)):
        ax.text(c_val[i] + 10, y[i] - 0.15, f'{c_val[i]} B', va='center', fontsize=8)
        ax.text(p_val[i] + 10, y[i] + 0.15, f'{p_val[i]} B ({p_val[i]/c_val[i]:.1f}×)',
                va='center', fontsize=8, color=COLOR_PQ)

    ax.set_xlabel('Size (bytes)')
    ax.set_title('Metric #6: Prekey Bundle Upload Size')
    ax.set_yticks(y)
    ax.set_yticklabels(categories)
    ax.legend()
    fig.tight_layout()
    fig.savefig(os.path.join(outdir, 'fig6_key_sizes.png'))
    fig.savefig(os.path.join(outdir, 'fig6_key_sizes.pdf'))
    plt.close(fig)
    print("  ✓ fig6_key_sizes")


# ═══════════════════════════════════════════════════════════════
#  Metric #7: KEM Primitives — Grouped Bar Chart
# ═══════════════════════════════════════════════════════════════
def chart_kem(data, outdir):
    d = data.get('07_kem_primitives', {})
    if not d:
        return

    categories = ['Key\nGeneration', 'Key Exchange /\nEncapsulation']
    c_means = [
        ns_to_us(safe_get(d, 'keygen', 'x3dh_dr', 'summary', 'mean',
                          default=safe_get(d, 'keygen', 'x25519', 'summary', 'mean'))),
        ns_to_us(safe_get(d, 'exchange', 'x3dh_dr_dh', 'summary', 'mean',
                          default=safe_get(d, 'exchange', 'x25519_dh', 'summary', 'mean'))),
    ]
    p_means = [
        ns_to_us(safe_get(d, 'keygen', 'pqxdh_spqr', 'summary', 'mean',
                          default=safe_get(d, 'keygen', 'ml_kem_768', 'summary', 'mean'))),
        ns_to_us(safe_get(d, 'exchange', 'pqxdh_spqr_encaps', 'summary', 'mean',
                          default=safe_get(d, 'exchange', 'ml_kem_768_encaps', 'summary', 'mean'))),
    ]

    x = np.arange(len(categories))
    fig, ax = plt.subplots(figsize=(5, 4))
    ax.bar(x - BAR_WIDTH/2, c_means, BAR_WIDTH, label='X25519 (X3DH+DR)',
           color=COLOR_CLASSICAL, edgecolor='black', linewidth=0.5)
    ax.bar(x + BAR_WIDTH/2, p_means, BAR_WIDTH, label='ML-KEM-768 (PQXDH+SPQR)',
           color=COLOR_PQ, edgecolor='black', linewidth=0.5)

    for i in range(len(categories)):
        if c_means[i] > 0:
            overhead = p_means[i] / c_means[i]
            ax.annotate(f'{overhead:.1f}×', xy=(x[i] + BAR_WIDTH/2, p_means[i]),
                        ha='center', va='bottom', fontsize=9, color=COLOR_PQ, fontweight='bold')

    ax.set_ylabel('Latency (µs)')
    ax.set_title('Metric #7: Cryptographic Primitive Times')
    ax.set_xticks(x)
    ax.set_xticklabels(categories)
    ax.legend()
    fig.tight_layout()
    fig.savefig(os.path.join(outdir, 'fig7_kem_primitives.png'))
    fig.savefig(os.path.join(outdir, 'fig7_kem_primitives.pdf'))
    plt.close(fig)
    print("  ✓ fig7_kem_primitives")


# ═══════════════════════════════════════════════════════════════
#  Metric #9: Bandwidth — Stacked/Grouped Bar Chart
# ═══════════════════════════════════════════════════════════════
def chart_bandwidth(data, outdir):
    d = data.get('09_bandwidth', {})
    if not d or 'per_conversation' not in d:
        return

    rows = d['per_conversation']
    msgs = [r['message_count'] for r in rows]
    c_bytes = [r['classical_bytes'] / 1024 for r in rows]
    p_bytes = [r['pq_bytes'] / 1024 for r in rows]

    x = np.arange(len(msgs))
    fig, ax = plt.subplots()
    ax.bar(x - BAR_WIDTH/2, c_bytes, BAR_WIDTH, label='X3DH + DR',
           color=COLOR_CLASSICAL, edgecolor='black', linewidth=0.5)
    ax.bar(x + BAR_WIDTH/2, p_bytes, BAR_WIDTH, label='PQXDH + SPQR',
           color=COLOR_PQ, edgecolor='black', linewidth=0.5)

    for i in range(len(msgs)):
        if c_bytes[i] > 0:
            overhead_pct = ((p_bytes[i] - c_bytes[i]) / c_bytes[i]) * 100
            ax.annotate(f'+{overhead_pct:.0f}%', xy=(x[i] + BAR_WIDTH/2, p_bytes[i]),
                        ha='center', va='bottom', fontsize=7, color=COLOR_PQ)

    ax.set_ylabel('Total Data (KB)')
    ax.set_title('Metric #9: Bandwidth per Conversation')
    ax.set_xticks(x)
    ax.set_xticklabels([str(m) for m in msgs])
    ax.set_xlabel('Messages in Conversation')
    ax.legend()
    fig.tight_layout()
    fig.savefig(os.path.join(outdir, 'fig9_bandwidth.png'))
    fig.savefig(os.path.join(outdir, 'fig9_bandwidth.pdf'))
    plt.close(fig)
    print("  ✓ fig9_bandwidth")


# ═══════════════════════════════════════════════════════════════
#  Metric #10: Jitter — Box Plot + Histogram
# ═══════════════════════════════════════════════════════════════
def chart_jitter(data, outdir):
    # Try both key naming conventions
    d = data.get('10_jitter', {})
    if not d:
        return

    c_data = d.get('x3dh_dr', d.get('classical', {}))
    p_data = d.get('pqxdh_spqr', d.get('pq', {}))

    c_hist = c_data.get('histogram', [])
    p_hist = p_data.get('histogram', [])

    if not c_hist or not p_hist:
        return

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 4))

    # Left: X3DH+DR histogram
    c_counts = [b.get('count', 0) for b in c_hist]
    c_labels = [b.get('range_ns', '') for b in c_hist]
    ax1.bar(range(len(c_counts)), c_counts, color=COLOR_CLASSICAL,
            edgecolor='black', linewidth=0.5, alpha=0.8)
    ax1.set_xticks(range(len(c_labels)))
    ax1.set_xticklabels(c_labels, rotation=45, ha='right', fontsize=7)
    ax1.set_ylabel('Count')
    ax1.set_title('X3DH + DR Latency Distribution')

    # Right: PQXDH+SPQR histogram
    p_counts = [b.get('count', 0) for b in p_hist]
    p_labels = [b.get('range_ns', '') for b in p_hist]
    ax2.bar(range(len(p_counts)), p_counts, color=COLOR_PQ,
            edgecolor='black', linewidth=0.5, alpha=0.8)
    ax2.set_xticks(range(len(p_labels)))
    ax2.set_xticklabels(p_labels, rotation=45, ha='right', fontsize=7)
    ax2.set_ylabel('Count')
    ax2.set_title('PQXDH + SPQR Latency Distribution')

    # Add jitter stats as text
    c_j = c_data.get('jitter', {})
    p_j = p_data.get('jitter', {})
    if c_j:
        ax1.text(0.97, 0.95, f"CV={c_j.get('cv',0):.3f}\nIQR={c_j.get('iqr',0):.0f}ns",
                 transform=ax1.transAxes, va='top', ha='right', fontsize=8,
                 bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.8))
    if p_j:
        ax2.text(0.97, 0.95, f"CV={p_j.get('cv',0):.3f}\nIQR={p_j.get('iqr',0):.0f}ns",
                 transform=ax2.transAxes, va='top', ha='right', fontsize=8,
                 bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.8))

    fig.suptitle('Metric #10: Latency Jitter Distribution (256B)', fontsize=11, fontweight='bold')
    fig.tight_layout()
    fig.savefig(os.path.join(outdir, 'fig10_jitter.png'))
    fig.savefig(os.path.join(outdir, 'fig10_jitter.pdf'))
    plt.close(fig)
    print("  ✓ fig10_jitter")


# ═══════════════════════════════════════════════════════════════
#  Summary Radar / Overview Chart
# ═══════════════════════════════════════════════════════════════
def chart_summary(data, outdir):
    """Create a summary comparison bar chart of all major overhead factors."""
    overheads = {}

    # Handshake roundtrip overhead
    h = data.get('01_handshake', {}).get('roundtrip', {})
    c = safe_get(h, 'classical', 'summary', 'mean')
    p = safe_get(h, 'pq', 'summary', 'mean')
    if c > 0:
        overheads['Handshake'] = p / c

    # Ratchet overhead
    r = data.get('02_ratchet', {})
    c = safe_get(r, 'classical', 'summary', 'mean')
    p = safe_get(r, 'pq', 'summary', 'mean')
    if c > 0:
        overheads['Ratchet Step'] = p / c

    # Encrypt/Decrypt overhead (256B)
    ed = data.get('05_encrypt_decrypt', {}).get('256B', {})
    c = safe_get(ed, 'encrypt', 'classical', 'summary', 'mean')
    p = safe_get(ed, 'encrypt', 'pq', 'summary', 'mean')
    if c > 0:
        overheads['Encrypt (256B)'] = p / c

    c = safe_get(ed, 'decrypt', 'classical', 'summary', 'mean')
    p = safe_get(ed, 'decrypt', 'pq', 'summary', 'mean')
    if c > 0:
        overheads['Decrypt (256B)'] = p / c

    # Bundle size overhead
    b = data.get('06_key_sizes', {}).get('bundles', {})
    c = b.get('x3dh_dr_bundle_bytes', b.get('classical_bundle_bytes', 0))
    p = b.get('pqxdh_spqr_bundle_bytes', b.get('pq_bundle_bytes', 0))
    if c > 0:
        overheads['Bundle Size'] = p / c

    if not overheads:
        return

    labels = list(overheads.keys())
    values = list(overheads.values())

    fig, ax = plt.subplots(figsize=(7, 4))
    colors = [COLOR_PQ if v > 1.5 else '#FFA500' if v > 1.1 else '#2ECC71' for v in values]
    bars = ax.barh(range(len(labels)), values, color=colors, edgecolor='black', linewidth=0.5)

    ax.axvline(x=1.0, color='black', linestyle=':', linewidth=1, label='1.0× (no overhead)')

    for i, (v, bar) in enumerate(zip(values, bars)):
        ax.text(v + 0.05, i, f'{v:.2f}×', va='center', fontsize=9, fontweight='bold')

    ax.set_yticks(range(len(labels)))
    ax.set_yticklabels(labels)
    ax.set_xlabel('Overhead Factor (PQXDH+SPQR / X3DH+DR)')
    ax.set_title('Summary: PQXDH+SPQR Overhead vs X3DH+DR')
    ax.invert_yaxis()
    fig.tight_layout()
    fig.savefig(os.path.join(outdir, 'fig_summary_overhead.png'))
    fig.savefig(os.path.join(outdir, 'fig_summary_overhead.pdf'))
    plt.close(fig)
    print("  ✓ fig_summary_overhead")


def main():
    parser = argparse.ArgumentParser(description='Generate publication-quality charts from pq-olm-bench results')
    parser.add_argument('--results', default='results/all_results.json',
                        help='Path to all_results.json')
    parser.add_argument('--outdir', default='charts/',
                        help='Output directory for charts')
    args = parser.parse_args()

    if not os.path.exists(args.results):
        print(f"ERROR: Results file not found: {args.results}")
        print("Run the benchmark first: cargo run --release")
        sys.exit(1)

    os.makedirs(args.outdir, exist_ok=True)
    data = load_results(args.results)

    print(f"Generating charts from {args.results} → {args.outdir}/")
    print()

    chart_handshake(data, args.outdir)
    chart_ratchet(data, args.outdir)
    chart_message_size(data, args.outdir)
    chart_encrypt_decrypt(data, args.outdir)
    chart_key_sizes(data, args.outdir)
    chart_kem(data, args.outdir)
    chart_bandwidth(data, args.outdir)
    chart_jitter(data, args.outdir)
    chart_summary(data, args.outdir)

    print(f"\n✓ All charts saved to {args.outdir}/")
    print("  PNG (300 DPI) for drafts, PDF for LaTeX/Word submission.")


if __name__ == '__main__':
    main()
