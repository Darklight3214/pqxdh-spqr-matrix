import matplotlib.pyplot as plt
import numpy as np

# 1. Classical X3DH vs PQXDH
labels = ['Keygen', 'Initiate', 'Complete', 'Total']
x3dh = [0.16, 0.41, 0.22, 0.79]
pqxdh = [0.74, 0.71, 0.71, 2.16]

x = np.arange(len(labels))
width = 0.35

fig, ax = plt.subplots(figsize=(8, 5))
rects1 = ax.bar(x - width/2, x3dh, width, label='Classical X3DH', color='#4a90e2')
rects2 = ax.bar(x + width/2, pqxdh, width, label='PQXDH', color='#e74c3c')

ax.set_ylabel('Latency (ms)')
ax.set_title('Protocol Overheads: Classical X3DH vs PQXDH')
ax.set_xticks(x)
ax.set_xticklabels(labels)
ax.legend()
plt.tight_layout()
plt.savefig('/home/csnd1/graph_classical_vs_pqxdh.png')

# 2. ML-KEM-768 Metrics 
plt.figure(figsize=(6, 4))
tasks = ['Encapsulation', 'Decapsulation', 'Key Generation']
times = [0.35, 0.13, 26.40]
colors = ['#2ecc71', '#f1c40f', '#34495e']
plt.pie(times, labels=tasks, colors=colors, autopct='%1.1f%%', startangle=140)
plt.title('ML-KEM-768 Handshake Overhead Distributions')
plt.axis('equal')
plt.tight_layout()
plt.savefig('/home/csnd1/graph_mlkem_latency.png')

# 3. High-Throughput Scaling
plt.figure(figsize=(8, 5))
sessions = ['1 (Baseline)', '100 Concurrent', '500 Concurrent']
throughput_mbps = [67.96, 8.95, 14.10]
plt.plot(sessions, throughput_mbps, marker='o', linestyle='-', color='#8e44ad', linewidth=2, markersize=8)
plt.ylabel('Average Throughput (MB/s)')
plt.title('Matrix PQXDH Concurrent High-Throughput Matrix Performance')
plt.grid(True, linestyle='--', alpha=0.7)
plt.tight_layout()
plt.savefig('/home/csnd1/graph_throughput.png')

print("Charts generated successfully at ~/graph_*.png")
