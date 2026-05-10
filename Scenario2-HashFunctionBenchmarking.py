# =============================================================
# Scenario 2: Hash Function Benchmarking
# Thesis: A Performance Evaluation of Classical, Post-Quantum,
#         and Hybrid Cryptographic Mechanisms
# Student: Muhammad Bilal Zahid | C00315721 | SETU | May 2026
# =============================================================

import time
import hashlib
import os                          # use os.urandom not b"A"*size
import numpy as np
import matplotlib.pyplot as plt
from scipy import stats

# ─────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────
RUNS       = 2000
SMALL_SIZE = 1024           # 1 KB
LARGE_SIZE = 1024 * 1024    # 1 MB

# Use os.urandom 
# pre-generated as random bytes, not repeated ASCII characters
small_data = os.urandom(SMALL_SIZE)
large_data = os.urandom(LARGE_SIZE)

results = {}

# ─────────────────────────────────────────────────────────────
# Benchmark Function
# Timed scope: single hash call per iteration
# Data pre-generated OUTSIDE timed block (Under IV.E)
# ─────────────────────────────────────────────────────────────
def benchmark_hash(name, hash_func, data, output_length=32):
    times = []

    for _ in range(RUNS):
        start = time.perf_counter()          # === timed block start ===

        if name == "SHAKE256":
            h = hash_func(data)
            h.digest(output_length)          # 32-byte output 
        else:
            hash_func(data).digest()

        times.append(time.perf_counter() - start)   # === timed block end ===

    times = np.array(times)

    median     = np.median(times)
    iqr        = np.percentile(times, 75) - np.percentile(times, 25)
    p5         = np.percentile(times, 5)
    p95        = np.percentile(times, 95)
    skew       = stats.skew(times)
    # Throughput uses median (median-based reporting)
    throughput = (len(data) / (1024 * 1024)) / median   # MB/s

    return {
        "median":     median,
        "iqr":        iqr,
        "p5":         p5,
        "p95":        p95,
        "skew":       skew,
        "throughput": throughput
    }

# ─────────────────────────────────────────────────────────────
# Algorithms  hashlib stdlib 
# ─────────────────────────────────────────────────────────────
algorithms = {
    "SHA-256":  hashlib.sha256,
    "SHA3-256": hashlib.sha3_256,
    "SHAKE256": hashlib.shake_256
}

# ─────────────────────────────────────────────────────────────
# Run Benchmarks
# ─────────────────────────────────────────────────────────────
for name, func in algorithms.items():
    print(f"\nRunning {name} (1 KB)...")
    small_result = benchmark_hash(name, func, small_data)

    print(f"Running {name} (1 MB)...")
    large_result = benchmark_hash(name, func, large_data)

    results[name] = {
        "1KB": small_result,
        "1MB": large_result
    }

# ─────────────────────────────────────────────────────────────
# Print Results
# ─────────────────────────────────────────────────────────────
for algo, sizes in results.items():
    print(f"\n===== {algo} =====")
    for size, metrics in sizes.items():
        print(f"\n  Input Size: {size}")
        print(f"  Median:          {metrics['median']:.6f} s  ({metrics['median']*1000:.4f} ms)")
        print(f"  IQR:             {metrics['iqr']:.6f} s")
        print(f"  5th-95th pct:    ({metrics['p5']:.6f}, {metrics['p95']:.6f})")
        print(f"  Skewness:        {metrics['skew']:.2f}")
        print(f"  Throughput:      {metrics['throughput']:.2f} MB/s")

# ─────────────────────────────────────────────────────────────
# FIGURE V.3 Line Chart: Throughput (MB/s) at 1 KB and 1 MB
# Caption :
# "Hash function throughput (MB/s) at 1 KB and 1 MB input sizes.
#  SHA-256 outperforms SHA3-256 and SHAKE256 by approximately
#  19% at 1 MB due to hardware SHA-NI acceleration."
# ─────────────────────────────────────────────────────────────
labels     = list(results.keys())
size_keys  = ["1KB", "1MB"]
size_names = ["1 KB", "1 MB"]
colors     = ["#1f77b4", "#ff7f0e", "#2ca02c"]
markers    = ["o", "s", "^"]
linestyles = ["-", "--", ":"]

fig1, ax1 = plt.subplots(figsize=(7, 4.5))

for i, algo in enumerate(labels):
    tp_vals = [results[algo][s]["throughput"] for s in size_keys]
    ax1.plot(size_names, tp_vals,
             color=colors[i], marker=markers[i],
             linestyle=linestyles[i], linewidth=2.2,
             markersize=8, label=algo)

ax1.set_title("Figure V.3 — Hash Function Throughput (MB/s) by Input Size",
              fontsize=12, fontweight="bold", pad=10)
ax1.set_xlabel("Input Size", fontsize=11)
ax1.set_ylabel("Throughput (MB/s)", fontsize=11)
ax1.legend(loc="upper left", fontsize=10)
ax1.grid(True, linestyle="--", alpha=0.5)
plt.tight_layout()
plt.savefig("Figure_V3_Hash_Throughput_Line.png", dpi=150, bbox_inches="tight")
plt.show()
print("\nFigure V.3 saved as: Figure_V3_Hash_Throughput_Line.png")

# ─────────────────────────────────────────────────────────────
# Bar Chart
# ─────────────────────────────────────────────────────────────
x     = np.arange(len(labels))
width = 0.35

throughput_1kb = [results[algo]["1KB"]["throughput"] for algo in labels]
throughput_1mb = [results[algo]["1MB"]["throughput"] for algo in labels]

fig2, ax2 = plt.subplots(figsize=(8, 5))
bars1 = ax2.bar(x - width/2, throughput_1kb, width, label="1 KB", color="#1f77b4")
bars2 = ax2.bar(x + width/2, throughput_1mb, width, label="1 MB",  color="#ff7f0e")

# Annotate bar values
for bar in bars1 + bars2:
    ax2.text(bar.get_x() + bar.get_width() / 2,
             bar.get_height() * 1.01,
             f"{bar.get_height():.0f}",
             ha="center", va="bottom", fontsize=9)

ax2.set_xticks(x)
ax2.set_xticklabels(labels)
ax2.set_ylabel("Throughput (MB/s)", fontsize=11)
ax2.set_title("Hash Function Throughput Comparison — 1 KB vs 1 MB",
              fontsize=12, fontweight="bold", pad=10)
ax2.legend(fontsize=10)
ax2.grid(True, linestyle="--", alpha=0.5, axis="y")
plt.tight_layout()
plt.savefig("Figure_V3_Hash_Throughput_Bar.png", dpi=150, bbox_inches="tight")
plt.show()
print("Bar chart saved as: Figure_V3_Hash_Throughput_Bar.png")