# =============================================================
# Scenario 3: AES Symmetric Encryption Benchmark
# Thesis: A Performance Evaluation of Classical, Post-Quantum,
#         and Hybrid Cryptographic Mechanisms
# Student: Muhammad Bilal Zahid | C00315721 | SETU | May 2026
# Library: cryptography==44.0.2 | Python 3.13.2 | Windows 11
# =============================================================

import time
import os
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from scipy import stats

# ─────────────────────────────────────────────────────────────
# Configuration — Analysis under V.D of Dissertaion Document
# ─────────────────────────────────────────────────────────────
TRIALS  = 200    # 200 iterations per AES file-size workload
WARMUP  = 50     # 50 warm-up iterations discarded

FILE_SIZES = {
    "1 KB":   1 * 1024,
    "10 MB":  10 * 1024 * 1024,
    "100 MB": 100 * 1024 * 1024
}

# Keys — generated once, reused across all file sizes
key_128 = os.urandom(16)   # AES-128
key_192 = os.urandom(24)   # AES-192
key_256 = os.urandom(32)   # AES-256

# ─────────────────────────────────────────────────────────────
# PKCS7 Padding (Thesis V.E — full AES-CBC of PKCS7-padded plaintext)
# ─────────────────────────────────────────────────────────────
def apply_padding(data: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    return padder.update(data) + padder.finalize()

# ─────────────────────────────────────────────────────────────
# Benchmark Function
# Timed scope: encryptor.update() + encryptor.finalize() only
# IV and padded plaintext pre-generated OUTSIDE timed block
# (Under V.E — AES Encryption timing scope)
# ─────────────────────────────────────────────────────────────
def benchmark_aes_cbc(key: bytes, raw_data: bytes) -> np.ndarray:
    padded = apply_padding(raw_data)
    times = []

    # Warm-up — not recorded
    for _ in range(WARMUP):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        enc = cipher.encryptor()
        enc.update(padded) + enc.finalize()

    # Timed iterations
    for _ in range(TRIALS):
        iv = os.urandom(16)                   # outside timed block
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        enc = cipher.encryptor()

        start = time.perf_counter()           # === timed block start ===
        enc.update(padded) + enc.finalize()
        end = time.perf_counter()             # === timed block end ===

        times.append(end - start)

    return np.array(times)

# ─────────────────────────────────────────────────────────────
# Statistical Analysis — Under V.F
# median, IQR, 5th/95th pct, skewness, Shapiro-Wilk, throughput
# ─────────────────────────────────────────────────────────────
def analyze(times: np.ndarray, label: str, file_size_bytes: int):
    file_mb    = file_size_bytes / (1024 * 1024)
    median     = np.median(times)
    mean       = np.mean(times)
    iqr        = stats.iqr(times)
    p5, p95    = np.percentile(times, [5, 95])
    skewness   = stats.skew(times)
    _, shap_p  = stats.shapiro(times)
    throughput = file_mb / median              # MB/s using median (V.F)

    print(f"\n{label}")
    print(f"  Median:        {median*1000:.4f} ms")
    print(f"  Mean:          {mean*1000:.4f} ms")
    print(f"  IQR:           {iqr*1000:.4f} ms")
    print(f"  5th-95th pct:  {p5*1000:.4f}-{p95*1000:.4f} ms")
    print(f"  Skewness:      {skewness:.4f}")
    print(f"  Shapiro p:     {shap_p:.6f}")
    print(f"  Throughput:    {throughput:.2f} MB/s")

    return {"median": median, "mean": mean, "throughput": throughput}

# ─────────────────────────────────────────────────────────────
# Main Benchmark Loop
# ─────────────────────────────────────────────────────────────
size_labels  = list(FILE_SIZES.keys())          # ["1 KB", "10 MB", "100 MB"]
mean_times   = {"AES-128": [], "AES-192": [], "AES-256": []}
throughputs  = {"AES-128": [], "AES-192": [], "AES-256": []}
results_100  = {}                               # for Mann-Whitney tests

for size_label, size_bytes in FILE_SIZES.items():
    print(f"\n{'='*40}")
    print(f"File Size: {size_label}")
    print(f"{'='*40}")

    raw_data = os.urandom(size_bytes)

    t128 = benchmark_aes_cbc(key_128, raw_data)
    t192 = benchmark_aes_cbc(key_192, raw_data)
    t256 = benchmark_aes_cbc(key_256, raw_data)

    r128 = analyze(t128, "AES-128", size_bytes)
    r192 = analyze(t192, "AES-192", size_bytes)
    r256 = analyze(t256, "AES-256", size_bytes)

    for algo, r in [("AES-128", r128), ("AES-192", r192), ("AES-256", r256)]:
        mean_times[algo].append(r["mean"])
        throughputs[algo].append(r["throughput"])

    if size_label == "100 MB":
        results_100 = {"AES-128": t128, "AES-192": t192, "AES-256": t256}

# ─────────────────────────────────────────────────────────────
# Mann-Whitney U Tests — 100 MB (Under V.F)
# ─────────────────────────────────────────────────────────────
print("\nStatistical Significance Tests (100 MB):")
t128 = results_100["AES-128"]
t192 = results_100["AES-192"]
t256 = results_100["AES-256"]
print(f"  AES-128 vs AES-192: p = {stats.mannwhitneyu(t128, t192).pvalue:.4e}")
print(f"  AES-128 vs AES-256: p = {stats.mannwhitneyu(t128, t256).pvalue:.4e}")
print(f"  AES-192 vs AES-256: p = {stats.mannwhitneyu(t192, t256).pvalue:.4e}")

# ─────────────────────────────────────────────────────────────
# FIGURE V.4 — Mean AES Encryption Time (seconds) by file size
# Caption: "Mean AES encryption time (seconds) for AES-128,
# AES-192, and AES-256 at 1 KB, 10 MB, and 100 MB.
# The performance gap between key lengths narrows as file
# size increases."  (Under V.C, Figure V.4)
# ─────────────────────────────────────────────────────────────
colors     = ["#1f77b4", "#ff7f0e", "#2ca02c"]
markers    = ["o", "s", "^"]
linestyles = ["-", "--", ":"]

fig1, ax1 = plt.subplots(figsize=(7, 4.5))

for i, (algo, times_list) in enumerate(mean_times.items()):
    ax1.plot(size_labels, times_list,
             color=colors[i], marker=markers[i],
             linestyle=linestyles[i], linewidth=2.2,
             markersize=8, label=algo)

ax1.set_title("Figure V.4 — Mean AES Encryption Time (s) by File Size",
              fontsize=12, fontweight="bold", pad=10)
ax1.set_xlabel("File Size", fontsize=11)
ax1.set_ylabel("Mean Encryption Time (s)", fontsize=11)
ax1.legend(loc="upper left", fontsize=10)
ax1.grid(True, linestyle="--", alpha=0.5)
ax1.yaxis.set_major_formatter(ticker.FormatStrFormatter("%.4f"))
plt.tight_layout()
plt.savefig("Figure_V4_AES_Mean_Time.png", dpi=150, bbox_inches="tight")
plt.show()
print("\nFigure V.4 saved as: Figure_V4_AES_Mean_Time.png")

# ─────────────────────────────────────────────────────────────
# FIGURE V.5 — AES Throughput (MB/s) by key length and file size
# Caption: "AES throughput (MB/s) by key length and file size.
# All three variants converge to approximately 1,170–1,234 MB/s
# at 100 MB, indicating the AES round-count penalty is
# negligible at scale."  (Under V.C, Figure V.5)
# ─────────────────────────────────────────────────────────────
fig2, ax2 = plt.subplots(figsize=(7, 4.5))

for i, (algo, tp_list) in enumerate(throughputs.items()):
    ax2.plot(size_labels, tp_list,
             color=colors[i], marker=markers[i],
             linestyle=linestyles[i], linewidth=2.2,
             markersize=8, label=algo)

ax2.set_title("Figure V.5 — AES Throughput (MB/s) by Key Length and File Size",
              fontsize=12, fontweight="bold", pad=10)
ax2.set_xlabel("File Size", fontsize=11)
ax2.set_ylabel("Throughput (MB/s)", fontsize=11)
ax2.legend(loc="upper right", fontsize=10)
ax2.grid(True, linestyle="--", alpha=0.5)
plt.tight_layout()
plt.savefig("Figure_V5_AES_Throughput.png", dpi=150, bbox_inches="tight")
plt.show()
print("Figure V.5 saved as: Figure_V5_AES_Throughput.png")