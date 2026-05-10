# =============================================================
# Scenario 4:  Hybrid Cryptographic Benchmarking 
# Thesis: A Performance Evaluation of Classical, Post-Quantum,
#         and Hybrid Cryptographic Mechanisms
# Student: Muhammad Bilal Zahid | C00315721 | SETU | May 2026
# Library: cryptography==44.0.2 | Python 3.13.2 | Windows 11
# =============================================================
import time, os
import numpy as np
import matplotlib.pyplot as plt
from hashlib import sha256
from scipy import stats
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
import kybercffi

# ─────────────────────────────────────────
# Configuration 
# ─────────────────────────────────────────
RUNS      = 2000
WARM_UP   = 50
AES_SIZES = [1024, 1024 * 1024]   # 1 KB, 1 MB

# ─────────────────────────────────────────
# Warm-up (discarded — not recorded)
# ─────────────────────────────────────────
print("Running warm-up iterations (discarded)...")
ky_warmup = kybercffi.Kyber512()
for _ in range(WARM_UP):
    priv1 = ec.generate_private_key(ec.SECP256R1(), default_backend())
    priv2 = ec.generate_private_key(ec.SECP256R1(), default_backend())
    ss_ecdh = priv1.exchange(ec.ECDH(), priv2.public_key())

    pk, sk = ky_warmup.generate_keypair()
    ct, ss_kyber = ky_warmup.encapsulate(pk)
    ky_warmup.decapsulate(ct, sk)

    sha256(ss_ecdh + ss_kyber).digest()

# ─────────────────────────────────────────
# Component Timing Storage
# ─────────────────────────────────────────
ecdh_times  = []
kyber_times = []
kdf_times   = []
total_times = []
hybrid_keys = []   # keep last key for AES benchmark

# Pre-create Kyber object outside the loop
ky = kybercffi.Kyber512()

# ─────────────────────────────────────────
# Main Benchmark Loop — 2,000 iterations
# ─────────────────────────────────────────
print(f"Running {RUNS} hybrid key exchange iterations...")

for i in range(RUNS):
    # ── ECDH P-256 ──────────────────────
    t0 = time.perf_counter()
    priv1 = ec.generate_private_key(ec.SECP256R1(), default_backend())
    priv2 = ec.generate_private_key(ec.SECP256R1(), default_backend())
    ss_ecdh = priv1.exchange(ec.ECDH(), priv2.public_key())
    t_ecdh = time.perf_counter() - t0

    # ── Kyber512 (ML-KEM-512) ───────────
    t0 = time.perf_counter()
    pk, sk = ky.generate_keypair()
    ct, ss_kyber = ky.encapsulate(pk)
    ky.decapsulate(ct, sk)
    t_kyber = time.perf_counter() - t0

    # ── KDF (SHA-256 concatenation) ─────
    t0 = time.perf_counter()
    hybrid_key = sha256(ss_ecdh + ss_kyber).digest()   # 32-byte AES-256 key
    t_kdf = time.perf_counter() - t0

    ecdh_times.append(t_ecdh)
    kyber_times.append(t_kyber)
    kdf_times.append(t_kdf)
    total_times.append(t_ecdh + t_kyber + t_kdf)
    hybrid_keys.append(hybrid_key)

# Convert to numpy
ecdh_times  = np.array(ecdh_times)
kyber_times = np.array(kyber_times)
kdf_times   = np.array(kdf_times)
total_times = np.array(total_times)

# ─────────────────────────────────────────
# Statistical Summary Function As per Scenario 4
# ─────────────────────────────────────────
def summarize(name, data):
    median  = np.median(data)
    iqr     = np.percentile(data, 75) - np.percentile(data, 25)
    p5      = np.percentile(data, 5)
    p95     = np.percentile(data, 95)
    skewness = stats.skew(data)
    mean    = np.mean(data)
    std     = np.std(data)
    _, shapiro_p = stats.shapiro(data[:2000])
    print(f"\n{'='*40}")
    print(f"  {name}")
    print(f"{'='*40}")
    print(f"  Median      : {median*1000:.4f} ms")
    print(f"  Mean        : {mean*1000:.4f} ms")
    print(f"  Std Dev     : {std*1000:.4f} ms")
    print(f"  IQR         : {iqr*1000:.4f} ms")
    print(f"  5th  pct    : {p5*1000:.4f} ms")
    print(f"  95th pct    : {p95*1000:.4f} ms")
    print(f"  Skewness    : {skewness:.3f}")
    print(f"  Shapiro p   : {shapiro_p:.6f}")
    return median

print("\n========== HYBRID KEY EXCHANGE RESULTS ==========")
med_ecdh  = summarize("ECDH P-256", ecdh_times)
med_kyber = summarize("Kyber512 (ML-KEM-512)", kyber_times)
med_kdf   = summarize("KDF (SHA-256)", kdf_times)
med_total = summarize("Total Hybrid Workflow", total_times)

# Component percentage breakdown (median-based)
pct_ecdh  = (med_ecdh  / med_total) * 100
pct_kyber = (med_kyber / med_total) * 100
pct_kdf   = (med_kdf   / med_total) * 100
print(f"\n--- Median-Based Component Breakdown ---")
print(f"  ECDH  : {pct_ecdh:.1f}%")
print(f"  Kyber : {pct_kyber:.1f}%")
print(f"  KDF   : {pct_kdf:.1f}%")

# ─────────────────────────────────────────
# AES Encryption Benchmark (using last hybrid key)
# ─────────────────────────────────────────
print("\n========== AES ENCRYPTION BENCHMARK ==========")
AES_RUNS = 200
aes_key  = hybrid_keys[-1]   # 32-byte key → AES-256

for size in AES_SIZES:
    label = "1 KB" if size == 1024 else "1 MB"
    enc_times = []
    dec_times = []

    for _ in range(AES_RUNS):
        msg = os.urandom(size)
        iv  = os.urandom(16)

        t0 = time.perf_counter()
        ct = AES.new(aes_key, AES.MODE_CBC, iv).encrypt(pad(msg, AES.block_size))
        enc_times.append(time.perf_counter() - t0)

        t0 = time.perf_counter()
        unpad(AES.new(aes_key, AES.MODE_CBC, iv).decrypt(ct), AES.block_size)
        dec_times.append(time.perf_counter() - t0)

    enc_arr = np.array(enc_times)
    dec_arr = np.array(dec_times)
    throughput = (size / (1024 * 1024)) / np.median(enc_arr)

    print(f"\n  AES-256 CBC  |  {label}")
    print(f"  Encrypt Median : {np.median(enc_arr)*1000:.4f} ms")
    print(f"  Decrypt Median : {np.median(dec_arr)*1000:.4f} ms")
    print(f"  Throughput     : {throughput:.2f} MB/s")
    print(f"  Enc IQR        : {(np.percentile(enc_arr,75)-np.percentile(enc_arr,25))*1000:.4f} ms")
    print(f"  Enc Skewness   : {stats.skew(enc_arr):.3f}")

# ─────────────────────────────────────────
# Figure 1 — Component Timing Distributions (Box Plot)
# ─────────────────────────────────────────
fig, ax = plt.subplots(figsize=(8, 5))
ax.boxplot(
    [ecdh_times * 1000, kyber_times * 1000, kdf_times * 1000],
    labels=["ECDH P-256", "ML-KEM-512", "KDF\n(SHA-256)"],
    showfliers=False
)
ax.set_ylabel("Execution Time (ms)")
ax.set_title(
    "Figure V.6: Distribution of Hybrid Workflow Component Latencies\n"
    "(2,000 iterations, outliers excluded, AES-256-CBC key derived via SHA-256 KDF)"
)
ax.grid(True, axis="y", linestyle="--", alpha=0.5)
plt.tight_layout()
plt.savefig("hybrid_component_boxplot.png", dpi=150)
plt.show()
print("Saved: hybrid_component_boxplot.png")

# ─────────────────────────────────────────
# Figure 2 — Total Hybrid Latency Distribution (Histogram)
# ─────────────────────────────────────────
fig, ax = plt.subplots(figsize=(8, 4))
ax.hist(total_times * 1000, bins=60, color="steelblue", alpha=0.75, density=True)
ax.set_xlabel("Total Hybrid Workflow Time (ms)")
ax.set_ylabel("Density")
ax.set_title(
    "Figure V.7 Timing Distribution of Complete Hybrid Key Establishment Workflow\n"
    "(ECDH P-256 + ML-KEM-512 + SHA-256 KDF, 2,000 iterations)"
)
ax.axvline(np.median(total_times) * 1000, color="red", linestyle="--", label=f"Median = {np.median(total_times)*1000:.3f} ms")
ax.legend()
plt.tight_layout()
plt.savefig("hybrid_total_distribution.png", dpi=150)
plt.show()
print("Saved: hybrid_total_distribution.png")

# ─────────────────────────────────────────
# Figure 3 — Median Component Breakdown (Bar)
# ─────────────────────────────────────────
fig, ax = plt.subplots(figsize=(7, 5))
components = ["ECDH P-256", "Kyber512\n(ML-KEM-512)", "KDF (SHA-256)"]
medians_ms = [med_ecdh * 1000, med_kyber * 1000, med_kdf * 1000]
colors = ["#4C72B0", "#DD8452", "#55A868"]
bars = ax.bar(components, medians_ms, color=colors, width=0.5)
ax.set_ylabel("Median Execution Time (ms)")
ax.set_title(
    "Figure V.8: Median Latency Contribution of Each Hybrid Workflow Component\n"
    "(2,000 iterations — median-based decomposition)"
)
for bar, val in zip(bars, medians_ms):
    ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.01,
            f"{val:.3f} ms", ha="center", va="bottom", fontsize=9)
ax.grid(True, axis="y", linestyle="--", alpha=0.5)
plt.tight_layout()
plt.savefig("hybrid_component_median_bar.png", dpi=150)
plt.show()
print("Saved: hybrid_component_median_bar.png")

print("\nRun completed.")
