# =============================================================
# Scenario 1: Key Establishment Benchmarking
# Thesis: A Performance Evaluation of Classical, Post-Quantum,
#         and Hybrid Cryptographic Mechanisms
# Student: Muhammad Bilal Zahid | C00315721 | SETU
# Environment: Python 3.13.2, cryptography==44.0.2, Windows 11
# =============================================================
import time
import numpy as np
import matplotlib.pyplot as plt
from scipy import stats

from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

import kybercffi  # ML-KEM post-quantum KEM

# -----------------------------------------------------------------------------
# Configuration 
# ------------------------------------------------------------------------------
RUNS = 2000
RSA_SYM_KEY_SIZE = 32  # 32-byte symmetric key for RSA key exchange

# ----------------------------------------
# Storage
# ----------------------------------------
ecdh_times = []
rsa_times = []
kyber_times = []

# ----------------------------------------
# Warm-up
# ----------------------------------------
for _ in range(50):
    # ECDH
    priv1 = ec.generate_private_key(ec.SECP256R1(), default_backend())
    priv2 = ec.generate_private_key(ec.SECP256R1(), default_backend())
    priv1.exchange(ec.ECDH(), priv2.public_key())

    # RSA
    sender_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    receiver_pub = sender_key.public_key()
    symmetric_key = b'\x00' * RSA_SYM_KEY_SIZE
    receiver_pub.encrypt(symmetric_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                     algorithm=hashes.SHA256(), label=None))

    # ML-KEM-512
    ky = kybercffi.Kyber512()
    pk, sk = ky.generate_keypair()
    ct, ss1 = ky.encapsulate(pk)
    ss2 = ky.decapsulate(ct, sk)

# ----------------------------------------
# Pre-create ML-KEM object
# ----------------------------------------
ky = kybercffi.Kyber512()

# ----------------------------------------
# Benchmark Key Exchange Loops
# ----------------------------------------
for _ in range(RUNS):

    # ---- ECDH ----
    start = time.perf_counter()
    priv1 = ec.generate_private_key(ec.SECP256R1(), default_backend())
    priv2 = ec.generate_private_key(ec.SECP256R1(), default_backend())
    shared_ecdh = priv1.exchange(ec.ECDH(), priv2.public_key())
    ecdh_times.append(time.perf_counter() - start)

    # ---- RSA (encrypt 32-byte symmetric key) ----
    start = time.perf_counter()
    sender_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    receiver_pub = sender_key.public_key()
    symmetric_key = b'\x00' * RSA_SYM_KEY_SIZE
    ciphertext = receiver_pub.encrypt(symmetric_key, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ))
    rsa_times.append(time.perf_counter() - start)

    # ---- ML-KEM-512 ----
    start = time.perf_counter()
    pk, sk = ky.generate_keypair()
    ct, ss1 = ky.encapsulate(pk)
    ss2 = ky.decapsulate(ct, sk)
    kyber_times.append(time.perf_counter() - start)

# Convert to numpy arrays
ecdh_times = np.array(ecdh_times)
rsa_times = np.array(rsa_times)
kyber_times = np.array(kyber_times)

# ----------------------------------------
# Statistical Summary
# ----------------------------------------
def summarize(name, data):
    median = np.median(data)
    iqr = np.percentile(data, 75) - np.percentile(data, 25)
    perc5 = np.percentile(data, 5)
    perc95 = np.percentile(data, 95)
    print(f"\n{name}")
    print(f"Median: {median:.6f} s")
    print(f"IQR: {iqr:.6f} s")
    print(f"5th-95th percentile: ({perc5:.6f}, {perc95:.6f})")
    print(f"Skewness: {stats.skew(data):.2f}")

summarize("ECDH P-256 Key Exchange", ecdh_times)
summarize("RSA-2048 Key Exchange (32-byte key)", rsa_times)
summarize("ML-KEM-512 Key Exchange", kyber_times)

# ----------------------------------------
# Plottin Histograms For the Scenario (log scale)
# ----------------------------------------
def plot_hist(data, title):
    plt.figure(figsize=(7,4))
    plt.hist(data, bins=50, alpha=0.7, color='skyblue', density=True)
    plt.yscale('log')
    plt.xlabel("Time (s)")
    plt.ylabel("Density (log scale)")
    plt.title(title)
    plt.grid(True, linestyle='--', alpha=0.5)
    plt.show()

plot_hist(ecdh_times, "ECDH P-256 Key Exchange")
plot_hist(rsa_times, "RSA-2048 Key Exchange")
plot_hist(kyber_times, "ML-KEM-512 Key Exchange")

# ----------------------------------------
# Comparison Bar Chart For the Scenario (Median)
# ----------------------------------------
labels = ["ECDH P-256", "RSA-2048", "ML-KEM-512"]
medians = [np.median(ecdh_times), np.median(rsa_times), np.median(kyber_times)]

plt.figure(figsize=(7,5))
plt.bar(labels, medians, color=['green','red','blue'])
plt.ylabel("Median Time (s)")
plt.title("Cryptographic Key Exchange Performance")
plt.yscale('log')
plt.grid(True, axis='y', linestyle='--', alpha=0.5)
plt.show()