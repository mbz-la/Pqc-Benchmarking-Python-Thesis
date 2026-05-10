# PQC Benchmarking — MSc Cyber Security Thesis

Python benchmarking scripts for a controlled performance evaluation of 
classical, post-quantum, and hybrid cryptographic mechanisms.

**Author:** Muhammad Bilal Zahid  
**Institution:** South East Technological University (SETU), Carlow, Ireland  
**Programme:** MSc Cyber Security  
**Year:** 2026

---

## Benchmark Scenarios

| File | Scenario | Algorithms |
|------|----------|------------|
| KeyExchange_Scenario1.py | Scenario 1 — Key Establishment | ECDH P-256, RSA-2048, ML-KEM-512 |
| HashingFunction.py | Scenario 2 — Hash Functions | SHA-256, SHA3-256, SHAKE256 |
| PQC.py | Scenario 3 — Symmetric Encryption | AES-128, AES-192, AES-256 (CBC) |
| Hybrid.py | Scenario 4 — Hybrid Workflow | ECDH + ML-KEM-512 + SHA-256 KDF + AES-256-CBC |

---

## Environment

- Python 3.13.2
- Windows 11 Pro (x86-64)
- cryptography 44.0.2
- oqs-python 0.11.0 (liboqs 0.11.0)
- scipy 1.15.2

---

## Usage

Install dependencies:
pip install cryptography oqs scipy

Run any scenario:
python KeyExchange_Scenario1.py
