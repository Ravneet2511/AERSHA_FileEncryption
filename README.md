# 🔐 Hybrid Encryption System in C++

This project implements a hybrid encryption system using **AES-256 (CBC mode)** for fast file encryption and **RSA (2048-bit)** for secure key exchange. It also includes **digital signing and verification** to ensure file integrity and authenticity using RSA and SHA-256.

## 📦 Features

- ✅ Generate RSA key pair (public & private)
- ✅ Generate AES-256 symmetric key and IV
- ✅ Encrypt files using AES-256-CBC
- ✅ Encrypt AES key using RSA public key (OAEP padding)
- ✅ Decrypt AES key using RSA private key
- ✅ Decrypt files using AES-256-CBC
- ✅ Sign a file using RSA-SHA256 digital signature
- ✅ Verify file signature using RSA public key

## 🛠 Dependencies

- OpenSSL (required)
- C++17 or later

### Install OpenSSL (Ubuntu)

```bash
sudo apt update
sudo apt install libssl-dev

```
```compile
g++ -o hybrid_encryption AERSHA.cpp -Isst -lcrypto

./hybrid_encryption
```

