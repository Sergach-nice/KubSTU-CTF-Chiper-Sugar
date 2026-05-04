# KubSTU-CTF-Chiper-Sugar
CTF KubSTU — "Сахар" | Encrypted shell client (AES-256-CBC).

---

# Cipher "Сахар" — CTF Shell Client

> **CTF:** KubSTU &nbsp;|&nbsp; **Team:** DarkHoleTeam &nbsp;|&nbsp; **Category:** Network / Crypto

> ⚠️ **Public Release Notice**  
> This code has been sanitized for public release.  
> Real target host have been replaced with placeholders.

---

## Challenge Summary

Traffic capture (`.pcap`) contained an encrypted shell session.  
Protocol reverse engineering revealed:

```
frame = [4B length][16B IV][AES-256-CBC ciphertext]
key   = SHA256(password + salt)
```

Password and salt were recovered from traffic analysis.  
This client replicates the protocol and establishes an interactive encrypted shell.


## Protocol

| Field      | Size     | Description             |
|------------|----------|-------------------------|
| Length     | 4 bytes  | Body length (big-endian)|
| IV         | 16 bytes | Random per message      |
| Ciphertext | variable | AES-256-CBC + PKCS7 pad |

---

## Setup

```bash
pip install pycryptodome
```

Edit placeholders in the config section of `client.py`:

```python
HOST = "TARGET_HOST"    # CTF server IP or hostname
PORT = 1337             # CTF server port
```

---

## Usage

```bash
python3 client.py
```
---
## Team

**DarkHoleTeam** @ CTF KubSTU 2026
---
*For educational purposes only.*
