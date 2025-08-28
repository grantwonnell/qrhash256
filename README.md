# qr256

`qr256` is a lightweight cryptographic hash function inspired by the **Quarter Round** (QR) step from [ChaCha20](https://cr.yp.to/chacha.html).  
It provides both a standalone hashing function and an **HMAC (RFC 2104)** implementation.

---

## Features

- 🔒 Quarter Round–based 256-bit hash function (`qr256`)
- 📜 RFC 2104–compliant HMAC implementation
- 🖥️ Simple C code, no external dependencies
- ⚡ Lightweight and fast to compile and run
- 🔧 **Easily customizable number of rounds** for tuning speed vs. diffusion

---

## Build & Run

### Compile
```bash
gcc qrhash.c
./a.out "hmac_key" "hash string"
./a.out "secret_key" "Hello, World!"
