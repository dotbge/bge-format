# Changelog

Revision history of the `.bge` file format specification.

This tracks changes to the *specification document*. The format's own on-disk
versions (v1, v2, v3) are recorded in §12 of [`FILE_FORMAT_V3.md`](FILE_FORMAT_V3.md).

## Format v3.0 — 2026-02-03

Current specification.

- Added **Password Mode** (PBKDF2-HMAC-SHA512) alongside RSA Identity Mode.
- Added **Key ID** (8 bytes) for fast private-key lookup without trial decryption.
- Added a mandatory **encrypted metadata block** (filename, type, dimensions).
- Changed the file extension from `.enc` to `.bge` and introduced the `BGE3`
  magic number.
- Upgraded password key derivation to SHA-512 with 1,000,000 iterations.

## Format v2.0 — 2025-11-25

- Introduced chunked encryption and constant-memory streaming.
- RSA Identity Mode only.

## Format v1.0 — 2024-11-01

- Original single-blob format. RSA Identity Mode only.
