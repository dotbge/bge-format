# Changelog

Revision history of the `.bge` file format specification.

This tracks changes to the *specification document*. The format's own on-disk
versions (v1, v2, v3) are recorded in §12 of [`FILE_FORMAT_V3.md`](FILE_FORMAT_V3.md).

## Document revision — 2026-09-22

Format v3.0, unchanged on disk: every file valid before is valid after.

- **Corrected** the Key ID input (§3.1, §4.4). It is `SHA256` of the PKCS#1
  `RSAPublicKey` DER, not of the SPKI DER as the text said. All reference
  implementations and the `rsa-identity-basic` vector already hash PKCS#1.
  Readers may also accept the SPKI-derived ID to read files from writers built
  on the earlier text; writers must use PKCS#1.
- **Chunk size**: writers now default to 4 MiB (was 64 MiB), bounding a reader's
  memory and seek cost to one small chunk. Stated the 1–256 MiB range, the
  chunk-count formula, and replaced the per-content-type table, which no
  implementation used (§5, §9, §10).
- **Metadata**: documented the optional keys `c`, `m` (timestamps), `b`
  (thumbnail) and `a` (archive kind), and added `p`, the original folder path
  written when folder encryption hides folder names. Readers must ignore
  unknown keys. Documented the encrypted-message marker
  `t = "public.plain-text; dotbge-kind=message"`.
- **Names**: a `.bge` file's name may be opaque; readers take the original name
  from `n` (§8.4).
- **Security**: added §8.6 on treating metadata as untrusted (filename and path
  sanitizing, safe ZIP extraction). Stated that no AES-GCM operation uses
  additional authenticated data.

## Format v3.0 — 2026-02-03

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
