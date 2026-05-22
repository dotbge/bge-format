# Test Vectors

Known-answer test vectors for verifying a `.bge` (v3) implementation. Each
vector pairs a `.bge` file with the inputs that produced it and the plaintext a
correct reader must recover.

## Two kinds of conformance

| | What it proves | Which vectors |
|---|---|---|
| **Reader** | Decrypting `expected.bge` with the supplied key/password yields `plaintext.bin` byte-for-byte. | **All** vectors. |
| **Writer** | Re-encrypting `plaintext.bin` with the *pinned* random values in `vector.json` reproduces `expected.bge` byte-for-byte. | **Password-mode only.** |

Writer-conformance does **not** apply to RSA-identity vectors: RSA-OAEP-SHA256
uses an internal random seed, so the encrypted key in the header is never
byte-reproducible. RSA vectors are therefore reader-conformance only.

Password mode is fully deterministic when every random value (master key, salt,
wrap nonce, metadata nonce, chunk nonces) is pinned — so password vectors carry
those pins and support both reader and writer conformance.

> **Safety:** the pinned-randomness inputs and the published private key exist
> *only* to make verification possible. **Never** use a pinned-nonce build or
> these keys to encrypt real data — fixed nonces/salt destroy AES-GCM security.

## The vectors

| Directory | Mode | Conformance | Covers |
|-----------|------|-------------|--------|
| [`rsa-identity-basic/`](rsa-identity-basic/) | RSA identity | reader | Single-chunk RSA-4096 file; key-ID lookup; OAEP-wrapped DEK. |
| [`password-basic/`](password-basic/) | Password | reader + writer | Single-chunk password file; PBKDF2-SHA512 → AES-GCM key wrap. |
| [`empty-file/`](empty-file/) | Password | reader + writer | Zero-byte payload (chunk count = 0); header + metadata only. |
| [`metadata-rich/`](metadata-rich/) | Password | reader + writer | Optional metadata fields (size, width, height) in the encrypted block. |

## Layout

```
test-vectors/
  <name>/
    vector.json        # parameters: mode, key/password, pinned values, sizes
    plaintext.bin      # the original file contents
    expected.bge       # the encrypted output
    bge-test-vector_DO-NOT-USE_private.pem   # RSA private key (RSA vectors only)
    bge-test-vector_DO-NOT-USE_public.pem    # RSA public key  (RSA vectors only)
```

### `vector.json`

Records everything needed to **decrypt** `expected.bge` and — for password
vectors — to **reproduce** it.

Password-mode example:

```json
{
  "name": "password-basic",
  "format_version": 3,
  "mode": "password",
  "conformance": ["reader", "writer"],
  "plaintext": "plaintext.bin",
  "expected": "expected.bge",
  "password": "correct horse battery staple",
  "chunk_size": 67108864,
  "metadata": { "n": "hello.txt", "t": "public.plain-text", "s": 12 },
  "pinned": {
    "master_key_hex": "000102…1f",
    "kdf": "pbkdf2-hmac-sha512",
    "salt_hex": "a0a1…af",
    "iterations": 1000000,
    "wrap_nonce_hex": "b0b1…bb",
    "metadata_nonce_hex": "c0c1…cb",
    "chunk_nonces_hex": ["d0d1…db"]
  }
}
```

RSA-identity vectors instead carry the published throwaway key pair
(`bge-test-vector_DO-NOT-USE_*.pem`) and the 8-byte `key_id_hex`; they have no
`pinned` block (see the OAEP note above).

The encrypted **metadata** JSON uses sorted keys and compact separators
(`{"h":1080,"n":"photo.jpg",…}`), matching the reference encoder — relevant when
reproducing password vectors byte-for-byte.

## How to use them

1. **Reader conformance** — decrypt `expected.bge` with the supplied
   the supplied private key (RSA) or `password` (password mode); the result must equal
   `plaintext.bin` byte-for-byte. Confirm decoded metadata matches the
   `metadata` field.
2. **Writer conformance (password vectors)** — encrypt `plaintext.bin` using the
   pinned values in `vector.json`; the result must equal `expected.bge`
   byte-for-byte.

All four vectors were generated and verified against the reference
implementation: RSA via the `bge` CLI round-trip, password mode via the
reference `decryptFileV3Password` reader.
