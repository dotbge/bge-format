# The .bge File Format — Specification v3.0

> An open container format for encrypted files.
> Free to implement — see [`LICENSE`](LICENSE).

| | |
|---|---|
| **Format** | `.bge` |
| **Specification version** | 3.0 |
| **Status** | Final |
| **Updated** | 2026-09-22 |
| **UTI** | `com.dotbge.encrypted` |
| **Magic number** | `BGE3` (`0x42 0x47 0x45 0x33`) |
| **Home** | https://dotbge.com |
| **Repository** | https://github.com/dotbge/bge-format |

---

## 1. Overview

BGE v3 is a secure, high-performance, hybrid encryption file format designed for the macOS and iOS ecosystem. It supersedes v2 by introducing **Identity-based sharing** and **Password-based encryption** modes, while maintaining the efficient chunked architecture for streaming large media files.

### Key Features

| Feature | Description |
|---------|-------------|
| **Extension** | `.bge` |
| **UTI** | `com.dotbge.encrypted` |
| **Magic Number** | `BGE3` (4 bytes: `0x42 0x47 0x45 0x33`) |
| **Encryption Modes** | RSA Identity Mode + Password Mode |
| **Metadata** | Encrypted metadata block (filename, type, dimensions, timestamps, thumbnail) |
| **Streaming** | Memory bounded by one chunk (4 MB by default) regardless of file size |
| **Random Access** | Supports seeking within encrypted files |

### Version Comparison

| Feature | v1 | v2 | v3 |
|---------|-----|-----|-----|
| **Magic Number** | None | `0x02` (1 byte) | `BGE3` (4 bytes) |
| **Memory Usage** | Entire file | Constant ~80MB | One chunk (1–256 MB, default 4 MB) |
| **Encryption Mode** | RSA only | RSA only | RSA + Password |
| **Key ID** | None | None | 8 bytes (fast key lookup) |
| **Metadata Block** | None | None | Encrypted JSON |
| **File Extension** | `.enc` | `.enc` | `.bge` |
| **Large File Support** | Limited | Unlimited | Unlimited |

---

## 2. File Architecture

The file consists of three linear segments:

```text
┌─────────────────────────────────────────────────────────────┐
│                       1. HEADER                              │
│   [Magic] [Ver] [Mode] [....Mode-specific Auth Data....]    │
│   [Chunk Size] [Original Size] [Chunk Count]                │
│   (Contains the encrypted Master Key DEK)                   │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                   2. METADATA BLOCK                          │
│   [Nonce] [Length] [Encrypted JSON] [Tag]                   │
│   (Encrypted using DEK. Contains filename, type, dims)      │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    3. CONTENT PAYLOAD                        │
│   [Chunk 0] [Chunk 1] ........................ [Chunk N]    │
│   (The actual file content, AES-GCM encrypted chunks)       │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Byte-Level Specification

> **Important:** All multi-byte integers are stored in **Big-Endian** format.

### 3.1 Header

#### Preamble (Common to all modes)

| Offset | Size | Type | Value / Description |
|--------|------|------|---------------------|
| 0 | 4 | `char[4]` | Magic: `BGE3` (`0x42 0x47 0x45 0x33`) |
| 4 | 1 | `uint8` | Format Version: `0x03` |
| 5 | 1 | `uint8` | Encryption Mode:<br>• `0x01`: RSA Identity Mode<br>• `0x02`: Password Mode |

#### Branch A: RSA Identity Mode (Mode == 0x01)

Used for secure sharing between users using asymmetric Public/Private key pairs.

| Relative Offset | Size | Type | Description |
|-----------------|------|------|-------------|
| +0 | 8 | `byte[8]` | **Key ID**: First 8 bytes of `SHA256(PKCS1_DER_Encoded_RSA_Public_Key)` (§4.4)<br>Used to quickly identify which private key to use for decryption. |
| +8 | 4 | `uint32` | **Cipher Length (N)**: Length of RSA ciphertext (typically 512 for RSA-4096) |
| +12 | N | `binary` | **RSA Ciphertext**: Master Key (DEK) encrypted via RSA-OAEP-SHA256 |

#### Branch B: Password Mode (Mode == 0x02)

Used for passphrase-based encryption. Compatible with users who don't have the BGE app.

| Relative Offset | Size | Type | Description |
|-----------------|------|------|-------------|
| +0 | 1 | `uint8` | **KDF Type**: Key derivation function<br>• `0x01`: PBKDF2-HMAC-SHA512 |
| +1 | 16 | `byte[16]` | **Salt**: Cryptographically random salt for KDF |
| +17 | 4 | `uint32` | **Iterations**: KDF iteration count (default: 1,000,000) |
| +21 | 12 | `byte[12]` | **Wrap Nonce**: AES-GCM nonce for key wrapping |
| +33 | 4 | `uint32` | **Wrap Length**: Length of wrapped key data (typically 48 bytes) |
| +37 | 48 | `binary` | **Wrapped Key**: AES-256-GCM encrypted Master Key (32 bytes) + Tag (16 bytes) |

#### Shared File Info (Follows Mode-specific Block)

This section immediately follows the mode-specific authentication data.

| Relative Offset | Size | Type | Description |
|-----------------|------|------|-------------|
| +0 | 8 | `int64` | **Chunk Size**: Plaintext bytes per chunk, 1 MiB–256 MiB (§5). Writers default to 4,194,304 (4 MiB); files written before 2026-09 use 67,108,864 (64 MiB) |
| +8 | 8 | `int64` | **Original File Size**: Size of original unencrypted file |
| +16 | 4 | `uint32` | **Chunk Count**: `ceil(Original File Size / Chunk Size)`; 0 for an empty file |

### 3.2 Encrypted Metadata Block

This block stores file attributes for Finder Preview / QuickLook integration. It is encrypted using the Master Key (DEK) obtained from the header.

| Order | Size | Type | Description |
|-------|------|------|-------------|
| 1 | 12 | `byte[12]` | **Block Nonce**: Unique AES-GCM IV for metadata encryption |
| 2 | 4 | `uint32` | **JSON Length (L)**: Size of the encrypted JSON blob, excluding the tag (equal to the plaintext JSON length) |
| 3 | L | `binary` | **Encrypted JSON**: AES-GCM ciphertext of metadata |
| 4 | 16 | `byte[16]` | **Auth Tag**: GCM integrity check tag |

#### Metadata JSON Schema

The plaintext is a UTF-8 JSON object. Keys are abbreviated to minimize storage overhead:

```json
{
  "n": "Financial_Report_Q4.pdf",  // Original Filename (Required)
  "t": "com.adobe.pdf",            // UTI / Content Type (Required)
  "s": 10485760,                   // File Size in bytes (Optional)
  "w": 1920,                       // Width in pixels (Optional, for images/video)
  "h": 1080,                       // Height in pixels (Optional)
  "d": 120.5,                      // Duration in seconds (Optional, for audio/video)
  "c": 1710000000.0,               // Creation date, Unix seconds (Optional)
  "m": 1710000000.0,               // Modification date, Unix seconds (Optional)
  "b": "/9j/4AAQSkZJRg…",          // Thumbnail, base64 JPEG (Optional)
  "a": "bge-folder",               // Archive kind (Optional)
  "p": "Photos/2024/Trip"          // Original folder path (Optional)
}
```

| Key | Type | Meaning |
|-----|------|---------|
| `n` | string | Original filename. The `.bge` file's own name may differ (§8.4); a reader names its output from `n` |
| `t` | string | UTI, or MIME type, of the content. May carry parameters after `;` (see *Encrypted messages*) |
| `s` | integer | Original file size in bytes |
| `w`, `h` | integer | Pixel dimensions of an image or video |
| `d` | number | Duration of audio or video, in seconds |
| `c`, `m` | number | Creation and modification dates of the original file, as Unix seconds. A reader may restore them on the decrypted file |
| `b` | string | Standard base64 of a JPEG thumbnail, about 200×200 px. Writers drop it when the JSON would exceed the maximum length |
| `a` | string | Archive kind. `"bge-folder"`: the payload is a ZIP archive the writer made from a folder or from several files, and `n` ends in `.zip` |
| `p` | string | Original folder path (see *Original folder path*) |

**Requirements:**
- Metadata Block is **MANDATORY** in v3 format
- If no metadata is available, use minimal JSON: `{"n":"","t":""}`
- Maximum JSON Length: 65,536 bytes (64KB)
- Readers MUST ignore keys they do not know. Writers add optional keys without a format version change
- Every value comes from whoever wrote the file and is untrusted (§8.6)

The reference writer encodes the JSON with sorted keys and no whitespace. Readers must not depend on key order.

#### Encrypted messages

A short text message travels as an ordinary `.bge` file whose payload is the UTF-8 text. Its `t` is `public.plain-text; dotbge-kind=message`, and `s` is the text's length in UTF-8 bytes. A reader that finds the `dotbge-kind=message` parameter on a plain-text type may show the text as a message instead of offering a file. Readers that ignore the parameter still see a plain-text file.

#### Original folder path

`p` is written when a folder is encrypted file by file and the output hides folder names, each folder being replaced by a pseudonym, one for one. It lists the folders the file was in, from the encrypted folder's own name down to the file's parent, `/`-separated, Unicode NFC. The filename stays in `n`. It is absent otherwise.

A reader decrypting a folder restores names from it: if the `.bge` sits `k` folders below the folder being decrypted, those `k` folders take the last `k` components of `p`, and folders deeper than `p` records keep their names. When `k` is less than the number of components, the folder being decrypted was itself named by the component just before them.

`p` is untrusted input. A reader sanitizes each component as it does `n` (§8.6), and ignores the whole path if any component is empty, `.` or `..`.

### 3.3 Content Payload (Chunks)

The file content is split into fixed-size chunks. Each chunk is independently encrypted.

#### Structure Per Chunk

| Component | Size | Description |
|-----------|------|-------------|
| Nonce | 12 bytes | Unique random nonce for this chunk |
| Ciphertext | Variable | Encrypted data (chunk size or remainder for last chunk) |
| Tag | 16 bytes | AES-GCM authentication tag |

**Algorithm:** AES-256-GCM using Master Key (DEK) + per-chunk random nonce. No additional authenticated data is used, here or in the metadata block and password key wrap.

**Last Chunk:** Holds the remainder, `Original File Size − (Chunk Count − 1) × Chunk Size` bytes; every other chunk holds exactly Chunk Size bytes.

---

## 4. Cryptographic Standards

All cryptographic operations comply with US Export Regulations (Mass Market) and industry best practices.

### 4.1 Symmetric Encryption (Payload & Key Wrapping)

| Parameter | Value |
|-----------|-------|
| **Algorithm** | AES-256-GCM |
| **Key Size** | 256 bits (32 bytes) |
| **Nonce Size** | 96 bits (12 bytes) - MUST be random per invocation |
| **Tag Size** | 128 bits (16 bytes) |

### 4.2 Asymmetric Encryption (RSA Identity Mode)

| Parameter | Value |
|-----------|-------|
| **Algorithm** | RSA-4096 |
| **Padding** | OAEP with SHA-256 and MGF1-SHA256 |
| **Output Size** | 512 bytes (4096 bits) |

### 4.3 Key Derivation (Password Mode)

| Parameter | Value |
|-----------|-------|
| **Algorithm** | PBKDF2-HMAC-SHA512 |
| **Salt Size** | 16 bytes (cryptographically random) |
| **Iterations** | 1,000,000 (default for writing) |
| **Output Key Size** | 256 bits (for AES-256 KEK) |

> **Note:** Iterations value is stored in the file header. Readers MUST use the stored value, not the default.

**Password text encoding clarification (2026-09):** Before PBKDF2, a writer MUST
normalize the user's Unicode password to NFC and then encode it as UTF-8, with
no BOM or NUL terminator. Readers MUST use the same rule for newly written
files. Earlier BGE3 implementations used unnormalized UTF-8; to retain access
to those files, a reader SHOULD retry the literal UTF-8 input after an NFC
unwrap failure, and MAY retry its NFD form. No new on-disk field is introduced.

### 4.4 Key ID Calculation

The Key ID enables fast private key lookup without attempting decryption:

```
Key ID = SHA256(PKCS1_DER)[0:8]

Where:
  PKCS1_DER = PKCS#1 RSAPublicKey DER encoding (SEQUENCE of modulus and exponent)
  [0:8]     = First 8 bytes of the hash
```

Hash the bare `RSAPublicKey` structure, not a `SubjectPublicKeyInfo` wrapping it: the wrapper changes the hash. A key supplied as SPKI (a PEM labelled `PUBLIC KEY`) is unwrapped to PKCS#1 first. The `rsa-identity-basic` test vector checks this.

> **Correction (2026-09-22):** revisions of this document before 2026-09-22 said `SHA256(SPKI_DER)`. That was an error: every reference implementation, and the test vector published with those revisions, hash PKCS#1. A reader may also accept `SHA256(SPKI_DER)[0:8]` when matching keys, to read files from writers built on the earlier text; writers MUST use PKCS#1.

---

## 5. Chunk Size

A chunk is the unit a reader has to hold: its GCM tag covers the whole chunk, so none of it can be used until all of it is decrypted. The chunk size therefore bounds a reader's memory, and how much it must decrypt to seek to any byte, such as a video player reading an encrypted file as it plays. Smaller chunks cost 28 bytes of overhead each (§9).

| | Value |
|---|---|
| **Allowed range** | 1 MiB (1,048,576) to 256 MiB (268,435,456). Writers MUST stay within it; readers MAY reject files outside it |
| **Default** | 4 MiB (4,194,304), for all content types |
| **Earlier default** | 64 MiB (67,108,864), used by files written before 2026-09 |

The chunk size is stored in the header, so readers always use the file's value: files written with any valid size stay readable.

---

## 6. Implementation Guide

### 6.1 Format Detection (Sniffer)

```swift
enum BGEFormat {
    case v1, v2, v3, unknown
}

func detectFormat(headerBytes: Data) -> BGEFormat {
    guard headerBytes.count >= 4 else { return .unknown }

    // V3: Starts with "BGE3"
    if headerBytes.prefix(4) == Data([0x42, 0x47, 0x45, 0x33]) {
        return .v3
    }

    // V2: First byte is 0x02
    if headerBytes[0] == 0x02 {
        return .v2
    }

    // V1: First 4 bytes are RSA length (typically 0x00 0x00 0x02 0x00 = 512)
    let rsaLen = headerBytes.prefix(4).withUnsafeBytes {
        $0.load(as: UInt32.self).bigEndian
    }
    if rsaLen == 512 {
        return .v1
    }

    return .unknown
}
```

### 6.2 Encryption Flow (v3)

```
┌─────────────────────────────────────────────────────────────┐
│                      ENCRYPTION                              │
├─────────────────────────────────────────────────────────────┤
│ 1. Generate Master Key (DEK)                                 │
│    └─ 32 random bytes via SecRandomCopyBytes                │
│                                                              │
│ 2. Encrypt DEK based on mode:                                │
│    ├─ RSA Mode: RSA-OAEP encrypt DEK with public key        │
│    │            Calculate Key ID from public key             │
│    └─ Password Mode:                                         │
│            Generate Salt (16 bytes)                          │
│            Derive KEK = PBKDF2(password, salt, iterations)   │
│            Wrap DEK with AES-GCM using KEK                   │
│                                                              │
│ 3. Write Header                                              │
│    └─ Magic + Version + Mode + Auth Data + File Info        │
│                                                              │
│ 4. Encrypt & Write Metadata Block                            │
│    └─ Nonce + Length + AES-GCM(JSON, DEK) + Tag             │
│                                                              │
│ 5. Encrypt Content Chunks                                    │
│    └─ For each chunk:                                        │
│        Generate random nonce                                 │
│        Write: Nonce + AES-GCM(chunk, DEK) + Tag             │
└─────────────────────────────────────────────────────────────┘
```

### 6.3 Decryption Flow (v3)

```
┌─────────────────────────────────────────────────────────────┐
│                      DECRYPTION                              │
├─────────────────────────────────────────────────────────────┤
│ 1. Read & Verify Preamble                                    │
│    └─ Check Magic "BGE3" and Version 0x03                   │
│                                                              │
│ 2. Read Mode & Recover Master Key (DEK):                     │
│    ├─ RSA Mode (0x01):                                       │
│    │   Read Key ID → Find matching private key in Keychain  │
│    │   RSA-OAEP decrypt → DEK                               │
│    └─ Password Mode (0x02):                                  │
│        Read Salt, Iterations                                 │
│        Prompt user for password                              │
│        Derive KEK = PBKDF2(password, salt, iterations)       │
│        Unwrap DEK with AES-GCM using KEK                     │
│                                                              │
│ 3. Read File Info                                            │
│    └─ Chunk Size, Original Size, Chunk Count                │
│                                                              │
│ 4. Decrypt Metadata Block                                    │
│    └─ Read Nonce + Length + Ciphertext + Tag                │
│        Decrypt with DEK → Parse JSON                         │
│        Display filename, type in Finder/QuickLook            │
│                                                              │
│ 5. Decrypt Content Chunks                                    │
│    └─ For each chunk (or seek to specific chunk):           │
│        Read Nonce + Ciphertext + Tag                         │
│        Decrypt with DEK → Write plaintext                    │
│                                                              │
│ 6. Verify Final Size                                         │
│    └─ Assert decrypted size == Original Size                │
└─────────────────────────────────────────────────────────────┘
```

---

## 7. Header Size Calculation

### RSA Identity Mode

```
Preamble:           4 (magic) + 1 (version) + 1 (mode) = 6 bytes
RSA Auth Data:      8 (key_id) + 4 (cipher_len) + 512 (cipher) = 524 bytes
File Info:          8 (chunk_size) + 8 (orig_size) + 4 (chunk_count) = 20 bytes
────────────────────────────────────────────────────────────────────────
Total Header:       550 bytes
```

### Password Mode

```
Preamble:           4 (magic) + 1 (version) + 1 (mode) = 6 bytes
Password Auth Data: 1 (kdf) + 16 (salt) + 4 (iter) + 12 (nonce) + 4 (wrap_len) + 48 (wrapped) = 85 bytes
File Info:          8 (chunk_size) + 8 (orig_size) + 4 (chunk_count) = 20 bytes
────────────────────────────────────────────────────────────────────────
Total Header:       111 bytes
```

---

## 8. Security Considerations

### 8.1 Memory Hygiene

- **Password Mode**: The password string and derived KEK MUST be zeroized (overwritten with zeros) in memory immediately after obtaining the Master Key (DEK).
- **Master Key**: Should be kept in memory only for the duration of the encryption/decryption operation.

### 8.2 Nonce Uniqueness

- Each chunk MUST use a unique random nonce generated via `SecRandomCopyBytes` (macOS) or equivalent CSPRNG.
- Nonce reuse with the same key completely breaks AES-GCM security.

### 8.3 Error Handling

- If any chunk fails authentication (GCM tag mismatch), the entire file is considered **corrupted**.
- Partial decryption is NOT supported - treat authentication failures as complete failures.

### 8.4 File Extension and Name

- Encrypted files MUST use `.bge` extension to ensure proper UTI association with the BGE application.
- Output filename format: `{original_filename}.bge` (e.g., `report.pdf` → `report.pdf.bge`). A writer MAY instead give the file an opaque name, so that the original name is not visible without the key, e.g. `k3j2x7…q4.bge`.
- A reader takes the original name from the metadata `n`, never by stripping `.bge` from the file's name.

### 8.5 Key ID and Recipient Privacy

- In RSA Identity Mode, the 8-byte **Key ID** (§3.1, §4.4) is stored in the header **in cleartext**. This is intentional: it lets a reader locate the matching private key in O(1) instead of trial-decrypting with every key.
- Because the Key ID is a deterministic fingerprint of the recipient's public key, anyone who obtains a `.bge` file — without any key — can:
  - **Correlate** files: identical Key IDs mean the files target the same recipient.
  - **Identify the recipient**: given a set of known public keys (e.g. shared identity cards), an observer can compute each key's Key ID and match it against the file.
- This does **not** weaken payload confidentiality — the contents stay encrypted. The exposure is **recipient metadata** ("who a file is encrypted for").
- Implementations whose threat model includes recipient anonymity should account for this. Password Mode carries no Key ID and does not have this property.

### 8.6 Untrusted Metadata

The metadata authenticates as coming from someone who could encrypt to the recipient, which in RSA Identity Mode is anyone holding the recipient's public key. Treat every value as untrusted input:

- **Filename (`n`)**: turn it into one safe path component before use. Take only the part after the last `/` or `\`; replace control characters and `:`; reject empty, `.` and `..`, falling back to a name of the reader's choosing; limit the length.
- **Folder path (`p`)**: sanitize each component the same way, and ignore the whole path if any component is empty, `.` or `..` (§3.2).
- **Archives (`a` = `"bge-folder"`)**: when extracting the ZIP, reject entries whose paths are absolute, contain `..`, or otherwise resolve outside the destination, and do not follow symbolic links out of it.
- **Sizes**: do not preallocate from `s`, `w`, `h` or the header's sizes without bounds.

---

## 9. File Overhead Analysis

### Overhead Components

```
Fixed Overhead:
  Header (RSA Mode):     550 bytes
  Header (Password Mode): 111 bytes
  Metadata Block:        12 (nonce) + 4 (len) + L (json) + 16 (tag) = 32 + L bytes

Per-Chunk Overhead:
  12 (nonce) + 16 (tag) = 28 bytes per chunk
```

### Example: 1GB File with 4MB Chunks (default)

```
File Size:        1,073,741,824 bytes (1 GB)
Chunks:           256 (each 4MB)
Header (RSA):     550 bytes
Metadata (~100B): 132 bytes
Chunk Overhead:   256 × 28 = 7,168 bytes
────────────────────────────────────────
Total Overhead:   7,850 bytes (0.0007%)
```

With the earlier 64MB default the same file has 16 chunks and 1,130 bytes of overhead (0.0001%). A thumbnail in the metadata typically adds 5–20 KB.

---

## 10. Constants Summary

```swift
public enum BGEFormatV3 {
    // Magic & Version
    public static let magic = Data([0x42, 0x47, 0x45, 0x33])  // "BGE3"
    public static let version: UInt8 = 0x03

    // Encryption Modes
    public static let modeRSA: UInt8 = 0x01
    public static let modePassword: UInt8 = 0x02

    // KDF Types
    public static let kdfPBKDF2_SHA512: UInt8 = 0x01

    // Field Sizes
    public static let magicSize = 4
    public static let versionSize = 1
    public static let modeSize = 1
    public static let keyIDSize = 8
    public static let saltSize = 16
    public static let iterationsSize = 4
    public static let wrapNonceSize = 12
    public static let wrapLengthSize = 4
    public static let wrappedKeySize = 48  // 32 (key) + 16 (tag)
    public static let chunkSizeFieldSize = 8
    public static let originalSizeFieldSize = 8
    public static let chunkCountFieldSize = 4
    public static let metadataNonceSize = 12
    public static let metadataLengthSize = 4
    public static let gcmTagSize = 16
    public static let gcmNonceSize = 12

    // Defaults
    public static let defaultChunkSize: Int64 = 4 * 1024 * 1024   // 4 MB (64 MB before 2026-09)
    public static let defaultIterations: UInt32 = 1_000_000
    public static let maxMetadataSize: UInt32 = 65_536  // 64 KB

    // Chunk Size Range
    public static let minChunkSize: Int64 = 1 * 1024 * 1024   // 1 MB
    public static let maxChunkSize: Int64 = 256 * 1024 * 1024 // 256 MB

    // File Extension
    public static let fileExtension = "bge"
}
```

---

## 11. References

- **NIST SP 800-38D**: Galois/Counter Mode (GCM) Specification
- **NIST SP 800-132**: Recommendation for Password-Based Key Derivation
- **FIPS 197**: Advanced Encryption Standard (AES)
- **FIPS 186-5**: Digital Signature Standard (RSA)
- **PKCS #1 v2.2**: RSA Cryptography Standard (OAEP)
- **RFC 8018**: PKCS #5 Password-Based Cryptography Specification v2.1

---

## 12. Version History

| Version | Date | Changes |
|---------|------|---------|
| 3.0 | 2026-09-22 | Document revision; the on-disk format is unchanged |
| | | - Corrected Key ID input: PKCS#1 `RSAPublicKey` DER, not SPKI (§4.4) |
| | | - Default chunk size 4 MiB (was 64 MiB); stated the 1–256 MiB range (§5) |
| | | - Documented metadata keys `c`, `m`, `b`, `a`; added `p` (original folder path) |
| | | - Documented the encrypted-message marker in `t` |
| | | - Readers ignore unknown metadata keys; `.bge` names may be opaque (§8.4) |
| | | - Added §8.6 Untrusted Metadata |
| 3.0 | 2026-02-03 | Initial v3 specification |
| | | - Added Password Mode support |
| | | - Added Key ID for fast key lookup |
| | | - Added encrypted Metadata Block |
| | | - Changed extension from `.enc` to `.bge` |
| | | - Upgraded PBKDF2 to use SHA-512 with 1M iterations |
| 2.0 | 2025-11-25 | Chunked encryption, streaming support |
| 1.0 | 2024-11-01 | Original single-blob format |

---

**Specification document revision:** 2026-09-22
**Maintained by:** dotbge — https://dotbge.com
**Implementations & apps:** https://dotbge.app
**License:** CC BY 4.0 — the format is free to implement (see [`LICENSE`](LICENSE))
