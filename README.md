# The `.bge` File Format

**An open container format for encrypted files.**

A `.bge` file is a complete, portable cryptographic object — it carries its own
encrypted key, an encrypted description of itself, and its contents as a
sequence of independently sealed chunks. There are no servers, no accounts, and
no proprietary dependencies.

This repository is the canonical home of the format: the specification, test
vectors, and version history. It is published so that `.bge` files outlive any
single program.

---

## What's here

| Path | Contents |
|------|----------|
| [`FILE_FORMAT_V3.md`](FILE_FORMAT_V3.md) | The complete v3 specification — byte-level layout, algorithms, encryption/decryption flows. |
| [`test-vectors/`](test-vectors/) | Sample `.bge` files with known keys and expected plaintext, for verifying an implementation. |
| [`CHANGELOG.md`](CHANGELOG.md) | Revision history of this specification. |
| [`LICENSE`](LICENSE) | CC BY 4.0 — the spec is free to share, adapt, and implement, with attribution. |

## At a glance

| | |
|---|---|
| Extension | `.bge` |
| UTI | `com.dotbge.encrypted` |
| Magic number | `BGE3` (`0x42 0x47 0x45 0x33`) |
| Payload encryption | AES-256-GCM, chunked |
| Identity mode | RSA-4096, OAEP-SHA256 |
| Password mode | PBKDF2-HMAC-SHA512 |
| Current version | 3.0 |

## Implementing `.bge`

The format is open. Anyone may build a reader or writer, in any language, for
any purpose including commercial use — with no licensing fee and no need to ask
permission. The specification and test vectors are everything you need.

If you ship an implementation, open an issue and we will list it.

## Reference applications

The official `dotbge` apps for iPhone and iPad (with macOS and a CLI in
development) implement this format. They are a separate, independently licensed
product — see **[dotbge.app](https://dotbge.app)**.

## License

The specification and test vectors are licensed **CC BY 4.0** — free to share,
adapt, and implement, with attribution. See [`LICENSE`](LICENSE) for the full
terms.

---

Maintained by [dotbge](https://dotbge.com).
