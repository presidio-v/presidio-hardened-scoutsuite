# Vendored test vectors

These files are the family evidence contract test vectors, copied byte-for-byte
(not depended on) so this repository can prove conformance offline. They are
append-only upstream: do not edit them here. If the contract publishes new
vectors, copy the new files in and update the digests below.

| File | Pins | SHA-256 |
|---|---|---|
| `canonical-json/vectors.json` | Strict canonical JSON: sorted keys, `(",", ":")` separators, UTF-8 without ASCII escaping, floats rejected; plus the SHA-256 content hash of each case | `921b8127e8fc3a1dd18a84b06df554f2bd3a2c3a544fe586c1cd6c26810c3c82` |
| `signing/hmac-sha256-golden.json` | The signing message `canonical({content_hash, signer})` and its HMAC-SHA256 signature, with tamper cases that must fail | `89ad270a83d4abba8b716fc95e68fbf893d13993587dc341749df1cdfb64511b` |

Copied on 2026-10-18 for v0.30.0. Exercised by `tests/test_evidence_conformance.py`.
