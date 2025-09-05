**PQC-for-Email: Detailed Design (with a focus on the email client)**

Below is a practical end-to-end design for making email “quantum-resistant.” It covers the whole stack for context, but goes deep on what must change in the **email client (MUA)**.

**1) Goals & scope**

- **Protect against store-now-decrypt-later.** Even if mail is recorded today, it shouldn’t be decrypted by a future quantum attacker.
- **Backwards compatible.** Interoperate with existing S/MIME and OpenPGP users and today’s MTAs.
- **Incremental rollout.** Start with transport, then message-layer **sign** and **encrypt**, migrate to pure-PQC when the ecosystem catches up.

**2) Cryptographic building blocks (standards you can ship against)**

- **KEM (encryption key agreement):** NIST ML-KEM (Kyber) — ML-KEM-768 is the sweet spot. Key and ciphertext sizes are standardized; e.g., ML-KEM-768 public key = 1184 bytes, ciphertext = 1088 bytes (Table 3).
- **Signatures:** NIST ML-DSA (Dilithium). Parameter sets ML-DSA-44/65/87; choose **ML-DSA-65** for balanced security/perf. (FIPS 204). ([NIST Publications](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf))
- **Message container:** CMS (aka PKCS#7) as used by **S/MIME 4.0** (RFC 8551). ([GitHub](https://github.com/open-quantum-safe/oqs-provider?utm_source=chatgpt.com))
- **CMS + KEM:** Use the IETF LAMPS **KEMRecipientInfo** for CMS to carry ML-KEM (draft; widely tracked by vendors). ([Wikipedia](https://en.wikipedia.org/wiki/DNS-based_Authentication_of_Named_Entities?utm_source=chatgpt.com), [OpenPGP](https://www.openpgp.org/community/email-summit/2024/minutes/?utm_source=chatgpt.com))
- **Symmetric content encryption inside CMS:** AES-GCM or ChaCha20-Poly1305 profiles (RFC 5084 / RFC 8103). ([RFC Editor](https://www.rfc-editor.org/info/rfc8103?utm_source=chatgpt.com), [IETF Datatracker](https://datatracker.ietf.org/doc/html/rfc8103?utm_source=chatgpt.com))
- **Certificates & algorithm identifiers:** Emerging LAMPS drafts define PQC/HYBRID alg IDs for X.509; use vendor toolchains that follow these drafts while standards finalize.
- **Key discovery:**
  - S/MIME: DANE **SMIMEA** (RFC 8162) for publishing certs in DNSSEC. ([IETF Datatracker](https://datatracker.ietf.org/doc/draft-ietf-lamps-kyber-certificates/?utm_source=chatgpt.com))
  - OpenPGP: **WKD** (Web Key Directory) and **OPENPGPKEY** (RFC 7929). ([wiki.gnupg.org](https://wiki.gnupg.org/WKD?utm_source=chatgpt.com), [IETF Datatracker](https://datatracker.ietf.org/doc/html/rfc7929?utm_source=chatgpt.com))
- **Transport hardening (MTAs):** STARTTLS (RFC 3207) + **MTA-STS** (RFC 8461) and/or **DANE for SMTP** (RFC 7672), with PQC-TLS at the ciphersuite layer where available. ([IETF Datatracker](https://datatracker.ietf.org/doc/html/rfc3207?utm_source=chatgpt.com))

Notes on sizes you’ll feel in the UI and storage: ML-KEM-768 adds ~1.1 KB per recipient (ciphertext). ML-DSA signatures and public keys are a few kilobytes depending on the parameter set (see FIPS 204 tables). Plan for message size growth and caching.

**3) High-level architecture**

1. **Transport layer (today):** Client↔server IMAP/SMTP/Submission over PQC-ready TLS (hybrid X25519+ML-KEM where available), plus MTA-STS/TLS-RPT/DANE for server↔server. ([IETF Datatracker](https://datatracker.ietf.org/doc/html/rfc8461?utm_source=chatgpt.com))
2. **Message layer (core of this design):** End-to-end **S/MIME** using CMS:
    - **Sign** with ML-DSA (optionally **hybrid sign**: ML-DSA + ECDSA/Ed25519 until all clients verify ML-DSA).
    - **Encrypt** the per-message content-encryption key (CEK) to recipients using **KEMRecipientInfo (ML-KEM)**; can include **multiple RecipientInfos** (legacy RSA/ECDH + ML-KEM) for graceful fallback (standard CMS behavior). ([Wikipedia](https://en.wikipedia.org/wiki/DNS-based_Authentication_of_Named_Entities?utm_source=chatgpt.com), [RFC Editor](https://www.rfc-editor.org/rfc/rfc8933.txt?utm_source=chatgpt.com))
3. **Discovery & trust:** Pull recipient PQC certs using **SMIMEA** (DNSSEC) or directory/enterprise CA; for OpenPGP users, discover using **WKD/OPENPGPKEY** (until PQC for OpenPGP is finalized). ([IETF Datatracker](https://datatracker.ietf.org/doc/draft-ietf-lamps-kyber-certificates/?utm_source=chatgpt.com), [wiki.gnupg.org](https://wiki.gnupg.org/WKD?utm_source=chatgpt.com))

**4) What changes in the email client (MUA)**

**4.1 Crypto & keyring**

- **Add PQC primitives** via a modern crypto stack (e.g., OpenSSL 3 with the OQS provider) and wire them into CMS/S/MIME operations. ([RFC Editor](https://www.rfc-editor.org/info/rfc5753?utm_source=chatgpt.com))
- **Dual keypairs per identity:**
  - **Signature keypair:** ML-DSA-65 (optionally also keep an ECDSA/Ed25519 key for hybrid signatures). ([NIST Publications](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf))
  - **KEM keypair:** ML-KEM-768 **for decryption** (separate from the signing key). ([NIST Publications](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf))
- **Key storage changes:**
  - Extend the keyring/Keystore schema to store: algorithm family, parameter set, public-key and private-key encodings, issuance/expiry, and linkages to X.509 or PGP key IDs.
  - Support **hardware-backed** private keys (OS keystore, smart cards, tokens) when vendors ship ML-KEM/ML-DSA modules.

**4.2 Certificates & identity**

- **S/MIME:**
  - Import/validate **PQC or hybrid X.509 certs** (look for LAMPS-specified OIDs once finalized). Maintain chains as usual (RFC 5280), stapled OCSP, CRLs, and respect CA/Browser Forum S/MIME Baseline Requirements. ([CA/Browser Forum](https://cabforum.org/working-groups/smime/requirements/?utm_source=chatgpt.com))
  - Evaluate **S/MIME Capabilities** (in signed messages and the X.509 extension) to pick the best AEAD and to learn if the peer can handle KEM. ([GitHub](https://github.com/open-quantum-safe/oqs-provider?utm_source=chatgpt.com), [RFC Editor](https://www.rfc-editor.org/rfc/rfc4262.html?utm_source=chatgpt.com))
  - Implement **SMIMEA** lookups for user@domain to fetch/refresh recipient certs through DNSSEC (when present). ([IETF Datatracker](https://datatracker.ietf.org/doc/draft-ietf-lamps-kyber-certificates/?utm_source=chatgpt.com))
- **OpenPGP:** Keep today’s PGP UX, but add **WKD and OPENPGPKEY** lookups by default. (OpenPGP RFC 9580 defines the format; PQC algorithm assignment is still emerging—plan but don’t ship custom IDs yet.) ([OpenPGP](https://www.openpgp.org/about/standard/?utm_source=chatgpt.com))

**4.3 Compose pipeline (send)**

1. **Recipient capability discovery**
    - Query local address book cache → recent signed mail’s **SMIMECapabilities** → SMIMEA DNSSEC → enterprise directory/IdP. Pick **policy**:
        - _PQC-only_, _Hybrid_, or _Classical-only_ per recipient/domain.
    - Cache results with TTL and provenance (e.g., SMIMEA vs. manual import). ([RFC Editor](https://www.rfc-editor.org/rfc/rfc4262.html?utm_source=chatgpt.com))
2. **Per-message encryption strategy**
    - Generate a random CEK and IV. Pick AEAD: AES-GCM or ChaCha20-Poly1305 (both standardized in CMS). ([RFC Editor](https://www.rfc-editor.org/info/rfc8103?utm_source=chatgpt.com), [IETF Datatracker](https://datatracker.ietf.org/doc/html/rfc8103?utm_source=chatgpt.com))
    - Build CMS **EnvelopedData** with one **RecipientInfo** per recipient:
        - For PQC-capable: **KEMRecipientInfo(ML-KEM-768)**
        - For legacy only: KeyTrans (RSA) or KeyAgree (ECDH).
        - For hybrid delivery: include **both** for the same recipient (CMS allows multiple RecipientInfos). ([Wikipedia](https://en.wikipedia.org/wiki/DNS-based_Authentication_of_Named_Entities?utm_source=chatgpt.com), [RFC Editor](https://www.rfc-editor.org/rfc/rfc8933.txt?utm_source=chatgpt.com))
3. **Signing**
    - Default: **hybrid signature** (ML-DSA + ECDSA/Ed25519) while the ecosystem upgrades; then toggle to **ML-DSA-only** by policy. (Use LAMPS hybrid/composite encoding when finalized.)
4. **Header protection**
    - Use “protected headers”/“memory-hole” style wrapping so **Subject/To/Cc** are inside the signed/encrypted part (supported by modern S/MIME and OpenPGP UIs). ([GitHub](https://github.com/open-quantum-safe/oqs-provider?utm_source=chatgpt.com))
5. **UX cues**
    - Show a small badge per recipient: **PQC**, **Hybrid**, or **Legacy** before sending.
    - If any recipient is legacy-only and org policy requires quantum-safe, prompt: “Remove legacy recipients or send hybrid?”

**4.4 Receive pipeline (verify & decrypt)**

- **Decryption:** For each RecipientInfo in CMS, attempt in order of policy (PQC first). For KEMRecipientInfo:
    1. ML-KEM decapsulation → shared secret → unwrap CEK → decrypt AEAD.
    2. Record telemetry (time/memory) for UX perf budgets. ([Wikipedia](https://en.wikipedia.org/wiki/DNS-based_Authentication_of_Named_Entities?utm_source=chatgpt.com))
- **Signature verification:** Verify **both** components for hybrid signatures and surface the result clearly:
    1. “Signed (ML-DSA ✅, ECDSA ✅)” or “Signed (ML-DSA ✅, legacy ✖)” to help support teams diagnose.
- **Trust checks:** Normal chain/path building, CRL/OCSP, expiry, EKUs; display identity as with current S/MIME.

**4.5 Key & certificate lifecycle (client UX)**

- **Enrollment:** CSR flows for PQC and (optionally) hybrid certs; ACME-S/MIME (RFC 8823) if your CA supports it. ([CA/Browser Forum](https://cabforum.org/working-groups/smime/requirements/?utm_source=chatgpt.com))
- **Rotation & escrow:**
  - **Encryption (KEM) keys rotate** periodically (e.g., yearly). Keep old _decryption_ keys available to read archived mail.
  - **Signature keys** rotate less frequently; ensure past signatures remain verifiable.
- **Backup/restore:** Export/import PQC private keys with proper wrapping and metadata (alg, params).
- **Roaming:** Sync public material (certs, WKD keys, SMIMEA proofs) across devices; private keys only if org policy allows.

**4.6 Policy engine (per-org/per-domain)**

- Admin-settable policy matrix:
  - **Minimum** algorithms (≥ ML-KEM-768 / ML-DSA-65),
  - Allowed modes (**PQC-only** | **Hybrid** | **Allow-legacy**),
  - Fallback rules (e.g., “block send if any recipient is legacy-only”),
  - Transport requirements for submission (TLS version, ciphersuites),
  - MTA-STS/TLS-RPT monitoring surfaced in client warnings. ([IETF Datatracker](https://datatracker.ietf.org/doc/html/rfc8461?utm_source=chatgpt.com))

**4.7 Performance & footprint**

- Expect +1–5 KB per message from signatures and per-recipient +~1.1 KB KEM ciphertext (ML-KEM-768). Implement:
  - **Recipient collapsing** (don’t duplicate CEK wraps when multiple addresses share the same PQC cert).
  - **Streaming CMS** to keep memory low on mobile.
- Provide a **“compact mode”** (prefer ChaCha20-Poly1305 over AES-GCM on devices without AES acceleration; both are standardized for CMS). ([IETF Datatracker](https://datatracker.ietf.org/doc/html/rfc8103?utm_source=chatgpt.com))

**4.8 Webmail & mobile specifics**

- **Webmail:** Use WASM builds of ML-KEM/ML-DSA (or WebCrypto extensions when available). Keep private keys in browser secure storage and **never** round-trip to servers.
- **Mobile:** Bind keys to Secure Enclave/Keystore when supported; adopt constant-time PQC libs.

**5) Protocol flows (concise)**

**5.1 Sending (S/MIME, hybrid-capable recipients)**

User hits Send

→ Resolve capabilities (cache → SMIMEA/WKD/dir)

→ Build CMS:

\- CEK ← random

\- EnvelopedData:

RecipientInfos:

\- KEMRecipientInfo(ML-KEM-768, pk_recipient)

\- \[optional\] KeyTrans/KeyAgree for legacy

\- SignedData:

\- Signature ML-DSA-65

\- \[optional\] Legacy signature (ECDSA/Ed25519)

→ MIME assemble with Protected Headers

→ Submit over TLS (client→server)

**5.2 Receiving**

On open:

→ Parse CMS

→ Try RecipientInfo (PQC first)

\- ML-KEM decapsulate → CEK → decrypt content (AES-GCM or ChaCha20-Poly1305)

→ Verify signatures (ML-DSA and optional legacy)

→ Render with security badges

**6) Backwards-compat strategies**

- **Multi-RecipientInfo** in CMS lets you ship one message that **both** legacy and PQC recipients can open. (Standard CMS behavior.) ([RFC Editor](https://www.rfc-editor.org/rfc/rfc8933.txt?utm_source=chatgpt.com))
- **Hybrid signatures** during the transition (verify-both, accept-either) using the LAMPS composite/hybrid approach as available.
- Keep **OpenPGP** support as-is but add discovery (WKD/OPENPGPKEY). Shift PGP users to S/MIME where policy demands PQC **today**; adopt PQC once OpenPGP assigns stable algorithm IDs. ([OpenPGP](https://www.openpgp.org/about/standard/?utm_source=chatgpt.com))

**7) Transport posture (MTAs & submission)**

- Ensure **client submission** to the first hop uses PQC-ready TLS when available; surface warnings otherwise.
- Encourage domains to publish **MTA-STS** and enable **TLS-RPT**; where DNSSEC is deployed, prefer **DANE for SMTP** to defeat STARTTLS downgrades. ([IETF Datatracker](https://datatracker.ietf.org/doc/html/rfc8461?utm_source=chatgpt.com))

**8) Security hardening & pitfalls**

- **Side-channels:** Use constant-time PQC implementations; forbid floating-point for ML-DSA as per FIPS guidance. ([NIST Publications](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf))
- **Randomness:** Follow FIPS requirements for hedged signing in ML-DSA; seed from OS CSPRNG. ([NIST Publications](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf))
- **Header leakage:** Always protect subject/recipient headers inside the signed/encrypted body. ([GitHub](https://github.com/open-quantum-safe/oqs-provider?utm_source=chatgpt.com))
- **Key separation:** Never reuse signing keys for KEM; rotate KEM keys more frequently.
- **Archival:** Keep historical _decryption_ keys (or re-encrypt archives) so old mail remains readable after rotations.

**9) Minimal implementation checklist (client)**

1. Crypto engine with ML-KEM & ML-DSA + CMS KEMRecipientInfo. ([Wikipedia](https://en.wikipedia.org/wiki/DNS-based_Authentication_of_Named_Entities?utm_source=chatgpt.com))
2. Keyring schema update (PQC keys; dual-keypairs).
3. S/MIME send/receive:
    - CMS EnvelopedData with KEMRecipientInfo (ML-KEM-768).
    - CMS SignedData with ML-DSA-65 (and optional legacy signature).
4. Capability discovery: SMIMECapabilities, SMIMEA, directory; for PGP: WKD/OPENPGPKEY. ([RFC Editor](https://www.rfc-editor.org/rfc/rfc4262.html?utm_source=chatgpt.com), [IETF Datatracker](https://datatracker.ietf.org/doc/draft-ietf-lamps-kyber-certificates/?utm_source=chatgpt.com), [wiki.gnupg.org](https://wiki.gnupg.org/WKD?utm_source=chatgpt.com))
5. UI: PQC/Hybrid/Legacy badges, policy prompts, protected-headers on by default.
6. Admin policy knobs: min algs, modes, fallback, transport requirements (MTA-STS/TLS-RPT notices). ([IETF Datatracker](https://datatracker.ietf.org/doc/html/rfc8461?utm_source=chatgpt.com))

**10) References you’ll build against**

- **NIST PQC FIPS (final):** ML-KEM (FIPS 203) & sizes; ML-DSA (FIPS 204).
- **CMS/S/MIME base:** RFC 5652 (CMS), RFC 8551 (S/MIME 4.0), AES-GCM (RFC 5084), ChaCha20-Poly1305 (RFC 8103). ([RFC Editor](https://www.rfc-editor.org/rfc/rfc8933.txt?utm_source=chatgpt.com), [GitHub](https://github.com/open-quantum-safe/oqs-provider?utm_source=chatgpt.com), [IETF Datatracker](https://datatracker.ietf.org/doc/html/rfc8103?utm_source=chatgpt.com))
- **CMS KEMRecipientInfo:** IETF LAMPS drafts for KEM in CMS and ML-KEM algorithm identifiers. ([Wikipedia](https://en.wikipedia.org/wiki/DNS-based_Authentication_of_Named_Entities?utm_source=chatgpt.com), [OpenPGP](https://www.openpgp.org/community/email-summit/2024/minutes/?utm_source=chatgpt.com))
- **X.509 PQC identifiers / hybrid:** LAMPS drafts for composite/hybrid certs & signatures.
- **Discovery:** SMIMEA (RFC 8162); OpenPGP WKD draft & RFC 7929. ([IETF Datatracker](https://datatracker.ietf.org/doc/draft-ietf-lamps-kyber-certificates/?utm_source=chatgpt.com))
- **Transport:** STARTTLS (RFC 3207), DANE for SMTP (RFC 7672), MTA-STS (RFC 8461), TLS-RPT (RFC 8460). ([IETF Datatracker](https://datatracker.ietf.org/doc/html/rfc3207?utm_source=chatgpt.com))
- **Open-source PQC stacks:** Open Quantum Safe (liboqs / OpenSSL provider). ([RFC Editor](https://www.rfc-editor.org/info/rfc5753?utm_source=chatgpt.com))

If you want, I can adapt this into a dev PRD or an engineering task list for your specific client platform (Outlook plugin, Thunderbird/NSS, a webmail frontend, etc.).