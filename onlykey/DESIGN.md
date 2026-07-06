# OnlyKey firmware: composite PQC PGP keys in RSA slots (new branch)

**Model:** one RSA slot (1–4) holds **one imported composite PQC PGP key** — all four private
seed components in a single ~160-byte blob. OnlyKey supports **up to 4 PQC keys** (slots 1–4),
each either RSA or a composite PQC key.

Import-first: the host (python-onlykey / lib-agent) loads a PGP key's private seeds into a slot.
The device stores only the seeds (~160 B), expands them at use time, and performs sign/decrypt.
The composite **public key is never stored** (3200 B ≫ 512 B slot); the host holds it, and it can
be re-derived on demand from the seeds if ever needed.

`feature/mlkem-768` is a **reference only** (reuse `mlkem_native` and the ML-KEM decaps structure);
this is a new branch that does not use that ECC-slot approach.

---

## 1. Slot contents (160 bytes, fixed layout)

A composite PGP key = ML-DSA+Ed25519 signing primary + ML-KEM+X25519 encryption subkey. OpenPGP
stores each private key as its **seed** (verified against draft-ietf-openpgp-pqc / openpgp.js):

| offset | bytes | component | role |
|---|---|---|---|
| `[0:32]`   | 32 | Ed25519 secret      | sign, ecc half |
| `[32:64]`  | 32 | ML-DSA-65 seed (ξ)  | sign, pqc half |
| `[64:96]`  | 32 | X25519 secret       | decrypt, ecc half |
| `[96:160]` | 64 | ML-KEM-768 seed (d‖z) | decrypt, pqc half |

Total **160 B**, well within the 512-byte RSA slot. Stored AES-GCM-encrypted like an RSA key.

> The ML-KEM seed is used **directly** as the keygen coins `(d,z)` — no SHAKE(32→64). (That SHAKE
> trick was only for `feature/mlkem-768`'s device-generated 32-byte seeds; imported keys carry the
> real 64-byte seed.) ML-DSA seed (32 B) and the two ECC secrets (32 B each) are used as-is.

---

## 2. Key type + storage (mirror RSA)

```c
// okcore.h
#define KEYTYPE_PQC_PGP     7        // slot 1-4 holds a composite PQC PGP key (160-byte seed blob)
#define PQC_PGP_BLOB_LEN    160
// component offsets
#define PQC_OFF_ED25519     0
#define PQC_OFF_MLDSA_SEED  32
#define PQC_OFF_X25519      64
#define PQC_OFF_MLKEM_SEED  96
#define MLDSA65_SEED_LEN    32
#define MLKEM768_SEED_LEN   64
```
Per-slot EEPROM type byte low nibble = 7. Feature bits: this key is both sign- and decrypt-capable
(bit 5 + bit 6), since the composite has both a signing and an encryption half.

Load (mirror `OKSETRSAPRIV`): a `==7` branch, `keysize = 160`, accumulate the blob in 57-byte chunks
into `rsa_private_key`, then `okeeprom_eeset_rsakey` + `okcore_aes_gcm_encrypt(..., 160)` + slot write.
Flashget (mirror `okcore_flashget_RSA`): read/decrypt 160 B, leave `type = 7`, no `rsa_getpub`.

---

## 3. Which half? — component selector

The composite's halves are independent operations that openpgp.js already requests as **separate
hooks** (`ecdh`, `mlkemDecaps`, `sign_ecc`, ML-DSA `signer`). For sign, both halves take the same
digest, so input size can't disambiguate → the request carries an explicit **component selector**:

```
buffer[6] (sub-op):  0 = ECC half (Ed25519 / X25519)   1 = PQC half (ML-DSA / ML-KEM)
```
(For decrypt the halves are also distinguishable by input size — 32-B ephemeral vs 1088-B ct — but
the explicit selector keeps sign/decrypt uniform.)

---

## 4. Sign dispatch (OKSIGN, slot 1–4, type 7)
```c
if ((type & 0x0F) == KEYTYPE_PQC_PGP) { okcrypto_pqc_pgp_sign(buffer); return; }  // in okcrypto_sign
```
`okcrypto_pqc_pgp_sign`:
- selector ECC → `ed25519_sign(sig64, digest, rsa_private_key + PQC_OFF_ED25519)` → 64 B.
- selector PQC → expand `rsa_private_key + PQC_OFF_MLDSA_SEED` (32 B) → SK 4032 → `mldsa65_sign` →
  **3309 B** signature (returned chunked from the large response region).

## 5. Decrypt dispatch (OKDECRYPT, slot 1–4, type 7)
```c
if ((type & 0x0F) == KEYTYPE_PQC_PGP) { okcrypto_pqc_pgp_decrypt(buffer); return; } // in okcrypto_decrypt
```
`okcrypto_pqc_pgp_decrypt`:
- selector ECC → `x25519(ss32, ephemeral, rsa_private_key + PQC_OFF_X25519)` → 32-B shared secret.
- selector PQC → expand `rsa_private_key + PQC_OFF_MLKEM_SEED` (64 B) → DK 2400 → `mlkem768_dec` on
  the 1088-B ct → 32-B shared secret.

openpgp.js does the KMAC combine (decrypt) / signature concatenation (sign); the device returns raw
component outputs. No secret leaves the device.

---

## 6. On-device primitives

| primitive | source |
|---|---|
| Ed25519 sign, X25519 | **existing** (nacl/tweetnacl already in firmware) |
| ML-KEM-768 keygen-from-seed + dec | **reuse `mlkem_native`** from `feature/mlkem-768` (copy the tree) |
| ML-DSA-65 keygen-from-seed + sign | **new**: vendor `mldsa-native` (same pq-code-package family as mlkem_native) or pq-crystals dilithium (DILITHIUM_MODE=3) |
| SHA3/SHAKE | comes with mlkem_native / mldsa-native |

API the glue calls:
```c
int mlkem768_keypair_from_seed(uint8_t pk[1184], uint8_t dk[2400], const uint8_t seed[64]); // coins = seed
int mlkem768_dec(uint8_t ss[32], const uint8_t ct[1088], const uint8_t dk[2400]);
int mldsa65_keypair_from_seed(uint8_t pk[1952], uint8_t sk[4032], const uint8_t seed[32]);
int mldsa65_sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t sk[4032]);
```

## 7. Response sizing
- ML-DSA signature is **3309 B** > `LARGE_RESP_BUFFER_SIZE` (1024). Return from a ≥3309-B region
  (the 18000-B `large_temp`/`ctap_buffer` scratch); the transport already fragments long responses.
- ML-KEM ct in is 1088 B; reassembles via the RSA `large_buffer` path (bump `LARGE_BUFFER_SIZE`
  1024→1152 if needed).

## 8. Host side (follow-on)
- **python-onlykey / lib-agent:** `OKSETPRIV type=7` loads the 160-B seed blob; the app extracts the
  four seeds from an imported PGP secret key (openpgp secret packet: X25519 32, mlkemSeed 64,
  Ed25519 32, mldsaSeed 32) and packs them in the fixed layout. No pubkey load (host has it).
- **openpgp.js hooks:** pass the component selector (ECC vs PQC) per hook; `mlkemDecaps` sends the
  1088-B ct → 32-B share; add the ML-DSA `signer` branch (digest → 3309-B sig).

## 9. New branch
Base off `master`; copy `mlkem_native/` from `feature/mlkem-768`; add `mldsa-native/` (or dilithium);
add `okcrypto_pqc_pgp.{cpp,h}` + the dispatch/load/flashget edits + `KEYTYPE_PQC_PGP`. **UNTESTED —
by inspection**, like #30; validate on hardware.
