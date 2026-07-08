# Composite PQC PGP — integration into a new branch

New files: `okcrypto_pqc_pgp.{h,cpp}`, `mlkem768.h`, `mldsa65.h`, `pqc_shim.c`.
Vendored: copy `mlkem_native/` from `feature/mlkem-768`; add `mldsa-native/` (or pq-crystals
dilithium, `DILITHIUM_MODE=3`). Below are the edits to existing files. **UNTESTED — by inspection.**

## okcore.h
```c
#include "okcrypto_pqc_pgp.h"   // KEYTYPE_PQC_PGP(7), offsets, sizes
// If the 1088-byte ML-KEM ct exceeds the reassembly cap:
// #define LARGE_BUFFER_SIZE 1152   // was 1024
```

## okcore.cpp — `okcore_flashget_RSA`: read the 160-byte blob
After the type read + `type==0` guard, before the RSA `type*128` read:
```c
if ((type & 0x0F) == KEYTYPE_PQC_PGP) {
    adr = adr + ((slot * MAX_RSA_KEY_SIZE) - MAX_RSA_KEY_SIZE);
    okcore_flashget_common((uint8_t *)rsa_private_key, (unsigned long *)adr, PQC_PGP_BLOB_LEN);
    okcore_aes_gcm_decrypt(rsa_private_key, slot, features, profilekey, PQC_PGP_BLOB_LEN);
    type = (type & 0x0F);   // leave type = 7 for the dispatchers
    return features;        // no rsa_getpub()
}
```

## okcore.cpp — `OKSETRSAPRIV`: import the 160-byte blob
```c
else if ((buffer[6] & 0x0F) == KEYTYPE_PQC_PGP) { keysize = PQC_PGP_BLOB_LEN; // 160
    if (buffer[0] != 0xBA && packet_buffer_offset <= (PQC_PGP_BLOB_LEN - 57)) {
        memcpy(rsa_private_key + packet_buffer_offset, buffer + 7, 57); packet_buffer_offset += 57; } }
```
Completion (`okeeprom_eeset_rsakey`, `okcore_aes_gcm_encrypt(..., 160)`, slot write) is unchanged.
The type byte should carry both feature bits (decrypt bit 5 + sign bit 6) since the composite does both.

## okcrypto.cpp — dispatch
`okcrypto_sign` (slot 1-4, after flashget + type!=0):
```c
if ((type & 0x0F) == KEYTYPE_PQC_PGP) { okcrypto_pqc_pgp_sign(buffer); return; }
```
`okcrypto_decrypt` (slot 1-4, after flashget + type!=0):
```c
if ((type & 0x0F) == KEYTYPE_PQC_PGP) { okcrypto_pqc_pgp_decrypt(buffer); return; }
```

## Component selector
The host sets `buffer[6]` = `PQC_HALF_ECC (0)` or `PQC_HALF_PQC (1)` to pick which half of the
composite to run. The glue captures it on the first (user-action) phase.

## ECC-half primitives
`okcrypto_pqc_pgp.cpp` calls `ok_ed25519_sign()` / `ok_x25519_shared()` — wire these to the
firmware's existing Ed25519/X25519 math (the same used by `okcrypto_ecdsa_eddsa` / `okcrypto_ecdh`),
operating on the 32-byte secret at the blob offset instead of an ECC-slot key. (Thin wrappers, a few
lines each.)

## Build
- Compile `mlkem_native/**` (reused) + `mldsa-native/**` (new) + `pqc_shim.c` + `okcrypto_pqc_pgp.cpp`.
- Gate behind the board `#ifdef` used for RSA (`STD_VERSION`).

## Response sizing
- ML-DSA signature is 3309 B > `LARGE_RESP_BUFFER_SIZE` (1024). The glue writes it from the
  `ctap_buffer` scratch (>= 3309); the transport fragments long responses.

## Host side
- python-onlykey / lib-agent: `OKSETPRIV type=7` packs the four seeds from an imported OpenPGP
  secret key into the 160-byte layout and loads it. No pubkey load.
- openpgp.js hooks: pass the selector per hook; `mlkemDecaps` sends the 1088-B ct; add an ML-DSA
  `signer` branch (digest -> 3309-B sig). `ecdh`/`sign_ecc` route to the ECC half.

## Verify on hardware
- 160-B import round-trip; four component ops; 3309-B response fragmentation; ML-DSA message framing
  ([0,0]||digest) matches openpgp.js verify.
