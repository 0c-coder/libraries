# Building the PQC firmware (composite ML-KEM-768 + ML-DSA-65)

Status: **compiles + links + runs on host** (crypto core verified). UNTESTED on the MK20DX256 —
needs a Teensyduino build + hardware pass.

## What's in the tree
Vendored at the **repo root** (same as `mbedtls-2.4.0`, `mlkem_native`):
- `mlkem_native/` — ML-KEM-768 (reused from `feature/mlkem-768`).
- `mldsa_native/` — ML-DSA-65, configured for OnlyKey (see below). Native asm backends removed
  (pure C for Cortex-M4).

In `onlykey/`:
- `okpqc.h` / `okpqc.cpp` — the composite PQC ops (new).
- `okcore.h`, `okcore.cpp`, `okcrypto.cpp` — **edited** (18 lines total; see `firmware-edits.patch`).

## mldsa_native configuration (already applied in the vendored copy)
`mldsa_native/mldsa_native_config.h`:
- `MLD_CONFIG_PARAMETER_SET = 65`  (ML-DSA-65)
- `MLD_CONFIG_REDUCE_RAM`  — **required**: signing workspace ~17 KB vs ~69 KB without (64 KB RAM)
- `MLD_CONFIG_CUSTOM_RANDOMBYTES` → bridges to `onlykey_mldsa_randombytes` (defined in `okpqc.cpp`,
  wraps the firmware `RNG`). `mlkem_native` bridges to `onlykey_mlkem_randombytes` likewise.

## Build model (matches mlkem_native)
The OnlyKey build compiles each library's **root** monolithic `.c` (which `#include`s its `src/`);
the `src/` subfolder is not compiled separately. So the build compiles:
- `mlkem_native/mlkem_native.c`  (define `MLK_CONFIG_PARAMETER_SET=768` if not set in a config)
- `mldsa_native/mldsa_native.c`
- `onlykey/okpqc.cpp` and the rest of `onlykey/`.

`okpqc.cpp` needs the Arduino Crypto library headers already used by the firmware:
`Ed25519.h`, `Curve25519.h`, `RNG.h`.

## Host compile-check performed
```
gcc  -O2 -std=c11  -I mlkem_native -DMLK_CONFIG_PARAMETER_SET=768  mlkem_native/mlkem_native.c -c
gcc  -O2 -std=c11  -I mldsa_native                                 mldsa_native/mldsa_native.c -c
g++  -O2 -std=gnu++11 -I onlykey -I <arduino-crypto-headers>       onlykey/okpqc.cpp -c
# link with the firmware -> resolves; a KEM+signature round-trip passes:
#   ML-KEM-768 decaps match: YES
#   ML-DSA-65 siglen=3309 verify: OK
```

## Integration (in `firmware-edits.patch`, already applied to the tree)
- `okcore.h`: `#include "okpqc.h"` (brings `KEYTYPE_PQC_PGP`=7, `PQC_PGP_BLOB_LEN`=160, op decls).
- `okcore_flashget_RSA`: read the 160-byte blob for a type-7 slot (no `rsa_getpub`).
- `OKSETRSAPRIV`: accept the 160-byte blob (`type==7`).
- `okcrypto_sign` / `okcrypto_decrypt`: dispatch type-7 slots to `okpqc_sign` / `okpqc_decrypt`.

## Flash budget — the one thing to watch on the real build
256 KB flash total; the firmware is already large and adds `mlkem_native` + `mldsa_native`
(tens of KB compiled). Check the `.map`/size output after the first Teensy build. RAM is fine
(sign ~17 KB, decaps ~14 KB; the 18 KB backup buffer isn't allocated during these ops).

## Remaining hardware validation
- ML-DSA message framing (`[0,0]||digest`) vs openpgp.js `ml_dsa.js` (see note in `okpqc.cpp`).
- 3309-byte signature response fragmentation over CTAP.
- Full round-trip: import a 160-byte composite key → sign/verify + encrypt/decrypt via openpgp.js.
