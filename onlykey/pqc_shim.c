/*
 * pqc_shim.c — maps mlkem768.h / mldsa65.h onto the vendored primitives.
 *   ML-KEM: reuse `mlkem_native` from feature/mlkem-768 (crypto_kem_* API).
 *   ML-DSA: add `mldsa-native` (same pq-code-package family) or pq-crystals dilithium (mode 3).
 *
 * The ML-KEM seed is the 64-byte OpenPGP mlkemSeed used DIRECTLY as keygen coins (d||z) — no
 * SHAKE(32->64). The ML-DSA seed is the 32-byte OpenPGP mldsaSeed used as the keygen seed.
 *
 * UNTESTED — by inspection. Confirm exact symbol names against the pinned vendored versions.
 */
#include "mlkem768.h"
#include "mldsa65.h"

/* ---- mlkem_native (ML-KEM-768) — same API feature/mlkem-768 already calls ---- */
extern int crypto_kem_keypair_derand(unsigned char *pk, unsigned char *sk, const unsigned char *coins);
extern int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

/* ---- ML-DSA-65 (mldsa-native / dilithium mode 3) ---- */
extern int mldsa_keypair_from_seed(unsigned char *pk, unsigned char *sk, const unsigned char seed[32]);
extern int mldsa_signature(unsigned char *sig, unsigned long *siglen,
                           const unsigned char *m, unsigned long mlen,
                           const unsigned char *ctx, unsigned long ctxlen,
                           const unsigned char *sk);

int mlkem768_keypair_from_seed(uint8_t pk[1184], uint8_t dk[2400], const uint8_t seed[64]) {
    return crypto_kem_keypair_derand(pk, dk, seed);  /* coins = 64-byte (d||z) */
}
int mlkem768_dec(uint8_t ss[32], const uint8_t ct[1088], const uint8_t dk[2400]) {
    return crypto_kem_dec(ss, ct, dk);
}

int mldsa65_keypair_from_seed(uint8_t pk[1952], uint8_t sk[4032], const uint8_t seed[32]) {
    return mldsa_keypair_from_seed(pk, sk, seed);
}
int mldsa65_sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t sk[4032]) {
    unsigned long sl = 0;
    /* openpgp.js signs [0x00,0x00] || digest with empty ML-DSA context; the host sends those
     * exact bytes as `m`, so ctx is empty here. */
    int rc = mldsa_signature(sig, &sl, m, (unsigned long)mlen, (const unsigned char*)0, 0, sk);
    if (siglen) *siglen = (size_t)sl;
    return rc;
}
