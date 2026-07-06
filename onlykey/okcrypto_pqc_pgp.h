/*
 * okcrypto_pqc_pgp.h — OnlyKey composite PQC PGP key in an RSA slot (1-4).
 *
 * One RSA slot holds one imported composite key as a 160-byte seed blob:
 *   [0:32] Ed25519 sk | [32:64] ML-DSA-65 seed | [64:96] X25519 sk | [96:160] ML-KEM-768 seed
 * The device expands the PQC seeds at use time and performs the requested half.
 * Public key is never stored (host holds it).
 *
 * UNTESTED — by inspection; reuses mlkem_native (from feature/mlkem-768) + adds ML-DSA.
 */
#ifndef OKCRYPTO_PQC_PGP_H
#define OKCRYPTO_PQC_PGP_H
#include <stdint.h>

#define KEYTYPE_PQC_PGP     7
#define PQC_PGP_BLOB_LEN    160
#define PQC_OFF_ED25519     0
#define PQC_OFF_MLDSA_SEED  32
#define PQC_OFF_X25519      64
#define PQC_OFF_MLKEM_SEED  96
#define MLDSA65_SEED_LEN    32
#define MLKEM768_SEED_LEN   64

/* component selector (buffer[6]) */
#define PQC_HALF_ECC        0   /* Ed25519 / X25519 */
#define PQC_HALF_PQC        1   /* ML-DSA / ML-KEM   */

/* sizes */
#define MLKEM_CT_SIZE       1088
#define MLKEM_SS_SIZE       32
#define MLKEM_DK_SIZE       2400
#define MLKEM_PK_SIZE       1184
#define MLDSA_SK_SIZE       4032
#define MLDSA_PK_SIZE       1952
#define MLDSA_SIG_SIZE      3309
#define ED25519_SIG_SIZE    64
#define X25519_SS_SIZE      32

#ifdef __cplusplus
extern "C" {
#endif
void okcrypto_pqc_pgp_sign    (uint8_t *buffer);  /* OKSIGN    on a type-7 slot */
void okcrypto_pqc_pgp_decrypt (uint8_t *buffer);  /* OKDECRYPT on a type-7 slot */
#ifdef __cplusplus
}
#endif
#endif
