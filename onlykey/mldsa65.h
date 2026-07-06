/* mldsa65.h — thin ML-DSA-65 API used by okcrypto_pqc.cpp (backed by pq-crystals). */
#ifndef MLDSA65_H
#define MLDSA65_H
#include <stdint.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Deterministically expand the 32-byte FIPS 204 seed to the keypair. */
int mldsa65_keypair_from_seed(uint8_t pk[1952], uint8_t sk[4032], const uint8_t seed[32]);
/* Sign message m (already the value the verifier will check, e.g. [0,0]||digest). */
int mldsa65_sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t sk[4032]);
#ifdef __cplusplus
}
#endif
#endif
