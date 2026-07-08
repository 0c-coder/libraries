/* mlkem768.h — thin ML-KEM-768 API used by okcrypto_pqc.cpp (backed by pq-crystals). */
#ifndef MLKEM768_H
#define MLKEM768_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Deterministically expand the 64-byte FIPS 203 seed (d||z) to the keypair. */
int mlkem768_keypair_from_seed(uint8_t pk[1184], uint8_t dk[2400], const uint8_t seed[64]);
/* Decapsulate: ss = Decaps(dk, ct). */
int mlkem768_dec(uint8_t ss[32], const uint8_t ct[1088], const uint8_t dk[2400]);
#ifdef __cplusplus
}
#endif
#endif
