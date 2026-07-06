/*
 * okpqc.cpp — OnlyKey composite PQC PGP key operations (ML-KEM-768 + ML-DSA-65).
 * See okpqc.h for the slot layout. Mirrors the two-phase CRYPTO_AUTH flow of the
 * existing okcrypto_mlkem_decaps. UNTESTED — by inspection; validate on hardware.
 *
 * Build notes:
 *   - mlkem-native: reuse the tree already vendored on feature/mlkem-768 (ML-KEM-768).
 *   - mldsa-native: add it with MLD_CONFIG_PARAMETER_SET=65 and MLD_CONFIG_REDUCE_RAM
 *     (ML-DSA-65 sign workspace ~17 KB with REDUCE_RAM vs ~69 KB without — the latter
 *     exceeds the MK20DX256's 64 KB RAM). Gate behind STD_VERSION like RSA.
 */
#include "okpqc.h"
#include <string.h>

#include "mlkem_native/mlkem_native.h"   /* ML-KEM-768 */
#include "mldsa_native/mldsa_native.h"   /* ML-DSA-65 (MLD_CONFIG_PARAMETER_SET=65) */

/* ---- mlkem-native ML-KEM-768 (same calls feature/mlkem-768 uses) ---- */
extern "C" int crypto_kem_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
extern "C" int crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

/* ---- mldsa-native ML-DSA-65 (namespaced) ---- */
extern "C" int PQCP_MLDSA_NATIVE_MLDSA65_keypair_internal(uint8_t *pk, uint8_t *sk, const uint8_t seed[32]);
extern "C" int PQCP_MLDSA_NATIVE_MLDSA65_signature(uint8_t *sig, size_t *siglen,
                   const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, const uint8_t *sk);

/* ---- firmware globals/APIs (okcore.cpp / okcrypto.cpp) ---- */
extern uint8_t  rsa_private_key[];       /* 160-byte blob after okcore_flashget_RSA */
extern uint8_t *large_buffer;            /* request in (digest / ct) */
extern uint8_t *large_resp_buffer;
extern int      large_buffer_offset;
extern uint8_t  CRYPTO_AUTH;
extern uint8_t  pending_operation;
extern int      outputmode;
extern uint32_t packet_buffer_details[];
extern uint8_t  profilekey[];
extern uint8_t  ctap_buffer[];           /* large scratch (>= MLDSA_SIG_SIZE 3309) */

extern "C" {
  void process_packets(uint8_t *buffer, uint8_t type, uint8_t contype);
  void okcore_aes_gcm_decrypt(uint8_t *state, uint8_t slot, uint8_t features, uint8_t *key, int len);
  void send_transport_response(uint8_t *data, int len, bool enc, bool storeread);
  void hidprint(const char *s);
  void fadeoff(int);
  /* ECC halves — thin wrappers over the firmware's existing Ed25519/X25519 primitives
   * (the same math okcrypto_ecdsa_eddsa / okcrypto_ecdh use), called on the 32-byte
   * secret in the blob rather than an ECC-slot key. Implement in okcrypto.cpp. */
  int okpqc_ed25519_sign (uint8_t sig[64], const uint8_t *m, unsigned long mlen, const uint8_t sk[32]);
  int okpqc_x25519_shared(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]);
}

#ifndef OKDECRYPT_ERR_USER_ACTION_PENDING
#define OKDECRYPT_ERR_USER_ACTION_PENDING 0xF9
#endif
#ifndef CTAP2_ERR_OPERATION_PENDING
#define CTAP2_ERR_OPERATION_PENDING 0xF2
#endif
#ifndef CTAP2_ERR_DATA_READY
#define CTAP2_ERR_DATA_READY 0xF1
#endif
#ifndef LARGE_BUFFER_SIZE
#define LARGE_BUFFER_SIZE 1024
#endif

/* One scratch for the expanded secret key: ML-DSA sk(4032) covers ML-KEM dk(2400); never
 * used simultaneously. In .bss (not on the deep call stack); the library keeps its own
 * ~14-17 KB workspace internally. */
static uint8_t pqc_expanded_sk[MLDSA_SK_SIZE];

/* component selector, captured on the user-action phase and reused on the completion phase */
static uint8_t pqc_component;

/* ============================== SIGN ============================== */
void okpqc_sign(uint8_t *buffer)
{
    if (!CRYPTO_AUTH) {
        pqc_component = buffer[6];
        process_packets(buffer, 0, 0);
        pending_operation = OKDECRYPT_ERR_USER_ACTION_PENDING;
        return;
    }
    if (CRYPTO_AUTH != 4) return;

    /* large_buffer holds the message digest to sign (transit-encrypted) */
    okcore_aes_gcm_decrypt(large_buffer, (uint8_t)packet_buffer_details[0],
                           (uint8_t)packet_buffer_details[1], profilekey, large_buffer_offset);
    pending_operation = CTAP2_ERR_OPERATION_PENDING;
    outputmode = (int)packet_buffer_details[2];

    if (pqc_component == PQC_HALF_ECC) {                 /* Ed25519 */
        uint8_t sig[ED25519_SIG_SIZE];
        int rc = okpqc_ed25519_sign(sig, large_buffer, (unsigned long)large_buffer_offset,
                                    rsa_private_key + PQC_OFF_ED25519);
        memset(large_buffer, 0, LARGE_BUFFER_SIZE);
        if (rc != 0) { pending_operation = 0; hidprint("Error Ed25519 sign"); return; }
        pending_operation = CTAP2_ERR_DATA_READY;
        send_transport_response(sig, ED25519_SIG_SIZE, false, true);
        memset(sig, 0, sizeof sig);
    } else {                                             /* ML-DSA-65 */
        uint8_t pk[MLDSA_PK_SIZE];
        uint8_t *sig = ctap_buffer;                      /* >= 3309 B scratch */
        size_t siglen = 0;
        int rc = PQCP_MLDSA_NATIVE_MLDSA65_keypair_internal(pk, pqc_expanded_sk,
                                                            rsa_private_key + PQC_OFF_MLDSA_SEED);
        /* NOTE (verify on hardware): openpgp.js ml_dsa.js signs [0x00,0x00]||digest with empty
         * ML-DSA context. Sending the RAW digest here and signing with ctx="" yields the same
         * FIPS 204 message representative (0x00||0x00||digest). If openpgp.js instead pre-frames,
         * switch to signature_internal over the raw bytes. */
        if (rc == 0) rc = PQCP_MLDSA_NATIVE_MLDSA65_signature(sig, &siglen, large_buffer,
                                    (size_t)large_buffer_offset, (const uint8_t*)0, 0, pqc_expanded_sk);
        memset(pqc_expanded_sk, 0, sizeof pqc_expanded_sk);
        memset(large_buffer, 0, LARGE_BUFFER_SIZE);
        if (rc != 0 || siglen != MLDSA_SIG_SIZE) { pending_operation = 0; hidprint("Error ML-DSA sign"); return; }
        pending_operation = CTAP2_ERR_DATA_READY;
        send_transport_response(sig, MLDSA_SIG_SIZE, false, true);   /* 3309 B, fragmented by transport */
        memset(sig, 0, MLDSA_SIG_SIZE);
    }
    fadeoff(85);
}

/* ============================= DECRYPT ============================ */
void okpqc_decrypt(uint8_t *buffer)
{
    if (!CRYPTO_AUTH) {
        pqc_component = buffer[6];
        process_packets(buffer, 0, 0);
        pending_operation = OKDECRYPT_ERR_USER_ACTION_PENDING;
        return;
    }
    if (CRYPTO_AUTH != 4) return;

    okcore_aes_gcm_decrypt(large_buffer, (uint8_t)packet_buffer_details[0],
                           (uint8_t)packet_buffer_details[1], profilekey, large_buffer_offset);
    pending_operation = CTAP2_ERR_OPERATION_PENDING;
    outputmode = (int)packet_buffer_details[2];

    if (pqc_component == PQC_HALF_ECC) {                 /* X25519 on the 32-byte ephemeral point */
        if (large_buffer_offset != X25519_SS_SIZE) { hidprint("Error X25519 point size");
            memset(large_buffer, 0, LARGE_BUFFER_SIZE); return; }
        uint8_t ss[X25519_SS_SIZE];
        int rc = okpqc_x25519_shared(ss, rsa_private_key + PQC_OFF_X25519, large_buffer);
        memset(large_buffer, 0, LARGE_BUFFER_SIZE);
        if (rc != 0) { pending_operation = 0; hidprint("Error X25519"); return; }
        memcpy(large_resp_buffer, ss, X25519_SS_SIZE); memset(ss, 0, sizeof ss);
        pending_operation = CTAP2_ERR_DATA_READY;
        send_transport_response(large_resp_buffer, X25519_SS_SIZE, false, true);
    } else {                                             /* ML-KEM-768 decapsulate 1088-B ct */
        if (large_buffer_offset != MLKEM_CT_SIZE) { hidprint("Error ML-KEM ct size");
            memset(large_buffer, 0, LARGE_BUFFER_SIZE); return; }
        uint8_t pk[MLKEM_PK_SIZE], ss[MLKEM_SS_SIZE];
        /* seed used DIRECTLY as coins (d||z) — no SHAKE(32->64); this is an imported key */
        int rc = crypto_kem_keypair_derand(pk, pqc_expanded_sk, rsa_private_key + PQC_OFF_MLKEM_SEED);
        if (rc == 0) rc = crypto_kem_dec(ss, large_buffer, pqc_expanded_sk);
        memset(pqc_expanded_sk, 0, MLKEM_DK_SIZE);
        memset(large_buffer, 0, LARGE_BUFFER_SIZE);
        if (rc != 0) { memset(ss, 0, sizeof ss); pending_operation = 0; hidprint("Error ML-KEM decaps"); return; }
        memcpy(large_resp_buffer, ss, MLKEM_SS_SIZE); memset(ss, 0, sizeof ss);
        pending_operation = CTAP2_ERR_DATA_READY;
        send_transport_response(large_resp_buffer, MLKEM_SS_SIZE, false, true);
    }
    fadeoff(85);
}
