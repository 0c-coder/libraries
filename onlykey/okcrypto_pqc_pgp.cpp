/*
 * okcrypto_pqc_pgp.cpp — composite PQC PGP key ops (one RSA slot = one key).
 * Mirrors the two-phase CRYPTO_AUTH flow of okcrypto_mlkem_decaps (feature/mlkem-768).
 * The 160-byte seed blob is loaded into rsa_private_key[] by okcore_flashget_RSA in dispatch.
 *
 * UNTESTED — by inspection. Validate on hardware.
 */
#include "okcrypto_pqc_pgp.h"
#include "mlkem768.h"
#include "mldsa65.h"
#include <string.h>

/* ---- firmware globals/APIs (defined in okcore.cpp / okcrypto.cpp) ---- */
extern uint8_t  rsa_private_key[];          /* holds the 160-byte seed blob after flashget */
extern uint8_t *large_buffer;               /* request in (digest / ct)                     */
extern uint8_t *large_resp_buffer;
extern int      large_buffer_offset;
extern uint8_t  CRYPTO_AUTH;
extern uint8_t  pending_operation;
extern int      outputmode;
extern uint32_t packet_buffer_details[];
extern uint8_t  profilekey[];
extern uint8_t  ctap_buffer[];              /* large scratch (>= MLDSA_SIG_SIZE) */

extern "C" {
  void process_packets(uint8_t *buffer, uint8_t type, uint8_t contype);
  void okcore_aes_gcm_decrypt(uint8_t *state, uint8_t slot, uint8_t features, uint8_t *key, int len);
  void send_transport_response(uint8_t *data, int len, bool enc, bool storeread);
  void hidprint(const char *s);
  void fadeoff(int);
  /* ECC halves — the firmware's existing Ed25519/X25519 primitives (nacl/tweetnacl):
   * wire these to the same math okcrypto_ecdsa_eddsa / okcrypto_ecdh already use,
   * called on the 32-byte secret from the blob rather than an ECC-slot key. */
  int ok_ed25519_sign  (uint8_t sig[64], const uint8_t *m, unsigned long mlen, const uint8_t sk[32]);
  int ok_x25519_shared (uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]);
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

/* component selector captured at request time (buffer[6]); persists across the two phases */
static uint8_t pqc_component;

/* ============================== SIGN ============================== */
void okcrypto_pqc_pgp_sign(uint8_t *buffer)
{
    if (!CRYPTO_AUTH) {
        pqc_component = buffer[6];             /* PQC_HALF_ECC | PQC_HALF_PQC */
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

    if (pqc_component == PQC_HALF_ECC) {
        uint8_t sig[ED25519_SIG_SIZE];
        int rc = ok_ed25519_sign(sig, large_buffer, (unsigned long)large_buffer_offset,
                                 rsa_private_key + PQC_OFF_ED25519);
        memset(large_buffer, 0, LARGE_BUFFER_SIZE);
        if (rc != 0) { pending_operation = 0; hidprint("Error Ed25519 sign"); return; }
        pending_operation = CTAP2_ERR_DATA_READY;
        send_transport_response(sig, ED25519_SIG_SIZE, false, true);
        memset(sig, 0, sizeof sig);
    } else { /* PQC_HALF_PQC : ML-DSA-65 */
        static uint8_t sk[MLDSA_SK_SIZE]; uint8_t pk[MLDSA_PK_SIZE];
        uint8_t *sig = ctap_buffer;            /* >= 3309 B scratch */
        size_t siglen = 0;
        int rc = mldsa65_keypair_from_seed(pk, sk, rsa_private_key + PQC_OFF_MLDSA_SEED); /* expand */
        if (rc == 0) rc = mldsa65_sign(sig, &siglen, large_buffer, (size_t)large_buffer_offset, sk);
        memset(sk, 0, sizeof sk);
        memset(large_buffer, 0, LARGE_BUFFER_SIZE);
        if (rc != 0 || siglen != MLDSA_SIG_SIZE) { pending_operation = 0; hidprint("Error ML-DSA sign"); return; }
        pending_operation = CTAP2_ERR_DATA_READY;
        send_transport_response(sig, MLDSA_SIG_SIZE, false, true);
        memset(sig, 0, MLDSA_SIG_SIZE);
    }
    fadeoff(85);
}

/* ============================= DECRYPT ============================ */
void okcrypto_pqc_pgp_decrypt(uint8_t *buffer)
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

    if (pqc_component == PQC_HALF_ECC) {       /* X25519 on the ephemeral point (32 B) */
        if (large_buffer_offset != X25519_SS_SIZE) { hidprint("Error X25519 point size");
            memset(large_buffer,0,LARGE_BUFFER_SIZE); return; }
        uint8_t ss[X25519_SS_SIZE];
        int rc = ok_x25519_shared(ss, rsa_private_key + PQC_OFF_X25519, large_buffer);
        memset(large_buffer, 0, LARGE_BUFFER_SIZE);
        if (rc != 0) { pending_operation = 0; hidprint("Error X25519"); return; }
        memcpy(large_resp_buffer, ss, X25519_SS_SIZE); memset(ss, 0, sizeof ss);
        pending_operation = CTAP2_ERR_DATA_READY;
        send_transport_response(large_resp_buffer, X25519_SS_SIZE, false, true);
    } else { /* PQC_HALF_PQC : ML-KEM-768 decapsulate (1088-B ct) */
        if (large_buffer_offset != MLKEM_CT_SIZE) { hidprint("Error ML-KEM ct size");
            memset(large_buffer,0,LARGE_BUFFER_SIZE); return; }
        static uint8_t dk[MLKEM_DK_SIZE]; uint8_t pk[MLKEM_PK_SIZE], ss[MLKEM_SS_SIZE];
        int rc = mlkem768_keypair_from_seed(pk, dk, rsa_private_key + PQC_OFF_MLKEM_SEED); /* seed used directly */
        if (rc == 0) rc = mlkem768_dec(ss, large_buffer, dk);
        memset(dk, 0, sizeof dk); memset(large_buffer, 0, LARGE_BUFFER_SIZE);
        if (rc != 0) { memset(ss,0,sizeof ss); pending_operation = 0; hidprint("Error ML-KEM decaps"); return; }
        memcpy(large_resp_buffer, ss, MLKEM_SS_SIZE); memset(ss, 0, sizeof ss);
        pending_operation = CTAP2_ERR_DATA_READY;
        send_transport_response(large_resp_buffer, MLKEM_SS_SIZE, false, true);
    }
    fadeoff(85);
}
