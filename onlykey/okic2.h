/*
 * okic2.h - I2C slave transport for OnlyKey (MK20 / Teensy 3.2)
 *
 * Second transport beside RAWHID. Tunnels the existing 64-byte OnlyKey report
 * protocol over I2C so an on-board host (LicheeRV/NanoKVM) can drive the device
 * for FDE unlock while the USB HID interface stays available to the computer
 * through the USB hub.
 *
 * The I2C bus is NOT trusted (on-board traces are probeable), so responses that
 * carry secrets are encrypted with a SINGLE-USE transit key.
 *
 * -- Transit key: one key, one message ------------------------------------
 * Mirrors what the web app already does over WebAuthn: every operation gets a
 * freshly derived transit key, so exactly one message is ever encrypted under
 * it. GCM only requires that (key, nonce) never repeat - a fresh key makes that
 * true no matter what the nonce is, which is why a fixed IV is safe here and
 * why no message counter is needed. The key is zeroized immediately after one
 * encrypted response (enforced in okic2_queue_response), so reuse is not
 * possible even if a caller forgets.
 *
 * Establishment (PQ-safe, reuses the existing X-Wing primitives):
 *   1. Host encapsulates to the device's DERIVED X-Wing key for the transit
 *      slot -> (ct 1120B, ss 32B). Encapsulation is randomised, so a fixed
 *      device key still yields a fresh ss every time.
 *   2. Host sends the ct as a normal OKDECRYPT to slot RESERVED_KEY_OA_FDE_TRANSIT
 *      (no special opcode: report[4] is the message byte recvmsg() switches on).
 *      The device derives that slot's key from its firmware-constant label,
 *      decapsulates on-device and RETAINS ss — that slot never emits a shared
 *      secret. No seed and no secret leaves the device, so this needs no touch.
 *   3. Both sides: transit_key = SHA256(ss). Device acks in plaintext.
 * Breaking a recorded exchange requires breaking BOTH X25519 and ML-KEM-768.
 *
 * Commands are never encrypted: they carry only public data (KEM ciphertexts),
 * which removes the whole host->device crypto path.
 *
 * -- Framing --------------------------------------------------------------
 *   cmd (always plaintext):
 *     0xA5, seq, len(=64), report[64], crc16                      (69 B)
 *   rsp plaintext:
 *     0x5A, seq, len(=64), report[64], crc16                      (69 B)
 *   rsp encrypted (AES-256-GCM, key = single-use transit key, IV = 0):
 *     0x5B, seq, len(=64), ct[64], tag[16], crc16                 (85 B)
 *   Master read of a single byte returns status (see OKIC2_ST_*).
 *
 * Real GCM tags are computed and verified. NOTE: okcrypto_aes_crypto_box() has
 * computeTag/checkTag commented out - safe for confidentiality given its own
 * one-message-per-key property, but it provides no integrity. Do not copy that
 * part onto a bus an attacker can physically reach.
 *
 * Concurrency: the Wire ISR only buffers; recvmsg() (which may block on a button
 * press) runs from the main loop via okic2_poll(). Responses are captured by a
 * RAW_I2C branch in send_transport_response().
 *
 * UNTESTED against hardware - by inspection. Validate framing on a device.
 */
#ifndef OKIC2_H
#define OKIC2_H

#include <stdint.h>
#include <stdbool.h>

#define OKIC2_ADDR        0x2C   // 7-bit I2C slave address
#define OKIC2_REPORT_LEN  64

// Frame markers
#define OKIC2_SOF_CMD     0xA5   // command (always plaintext)
#define OKIC2_SOF_RSP     0x5A   // plaintext response
#define OKIC2_SOF_RSP_ENC 0x5B   // encrypted response

#define OKIC2_FRAME_LEN     69   // 1 sof + 1 seq + 1 len + 64 report + 2 crc
#define OKIC2_ENC_FRAME_LEN 85   // 1 + 1 + 1 + 64 ct + 16 tag + 2 crc
#define OKIC2_MAX_FRAME     OKIC2_ENC_FRAME_LEN

// Transit-key setup has no opcode: report[4] is the OnlyKey message byte that
// recvmsg() switches on, so it cannot be repurposed. Setup is just an OKDECRYPT to
// slot RESERVED_KEY_OA_FDE_TRANSIT; the 1120-byte X-Wing ct arrives via the existing
// multi-packet reassembly into large_buffer, as okcrypto_xwing_decaps expects, and
// that function retains ss as the transit key instead of returning it.
#define OKIC2_CMD_SESSEND 0xE1   // zeroize the transit key (okic2-local, no dispatch)

// Status byte returned on a bare 1-byte master read.
#define OKIC2_ST_LOCKED   0x01   // powered, PIN not yet entered
#define OKIC2_ST_IDLE     0x02   // PIN entered, no command pending
#define OKIC2_ST_BUSY     0x03   // command executing (incl. waiting for button)
#define OKIC2_ST_READY    0x05   // a response frame is queued for read
#define OKIC2_ST_ERROR    0x06   // last command errored (CRC/parse)
#define OKIC2_ST_NOSESS   0x07   // secret response due but no transit key set

// okcore.h includes this from inside its own extern "C" block, so guard linkage
// here the same way okpqc.h does — otherwise okic2.cpp (which includes this header
// first, at C++ linkage) and okcore.cpp (C linkage) would disagree and fail to link.
#ifdef __cplusplus
extern "C" {
#endif

extern void okic2_begin(void);          // call from setup()
extern void okic2_poll(void);           // call from loop()
extern void okic2_queue_response(uint8_t *data, int len);

// Set the single-use transit key from ss (32B, from on-device X-Wing decaps).
// Called by okcrypto_xwing_decaps() for slot RESERVED_KEY_OA_FDE_TRANSIT.
extern int  okic2_session_set(const uint8_t *ss32);
// Zeroize the transit key. Called automatically after one encrypted response.
extern void okic2_session_end(void);

extern volatile bool okic2_active;

#ifdef __cplusplus
}
#endif

#endif // OKIC2_H
