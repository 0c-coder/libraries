/*
 * okic2.cpp - I2C slave transport for OnlyKey (MK20 / Teensy 3.2)
 * See okic2.h for the single-use transit key model, framing and concurrency.
 *
 * UNTESTED against hardware - by inspection.
 */
#include "okic2.h"
#include "okcore.h"
#include "okcrypto.h"
#include <Wire.h>
#include <Arduino.h>
#include <Crypto.h>
#include <AES.h>
#include <GCM.h>
#include "sha256.h"

// Provided by okcore.cpp
extern uint8_t recv_buffer[64];
extern int outputmode;
extern void recvmsg(int n);
extern bool unlocked;

volatile bool okic2_active = false;

// -- Single-use transit key ------------------------------------------------
static uint8_t transit_key_i2c[32];
static bool    transit_set = false;

// -- RX staging, filled in the Wire ISR ------------------------------------
static volatile uint8_t rx_frame[OKIC2_FRAME_LEN];
static volatile bool    rx_complete = false;
static volatile uint8_t last_seq = 0;
static volatile uint8_t err_flag = 0;

// -- TX response -----------------------------------------------------------
static uint8_t tx_frame[OKIC2_MAX_FRAME];
static volatile uint8_t tx_len = 0;      // 0 = nothing queued
static volatile uint8_t tx_sent = 0;

// CRC16-CCITT (0x1021, init 0xFFFF)
static uint16_t crc16(const uint8_t *p, int n)
{
    uint16_t crc = 0xFFFF;
    for (int i = 0; i < n; i++) {
        crc ^= (uint16_t)p[i] << 8;
        for (int b = 0; b < 8; b++)
            crc = (crc & 0x8000) ? (crc << 1) ^ 0x1021 : (crc << 1);
    }
    return crc;
}

int okic2_session_set(const uint8_t *ss32)
{
    // transit_key = SHA256(ss); ss came from on-device X-Wing decapsulation.
    SHA256_CTX c;
    sha256_init(&c);
    sha256_update(&c, (uint8_t *)ss32, 32);
    sha256_final(&c, transit_key_i2c);
    transit_set = true;
    return 0;
}

void okic2_session_end(void)
{
    memset(transit_key_i2c, 0, sizeof(transit_key_i2c));
    transit_set = false;
}

static uint8_t compute_status(void)
{
    if (err_flag)                    return OKIC2_ST_ERROR;
    if (rx_complete || okic2_active) return OKIC2_ST_BUSY;
    if (tx_len)                      return OKIC2_ST_READY;
    if (!unlocked)                   return OKIC2_ST_LOCKED;
    return OKIC2_ST_IDLE;
}

// -- Wire ISR: master -> slave (commands, always plaintext) ----------------
static void on_receive(int count)
{
    if (rx_complete) {                        // previous frame not consumed
        while (Wire.available()) Wire.read();
        return;
    }
    uint8_t i = 0;
    while (Wire.available() && i < OKIC2_FRAME_LEN) rx_frame[i++] = Wire.read();
    while (Wire.available()) Wire.read();     // flush overrun

    if (i == OKIC2_FRAME_LEN && rx_frame[0] == OKIC2_SOF_CMD &&
        rx_frame[2] == OKIC2_REPORT_LEN) {
        uint16_t want = ((uint16_t)rx_frame[67] << 8) | rx_frame[68];
        if (crc16((const uint8_t *)rx_frame, 67) == want) {
            last_seq = rx_frame[1];
            rx_complete = true;
            err_flag = 0;
            return;
        }
    }
    err_flag = 1;                             // bad framing/CRC
}

// -- Wire ISR: slave -> master ---------------------------------------------
static void on_request(void)
{
    if (tx_len && !tx_sent) {
        Wire.write((const uint8_t *)tx_frame, tx_len);
        tx_sent = 1;
        tx_len = 0;
    } else {
        Wire.write(compute_status());
    }
}

void okic2_begin(void)
{
    Wire.begin(OKIC2_ADDR);
    Wire.onReceive(on_receive);
    Wire.onRequest(on_request);
    okic2_session_end();
}

void okic2_queue_response(uint8_t *data, int len)
{
    if (len > OKIC2_REPORT_LEN) len = OKIC2_REPORT_LEN;
    uint8_t report[OKIC2_REPORT_LEN];
    memset(report, 0, sizeof(report));
    memcpy(report, data, len);

    if (transit_set) {
        // Single-use key => a fixed IV can never collide. Zeroized below.
        uint8_t iv[12];
        memset(iv, 0, sizeof(iv));
        GCM<AES256> gcm;
        gcm.clear();
        gcm.setKey(transit_key_i2c, 32);
        gcm.setIV(iv, 12);
        tx_frame[0] = OKIC2_SOF_RSP_ENC;
        tx_frame[1] = last_seq;
        tx_frame[2] = OKIC2_REPORT_LEN;
        gcm.encrypt(&tx_frame[3], report, OKIC2_REPORT_LEN);
        gcm.computeTag(&tx_frame[67], 16);
        uint16_t c = crc16(tx_frame, 83);
        tx_frame[83] = (uint8_t)(c >> 8);
        tx_frame[84] = (uint8_t)(c & 0xFF);
        tx_len = OKIC2_ENC_FRAME_LEN;
        okic2_session_end();                  // ENFORCE one message per key
    } else {
        tx_frame[0] = OKIC2_SOF_RSP;
        tx_frame[1] = last_seq;
        tx_frame[2] = OKIC2_REPORT_LEN;
        memcpy(&tx_frame[3], report, OKIC2_REPORT_LEN);
        uint16_t c = crc16(tx_frame, 67);
        tx_frame[67] = (uint8_t)(c >> 8);
        tx_frame[68] = (uint8_t)(c & 0xFF);
        tx_len = OKIC2_FRAME_LEN;
    }
    tx_sent = 0;
    memset(report, 0, sizeof(report));
}

void okic2_poll(void)
{
    if (!rx_complete) return;

    uint8_t report[OKIC2_REPORT_LEN];
    noInterrupts();
    memcpy(report, (const void *)&rx_frame[3], OKIC2_REPORT_LEN);
    rx_complete = false;
    interrupts();

    if (report[4] == OKIC2_CMD_SESSEND) {
        okic2_session_end();
        uint8_t ack[2] = {0x01, 0x00};
        okic2_queue_response(ack, 2);         // plaintext: key already gone
        memset(report, 0, sizeof(report));
        return;
    }

    // No session opcode: report[4] is the OnlyKey message byte (e.g. OKDECRYPT) and
    // recvmsg() switches on it, so it cannot be repurposed. The transit-key setup is
    // identified by the SLOT instead (report[5] == RESERVED_KEY_OA_FDE_TRANSIT),
    // which okcrypto_xwing_decaps() checks directly. See INTEGRATION-i2c.md.
    okic2_active = true;
    memcpy(recv_buffer, report, OKIC2_REPORT_LEN);
    memset(report, 0, sizeof(report));
    outputmode = RAW_I2C;                     // route send_transport_response()
    recvmsg(1);                               // may block on button press
    okic2_active = false;
}
