# I2C transport + derived X-Wing — integration into the firmware

New files: `okic2.{h,cpp}`. Adds an I2C slave transport (address 0x2C) tunnelling the existing
64-byte report protocol, so the on-board LicheeRV/NanoKVM can drive the OnlyKey for FDE unlock
while USB HID stays available to the host. **UNTESTED — by inspection.**

Two pieces:
1. **§1–4** the transport itself (framing, RAW_I2C output mode, single-use transit key).
2. **§5** *derived X-Wing* — X-Wing keys from `(web-derivation key, label)` with **full on-device
   decapsulation**, so no ECC slot is consumed and the ML-KEM seed never leaves the device.

Depends on the Arduino `Wire` library plus the `Crypto`/`AES`/`GCM` headers already vendored here.
If the board uses `i2c_t3`, swap the `Wire.*` calls (same onReceive/onRequest model).

## 1. okcore.h — add the RAW_I2C output mode
```c
#define RAW_USB 0
#define WEBAUTHN 1
#define KEYBOARD_USB 3
#define DISCARD 4
#define RAW_I2C 5          // <-- add
```
And near the other includes:
```c
#include "okic2.h"
```

## 2. okcore.cpp — route responses to I2C in send_transport_response()
Add a branch alongside the `WEBAUTHN` / `KEYBOARD_USB` cases (before the final
`changeoutputmode(RAW_USB)`):
```c
    else if (outputmode == RAW_I2C)
    { // I2C transport — encrypt+queue 64-byte frame(s) for the master to read
        for (int i = 0; i < len; i += 64) {
            int chunk = (len - i >= 64) ? 64 : (len - i);
            okic2_queue_response(data + i, chunk);
        }
    }
```
The `encrypt` argument is ignored here: okic2 encrypts at the transport layer whenever a
single-use transit key is set.

**Multi-frame limitation (v1):** `okic2_queue_response()` holds ONE frame, so responses >64 bytes
(the 1216-byte X-Wing pubkey) need a ring buffer here. The FDE flow avoids this — the pubkey is
read once at provisioning (over USB, or add the ring buffer) and cached in the host-side blob; the
per-boot unlock only moves 32-byte responses.

## 3. setup / loop
```c
    okic2_begin();   // in setup()
    okic2_poll();    // in loop(), alongside the existing recvmsg(1) USB poll
```
`okic2_poll()` dispatches from the main loop, not the ISR, so button-press waits inside
`recvmsg()` behave exactly as over USB.

## 4. Transit key: one key, one message

The web app already gets this right: every operation sends its own `OKCONNECT` with a fresh
transit pubkey, the firmware regenerates the keypair (`crypto_box_keypair`) and emits exactly one
`send_transport_response()` per call — so each transit key encrypts exactly one message and the
fixed IV in `okcrypto_aes_crypto_box()` can never collide. okic2 follows the same rule and
**enforces** it: `okic2_queue_response()` zeroizes the key immediately after one encrypted frame.
No counters, no session state.

`LARGE_BUFFER_SIZE` is 1120 — exactly one X-Wing ct — so the transit ct and the payload ct cannot
share a message. The flow is therefore two messages: set the transit key, then one encrypted op.

> Worth a separate look: `okcrypto_aes_gcm_encrypt2/decrypt2` have `computeTag`/`checkTag`
> commented out, so the web transit has **no integrity** — a MITM on USB can flip bits in a
> returned `ss_X`/`pk_X` (CTR-mode bit flips are surgical). Confidentiality is fine. Fixing it
> changes the wire format, so firmware + web app must move together; version it.

## 5. Derived X-Wing (no slot, no seed release)

`okcrypto_xwing_getpubkey()` and `okcrypto_xwing_decaps()` both take the 32-byte X-Wing seed from
`ecc_private_key` (loaded by `okcore_flashget_ECC` in dispatch) and expand it with
`xwing_shake256(expanded, 96, ecc_private_key, 32)` → ML-KEM keypair from `expanded[0:64]`,
`sk_X = expanded[64:96]`.

So a *derived* X-Wing key needs only one new function: put a **derived** seed in `ecc_private_key`
instead of a flash-loaded one. Everything downstream then works verbatim.

The seed is the **HKDF output itself** — no extra hashing. `okcrypto_derive_key(..., slot =
RESERVED_KEY_WEB_DERIVATION)` runs the RFC 5869 HKDF in `okcrypto_hkdf()`:

```
PRK  = HMAC-SHA256(salt = additional_data[33], ikm = web-derivation key from flash)
seed = HMAC-SHA256(PRK, SHA256(RPID) || 0x01)      -> ecc_private_key, 32 bytes
```

```c
/* Derive a 32-byte X-Wing seed from (web-derivation key, label) into
   ecc_private_key. The seed feeds the FULL on-device X-Wing and is never sent
   to the host. The seed IS the HKDF output — do not hash it again. */
void okcrypto_xwing_derive_seed (uint8_t *label32) {
    extern uint8_t ctap_buffer[CTAPHID_BUFFER_SIZE];
    // Stage RPID where okcrypto_hkdf() reads it (same as okcrypto_xwing_web_derive)
    const char rpid[] = "onlyagent.app";
    memcpy(ctap_buffer + 4, rpid, sizeof(rpid) - 1);
    ctap_buffer[4 + sizeof(rpid) - 1] = 0x02;

    uint8_t additional_data[33];
    additional_data[0] = 2;   // domain separator, see note below (0/1 are taken)
    memcpy(additional_data + 1, label32, 32);

    // KEYTYPE_XWING is load-bearing: okcrypto_compute_pubkey() early-returns for
    // PQ key types, so the HKDF output stays pristine. The CURVE25519 path would
    // run swap_buffer(0,31,ecc_private_key) and byte-REVERSE the seed in place.
    // It also leaves type = KEYTYPE_XWING, which is what the dispatch below wants.
    okcrypto_derive_key(KEYTYPE_XWING, additional_data, RESERVED_KEY_WEB_DERIVATION);

    memset(additional_data, 0, sizeof(additional_data));
}
```

**Domain separation — the salt flag byte.** `additional_data[0]` is part of the HKDF *salt* and is
what keeps derivation families that share a label disjoint. Current allocation — a new family takes
the next free value, never reuses `0`:

| flag | derives | IKM |
|------|---------|-----|
| 0 | `sk_X` — web/age derive, non-REQ_PRESS | web_derivation_key |
| 1 | `sk_X` — web/age derive, REQ_PRESS | web_derivation_key |
| 2 | **OnlyAgent FDE X-Wing seed** (this doc) | web_derivation_key |
| 3 | age `mlkem_seed` | `sk_X` |

With flag `0` the FDE seed would have been **identical to the age plugin's `sk_X` for the same
label** — one secret serving as both an X25519 private scalar (whose `pk_X` is queryable via
`DERIVE_PUBLIC_KEY`) and an X-Wing seed. Flag `2` prevents that.

**Ordering note:** `okcrypto_xwing_derive_seed()` stages the RPID in `ctap_buffer`, and
`okcrypto_xwing_getpubkey()`/`decaps()` later reuse `ctap_buffer` for `sk_M`/`pk_M`. The derive
completes before either runs, so there is no conflict — but keep that order.

**Fixed (was: raw-hash seed).** `okcrypto_xwing_web_derive()` and the X-Wing branch in
`fido2/ok_extension.cpp` derived the age plugin's `mlkem_seed` as `SHA256(sk_X || tag)` — which did
not match the construction their own spec called for
(`onlykey.github.io/src/plugins/age/INTEGRATION.md` §3 specified HKDF). Both now use
`okcrypto_hkdf(salt=[3|label32], IKM=sk_X, L=32)`. This changes every derived X-Wing `mlkem_seed`,
hence `pk_M` and the recipient string — safe because that path was never released (fork only,
marked UNTESTED, absent from `trustcrypto/libraries` master). No host change was needed: the
browser/CLI receive the seed and never recompute it.

### The slot is the discriminator (not a keytype byte)

The purpose — and therefore the label — is selected by the **slot** (`buffer[5]`), using two new
reserved defines in `okcore.h`:

```c
#define RESERVED_KEY_OA_FDE_KEK     127   // label "fde:onlyagent"
#define RESERVED_KEY_OA_FDE_TRANSIT 126   // label "fde-transit:onlyagent"
```

Why not a keytype byte or a host-supplied label — three hard constraints:

1. **`buffer[6]` is already taken.** On the multi-packet path `process_packets()` reads `buffer[6]`
   as the chunk length / `0xFF` continuation flag. The 1120-byte X-Wing ct *must* be packetized, so
   `buffer[6]` cannot also carry a keytype. (The existing split-custody branch gets away with
   `buffer[6] & 0x0F` only because its input is a single 64-byte report — and its own comment
   already flags that framing as unvalidated.)
2. **`label32 || ct` does not fit.** `LARGE_BUFFER_SIZE == PACKET_BUFFER_SIZE == 1120`, which is
   exactly `XWING_CT_SIZE`. Sending a label alongside the ct would need both buffers grown.
3. **`buffer[5]` survives.** `process_packets()` stores the slot in `packet_buffer_details[1]` and
   rejects packets whose slot changes mid-message, so the slot is reliable in both phases of the
   CRYPTO_AUTH flow.

Making the labels firmware constants is also a security gain: the host names a *purpose*, never
label bytes, so a compromised host cannot steer derivation. `okcrypto_xwing_slot_label()` maps slot
→ `SHA256(utf8(label))`; it must stay in sync with `okfde-client`'s `SLOT_FDE_KEK`/`SLOT_FDE_TRANSIT`.

With the ct alone in `large_buffer`, `okcrypto_xwing_decaps()` is reused **verbatim**.

### Dispatch
`okcrypto_getpubkey()` — before the split-custody branch:
```c
} else if (buffer[5] == RESERVED_KEY_OA_FDE_KEK || buffer[5] == RESERVED_KEY_OA_FDE_TRANSIT) {
    uint8_t label32[32];
    if (okcrypto_xwing_slot_label(buffer[5], label32)) {
        okcrypto_xwing_derive_seed(label32);
        okcrypto_xwing_getpubkey(buffer);      // pk_M||pk_X (1216B); seed NOT disclosed
        memset(ecc_private_key, 0, MAX_ECC_KEY_SIZE);
        memset(label32, 0, sizeof(label32));
    }
}
```
`okcrypto_decrypt()` — first, before the slot lookup. Re-derives on **both** phases (the seed is
not retained across the button press), which is safe because `buffer[5]` is preserved:
```c
if (buffer[5] == RESERVED_KEY_OA_FDE_KEK || buffer[5] == RESERVED_KEY_OA_FDE_TRANSIT) {
    uint8_t label32[32];
    if (okcrypto_xwing_slot_label(buffer[5], label32)) {
        okcrypto_xwing_derive_seed(label32);
        memset(label32, 0, sizeof(label32));
        okcrypto_xwing_decaps(buffer);
    }
    return;
}
```

### Transit retain + touch policy
`okcrypto_xwing_decaps()` ended with `send_transport_response(ss, XWING_SS_SIZE, true, true)`.
For the transit slot `ss` is RETAINED instead — unconditionally, so that slot can never emit a
shared secret on any transport:
```c
    if (packet_buffer_details[1] == RESERVED_KEY_OA_FDE_TRANSIT) {
        okic2_session_set(ss);                 // transit_key = SHA256(ss)
        uint8_t ack[2] = {0x01, 0x00};
        send_transport_response(ack, 2, false, false);   // plaintext ack, no secret
    } else {
        send_transport_response(ss, XWING_SS_SIZE, true, true);
    }
```
(Phase 2 reads the slot from `packet_buffer_details[1]`, not `buffer[5]`.)

Touch: keep `CRYPTO_AUTH` for the KEK, skip it for transit setup — nothing leaves the device, so a
touch buys nothing. This uses the same "no press required" idiom as the HMAC challenge-mode path
(`okcore.cpp` ~7471: `CRYPTO_AUTH = 4; op(); CRYPTO_AUTH = 0;`):
```c
    if (!CRYPTO_AUTH) {
        process_packets(buffer, 0, 0);
        // done_process_packets() sets CRYPTO_AUTH=1 only once the LAST packet has
        // landed, so this fires exactly once, fully staged.
        if (buffer[5] == RESERVED_KEY_OA_FDE_TRANSIT && CRYPTO_AUTH == 1) {
            CRYPTO_AUTH = 4;
            okcrypto_xwing_decaps(buffer);
            CRYPTO_AUTH = 0;
            return;
        }
        pending_operation = OKDECRYPT_ERR_USER_ACTION_PENDING;
    }
```
Slot 126/127 are >116 and not >200, so `done_process_packets()` loads neither
`derived_key_challenge_mode` nor `stored_key_challenge_mode` — CRYPTO_AUTH lands on 1, never 3.
Net boot UX: PIN + one touch (for the KEK).

### Why derived rather than an ECC slot key
- No user ECC slot consumed. 101–116 are the user's; 117–132 are reserved and host writes there are
  already rejected, so 126/127 are safe to claim as *purpose selectors* (no key is stored in them).
- Deterministic from `(web-derivation key, label)` — and the web-derivation key is already covered
  by OnlyKey backup/restore, so the FDE key survives device replacement with no extra provisioning.
- The seed never leaves, unlike the split-custody `okcrypto_xwing_web_derive()` path used by the
  age plugin. A host compromised once cannot derive future KEKs offline.

Labels used by the FDE flow (`okfde-client`):
```
  KEK      : SHA256("fde:onlyagent")
  transit  : SHA256("fde-transit:onlyagent")
```

## Notes
- The ISR only buffers; all crypto/dispatch stays on the main loop. Keep Wire clock stretching
  under ~1 ms.
- `unlocked` gates FDE commands exactly as on the USB path — no new bypass.
- Address 0x2C must match `okfde-client --addr` and the board pull-ups.
