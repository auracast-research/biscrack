# Decrypt BIS PDUs

## what we need

- Broadcast_Code (secret)
- GIV (broadcasted in BIGInfo)
- GSKD (broadcasted in BIGInfo)
- bisPayloadCount (broadcasted in BIGInfo)
- SeedAccessAdress (broadcasted in BIGInfo)
- BIS number

## what we have to do

1. Derive GSK
2. Create Nonce
3. Decrypt

## derive GSK

1. IGLTK = h7(“BIG1”, Broadcast_Code)
2. GLTK = h6(IGLTK, “BIG2”)
3. GSK = h8 (GLTK, GSKD, “BIG3”)

## create nonce

Nonce comoponents are:

- Counter
- Direction Bit
- IV

### Counter

The counter is just ``bisPayloadCount`` from the last ``BIGInfo``

### Direction Bit

Is 1 for all BIS (because BIS only ever have one direction)

### IV

Is derived from IVbase and AccessAdress_BIS.

IVbase is just GIV.

AccessAdress is more complicated:

1. Get SeedAccessAdress from BIGInfo
2. Calculate the diversifier word (DW) from the BIS number n:
    a. D = ((35 * n) + 42) MOD 128
    b. DW = 0bD₀D₀D₀D₀D₀D₀D₁D₆_D₁0D₅D₄0D₃D₂0_00000000_00000000
3. AccessAdress_BIS = SeedAccessAdress ^ DW

Finally the IV is:

IV[31:0] = IVbase[31:0] ^  AccessAdress_BIS
IV [63:32] = IVbase[63:32]

### combine them

nonce[0:4]  = bisPayloadCount
nonce[4]   |= directionBit << 7 // sets the last bit of nonce[4]
nonce[5:12] = IV

# decrypt

Well, use the key and nonce to decrypt

```c
uint8_t decrypted_payload[paload_len+mic_len];

struct tc_ccm_mode_struct c;
struct tc_aes_key_sched_struct sched;

tc_aes128_set_encrypt_key(&sched, key);

result = tc_ccm_config(&c, &sched, nonce, nlen, mlen);
if (result == 0) {
	printf("CCM config failed.\n");
}

result = tc_ccm_decryption_verification(decrypted_payload, TC_CCM_MAX_PT_SIZE, pdu_hdr,
					hlen, pdu_ciphertext, paload_len+mic_len, &c);
if (result == 0) {
	TC_ERROR("ccm_decrypt failed");
}

```

<!--

IVbase = GIV
IV[31:0] = IVbase[31:0] ^  AccessAdress_BIS
IV [63:32] = IVbase[63:32]


AccessAdress_BIS is derived from SeedAccessAdress
For each BIS logical transport, the Access Address shall be equal to the SAA
bit-wise XORed with a diversifier word (DW) for that logical transport derived
from a Diversifier (D) as follows:

D = ((35 * n) + 42) MOD 128 where n is the BIS number, or 0 for the BIG Control logical link
DW = 0bD₀D₀D₀D₀D₀D₀D₁D₆_D₁0D₅D₄0D₃D₂0_00000000_00000000

For example, if n=1, D=77=0b01001101 and DW = 0xFD060000


ctx_ccm.nonce.counter = ccm->counter;	/* LSO to MSO, counter is LE */
	/* The directionBit set to 1 for Data Physical Chan PDUs sent by
	 * the central and set to 0 for Data Physical Chan PDUs sent by the
	 * peripheral
	 */
	ctx_ccm.nonce.bytes[4] |= ccm->direction << 7; // for BIS dir bit is 1
	memcpy(&ctx_ccm.nonce.bytes[5], ccm->iv, 8); /* LSO to MSO */

>