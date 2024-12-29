/** @file bt_bis.c
 *  @brief This unit hold most of the actual code I (fsteinmetz@ernw.de) wrote.
 *  
 */

#include <bt_bis.h>
#include <util.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <bt_crypto.h>
#include <byteorder.h>
#include <ccm_mode.h>
#include <aes_ni.h>

// lacks a unit test
void bt_bis_iv(uint8_t giv[8], uint8_t saa[4], uint8_t bis_num, uint8_t iv[8]) {
    uint8_t aa[4];
    memcpy(iv+4, giv+4, 4);
    util_bis_aa_le32(bis_num, saa, aa);
    mem_xor_n(iv, giv, aa, 4);
}

// is tested in test_nonce_and_decrypt()
void bt_bis_nonce(uint8_t bis_payload_count[5], uint8_t iv[8], uint8_t direction, uint8_t nonce[13]) {
    memcpy(nonce, bis_payload_count, 5);
    // set direction bit to 1 bc for BIS it's always 1
    nonce[4] |= direction << 7;
    memcpy(&nonce[5], iv, 8);
}

//is tested in test_bt_bis_gsk()
// ret == 0 indicates success
int bt_bis_gsk(uint8_t broadcast_code[16],uint8_t gskd[16], uint8_t gsk[16]) {
    // IGLTK = h7(“BIG1”, Broadcast_Code)
    uint8_t salt[16] = "\x31\x47\x49\x42\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    uint8_t igltk[16];

    int ret = bt_crypto_h7(salt, broadcast_code, igltk);
    if (ret != 0)
    {
        return ret;
    }

    // GLTK = h6(IGLTK, “BIG2”)
    const uint8_t key_id_h6[4] = "\x32\x47\x49\x42";
    uint8_t gltk[16];

    ret = bt_crypto_h6(igltk, key_id_h6, gltk);
    if (ret != 0)
    {
        return ret;
    }

    // GSK = h8 (GLTK, GSKD, “BIG3”)
    const uint8_t key_id_h8[4] = "\x33\x47\x49\x42";

    ret = bt_crypto_h8(gltk, gskd, key_id_h8, gsk);
    if (ret != 0)
    {
        return ret;
    }

    // doing sys_memcpy_swap coudl be more efficient
    sys_mem_swap(gsk, 16);
    return 0;
}

// is tested in test_nonce_and_decrypt()
int bt_bis_pdu_decrypt(uint8_t * pdu, uint8_t plen, uint8_t gsk[16], uint8_t nonce[13], uint8_t nrf, uint8_t * out) {
    // check the nrf param is either 0 or 1
    // the reason for this variable is
    // that nrfs insert an additional byte in
    // the encrypted PDU and we need to account for
    // that when decrypting
    if(nrf != 0 && nrf != 1) {
        return -1;
    }

    // decrypt
    struct tc_ccm_mode_struct c;
    __m128i sched_array[20];
    TCAesKeySched_t sched = sched_array;

    tc_aes128_set_encrypt_key(sched, gsk);
    
    int ret =  tc_ccm_config(&c, sched, nonce, 13, 4);
    if (ret == 0)
    {
        return -1;
    }

    // The packet header byte is authenticated but not encrypted
    // For AES-CCM maccheck some bits must be masked to 0
    // For Broadcast Isochronous PDU the bits are: CSSN, CSTF.
    // This means the mask byte should be C3
    uint8_t aad = pdu[0] & 0xC3; // nrf might already do the masking in hardware
   
    ret = tc_ccm_decryption_verification(out, pdu[1] - 4, &aad, 1, pdu + 2 + nrf, plen - 2 - nrf, &c);

    if (ret == 0)
    {
        return -1;
    }

    return 0;
}