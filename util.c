/**
 * @file util.c
 * @brief Helper functions.
 * Most are taken from all over the Zephyr codebase.
 */

#include <util.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <byteorder.h>


/**
 * @brief Calculate BIS AccessAdress
 *
 * @param bis  Number of the BIS this AccessAddress is for.
 * @param saa  The Seed Accesss Adress. Shall be 4 bytes.
 * @param dst  Destination of where to store result. Shall be 4 bytes.
 */
void util_bis_aa_le32(uint8_t bis, uint8_t *saa, uint8_t *dst)
{
	/* Refer to Bluetooth Core Specification Version 5.2 Vol 6, Part B,
	 * section 2.1.2 Access Address
	 */
	uint8_t dwh[2]; /* Holds the two most significant bytes of DW */
	uint8_t d;

	/* 8-bits for d is enough due to wrapping math and requirement to do
	 * modulus 128.
	 */
	d = ((35 * bis) + 42) & 0x7f;

	/* Most significant 6 bits of DW are bit extension of least significant
	 * bit of D.
	 */
	if (d & 1) {
		dwh[1] = 0xFC;
	} else {
		dwh[1] = 0;
	}

	/* Set the bits 25 to 17 of DW */
	dwh[1] |= (d & 0x02) | ((d >> 6) & 0x01);
	dwh[0] = ((d & 0x02) << 6) | (d & 0x30) | ((d & 0x0C) >> 1);

	/* Most significant 16-bits of SAA XOR DW, least significant 16-bit are
	 * zeroes, needing no operation on them.
	 */
	memcpy(dst, saa, sizeof(uint32_t));
	dst[3] ^= dwh[1];
	dst[2] ^= dwh[0];
}


/**
 * @brief XOR n bytes
 *
 * @param dst  Destination of where to store result. Shall be @p len bytes.
 * @param src1 First source. Shall be @p len bytes.
 * @param src2 Second source. Shall be @p len bytes.
 * @param len  Number of bytes to XOR.
 */
void mem_xor_n(uint8_t *dst, const uint8_t *src1, const uint8_t *src2, size_t len)
{
	while (len--) {
		*dst++ = *src1++ ^ *src2++;
	}
}

void hexprint_swapped(uint8_t * buf, int len, char title[3]) {
    uint8_t * buf_s = malloc(len);
    sys_memcpy_swap(buf_s, buf, len);
    printf("%s: ", title);

    for (int i = 0; i < len; i++)
    {
        //if (i > 0) printf(" ");
        printf("%02x", buf_s[i]);
    }
    printf("\n");
}

void print_swapped(uint8_t * buf, int len, char title[3]) {
uint8_t * buf_s = malloc(len);
    sys_memcpy_swap(buf_s, buf, len);
	printf("\033[92;1;4m");
    printf("%s: ", title);

    for (int i = 0; i < len; i++)
    {
        printf("%c", buf_s[i]);
    }
	printf("\033[0m");
    printf("\n");
}

void print(uint8_t * buf, int len, char title[3]) {
	printf("\033[92;1;4m");
    printf("%s: ", title);

    for (int i = 0; i < len; i++)
    {
        printf("%c", buf[i]);
    }
	printf("\033[0m");
    printf("\n");
}

void hexprint(uint8_t * buf, int len, char title[3]) {
    printf("%s: ", title);

    for (int i = 0; i < len; i++)
    {
        //if (i > 0) printf(" ");
        printf("%02x", buf[i]);
    }
    printf("\n");
}