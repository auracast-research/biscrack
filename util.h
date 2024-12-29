/* util.h
 */

#include <types.h>

void util_bis_aa_le32(uint8_t bis, uint8_t *saa, uint8_t *dst);
void mem_xor_n(uint8_t *dst, const uint8_t *src1, const uint8_t *src2, size_t len);
void hexprint_swapped(uint8_t * buf, int len, char title[3]);
void print_swapped(uint8_t * buf, int len, char title[3]);
void print(uint8_t * buf, int len, char title[3]);
void hexprint(uint8_t * buf, int len, char title[3]);