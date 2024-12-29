#include <types.h>

/* Channel Map Size */
#define PDU_CHANNEL_MAP_SIZE 5

struct pdu_big_info {
	/* offs:14          [0].0 - [1].5
	 * offs_units:1     [1].6
	 * iso_interval:12  [1].7 - [3].2
	 * num_bis:5        [3].3 - [3].7
	 */
	uint8_t bi_packed_0_3[4];

	/* nse:5            [0].0 - [0].4
	 * bn:3             [0].5 - [0].7
	 * sub_interval:20  [1].0 - [3].3
	 * pto:4            [3].4 - [3].7
	 */
	uint8_t bi_packed_4_7[4];

	/* spacing:20       [0].0 - [2].3
	 * irc:4            [2].4 - [2].7
	 */
	uint8_t bi_packed_8_11[3];

	uint8_t max_pdu;

	uint8_t  rfu;

	uint8_t seed_access_addr[4];

	/* sdu_interval:20  [0].0 - [2].3
	 * max_sdu:12;      [2].4 - [3].7
	 */
	uint8_t  sdu_packed[4];

	uint8_t base_crc_init[2];

	uint8_t chm_phy[PDU_CHANNEL_MAP_SIZE]; /* 37 bit chm; 3 bit phy */
	uint8_t payload_count_framing[5]; /* 39 bit count; 1 bit framing */

	uint8_t giv[8]; /* encryption required */
	uint8_t gskd[16]; /* encryption required */
} __attribute__((packed));

typedef struct pdu_big_info pdu_big_info;

void bt_bis_iv(uint8_t giv[8], uint8_t saa[4], uint8_t bis_num, uint8_t iv[8]);
void bt_bis_nonce(uint8_t bis_payload_count[5], uint8_t iv[8], uint8_t direction, uint8_t nonce[13]);
int bt_bis_gsk(uint8_t broadcast_code[16],uint8_t gskd[16], uint8_t gsk[16]);
int bt_bis_pdu_decrypt(uint8_t * pdu, uint8_t plen, uint8_t gsk[16], uint8_t nonce[13], uint8_t nrf, uint8_t * out);
void test_nonce_and_decrypt();
void test_bt_bis_gsk();