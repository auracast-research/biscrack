/** @file zephyr/include/zephyr/bluetooth/addr.h
 *  @brief Bluetooth device address definitions and utilities.
 *  
 */

/*
 * Copyright (c) 2019 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <types.h>

/** Length in bytes of a standard Bluetooth address */
#define BT_ADDR_SIZE 6

/** Bluetooth Device Address */
typedef struct {
	uint8_t  val[BT_ADDR_SIZE];
} bt_addr_t;
/**/

/** Length in bytes of an LE Bluetooth address. Not packed, so no sizeof() */
#define BT_ADDR_LE_SIZE 7

/** Bluetooth LE Device Address */
typedef struct {
	uint8_t      type;
	bt_addr_t a;
} bt_addr_le_t;