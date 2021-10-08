/*******************************************************************************
*  (c) 2019 Zondax GmbH
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#define CLA                             0x33

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "zxmacros.h"

#define HDPATH_LEN_DEFAULT   5

#define HDPATH_0_DEFAULT     (0x80000000u | 0x2cu)
#define HDPATH_1_DEFAULT     (0x80000000u | 0x21bu)
#define HDPATH_2_DEFAULT     (0x80000000u | 0u)
#define HDPATH_3_DEFAULT     (0u)
#define HDPATH_4_DEFAULT     (0u)

#define HDPATH_0_TESTNET     (0x80000000u | 0x2cu)
#define HDPATH_1_TESTNET     (0x80000000u | 0x1u)

typedef struct {
    uint32_t data[HDPATH_LEN_DEFAULT];
} flow_path_t;


__Z_INLINE bool path_is_mainnet(const flow_path_t path) {
    return (path.data[0] == HDPATH_0_DEFAULT && path.data[1] == HDPATH_1_DEFAULT);
}

__Z_INLINE bool path_is_testnet(const flow_path_t path) { //or emulatornet
    return (path.data[0] == HDPATH_0_TESTNET && path.data[1] == HDPATH_1_TESTNET);
}

__Z_INLINE bool path_is_empty(const flow_path_t path) {
    return path.data[0] == 0 && path.data[1] == 0;
}

#define PUBLIC_KEY_LEN       65u

typedef enum {
    ADDR_SECP256K1 = 0,
} address_kind_e;

#define CODEWORD_MAINNET     ((uint64_t) 0x0000000000000000)
#define CODEWORD_TESTNET     ((uint64_t) 0x6834ba37b3980209)
#define CODEWORD_EMULATORNET ((uint64_t) 0x1cb159857af02018)

bool validateChainAddress(uint64_t chainCodeWord, uint64_t address);

#define COIN_AMOUNT_DECIMAL_PLACES          0           // FIXME: Adjust this
#define COIN_SUPPORTED_TX_VERSION           0

#define MENU_MAIN_APP_LINE1 "Flow"
#define MENU_MAIN_APP_LINE2 "Ready"
#define APPVERSION_LINE1 "Version"
#define APPVERSION_LINE2 "v" APPVERSION

#ifdef __cplusplus
}
#endif
