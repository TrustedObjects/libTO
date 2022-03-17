/*
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (C) 2019 Trusted Objects. All rights reserved.
 */

/**
 * @file TODRV_HSE_defs.h
 * @brief Hardware Secure Element constants
 */

#ifndef _TODRV_HSE_CMDS_H_
#define _TODRV_HSE_CMDS_H_

#include "TO_defs.h"
#include "TODRV_HSE_cfg.h"

/** @addtogroup se_constants Hardware Secure Element constants
 * Hardware Secure Element constants
 * @{ */

#define TODRV_HSE_CMDHEAD_SIZE 5UL
#define TODRV_HSE_RSPHEAD_SIZE 4UL

#ifdef TODRV_HSE_ENABLE_SECLINK_ARC4
#define TODRV_HSE_SECLINK_RSP_OVERHEAD_MAXSIZE (TODRV_HSE_RSPHEAD_SIZE + TO_CRC_SIZE)
#elif TODRV_HSE_ENABLE_SECLINK_AESHMAC
#define TODRV_HSE_SECLINK_RSP_OVERHEAD_MAXSIZE (TODRV_HSE_RSPHEAD_SIZE + TO_AES_BLOCK_SIZE + TO_HMAC_SIZE)
#else
#define TODRV_HSE_SECLINK_RSP_OVERHEAD_MAXSIZE 0
#endif

#define TODRV_HSE_RSP_MAXSIZE (TODRV_HSE_LIB_INTERNAL_IO_BUFFER_SIZE - TODRV_HSE_RSPHEAD_SIZE - TODRV_HSE_SECLINK_RSP_OVERHEAD_MAXSIZE)

/** @} */

/** @addtogroup command_codes Hardware Secure Element command codes
 * Hardware Secure Element command codes
 * @{ */

/* System */
#define TODRV_HSE_CMD_GET_SN ((unsigned short)0x0001)
#define TODRV_HSE_CMD_GET_HW_SN ((unsigned short)0x00B0)
#define TODRV_HSE_CMD_RES ((unsigned short)0x0000)
#define TODRV_HSE_CMD_GET_PN ((unsigned short)0x0002)
#define TODRV_HSE_CMD_GET_HW_VERSION ((unsigned short)0x0003)
#define TODRV_HSE_CMD_GET_SW_VERSION ((unsigned short)0x0004)
#define TODRV_HSE_CMD_GET_PRODUCT_ID ((unsigned short)0x0048)
#define TODRV_HSE_CMD_GET_RANDOM ((unsigned short)0x0005)
#define TODRV_HSE_CMD_ECHO ((unsigned short)0x0010)
#define TODRV_HSE_CMD_SLEEP ((unsigned short)0x0011)
#define TODRV_HSE_CMD_READ_NVM ((unsigned short)0x0021)
#define TODRV_HSE_CMD_WRITE_NVM ((unsigned short)0x0022)
#define TODRV_HSE_CMD_GET_NVM_SIZE ((unsigned short)0x0050)
#define TODRV_HSE_CMD_SET_STATUS_PIO_CONFIG ((unsigned short)0x00B1)
#define TODRV_HSE_CMD_GET_STATUS_PIO_CONFIG ((unsigned short)0x00B2)

/* Secure Element Authentication */
#define TODRV_HSE_CMD_SET_CERTIFICATE_SIGNING_REQUEST_DN ((unsigned short)0x0055)
#define TODRV_HSE_CMD_GET_CERTIFICATE_SIGNING_REQUEST ((unsigned short)0x0056)
#define TODRV_HSE_CMD_GET_CERTIFICATE_SUBJECT_CN ((unsigned short)0x0046)
#define TODRV_HSE_CMD_GET_CERTIFICATE ((unsigned short)0x0006)
#define TODRV_HSE_CMD_SET_CERTIFICATE ((unsigned short)0x0057)
#define TODRV_HSE_CMD_SET_CERTIFICATE_INIT ((unsigned short)0x005D)
#define TODRV_HSE_CMD_SET_CERTIFICATE_UPDATE ((unsigned short)0x005E)
#define TODRV_HSE_CMD_SET_CERTIFICATE_FINAL ((unsigned short)0x005F)
#define TODRV_HSE_CMD_GET_CERTIFICATE_INIT ((unsigned short)0x0060)
#define TODRV_HSE_CMD_GET_CERTIFICATE_UPDATE ((unsigned short)0x0061)
#define TODRV_HSE_CMD_GET_CERTIFICATE_FINAL ((unsigned short)0x0062)
#define TODRV_HSE_CMD_SIGN ((unsigned short)0x0007)
#define TODRV_HSE_CMD_VERIFY ((unsigned short)0x0012)
#define TODRV_HSE_CMD_SIGN_HASH ((unsigned short)0x001E)
#define TODRV_HSE_CMD_VERIFY_HASH_SIGNATURE ((unsigned short)0x001F)
#define TODRV_HSE_CMD_GET_CERTIFICATE_AND_SIGN ((unsigned short)0x0008)

/* Remote device Authentication */
#define TODRV_HSE_CMD_VERIFY_CERTIFICATE_AND_STORE ((unsigned short)0x0009)
#define TODRV_HSE_CMD_VERIFY_CA_CERTIFICATE_AND_STORE ((unsigned short)0x0047)
#define TODRV_HSE_CMD_GET_CHALLENGE_AND_STORE ((unsigned short)0x000A)
#define TODRV_HSE_CMD_VERIFY_CHALLENGE_SIGNATURE ((unsigned short)0x000B)
#define TODRV_HSE_CMD_VERIFY_CHAIN_CERTIFICATE_AND_STORE_INIT ((unsigned short)0x00AD)
#define TODRV_HSE_CMD_VERIFY_CHAIN_CERTIFICATE_AND_STORE_UPDATE ((unsigned short)0x00AE)
#define TODRV_HSE_CMD_VERIFY_CHAIN_CERTIFICATE_AND_STORE_FINAL ((unsigned short)0x00AF)
#define TODRV_HSE_CMD_VERIFY_CHAIN_CA_CERTIFICATE_AND_STORE_INIT ((unsigned short)0x00B3)
#define TODRV_HSE_CMD_VERIFY_CHAIN_CA_CERTIFICATE_AND_STORE_UPDATE ((unsigned short)0x00B4)
#define TODRV_HSE_CMD_VERIFY_CHAIN_CA_CERTIFICATE_AND_STORE_FINAL ((unsigned short)0x00B5)

/* HMAC */
#define TODRV_HSE_CMD_COMPUTE_HMAC ((unsigned short)0x000C)
#define TODRV_HSE_CMD_COMPUTE_HMAC_INIT ((unsigned short)0x0023)
#define TODRV_HSE_CMD_COMPUTE_HMAC_UPDATE ((unsigned short)0x0024)
#define TODRV_HSE_CMD_COMPUTE_HMAC_FINAL ((unsigned short)0x0025)
#define TODRV_HSE_CMD_VERIFY_HMAC ((unsigned short)0x000D)
#define TODRV_HSE_CMD_VERIFY_HMAC_INIT ((unsigned short)0x0026)
#define TODRV_HSE_CMD_VERIFY_HMAC_UPDATE ((unsigned short)0x0027)
#define TODRV_HSE_CMD_VERIFY_HMAC_FINAL ((unsigned short)0x0028)

/* AES (CBC) */
#define TODRV_HSE_CMD_AES128CBC_ENCRYPT ((unsigned short)0x000E)
#define TODRV_HSE_CMD_AES128CBC_DECRYPT ((unsigned short)0x000F)
#define TODRV_HSE_CMD_AES128CBC_IV_ENCRYPT ((unsigned short)0x0020)

/* AES (GCM) */
#define TODRV_HSE_CMD_AES128GCM_ENCRYPT ((unsigned short)0x0030)
#define TODRV_HSE_CMD_AES128GCM_DECRYPT ((unsigned short)0x0034)

/* AES (CCM) */
#define TODRV_HSE_CMD_AES128CCM_ENCRYPT ((unsigned short)0x004C)
#define TODRV_HSE_CMD_AES128CCM_DECRYPT ((unsigned short)0x004D)

/* AES (ECB) */
#define TODRV_HSE_CMD_AES128ECB_ENCRYPT ((unsigned short)0x004E)
#define TODRV_HSE_CMD_AES128ECB_DECRYPT ((unsigned short)0x004F)

/* CMAC */
#define TODRV_HSE_CMD_COMPUTE_CMAC ((unsigned short)0x001C)
#define TODRV_HSE_CMD_VERIFY_CMAC ((unsigned short)0x001D)

/* HASH: SHA256 */
#define TODRV_HSE_CMD_SHA256 ((unsigned short)0x00A2)
#define TODRV_HSE_CMD_SHA256_INIT ((unsigned short)0x00AA)
#define TODRV_HSE_CMD_SHA256_UPDATE ((unsigned short)0x00AB)
#define TODRV_HSE_CMD_SHA256_FINAL ((unsigned short)0x00AC)

/* MESSAGE: AES + HMAC */
#define TODRV_HSE_CMD_AES128CBC_HMAC_SECURE_MESSAGE ((unsigned short)0x00A0)
#define TODRV_HSE_CMD_AES128CBC_HMAC_UNSECURE_MESSAGE ((unsigned short)0x00A1)

/* MESSAGE: AES + CMAC */
#define TODRV_HSE_CMD_AES128CBC_CMAC_SECURE_MESSAGE ((unsigned short)0x00C1)
#define TODRV_HSE_CMD_AES128CBC_CMAC_UNSECURE_MESSAGE ((unsigned short)0x00C2)

/* ECIES Key Managment */
#define TODRV_HSE_CMD_SET_REMOTE_PUBLIC_KEY ((unsigned short)0x00A3)
#define TODRV_HSE_CMD_RENEW_ECC_KEYS ((unsigned short)0x00A4)
#define TODRV_HSE_CMD_GET_PUBLIC_KEY ((unsigned short)0x00A5)
#define TODRV_HSE_CMD_GET_UNSIGNED_PUBLIC_KEY ((unsigned short)0x002E)
#define TODRV_HSE_CMD_RENEW_SHARED_KEYS ((unsigned short)0x00A6)
#define TODRV_HSE_CMD_GET_KEY_FINGERPRINT ((unsigned short)0x0019)

/* TLS */
#define TODRV_HSE_CMD_TLS_GET_RANDOM_AND_STORE ((unsigned short)0x0029)
#define TODRV_HSE_CMD_TLS_RENEW_KEYS ((unsigned short)0x002A)
#define TODRV_HSE_CMD_TLS_GET_MASTER_SECRET ((unsigned short)0x002B)
#define TODRV_HSE_CMD_TLS_GET_MASTER_SECRET_DERIVED_KEYS ((unsigned short)0x006B)
#define TODRV_HSE_CMD_TLS_SET_SERVER_RANDOM ((unsigned short)0x002F)
#define TODRV_HSE_CMD_TLS_SET_SERVER_EPUBLIC_KEY ((unsigned short) 0x002C)
#define TODRV_HSE_CMD_TLS_RENEW_KEYS_ECDHE ((unsigned short) 0x002D)
#define TODRV_HSE_CMD_TLS_CALCULATE_FINISHED ((unsigned short)0x0031)

/* TLS optimized */
#define TODRV_HSE_CMD_TLS_RESET ((unsigned short)0x00B6)
#define TODRV_HSE_CMD_TLS_SET_MODE ((unsigned short)0x0042)
#define TODRV_HSE_CMD_TLS_SET_CONFIG ((unsigned short)0x0051)
#define TODRV_HSE_CMD_TLS_SET_SESSION ((unsigned short)0x00C0)
#define TODRV_HSE_CMD_TLS_SET_CONNECTION_ID_EXT_ID ((unsigned short)0x00CB)
#define TODRV_HSE_CMD_TLS_GET_CLIENT_HELLO ((unsigned short)0x0032)
#define TODRV_HSE_CMD_TLS_GET_CLIENT_HELLO_INIT ((unsigned short)0x0063)
#define TODRV_HSE_CMD_TLS_GET_CLIENT_HELLO_UPDATE ((unsigned short)0x0064)
#define TODRV_HSE_CMD_TLS_GET_CLIENT_HELLO_FINAL ((unsigned short)0x0065)
#define TODRV_HSE_CMD_TLS_HANDLE_HELLO_VERIFY_REQUEST ((unsigned short)0x0041)
#define TODRV_HSE_CMD_TLS_HANDLE_SERVER_HELLO ((unsigned short)0x0033)
#define TODRV_HSE_CMD_TLS_HANDLE_SERVER_HELLO_INIT ((unsigned short)0x0066)
#define TODRV_HSE_CMD_TLS_HANDLE_SERVER_HELLO_UPDATE ((unsigned short)0x0067)
#define TODRV_HSE_CMD_TLS_HANDLE_SERVER_HELLO_FINAL ((unsigned short)0x0068)
#define TODRV_HSE_CMD_TLS_HANDLE_SERVER_CERTIFICATE ((unsigned short)0x0054)
#define TODRV_HSE_CMD_TLS_HANDLE_SERVER_CERTIFICATE_INIT ((unsigned short)0x0043)
#define TODRV_HSE_CMD_TLS_HANDLE_SERVER_CERTIFICATE_UPDATE ((unsigned short)0x0044)
#define TODRV_HSE_CMD_TLS_HANDLE_SERVER_CERTIFICATE_FINAL ((unsigned short)0x0045)
#define TODRV_HSE_CMD_TLS_HANDLE_SERVER_KEY_EXCHANGE ((unsigned short)0x0035)
#define TODRV_HSE_CMD_TLS_HANDLE_SERVER_KEY_EXCHANGE_INIT ((unsigned short)0x005A)
#define TODRV_HSE_CMD_TLS_HANDLE_SERVER_KEY_EXCHANGE_UPDATE ((unsigned short)0x005B)
#define TODRV_HSE_CMD_TLS_HANDLE_SERVER_KEY_EXCHANGE_FINAL ((unsigned short)0x005C)
#define TODRV_HSE_CMD_TLS_HANDLE_CERTIFICATE_REQUEST ((unsigned short)0x0036)
#define TODRV_HSE_CMD_TLS_HANDLE_SERVER_HELLO_DONE ((unsigned short)0x0037)
#define TODRV_HSE_CMD_TLS_HANDLE_MEDIATOR_CERTIFICATE ((unsigned short)0x0058)
#define TODRV_HSE_CMD_TLS_GET_CERTIFICATE ((unsigned short)0x0038)
#define TODRV_HSE_CMD_TLS_GET_CERTIFICATE_INIT ((unsigned short)0x00BD)
#define TODRV_HSE_CMD_TLS_GET_CERTIFICATE_UPDATE ((unsigned short)0x00BE)
#define TODRV_HSE_CMD_TLS_GET_CERTIFICATE_FINAL ((unsigned short)0x00BF)
#define TODRV_HSE_CMD_TLS_GET_CLIENT_KEY_EXCHANGE ((unsigned short)0x0039)
#define TODRV_HSE_CMD_TLS_GET_CERTIFICATE_VERIFY ((unsigned short)0x003A)
#define TODRV_HSE_CMD_TLS_GET_CHANGE_CIPHER_SPEC ((unsigned short)0x003B)
#define TODRV_HSE_CMD_TLS_GET_FINISHED ((unsigned short)0x003C)
#define TODRV_HSE_CMD_TLS_HANDLE_CHANGE_CIPHER_SPEC ((unsigned short)0x003D)
#define TODRV_HSE_CMD_TLS_HANDLE_FINISHED ((unsigned short)0x003E)
#define TODRV_HSE_CMD_TLS_GET_CERTIFICATE_SLOT ((unsigned short)0x0059)
#define TODRV_HSE_CMD_TLS_SECURE_MESSAGE ((unsigned short)0x003F)
#define TODRV_HSE_CMD_TLS_SECURE_MESSAGE_INIT ((unsigned short)0x00B7)
#define TODRV_HSE_CMD_TLS_SECURE_MESSAGE_UPDATE ((unsigned short)0x00B8)
#define TODRV_HSE_CMD_TLS_SECURE_MESSAGE_FINAL ((unsigned short)0x00B9)
#define TODRV_HSE_CMD_TLS_UNSECURE_MESSAGE ((unsigned short)0x0040)
#define TODRV_HSE_CMD_TLS_UNSECURE_MESSAGE_INIT ((unsigned short)0x00BA)
#define TODRV_HSE_CMD_TLS_UNSECURE_MESSAGE_UPDATE ((unsigned short)0x00BB)
#define TODRV_HSE_CMD_TLS_UNSECURE_MESSAGE_FINAL ((unsigned short)0x00BC)

/* Secure messaging */
#define TODRV_HSE_CMD_SECURE_MESSAGE ((unsigned short)0x00C3)
#define TODRV_HSE_CMD_SECURE_MESSAGE_INIT ((unsigned short)0x00C4)
#define TODRV_HSE_CMD_SECURE_MESSAGE_UPDATE ((unsigned short)0x00C5)
#define TODRV_HSE_CMD_SECURE_MESSAGE_FINAL ((unsigned short)0x00C6)
#define TODRV_HSE_CMD_UNSECURE_MESSAGE ((unsigned short)0x00C7)
#define TODRV_HSE_CMD_UNSECURE_MESSAGE_INIT ((unsigned short)0x00C8)
#define TODRV_HSE_CMD_UNSECURE_MESSAGE_UPDATE ((unsigned short)0x00C9)
#define TODRV_HSE_CMD_UNSECURE_MESSAGE_FINAL ((unsigned short)0x00CA)

/* LoRa */
#define TODRV_HSE_CMD_LORA_GET_APPEUI ((unsigned short)0x0108)
#define TODRV_HSE_CMD_LORA_GET_DEVEUI ((unsigned short)0x0109)
#define TODRV_HSE_CMD_LORA_COMPUTE_MIC ((unsigned short)0x010A)
#define TODRV_HSE_CMD_LORA_ENCRYPT_PAYLOAD ((unsigned short)0x010B)
#define TODRV_HSE_CMD_LORA_DECRYPT_JOIN ((unsigned short)0x010C)
#define TODRV_HSE_CMD_LORA_COMPUTE_SHARED_KEYS ((unsigned short)0x010D)
#define TODRV_HSE_CMD_LORA_GET_DEVADDR ((unsigned short)0x0110)

/* LoRa optimized */
#define TODRV_HSE_CMD_LORA_GET_JOIN_REQUEST ((unsigned short)0x0100)
#define TODRV_HSE_CMD_LORA_HANDLE_JOIN_ACCEPT ((unsigned short)0x0101)
#define TODRV_HSE_CMD_LORA_SECURE_PHYPAYLOAD ((unsigned short)0x0102)
#define TODRV_HSE_CMD_LORA_UNSECURE_PHYPAYLOAD ((unsigned short)0x0103)

/* Personalization */
#define TODRV_HSE_CMD_SET_PRE_PERSONALIZATION_DATA ((unsigned short)0x0013)
#define TODRV_HSE_CMD_SET_NEXT_STATE ((unsigned short)0x0015)
#define TODRV_HSE_CMD_GET_STATE ((unsigned short)0x0016)

/* Administration commands */
#define TODRV_HSE_CMD_ADMIN_SET_SLOT ((unsigned short)0x0053)
#define TODRV_HSE_CMD_INIT_ADMIN_SESSION ((unsigned short)0x0049)
#define TODRV_HSE_CMD_AUTH_ADMIN_SESSION ((unsigned short)0x004A)
#define TODRV_HSE_CMD_FINI_ADMIN_SESSION ((unsigned short)0x004B)
#define TODRV_HSE_CMD_ADMIN_COMMAND ((unsigned short)0x0014)
#define TODRV_HSE_CMD_ADMIN_COMMAND_WITH_RESPONSE ((unsigned short)0x0052)

/* Lock */
#define TODRV_HSE_CMD_LOCK ((unsigned short)0x0017)
#define TODRV_HSE_CMD_UNLOCK ((unsigned short)0x0018)

/* Symmetric key Management */
#define TODRV_HSE_CMD_SET_AES_KEY ((unsigned short)0x00A7)
#define TODRV_HSE_CMD_SET_HMAC_KEY ((unsigned short)0x00A8)
#define TODRV_HSE_CMD_SET_CMAC_KEY ((unsigned short)0x00A9)

/* Secure link */
#define TODRV_HSE_CMD_SECLINK_ARC4 ((unsigned short)0xFF00)
#define TODRV_HSE_CMD_SECLINK_ARC4_GET_IV ((unsigned short)0xFF01)
#define TODRV_HSE_CMD_SECLINK_ARC4_GET_NEW_KEY ((unsigned short)0xFF04)
#define TODRV_HSE_CMD_SECLINK_AESHMAC ((unsigned short)0xFF02)
#define TODRV_HSE_CMD_SECLINK_AESHMAC_GET_IV ((unsigned short)0xFF03)
#define TODRV_HSE_CMD_SECLINK_AESHMAC_GET_NEW_KEYS ((unsigned short)0xFF05)

/* Bootloader */
#define TODRV_HSE_CMD_LOADER_BCAST_GET_INFO ((unsigned short)0xFFFF)
#define TODRV_HSE_CMD_LOADER_BCAST_RESTORE ((unsigned short)0x00D7)
#define TODRV_HSE_CMD_LOADER_BCAST_INITIALIZE_UPGRADE ((unsigned short)0xFFF2)
#define TODRV_HSE_CMD_LOADER_BCAST_WRITE_DATA ((unsigned short)0xFFF3)
#define TODRV_HSE_CMD_LOADER_BCAST_COMMIT_RELEASE ((unsigned short)0xFFF4)

/* Migration */
#define TODRV_HSE_CMD_DATA_MIGRATION ((unsigned short)0x00D6)

/* Measure boot */
#define TODRV_HSE_CMD_SET_MEASURE_BOOT          ((unsigned short)0x00E0)
#define TODRV_HSE_CMD_VALIDATE_NEW_FW_HASH      ((unsigned short)0x00E1)
#define TODRV_HSE_CMD_COMMIT_NEW_FW_HASH        ((unsigned short)0x00E2)
#define TODRV_HSE_CMD_STORE_NEW_TRUSTED_FW_HASH ((unsigned short)0x00E3)
#define TODRV_HSE_CMD_GET_BOOT_MEASUREMENT      ((unsigned short)0x00E4)
#define TODRV_HSE_CMD_GET_SE_MEASUREMENT      ((unsigned short)0x00E6)
#define TODRV_HSE_CMD_INVALIDATE_NEW_HASH       ((unsigned short)0x00E5)

/** @} */

#endif /* _TODRV_HSE_CMDS_H_ */

