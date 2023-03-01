/*
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (C) 2016-2017 Trusted Objects. All rights reserved.
 */

/**
 * @file TO_defs.h
 * @brief Secure Element constants.
 */

#ifndef _TO_DEFS_H_
#define _TO_DEFS_H_

#include "TO_utils.h"
#include "TO_stdint.h"
#include "TO_log.h"

/** @addtogroup key_types
 * @{ */

/**
 * Secure Element key types
 */
typedef enum TO_key_type_e {
	KTYPE_CERT_KPUB = 0x00,
	KTYPE_CERT_KPRIV = 0x01,
	KTYPE_CA_KPUB = 0x02,
	KTYPE_REMOTE_KPUB = 0x03,
	KTYPE_ECIES_KPUB = 0x04,
	KTYPE_ECIES_KPRIV = 0x05,
	KTYPE_ECIES_KAES = 0x06,
	KTYPE_ECIES_KMAC = 0x07,
	KTYPE_LORA_KAPP = 0x08,
	KTYPE_LORA_KNET = 0x09,
	KTYPE_LORA_KSAPP = 0x0A,
	KTYPE_LORA_KSNET = 0x0B
} PACKED TO_key_type_t;

/** @} */

COMPILE_ASSERT(sizeof(TO_key_type_t) == sizeof(uint8_t));

/** @addtogroup constants
 * Misc constants
 * @{ */

#define TO_INDEX_SIZE 1UL
#define TO_FORMAT_SIZE 1UL
#define TO_AES_BLOCK_SIZE 16UL
#define TO_INITIALVECTOR_SIZE TO_AES_BLOCK_SIZE
#define TO_AES_KEYSIZE 16UL
#define TO_AESGCM_INITIALVECTOR_SIZE 12UL
#define TO_AESGCM_TAG_SIZE 16UL
#define TO_AESGCM_AAD_LEN_SIZE 2UL
#define TO_AESCCM_NONCE_SIZE 13UL
#define TO_AESCCM_TAG_SIZE 16UL
#define TO_AESCCM_8_TAG_SIZE 8UL
#define TO_AESCCM_AAD_LEN_SIZE 2UL
#define TO_HMAC_KEYSIZE 16UL
#define TO_HMAC_SIZE TO_SHA256_HASHSIZE
#define TO_HMAC_MINSIZE 10UL
#define TO_CMAC_KEYSIZE 16UL
#define TO_CMAC_SIZE TO_AES_BLOCK_SIZE
#define TO_CMAC_MIN_SIZE 4UL
#define TO_SEQUENCE_SIZE 4UL

#define TO_SHA256_HASHSIZE 32UL
#define TO_HASH_SIZE TO_SHA256_HASHSIZE

#define TO_CHALLENGE_SIZE 32UL
#define TO_KEY_FINGERPRINT_SIZE 3UL
#define TO_TIMESTAMP_SIZE 4UL
#define TO_CRC_SIZE 2UL

#define TO_SN_SIZE (TO_SN_CA_ID_SIZE+TO_SN_NB_SIZE)
#define TO_HW_SN_SIZE 23UL
#define TO_SN_CA_ID_SIZE 3UL
#define TO_SN_NB_SIZE 5UL

#define TO_PN_SIZE 12UL

#define TO_HW_VERSION_SIZE 2UL

#define TO_SW_VERSION_SIZE 3UL

#define TO_PRODUCT_ID_SIZE 15UL

#define TO_SEED_SIZE 32UL

/** @} */

/** @addtogroup cert_constants
 * Certificate constants
 * @{ */

#define TO_CERTIFICATE_SIZE (TO_SN_SIZE+TO_ECC_PUB_KEYSIZE+TO_SIGNATURE_SIZE)
#define TO_CERT_PRIVKEY_SIZE 32UL
#define TO_ECC_PRIV_KEYSIZE TO_CERT_PRIVKEY_SIZE
#define TO_ECC_PUB_KEYSIZE (2*TO_ECC_PRIV_KEYSIZE)
#define TO_SIGNATURE_SIZE TO_ECC_PUB_KEYSIZE

#define TO_CERT_GENERALIZED_TIME_SIZE  15UL /* YYYYMMDDHHMMSSZ */
#define TO_CERT_DATE_SIZE ((TO_CERT_GENERALIZED_TIME_SIZE - 1) / 2)
#define TO_CERT_SUBJECT_PREFIX_SIZE 15UL
#define TO_SHORTV2_CERT_SIZE (TO_CERTIFICATE_SIZE + TO_CERT_DATE_SIZE)

#define TO_REMOTE_CERTIFICATE_SIZE (TO_SN_SIZE+TO_ECC_PUB_KEYSIZE)
#define TO_REMOTE_CAID_SIZE TO_SN_CA_ID_SIZE

#define TO_CERT_SUBJECT_CN_MAXSIZE 64UL
#define TO_CERT_SUBJECT_CN_PREFIX_MAXSIZE (TO_CERT_SUBJECT_CN_MAXSIZE - TO_SN_SIZE * 2)
#define TO_CERT_DN_MAXSIZE 127UL

#define TO_KEYTYPE_SIZE TO_SN_CA_ID_SIZE
#define TO_CA_PUBKEY_SIZE TO_ECC_PUB_KEYSIZE
#define TO_CA_PUBKEY_CAID_SIZE TO_SN_CA_ID_SIZE

#define TO_KEY_IDENTIFIER_SIZE 20UL
#define TO_KEY_IDENTIFIER_SHORT_SIZE 8UL

/** @} */

/** @addtogroup tls_constants
 * TLS constants
 * @{ */

/**
 * @brief maximum data overhead between a protected record and its plain text version
 *
 * The theorical maximum data overhead between a protected record
 * and its plain text version is 1024 but in practice it should not exceed
 * AES256 with SHA512 in CBC mode with max padding:
 * (32 (IV) + 64 (hmac) + 256 (max padding)) => 352
 * This value is used when the real overhead is not known, to determine
 * if a plain text record to send need to be fragmented before
 * encryption */
#define TO_TLS_RECORD_CIPHER_OVERHEAD_MAX (352UL)

#define TO_TLS_MAJOR 3
#define TO_TLS_MINOR 3
#define TO_TLS_RECORD_MAX_SIZE (1UL << 14)
#define TO_TLS_RANDOM_SIZE (TO_TIMESTAMP_SIZE + 28UL)
#define TO_TLS_MASTER_SECRET_SIZE 48UL
#define TO_TLS_SERVER_PARAMS_SIZE 69UL
#define TO_TLS_HMAC_KEYSIZE 32UL
#define TO_TLS_FINISHED_SIZE 12UL
#define TO_TLS_CHANGE_CIPHER_SPEC_SIZE 1UL
#define TO_TLS_HEADER_SIZE 5UL
#define TO_TLS_HANDSHAKE_HEADER_SIZE 4UL
#define TO_TLS_AEAD_IMPLICIT_NONCE_SIZE 4UL
#define TO_TLS_AEAD_EXPLICIT_NONCE_SIZE 8UL
#define TO_TLS_SNI_LENGTH_MAX 253U

#define TO_DTLS_MAJOR 254
#define TO_DTLS_MINOR 253
#define TO_DTLS_CONNECTION_ID_MAXSIZE 8UL
#define TO_DTLS_HEADER_SIZE 13UL
#define TO_DTLS_HEADER_MAXSIZE (TO_DTLS_HEADER_SIZE + TO_DTLS_CONNECTION_ID_MAXSIZE)
#define TO_DTLS_HANDSHAKE_HEADER_SIZE 12UL
#define TO_DTLS_HANDSHAKE_HEADER_MAXSIZE (TO_DTLS_HANDSHAKE_HEADER_SIZE + TO_DTLS_CONNECTION_ID_MAXSIZE)

/**
 * @brief Different modes available for TO-Protect TLS
 */
typedef enum TO_tls_mode_e {
		/** Unknown mode (uninitialized) */
	TO_TLS_MODE_UNKNOWN = 0,

		/** Handshake Only mode */
	TO_TLS_MODE_HANDSHAKE_ONLY = 0x08,

		/** TLS 1.2 only */
	TO_TLS_MODE_TLS_1_2 = 0x13,

		/** TLS 1.2, in Handshake only */
	TO_TLS_MODE_TLS_1_2_HANDSHAKE_ONLY = TO_TLS_MODE_TLS_1_2 | TO_TLS_MODE_HANDSHAKE_ONLY,

		/** DTLS 1.2 only */
	TO_TLS_MODE_DTLS_1_2 = 0x23,

		/** DTLS 1.2, in Handshake only */
	TO_TLS_MODE_DTLS_1_2_HANDSHAKE_ONLY = TO_TLS_MODE_DTLS_1_2  | TO_TLS_MODE_HANDSHAKE_ONLY,
} PACKED TO_tls_mode_t;

typedef enum TO_tls_config_id_e {
	TO_TLS_CONFIG_ID_UNKNOWN = 0x0000,

	/**
	 * Configure mode on 1 byte. See TO_tls_mode_e.
	 */
	TO_TLS_CONFIG_ID_MODE = 0x0001,

	/**
	 * Configure cipher suites list (each cipher suite on 2 bytes, big-endian)
	 */
	TO_TLS_CONFIG_ID_CIPHER_SUITES = 0x0002,

	/**
	 * Configure certificate slot
	 */
	TO_TLS_CONFIG_ID_CERTIFICATE_SLOT = 0x0003,

	TO_TLS_CONFIG_ID_MAX,

	TO_TLS_CONFIG_ID_LAST = 0xffff,
} PACKED TO_tls_config_id_t;

typedef enum TO_tls_record_type_e {
	TO_TLS_RECORD_TYPE_CHANGE_CIPHER_SPEC = 0x14,
	TO_TLS_RECORD_TYPE_ALERT = 0x15,
	TO_TLS_RECORD_TYPE_HANDSHAKE = 0x16,
	TO_TLS_RECORD_TYPE_APPLICATION_DATA = 0x17,
	TO_TLS_RECORD_TYPE_TLS_12_CID = 0x19,
} PACKED TO_tls_record_type_t;

typedef enum TO_tls_cipher_suite_e {
	TO_TLS_PSK_WITH_AES_128_CBC_SHA256 = 0x00AE,
	TO_TLS_PSK_WITH_AES_128_CCM = 0xC0A4,
	TO_TLS_PSK_WITH_AES_128_CCM_8 = 0xC0A8,
	TO_TLS_PSK_WITH_AES_128_GCM_SHA256 = 0x00A8,
	TO_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = 0xC023,
	TO_TLS_ECDHE_ECDSA_WITH_AES_128_CCM = 0xC0AC,
	TO_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 = 0xC0AE,
	TO_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xC02B,
	TO_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = 0xC027,
	TO_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xC02F,
} PACKED TO_tls_cipher_suite_t;

typedef enum TO_tls_cipher_suite_type_e {
	TO_TLS_CIPHER_SUITE_ECDHE,
	TO_TLS_CIPHER_SUITE_PSK,
} PACKED TO_tls_cipher_suite_type_t;

typedef enum TO_tls_encryption_type_e {
	TO_TLS_ENCRYPTION_AES_CBC,
	TO_TLS_ENCRYPTION_AES_CCM,
	TO_TLS_ENCRYPTION_AES_CCM_8,
	TO_TLS_ENCRYPTION_AES_GCM,
} PACKED TO_tls_encryption_type_t;

typedef enum TO_tls_handshake_type_e {
	TO_TLS_HANDSHAKE_TYPE_CLIENT_HELLO = 0x01,
	TO_TLS_HANDSHAKE_TYPE_SERVER_HELLO = 0x02,
	TO_TLS_HANDSHAKE_TYPE_HELLO_VERIFY_REQUEST = 0x03,
	TO_TLS_HANDSHAKE_TYPE_CERTIFICATE = 0x0b,
	TO_TLS_HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE = 0x0c,
	TO_TLS_HANDSHAKE_TYPE_CERTIFICATE_REQUEST = 0x0d,
	TO_TLS_HANDSHAKE_TYPE_SERVER_HELLO_DONE = 0x0e,
	TO_TLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY = 0x0f,
	TO_TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE = 0x10,
	TO_TLS_HANDSHAKE_TYPE_FINISHED = 0x14,
	TO_TLS_HANDSHAKE_TYPE_MEDIATOR_CERTIFICATE = 0xf0,
} PACKED TO_tls_handshake_type_t;

typedef enum TO_tls_state_e {
	TO_TLS_STATE_HANDSHAKE_START = 0,
	TO_TLS_STATE_FLIGHT_1 = 0x0100,
	TO_TLS_STATE_CLIENT_HELLO = TO_TLS_STATE_FLIGHT_1 | TO_TLS_HANDSHAKE_TYPE_CLIENT_HELLO,
	TO_TLS_STATE_FLIGHT_1_INIT = TO_TLS_STATE_CLIENT_HELLO,
	TO_TLS_STATE_FLIGHT_2 = 0x0200,
	TO_TLS_STATE_SERVER_HELLO_VERIFY_REQUEST = TO_TLS_STATE_FLIGHT_2 | TO_TLS_HANDSHAKE_TYPE_HELLO_VERIFY_REQUEST,
	TO_TLS_STATE_FLIGHT_2_INIT = TO_TLS_STATE_SERVER_HELLO_VERIFY_REQUEST,
	TO_TLS_STATE_FLIGHT_3 = 0x0400,
	TO_TLS_STATE_CLIENT_HELLO_WITH_COOKIE = TO_TLS_STATE_FLIGHT_3 | TO_TLS_HANDSHAKE_TYPE_CLIENT_HELLO,
	TO_TLS_STATE_FLIGHT_3_INIT = TO_TLS_STATE_CLIENT_HELLO_WITH_COOKIE,
	TO_TLS_STATE_FLIGHT_4 = 0x0800,
	TO_TLS_STATE_SERVER_HELLO = TO_TLS_STATE_FLIGHT_4 | TO_TLS_HANDSHAKE_TYPE_SERVER_HELLO,
	TO_TLS_STATE_FLIGHT_4_INIT = TO_TLS_STATE_SERVER_HELLO,
	TO_TLS_STATE_SERVER_CERTIFICATE = TO_TLS_STATE_FLIGHT_4 | TO_TLS_HANDSHAKE_TYPE_CERTIFICATE,
	TO_TLS_STATE_SERVER_KEY_EXCHANGE = TO_TLS_STATE_FLIGHT_4 | TO_TLS_HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE,
	TO_TLS_STATE_SERVER_CERTIFICATE_REQUEST = TO_TLS_STATE_FLIGHT_4 | TO_TLS_HANDSHAKE_TYPE_CERTIFICATE_REQUEST,
	TO_TLS_STATE_SERVER_HELLO_DONE = TO_TLS_STATE_FLIGHT_4 | TO_TLS_HANDSHAKE_TYPE_SERVER_HELLO_DONE,
	TO_TLS_STATE_MEDIATOR_CERTIFICATE = TO_TLS_STATE_FLIGHT_4 | TO_TLS_HANDSHAKE_TYPE_MEDIATOR_CERTIFICATE,
	TO_TLS_STATE_FLIGHT_5 = 0x1000,
	TO_TLS_STATE_CLIENT_CERTIFICATE = TO_TLS_STATE_FLIGHT_5 | TO_TLS_HANDSHAKE_TYPE_CERTIFICATE,
	TO_TLS_STATE_FLIGHT_5_INIT = TO_TLS_STATE_CLIENT_CERTIFICATE,
	TO_TLS_STATE_CLIENT_KEY_EXCHANGE = TO_TLS_STATE_FLIGHT_5 | TO_TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE,
	TO_TLS_STATE_FLIGHT_5_INIT_NO_CLIENT_AUTH = TO_TLS_STATE_CLIENT_KEY_EXCHANGE,
	TO_TLS_STATE_CLIENT_CERTIFICATE_VERIFY = TO_TLS_STATE_FLIGHT_5 | TO_TLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY,
	TO_TLS_STATE_CLIENT_CHANGE_CIPHER_SPEC = TO_TLS_STATE_FLIGHT_5 | 0xff,
	TO_TLS_STATE_CLIENT_FINISHED = TO_TLS_STATE_FLIGHT_5 | TO_TLS_HANDSHAKE_TYPE_FINISHED,
	TO_TLS_STATE_FLIGHT_6 = 0x2000,
	TO_TLS_STATE_SERVER_CHANGE_CIPHER_SPEC = TO_TLS_STATE_FLIGHT_6 | 0xff,
	TO_TLS_STATE_FLIGHT_6_INIT = TO_TLS_STATE_SERVER_CHANGE_CIPHER_SPEC,
	TO_TLS_STATE_SERVER_FINISHED = TO_TLS_STATE_FLIGHT_6 | TO_TLS_HANDSHAKE_TYPE_FINISHED,
	TO_TLS_STATE_HANDSHAKE_DONE = 0x8000,
	TO_TLS_STATE_HANDSHAKE_FAILED = 0x8001,
	TO_TLS_STATE_FATAL_RECEIVED = 0x10000,
	TO_TLS_STATE_CLOSE_RECEIVED = 0x20000,
} TO_tls_state_t;

typedef enum TO_tls_extensions_e {
	TO_TLS_EXTENSION_SERVER_NAME = 0x0000,
	TO_TLS_EXTENSION_SIG_ALG = 0x000d,
	TO_TLS_EXTENSION_ECC = 0x000a,
	TO_TLS_EXTENSION_ECC_POINT_FORMAT = 0x000b,
	TO_TLS_EXTENSION_TRUNCATED_HMAC = 0x0004,
	TO_TLS_EXTENSION_CONNECTION_ID = 0x0036,
	TO_TLS_EXTENSION_DUMMY_MAX = 0xffff
} PACKED  TO_tls_extension_t;

/** @} */

COMPILE_ASSERT(sizeof(TO_tls_mode_t) == sizeof(uint8_t));
COMPILE_ASSERT(sizeof(TO_tls_config_id_t) == sizeof(uint16_t));
COMPILE_ASSERT(sizeof(TO_tls_record_type_t) == sizeof(uint8_t));
COMPILE_ASSERT(sizeof(TO_tls_cipher_suite_t) == sizeof(uint16_t));
COMPILE_ASSERT(sizeof(TO_tls_cipher_suite_type_t) == sizeof(uint8_t));
COMPILE_ASSERT(sizeof(TO_tls_encryption_type_t) == sizeof(uint8_t));
COMPILE_ASSERT(sizeof(TO_tls_handshake_type_t) == sizeof(uint8_t));
COMPILE_ASSERT(sizeof(TO_tls_extension_t) == sizeof(uint16_t));

/** @addtogroup seclink_constants
 * Seclink constants
 * @{ */

#define TO_ARC4_KEY_SIZE 16UL
#define TO_ARC4_INITIALVECTOR_SIZE 16UL

/** @} */

/** @addtogroup i2c_constants
 * I2C constants
 * @{ */

#define TO_I2CADDR_SIZE 1UL

#define TO_I2C_SEND_MSTIMEOUT TO_I2C_MSTIMEOUT
#define TO_I2C_RECV_MSTIMEOUT TO_I2C_MSTIMEOUT
/* 5s for any I2C transaction */
#define TO_I2C_MSTIMEOUT 5000UL
/* 10s waiting Start Condition to send response */
#define TO_I2C_RESPONSE_MSTIMEOUT 10000UL
/* 10s waiting Start Condition to send Error */
#define TO_I2C_ERROR_MSTIMEOUT 10000UL

/** @} */

/** @addtogroup admin_constants
 * Admin constants
 * @{ */

#define TO_ADMIN_DIVERS_DATA_SIZE TO_SN_SIZE
#define TO_ADMIN_PROTO_INFO_SIZE 4UL
#define TO_ADMIN_OPTIONS_SIZE 2UL
#define TO_ADMIN_CHALLENGE_SIZE 8UL
#define TO_ADMIN_CRYPTOGRAM_SIZE 8UL
#define TO_ADMIN_MAC_SIZE 8UL

#define TO_ADMIN_DATAIDX_SIZE 4

/** @} */

/** @addtogroup lora_constants
 * LoRa constants
 * @{ */

#define TO_LORA_PHYPAYLOAD_MINSIZE 10UL
#define TO_LORA_MHDR_SIZE 1UL
#define TO_LORA_APPEUI_SIZE 8UL
#define TO_LORA_DEVEUI_SIZE 8UL
#define TO_LORA_DEVADDR_SIZE 4UL
#define TO_LORA_DEVNONCE_SIZE 2UL
#define TO_LORA_APPNONCE_SIZE 3UL
#define TO_LORA_NETID_SIZE 3UL
#define TO_LORA_MIC_SIZE 4UL
#define TO_LORA_FCTRL_SIZE 1UL
#define TO_LORA_FCNT_SIZE 4UL
#define TO_LORA_APPKEY_SIZE 16UL
#define TO_LORA_APPSKEY_SIZE 16UL
#define TO_LORA_NWKSKEY_SIZE 16UL
#define TO_LORA_DLSETTINGS_SIZE 1UL
#define TO_LORA_RXDELAY_SIZE 1UL
#define TO_LORA_CFLIST_SIZE 16UL
#define TO_LORA_JOINREQUEST_SIZE (TO_LORA_MHDR_SIZE + TO_LORA_APPEUI_SIZE + TO_LORA_DEVEUI_SIZE + TO_LORA_DEVNONCE_SIZE + TO_LORA_MIC_SIZE)
#define TO_LORA_JOINACCEPT_CLEAR_MAXSIZE (TO_LORA_MHDR_SIZE + TO_LORA_APPNONCE_SIZE + TO_LORA_NETID_SIZE + TO_LORA_DEVADDR_SIZE + TO_LORA_DLSETTINGS_SIZE + TO_LORA_RXDELAY_SIZE + TO_LORA_CFLIST_SIZE)
#define TO_LORA_JOINACCEPT_MAXSIZE (TO_LORA_JOINACCEPT_CLEAR_MAXSIZE + TO_LORA_MIC_SIZE)

/** @} */

/** @addtogroup status_pio_constants
 * Status PIO constants
 * @{ */

#define TO_STATUS_PIO_ENABLE 0x80
#define TO_STATUS_PIO_READY_LEVEL_MASK 0x01
#define TO_STATUS_PIO_HIGH_OPENDRAIN_MASK 0x02
#define TO_STATUS_PIO_IDLE_HZ_MASK 0x04

/** @} */

/** @addtogroup certificates
 * @{ */

/*
 * Certificates Format
 */

#define TOCERTF_STANDALONE ((unsigned char)0x00)
#define TOCERTF_SHORT ((unsigned char)0x01)
#define TOCERTF_X509 ((unsigned char)0x02)
#define TOCERTF_SHORT_V2 ((unsigned char)0x03)
#define TOCERTF_NONE ((unsigned char)0xFF)
#define TOCERTF_UNKNOWN ((unsigned char)0xFE)
#define TOCERTF_VALIDITY_DATE_SIZE 7UL
#define TOCERTF_SUBJECT_NAME_SIZE 15UL

/**
 * Certificates formats
 *
 * - TO_CERTIFICATE_X509 is used for Secure Element and remote certificate
 *   verification
 * - TO_CERTIFICATE_STANDALONE is only used for remote certificate
 *   verification
 * - TO_CERTIFICATE_SHORT is only used for Secure Element certificates
 */
typedef enum TO_certificate_format_e {
	TO_CERTIFICATE_STANDALONE = TOCERTF_STANDALONE,
	TO_CERTIFICATE_SHORT = TOCERTF_SHORT,
	TO_CERTIFICATE_X509 = TOCERTF_X509,
	TO_CERTIFICATE_SHORT_V2 = TOCERTF_SHORT_V2,
	TO_CERTIFICATE_NONE = TOCERTF_NONE,
	TO_CERTIFICATE_UNKNOWN = TOCERTF_UNKNOWN
} PACKED TO_certificate_format_t;

/**
 * Standalone certificate structure
 */
struct TO_cert_standalone_s {
	uint8_t ca_id[TO_SN_CA_ID_SIZE]; /**< Certificate Authority ID */
	uint8_t serial_number[TO_SN_NB_SIZE]; /**< SE serial number */
	uint8_t public_key[TO_ECC_PUB_KEYSIZE]; /**< Public key */
	uint8_t signature[TO_SIGNATURE_SIZE]; /**< Certificate signature */
};
typedef struct TO_cert_standalone_s TO_cert_standalone_t;

/**
 * Short certificate structure
 */
struct TO_cert_short_s {
	uint8_t ca_id[TO_SN_CA_ID_SIZE]; /**< Certificate Authority ID */
	uint8_t serial_number[TO_SN_NB_SIZE]; /**< SE serial number */
	uint8_t public_key[TO_ECC_PUB_KEYSIZE]; /**< Public key */
	uint8_t signature[TO_SIGNATURE_SIZE]; /**< Certificate signature */
};
typedef struct TO_cert_short_s TO_cert_short_t;

/**
 * Short v2 certificate structure
 */
struct TO_cert_short_v2_s {
	uint8_t ca_id[TO_SN_CA_ID_SIZE]; /**< Certificate Authority ID */
	uint8_t serial_number[TO_SN_NB_SIZE]; /**< SE serial number */
	uint8_t date[TOCERTF_VALIDITY_DATE_SIZE]; /**< Validity date (not to be used after xxx)
						    (Zulu date (UTC)) */
	uint8_t public_key[TO_ECC_PUB_KEYSIZE]; /**< Public key */
	uint8_t signature[TO_SIGNATURE_SIZE]; /**< Certificate signature */
};
typedef struct TO_cert_short_v2_s TO_cert_short_v2_t;

typedef enum TO_cert_CA_capabilities_e {
	TO_CERT_CA_CAP_EMPTY = 0, /**< No capability */
	TO_CERT_CA_CAP_ADMIN = (1 << 0), /**< Admin capability */
	TO_CERT_CA_CAP_UPDATE_CA = (1 << 1), /**< CA update capability */
} PACKED TO_cert_CA_capabilities_t;

/**
 * Index to enable automatic certificate detection
 */
#define TO_IDX_AUTO 0xFF

/**
 * @deprecated
 *
 * Retro-compatibility
 */
#define TO_CA_IDX_AUTO TO_IDX_AUTO

/** @} */

COMPILE_ASSERT(sizeof(TO_certificate_format_t) == sizeof(uint8_t));
COMPILE_ASSERT(sizeof(TO_cert_CA_capabilities_t) == sizeof(uint8_t));

/** @addtogroup algorithms
 * @{ */

/**
 * Encryption algorithms
 */
typedef enum TO_enc_alg_e {
    TO_ENC_ALG_UNDEFINED = 0, /**< Undefined */
    TO_ENC_ALG_AES128CBC, /**< AES128 CBC */
    TO_ENC_ALG_AES128GCM, /**< AES128 GCM */
    TO_ENC_ALG_ARC4, /**< ARC4 */
    TO_ENC_ALG_AES128CCM, /**< AES128 CCM */
    TO_ENC_ALG_MAX
} PACKED TO_enc_alg_t;

/**
 * MAC algorithms
 */
typedef enum TO_mac_alg_e {
    TO_MAC_ALG_UNDEFINED = 0, /**< @deprecated, use #TO_MAC_ALG_NONE instead */
    TO_MAC_ALG_NONE = 0, /**< no MAC for AEAD cipher suites */
    TO_MAC_ALG_HMAC, /**< HMAC */
    TO_MAC_ALG_CMAC, /**< CMAC */
    TO_MAC_ALG_MAX
} PACKED TO_mac_alg_t;

/** @} */

COMPILE_ASSERT(sizeof(TO_enc_alg_t) == sizeof(uint8_t));
COMPILE_ASSERT(sizeof(TO_mac_alg_t) == sizeof(uint8_t));

/** @addtogroup payloads
 * @{ */

/**
 * Payload MAC size
 */
#define TO_PAYLOAD_MAC_SIZE(enc_alg, mac_alg) ((enc_alg) == TO_ENC_ALG_AES128CCM ? TO_AESCCM_TAG_SIZE : ((enc_alg) == TO_ENC_ALG_AES128GCM ? TO_AESGCM_TAG_SIZE : ((enc_alg) == TO_ENC_ALG_AES128CBC ? ((mac_alg) == TO_MAC_ALG_HMAC ? TO_HMAC_SIZE : ((mac_alg) == TO_MAC_ALG_CMAC ? TO_CMAC_SIZE : 0)) : 0)))

/**
 * Payload padding size
 */
#define TO_PAYLOAD_PADDING_SIZE(enc_alg, data_len) ((enc_alg) == TO_ENC_ALG_AES128CBC ? (((TO_AES_BLOCK_SIZE - (((data_len) + 1) % TO_AES_BLOCK_SIZE)) % TO_AES_BLOCK_SIZE) + 1) : 0)

/**
 * Payload initial vector size
 */
#define TO_PAYLOAD_IV_SIZE(enc_alg) ((enc_alg) == TO_ENC_ALG_AES128CBC ? TO_INITIALVECTOR_SIZE : 0)

/**
 * Secured payload size from clear data size
 */
#define TO_PAYLOAD_SECURED_PAYLOAD_SIZE(enc_alg, mac_alg, data_len) (TO_SEQUENCE_SIZE + TO_PAYLOAD_IV_SIZE(enc_alg) + data_len + TO_PAYLOAD_MAC_SIZE(enc_alg, mac_alg) + TO_PAYLOAD_PADDING_SIZE(enc_alg, data_len))

/**
 * Clear data max size from secured payload size
 */
#define TO_PAYLOAD_CLEAR_DATA_SIZE(enc_alg, mac_alg, payload_len) ((payload_len) - TO_SEQUENCE_SIZE - TO_PAYLOAD_IV_SIZE(enc_alg) - TO_PAYLOAD_MAC_SIZE(enc_alg, mac_alg))

/** @} */

/** @addtogroup loader_constants
 * Hardware Secure Element secure bootloader constants
 * @{ */

#define TO_LD_BCAST_ID 0x01
#define TO_LD_BCAST_INFO_SIZE_SHORT 7u /* Until loader broadcast 3.17.0 */
#define TO_LD_BCAST_INFO_SIZE 10u
#define TO_LD_BCAST_NONCE_SIZE 12u
#define TO_LD_BCAST_INIT_DATA_SIZE \
	TO_SW_VERSION_SIZE + TO_LD_BCAST_NONCE_SIZE
#define TO_LD_BCAST_WRITE_BLOCK_SIZE 512
#define TO_LD_BCAST_SEGMENT_SIZE \
	4 + TO_LD_BCAST_WRITE_BLOCK_SIZE + TO_CMAC_SIZE
#define TO_LD_BCAST_RESTORE_PASSWORD_SIZE 16
#define TO_LD_BCAST_TUP_ID 0x00
#define TO_LD_BCAST_TUP_FMT_00 0x00
#define TO_LD_BCAST_TUP_FMT_01 0x01

/** @} */

/** @addtogroup measured_boot
 * Measured boot constants and types
 * @{ */

#define TO_MEASURED_BOOT_PASSWORD_SIZE 16u

/*
 * Enum constants used to signal if measured boot value:
 * - Doesn't matches "Trusted boot hash" value and "Trusted new MCU hash" is empty -> FAILURE_NO_NEW
 * - Matches neither new "Trusted boot MCU hash" value nor "Trusted new MCU hash"  -> FAILURE
 * - Matches "Trusted boot MCU hash", "old" FW still running                       -> CURRENT
 * - Matches "Trusted new MCU hash", "new" upgraded FW is now running              -> NEW
 */
typedef enum {
	FAILURE_NO_NEW,
	FAILURE,
	CURRENT,
	NEW
} measure_outcome_t;

/** @} */

/** @addtogroup tose_defs
 * @{ */

/* Forward declaration to avoid circular dependancy issue */
struct TODRV_api_s;

/**
 * @brief Context structure for Secure Elements (Hardware / Software / other)
 */
typedef struct TOSE_drv_ctx_s {
	const struct TODRV_api_s *api; /**< Driver API */
	uint32_t func_offset; /**< Offset to add to driver API functions */
	TO_log_ctx_t *log_ctx; /**< Running-platform specific log function */
	void *priv_ctx; /**< Driver private context */
} TOSE_drv_ctx_t;

/**
 * @brief Context structure for Secure Elements (Hardware / Software / other)
 */
typedef struct TOSE_ctx_s {
	TOSE_drv_ctx_t *drv; /**< Driver context */
	uint8_t initialized; /**< Context initialization state */
} TOSE_ctx_t;

/** @} */

#endif

