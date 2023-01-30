/*
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (C) 2016-2021 Trusted Objects. All rights reserved.
 *
 * Secure Element helpers, based on Secure Element APIs to simplify complex processes.
 */

#include <string.h>
#include "TO.h"
#include "TO_helper.h"

#ifndef TO_DISABLE_TLS_HELPER

#if defined(TOSE_DRIVER_HSE) && !defined(TODRV_HSE_DRIVER_DISABLE)
#include "TODRV_HSE_cfg.h"
#include "TODRV_HSE_defs.h"
#include "TODRV_HSE_cmd.h"
#endif

#ifdef TO_ENABLE_DTLS
#define _TLS_HEADER_SIZE TO_DTLS_HEADER_SIZE
#define _TLS_HANDSHAKE_HEADER_SIZE TO_DTLS_HANDSHAKE_HEADER_SIZE
#define _TLS_MAJOR TO_DTLS_MAJOR
#define _TLS_MINOR TO_DTLS_MINOR
#else
#define _TLS_HEADER_SIZE TO_TLS_HEADER_SIZE
#define _TLS_HANDSHAKE_HEADER_SIZE TO_TLS_HANDSHAKE_HEADER_SIZE
#define _TLS_MAJOR TO_TLS_MAJOR
#define _TLS_MINOR TO_TLS_MINOR
#endif

#if defined(TOSE_DRIVER_HSE) && !defined(TODRV_HSE_DRIVER_DISABLE)
#define TLS_CAPI_MAX_UPDATE_SIZE (MIN(TODRV_HSE_MAXSIZE, TODRV_HSE_LIB_INTERNAL_IO_BUFFER_SIZE) - TODRV_HSE_CMDHEAD_SIZE)
#define TLS_HANDLE_SERVER_HELLO_UPDATE_SIZE TODRV_HSE_get_msg_data_size_max(MSG_TYPE_RESPONSE)

#else // TOSE_DRIVER_HSE && !defined(TODRV_HSE_DRIVER_DISABLE)
#define TLS_CAPI_MAX_UPDATE_SIZE UINT16_MAX
#define TLS_HANDLE_SERVER_HELLO_UPDATE_SIZE UINT16_MAX
#endif

#ifndef TO_DISABLE_API_HELPER_TLS_SECURE_PAYLOAD_CBC
TO_lib_ret_t TOSE_helper_tls_secure_payload_cbc(TOSE_ctx_t *ctx,
		const uint8_t header[], const uint16_t header_len,
		const uint8_t* data, const uint16_t data_len,
		uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		uint8_t *cryptogram, uint16_t *cryptogram_len)
{
	uint32_t offset = 0;
	uint16_t len;
	TO_ret_t ret;

	*cryptogram_len = 0;

	ret = TOSE_tls_secure_payload_init_cbc(ctx, header, header_len, initial_vector);
	if (ret != TORSP_SUCCESS) {
		return TO_ERROR | ret;
	}

	while (data_len - offset >= TO_AES_BLOCK_SIZE) {
		len = MIN(TLS_CAPI_MAX_UPDATE_SIZE, data_len - offset);
		len -= len % TO_AES_BLOCK_SIZE;
		ret = TOSE_tls_secure_payload_update(ctx, data + offset, len, cryptogram + offset);
		if (ret != TORSP_SUCCESS) {
			return TO_ERROR | ret;
		}
		offset += len;
		*cryptogram_len += len;
	}

	ret = TOSE_tls_secure_payload_final(ctx, data + offset, data_len - offset, cryptogram + offset, &len);
	if (ret != TORSP_SUCCESS) {
		return TO_ERROR | ret;
	}

	*cryptogram_len += len;

	return TO_OK;
}
#endif

#ifndef TO_DISABLE_API_HELPER_TLS_SECURE_PAYLOAD_AEAD
TO_lib_ret_t TOSE_helper_tls_secure_payload_aead(TOSE_ctx_t *ctx,
		const uint8_t header[], const uint16_t header_len,
		const uint8_t* data, const uint16_t data_len,
		uint8_t initial_vector[TO_TLS_AEAD_EXPLICIT_NONCE_SIZE],
		uint8_t *cryptogram, uint16_t *cryptogram_len)
{
	uint32_t offset = 0;
	uint16_t len;
	TO_ret_t ret;

	*cryptogram_len = 0;

	ret = TOSE_tls_secure_payload_init_aead(ctx, header, header_len, initial_vector);
	if (ret != TORSP_SUCCESS) {
		return TO_ERROR | ret;
	}

	while (data_len - offset >= TO_AES_BLOCK_SIZE) {
		len = MIN(TLS_CAPI_MAX_UPDATE_SIZE, data_len - offset);
		len -= len % TO_AES_BLOCK_SIZE;
		ret = TOSE_tls_secure_payload_update(ctx, data + offset, len, cryptogram + offset);
		if (ret != TORSP_SUCCESS) {
			return TO_ERROR | ret;
		}
		offset += len;
		*cryptogram_len += len;
	}

	ret = TOSE_tls_secure_payload_final(ctx, data + offset, data_len - offset, cryptogram + offset, &len);
	if (ret != TORSP_SUCCESS) {
		return TO_ERROR | ret;
	}

	*cryptogram_len += len;

	return TO_OK;
}
#endif


#ifndef TO_DISABLE_API_HELPER_TLS_UNSECURE_PAYLOAD_CBC
TO_lib_ret_t TOSE_helper_tls_unsecure_payload_cbc(TOSE_ctx_t *ctx,
		const uint8_t *header, const uint16_t header_len,
		const uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		const uint8_t* cryptogram, const uint16_t cryptogram_len,
		uint8_t *data, uint16_t *data_len)
{
	uint32_t offset = 0;
	TO_ret_t ret;

	*data_len = 0;

	ret = TOSE_tls_unsecure_payload_init_cbc(ctx,
			cryptogram_len, header, header_len, initial_vector,
			cryptogram + cryptogram_len - 2 * TO_AES_BLOCK_SIZE,
			cryptogram + cryptogram_len - TO_AES_BLOCK_SIZE);
	if (ret != TORSP_SUCCESS) {
		return TO_ERROR | ret;
	}

	while (offset < cryptogram_len) {
		uint16_t olen;
		uint16_t len = MIN(TLS_CAPI_MAX_UPDATE_SIZE, cryptogram_len - offset);
		len -= len % TO_AES_BLOCK_SIZE;
		ret = TOSE_tls_unsecure_payload_update(ctx, cryptogram + offset, len, data + *data_len, &olen);
		if (ret != TORSP_SUCCESS) {
			TO_secure_memset(data, 0, *data_len);
			*data_len = 0;
			return TO_ERROR | ret;
		}
		offset += len;
		*data_len += olen;
	}

	ret = TOSE_tls_unsecure_payload_final(ctx);
	if (ret != TORSP_SUCCESS) {
		TO_secure_memset(data, 0, *data_len);
		*data_len = 0;
		return TO_ERROR | ret;
	}

	return TO_OK;
}
#endif

#ifndef TO_DISABLE_API_HELPER_TLS_UNSECURE_PAYLOAD_AEAD
TO_lib_ret_t TOSE_helper_tls_unsecure_payload_aead(TOSE_ctx_t *ctx,
		const uint8_t *header, const uint16_t header_len,
		const uint8_t initial_vector[TO_TLS_AEAD_EXPLICIT_NONCE_SIZE],
		const uint8_t* cryptogram, const uint16_t cryptogram_len,
		uint8_t *data, uint16_t *data_len)
{
	uint32_t offset = 0;
	TO_ret_t ret;

	*data_len = 0;

	ret = TOSE_tls_unsecure_payload_init_aead(ctx,
			cryptogram_len, header, header_len, initial_vector);
	if (ret != TORSP_SUCCESS) {
		return TO_ERROR | ret;
	}

	while (offset < cryptogram_len) {
		uint16_t olen;
		uint16_t len = MIN(TLS_CAPI_MAX_UPDATE_SIZE, cryptogram_len - offset);
		if (len > TO_AES_BLOCK_SIZE) {
			len -= len % TO_AES_BLOCK_SIZE;
		}
		ret = TOSE_tls_unsecure_payload_update(ctx, cryptogram + offset, len, data + offset, &olen);
		if (ret != TORSP_SUCCESS) {
			return TO_ERROR | ret;
		}
		offset += len;
		*data_len += olen;
	}

	ret = TOSE_tls_unsecure_payload_final(ctx);
	if (ret != TORSP_SUCCESS) {
		return TO_ERROR | ret;
	}

	return TO_OK;
}
#endif

#ifndef TO_DISABLE_TLS_STACK

TO_lib_ret_t TOSE_helper_tls_get_client_hello_ext(TOSE_ctx_t *ctx,
		const uint8_t timestamp[TO_TIMESTAMP_SIZE],
		const uint8_t *ext_data, uint16_t ext_length,
		uint8_t *client_hello, uint16_t *client_hello_len)
{
	TO_ret_t ret;
	uint16_t offset = 0;
	uint8_t final_flag;
	uint16_t chunk_size;
	uint16_t buffer_len = *client_hello_len;

	ret = TOSE_tls_get_client_hello_init(ctx, timestamp,
			ext_data, ext_length, client_hello_len, &final_flag);
	if ((ret != TORSP_SUCCESS) || (buffer_len < *client_hello_len)){
		return TO_ERROR | ret;
	}

	while(!final_flag) {
		ret = TOSE_tls_get_client_hello_update(ctx,
				client_hello + offset, &chunk_size, &final_flag);
		if (ret != TORSP_SUCCESS) {
			return TO_ERROR | ret;
		}
		offset += chunk_size;
	}

	ret = TOSE_tls_get_client_hello_final(ctx, client_hello + offset);
	if (ret != TORSP_SUCCESS) {
		return TO_ERROR | ret;
	}
	return TO_OK;
}

TO_lib_ret_t TOSE_helper_tls_handle_server_hello(TOSE_ctx_t *ctx,
		const uint8_t *server_hello,
		const uint16_t server_hello_len)
{
	TO_ret_t ret;
	uint16_t offset;
	uint16_t chunk_size = TLS_HANDLE_SERVER_HELLO_UPDATE_SIZE;

	ret = TOSE_tls_handle_server_hello_init(ctx, server_hello_len);
	if (ret != TORSP_SUCCESS) {
		return TO_ERROR | ret;
	}
	for(offset = 0; offset + chunk_size < server_hello_len; offset += chunk_size) {
		ret = TOSE_tls_handle_server_hello_update(ctx,
				server_hello + offset, chunk_size);
		if (ret != TORSP_SUCCESS) {
			return TO_ERROR | ret;
		}
	}
	ret = TOSE_tls_handle_server_hello_final(ctx,
			server_hello + offset, server_hello_len - offset);
	if (ret != TORSP_SUCCESS) {
		return TO_ERROR | ret;
	}
	return TO_OK;
}

#ifndef TO_DISABLE_API_HELPER_TLS_HANDLE_SERVER_CERTIFICATE
TO_lib_ret_t TOSE_helper_tls_handle_server_certificate(TOSE_ctx_t *ctx, const uint8_t *server_certificate,
		const uint32_t server_certificate_len)
{
	uint32_t offset = 0;
	TO_ret_t ret;
	const uint16_t server_certificate_hdr_len = _TLS_HANDSHAKE_HEADER_SIZE + 3;

	ret = TOSE_tls_handle_server_certificate_init(ctx, server_certificate + offset, server_certificate_hdr_len);
	if (ret != TORSP_SUCCESS) {
		return TO_ERROR | ret;
	}
	offset += server_certificate_hdr_len;

	while (offset < server_certificate_len) {
		uint32_t len = MIN(TLS_CAPI_MAX_UPDATE_SIZE, server_certificate_len - offset);
		ret = TOSE_tls_handle_server_certificate_update(ctx, server_certificate + offset, len);
		if (ret != TORSP_SUCCESS) {
			return TO_ERROR | ret;
		}
		offset += len;
	}

	ret = TOSE_tls_handle_server_certificate_final(ctx);
	if (ret != TORSP_SUCCESS) {
		return TO_ERROR | ret;
	}

	return TO_OK;
}
#endif


#ifndef TO_DISABLE_API_HELPER_TLS_HANDLE_SERVER_KEY_EXCHANGE
TO_lib_ret_t TOSE_helper_tls_handle_server_key_exchange(TOSE_ctx_t *ctx, const uint8_t *server_key_exchange,
		const uint32_t server_key_exchange_len)
{
	uint32_t offset = 0;
	TO_ret_t ret;
	const uint16_t server_key_exchange_hdr_len = _TLS_HANDSHAKE_HEADER_SIZE + 4 + 1 + TO_ECC_PUB_KEYSIZE + 4;

	ret = TOSE_tls_handle_server_key_exchange_init(ctx, server_key_exchange + offset, server_key_exchange_hdr_len);
	if (ret != TORSP_SUCCESS) {
		return TO_ERROR | ret;
	}
	offset += server_key_exchange_hdr_len;

	while (offset < server_key_exchange_len) {
		uint32_t len = MIN(TLS_CAPI_MAX_UPDATE_SIZE, server_key_exchange_len - offset);
		ret = TOSE_tls_handle_server_key_exchange_update(ctx, server_key_exchange + offset, len);
		if (ret != TORSP_SUCCESS) {
			return TO_ERROR | ret;
		}
		offset += len;
	}

	ret = TOSE_tls_handle_server_key_exchange_final(ctx);
	if (ret != TORSP_SUCCESS) {
		return TO_ERROR | ret;
	}

	return TO_OK;
}
#endif

#ifndef TO_DISABLE_API_HELPER_TLS_GET_CERTIFICATE
TO_lib_ret_t TOSE_helper_tls_get_certificate(TOSE_ctx_t *ctx, uint8_t *certificate,
		uint16_t *certificate_len)
{
	uint16_t offset = 0;
	uint16_t len;
	TO_ret_t ret;

	ret = TOSE_tls_get_certificate_init(ctx, certificate + offset, &len);
	if (ret != TORSP_SUCCESS) {
		return TO_ERROR | ret;
	}
	offset += len;

	do {
		ret = TOSE_tls_get_certificate_update(ctx, certificate + offset, &len);
		if (ret != TORSP_SUCCESS) {
			return TO_ERROR | ret;
		}
		offset += len;
	} while (len > 0);

	ret = TOSE_tls_get_certificate_final(ctx);
	if (ret != TORSP_SUCCESS) {
		return TO_ERROR | ret;
	}

	*certificate_len = offset;

	return TO_OK;
}
#endif

#ifdef TO_ENABLE_DTLS
#define _TLS_EPOCH_MAX 1
#define _TLS_TIMEOUT_MIN 1000
#define _TLS_TIMEOUT_MAX 60000
#define _TLS_RETRANSMISSIONS_MAX UINT32_MAX
/* Fragment maximal size in bytes (not including headers) */
#define _TLS_FRAGMENT_MAXSIZE 256
#endif

#if !defined(TO_ENABLE_DTLS) || defined(TO_DISABLE_DTLS_RETRANSMISSION)
#undef TOSE_HELPER_TLS_FLIGHT_BUFFER_SIZE
#define TOSE_HELPER_TLS_FLIGHT_BUFFER_SIZE TOSE_HELPER_TLS_IO_BUFFER_SIZE
#endif

#ifndef TO_DISABLE_TLS_FULL_DUPLEX
/* the I/O buffer is split in 2, the first part reserved for RX, the second for TX */
#define TOSE_HELPER_TLS_TX_BUFFER_SIZE (TOSE_HELPER_TLS_IO_BUFFER_SIZE - TOSE_HELPER_TLS_RX_BUFFER_SIZE)
#define TOSE_HELPER_TLS_TX_BUFFER_OFFSET TOSE_HELPER_TLS_RX_BUFFER_SIZE
#else /* half duplex */
/* the whole I/O buffer is shared for RX and TX */
#undef TOSE_HELPER_TLS_RX_BUFFER_SIZE
#define TOSE_HELPER_TLS_RX_BUFFER_SIZE TOSE_HELPER_TLS_IO_BUFFER_SIZE
#define TOSE_HELPER_TLS_TX_BUFFER_SIZE TOSE_HELPER_TLS_IO_BUFFER_SIZE
#define TOSE_HELPER_TLS_TX_BUFFER_OFFSET 0
#endif

#define _TLS_SESSION_ID_MAXSIZE 32

#ifndef TO_TLS_SESSIONS_NB
#define TO_TLS_SESSIONS_NB 2
#endif

#if defined(TO_ENABLE_DTLS) && !defined(TO_DISABLE_DTLS_RETRANSMISSION)
typedef struct {
	uint8_t encryption;
	uint8_t type;
	uint16_t epoch;
} _tls_flight_header_t;
#define TLS_FLIGHT_HEADER_SIZE sizeof(_tls_flight_header_t)
#else
#define TLS_FLIGHT_HEADER_SIZE 0
#endif

typedef enum tls_alert_level_e {
	ALERT_LEVEL_WARNING = 0x01,
	ALERT_LEVEL_FATAL = 0x02,
} tls_alert_level_t;

typedef enum _tls_alert_desc_e {
	ALERT_DESC_CLOSE_NOTIFY = 0,
	ALERT_DESC_UNEXPECTED_MESSAGE = 10,
	ALERT_DESC_BAD_RECORD_MAC = 20,
	ALERT_DESC_DECRYPTION_FAILED_RESERVED = 21,
	ALERT_DESC_RECORD_OVERFLOW = 22,
	ALERT_DESC_DECOMPRESSION_FAILURE = 30,
	ALERT_DESC_HANDSHAKE_FAILURE = 40,
	ALERT_DESC_NO_CERTIFICATE_RESERVED = 41,
	ALERT_DESC_BAD_CERTIFICATE = 42,
	ALERT_DESC_UNSUPPORTED_CERTIFICATE = 43,
	ALERT_DESC_CERTIFICATE_REVOKED = 44,
	ALERT_DESC_CERTIFICATE_EXPIRED = 45,
	ALERT_DESC_CERTIFICATE_UNKNOWN = 46,
	ALERT_DESC_ILLEGAL_PARAMETER = 47,
	ALERT_DESC_UNKNOWN_CA = 48,
	ALERT_DESC_ACCESS_DENIED = 49,
	ALERT_DESC_DECODE_ERROR = 50,
	ALERT_DESC_DECRYPT_ERROR = 51,
	ALERT_DESC_EXPORT_RESTRICTION_RESERVED = 60,
	ALERT_DESC_PROTOCOL_VERSION = 70,
	ALERT_DESC_INSUFFICIENT_SECURITY = 71,
	ALERT_DESC_INTERNAL_ERROR = 80,
	ALERT_DESC_USER_CANCELED = 90,
	ALERT_DESC_NO_RENEGOTIATION = 100,
	ALERT_DESC_UNSUPPORTED_EXTENSION = 110,
} tls_alert_desc_t;

/**
 * @brief describes a TLS record
 *
 * This structure keeps the information needed to receive a record from the
 * lower layer and to transmit it to the upper layer.
 */
struct record {
	uint16_t header_length; /**<header length */
	uint16_t length; /**< content length,
				0 if the header is not entirerely received */
	uint16_t offset; /**< content offset of data consumed by the upper layer */
	uint8_t type; /**< type of record (Application, Handshake, Alert, CipherSpecChange, etc.) */
	uint8_t *fragment; /**< content data,
				NULL if the record is not entirely received */
};

/**
 * @brief TLS session context
 **/
struct TOSE_helper_tls_ctx_s {
	uint8_t index;
	uint8_t in_use;
	uint8_t *pbuf;
	uint8_t rx;
	uint32_t flight_offset;
#if defined(TO_ENABLE_DTLS) && !defined(TO_DISABLE_DTLS_RETRANSMISSION)
	uint8_t flight_buf[TOSE_HELPER_TLS_FLIGHT_BUFFER_SIZE];
#else
	uint8_t *flight_buf;
#endif
	uint8_t buf[TOSE_HELPER_TLS_IO_BUFFER_SIZE];
	uint8_t *rxbuf;
	uint32_t rxbuf_len;
	uint8_t *txbuf;
	uint32_t txbuf_len;
	uint32_t cache_offs;
	uint32_t cache_len;
	TO_tls_record_type_t cache_type;
	uint8_t encryption;
	uint8_t decryption;
	uint8_t auth_client;
	uint8_t abbreviated_handshake;
	uint8_t client_session_id_len;
	uint8_t client_session_id[_TLS_SESSION_ID_MAXSIZE];
	uint8_t iv_len;
	uint8_t is_rsa;
	TO_tls_cipher_suite_t cipher_suite;
	TO_tls_cipher_suite_type_t cipher_suite_type;
	TO_tls_encryption_type_t encryption_type;
	TO_tls_state_t state;
#ifdef TO_ENABLE_DTLS
	uint16_t epoch;
	uint64_t sequence_number_up[_TLS_EPOCH_MAX + 1];
	uint64_t sequence_number_down[_TLS_EPOCH_MAX + 1];
#ifndef TO_DISABLE_DTLS_RETRANSMISSION
	uint32_t timeout;
	uint32_t min_timeout;
	uint32_t max_timeout;
	uint32_t retransmissions;
	uint32_t max_retransmissions;
#endif
	uint16_t fragment_max_size;
	uint32_t record_cache_offs;
	uint32_t record_cache_len;
	uint8_t connection_id_len;
	uint8_t connection_id[TO_DTLS_CONNECTION_ID_MAXSIZE];
#endif
	struct record rx_rec; /**< reception record state */
	uint8_t *rx_next_data; /**< reception pointer (shall be inside rxbuf) */
	uint16_t rx_next_length; /**< length of received data that hasn't been consumed */
	uint16_t tx_ptrec_len_max; /**< max plain text length acceptable in
					 a record to be sent */
	TOSE_ctx_t *ctx; /**< libTO context */
	void *priv_ctx; /**< context to pass to user's callback send_func and receive_func */
	TOSE_helper_tls_send_func send_func; /**< user's callback to send data to the network */
	TOSE_helper_tls_receive_func receive_func; /**< user's callback to receive data from the network */
	void *cipher_ctx; /**< context to pass to the callback unsecure_record and secure_record */
	TOSE_helper_tls_setup_cipher_ctx setup_cipher_ctx; /**< callback to setup the cipher context */
	TOSE_helper_tls_unsecure_record unsecure_record; /**< callback to decrypt and authenticate
								receive record */
	TOSE_helper_tls_secure_record secure_record; /**< callback to encrypt record to send */
	uint8_t sni[TO_TLS_SNI_LENGTH_MAX]; /**< server name for Server Name Indication extension */
	uint8_t sni_length; /**< length of the server's name inside ::sni above */
};

static TOSE_helper_tls_ctx_t _tls_ctx[TO_TLS_SESSIONS_NB] = { 0 };

/**
 * @brief handle alert received from the peer
 *
 * @param[in,out] tls_ctx TLS context
 * @param[in] level level of the alert (warning or fatal)
 * @param[in] desc description of alert
 **/
static void tls_handle_alert(
		TOSE_helper_tls_ctx_t *tls_ctx,
		tls_alert_level_t level,
		tls_alert_desc_t desc
)
{

#if TO_LOG_LEVEL_MAX >= LOG_LEVEL_INF
	const char *level_str;
	const char *desc_str;

	switch (level) {
		case ALERT_LEVEL_WARNING:
			level_str = "Warning";
			break;
		case ALERT_LEVEL_FATAL:
			level_str = "Fatal";
			break;
		default:
			level_str = "Unknown alert level";
			break;
	}

	switch (desc) {
		case ALERT_DESC_CLOSE_NOTIFY:
			desc_str = "close notify";
			break;
		case ALERT_DESC_UNEXPECTED_MESSAGE:
			desc_str = "unexpected message";
			break;
		case ALERT_DESC_BAD_RECORD_MAC:
			desc_str = "bad record mac";
			break;
		case ALERT_DESC_DECRYPTION_FAILED_RESERVED:
			desc_str = "decryption failed reserved";
			break;
		case ALERT_DESC_RECORD_OVERFLOW:
			desc_str = "record overflow";
			break;
		case ALERT_DESC_DECOMPRESSION_FAILURE:
			desc_str = "decompression failure";
			break;
		case ALERT_DESC_HANDSHAKE_FAILURE:
			desc_str = "handshake failure";
			break;
		case ALERT_DESC_NO_CERTIFICATE_RESERVED:
			desc_str = "no certificate reserved";
			break;
		case ALERT_DESC_BAD_CERTIFICATE:
			desc_str = "bad certificate";
			break;
		case ALERT_DESC_UNSUPPORTED_CERTIFICATE:
			desc_str = "unsupported certificate";
			break;
		case ALERT_DESC_CERTIFICATE_REVOKED:
			desc_str = "certificate revoked";
			break;
		case ALERT_DESC_CERTIFICATE_EXPIRED:
			desc_str = "certificate expired";
			break;
		case ALERT_DESC_CERTIFICATE_UNKNOWN:
			desc_str = "certificate unknown";
			break;
		case ALERT_DESC_ILLEGAL_PARAMETER:
			desc_str = "illegal parameter";
			break;
		case ALERT_DESC_UNKNOWN_CA:
			desc_str = "unknown ca";
			break;
		case ALERT_DESC_ACCESS_DENIED:
			desc_str = "access denied";
			break;
		case ALERT_DESC_DECODE_ERROR:
			desc_str = "decode error";
			break;
		case ALERT_DESC_DECRYPT_ERROR:
			desc_str = "decrypt error";
			break;
		case ALERT_DESC_EXPORT_RESTRICTION_RESERVED:
			desc_str = "export restriction reserved";
			break;
		case ALERT_DESC_PROTOCOL_VERSION:
			desc_str = "protocol version";
			break;
		case ALERT_DESC_INSUFFICIENT_SECURITY:
			desc_str = "insufficient security";
			break;
		case ALERT_DESC_INTERNAL_ERROR:
			desc_str = "internal error";
			break;
		case ALERT_DESC_USER_CANCELED:
			desc_str = "user canceled";
			break;
		case ALERT_DESC_NO_RENEGOTIATION:
			desc_str = "no renegotiation";
			break;
		case ALERT_DESC_UNSUPPORTED_EXTENSION:
			desc_str = "unsupported extension";
			break;
		default:
			desc_str = "unknown description";
			break;
	}

	TO_LOG_WRN("TLS alert:\n%s: %s\n", level_str, desc_str);
#endif

	switch (desc) {
	case ALERT_DESC_CLOSE_NOTIFY:
		tls_ctx->state |= TO_TLS_STATE_CLOSE_RECEIVED;
		break;
	default:
		break;
	}
	if (level == ALERT_LEVEL_FATAL) {
		tls_ctx->state |= TO_TLS_STATE_FATAL_RECEIVED;
	}
}

#ifdef TO_ENABLE_DTLS
static TO_lib_ret_t _tls_send(
		TOSE_helper_tls_ctx_t *tls_ctx,
		TO_tls_record_type_t _type,
		uint8_t *_data,
		uint32_t _len,
		uint16_t epoch,
		uint8_t encryption
)
{
	uint8_t _offset = 0;
	uint16_t hdr_len;
	int32_t _ret;
	TO_ret_t ret2;
#if !defined(TO_DISABLE_DTLS_RETRANSMISSION)
	_tls_flight_header_t *_flight_hdr = (_tls_flight_header_t*)_data;
#endif
	uint32_t to_send_len;
	uint32_t frag_offset = 0;

	if (_type == TO_TLS_RECORD_TYPE_HANDSHAKE) {
		to_send_len = _len - _TLS_HANDSHAKE_HEADER_SIZE;
	} else
	{
		to_send_len = _len;
	}

#if !defined(TO_DISABLE_DTLS_RETRANSMISSION)
	/* Save record parameters in source buffer */
	_flight_hdr->encryption = encryption;
	_flight_hdr->type = _type;
	_flight_hdr->epoch = epoch;
#endif

	/* TLS header */
	if (_type != TO_TLS_RECORD_TYPE_CHANGE_CIPHER_SPEC && encryption && tls_ctx->connection_id_len > 0) {
		tls_ctx->txbuf[_offset++] = TO_TLS_RECORD_TYPE_TLS_12_CID;
	} else
	{
		tls_ctx->txbuf[_offset++] = _type;
	}
	tls_ctx->txbuf[_offset++] = _TLS_MAJOR;
	tls_ctx->txbuf[_offset++] = _TLS_MINOR;
	SET_BE16(epoch, tls_ctx->txbuf, _offset);
	/* Skip sequence */
	_offset += 6;
	if (_type != TO_TLS_RECORD_TYPE_CHANGE_CIPHER_SPEC && encryption && tls_ctx->connection_id_len > 0) {
		TO_secure_memcpy(tls_ctx->txbuf + _offset, tls_ctx->connection_id, tls_ctx->connection_id_len);
		_offset += tls_ctx->connection_id_len;
		/* Handle real record type */
		++_len;
	}
	SET_BE16(_len, tls_ctx->txbuf, _offset);
	hdr_len = _offset;

	do {
		uint32_t frag_len;
		uint32_t len;
		uint16_t __offset = _offset;

		__offset -= 6 + sizeof(uint16_t);
		if (_type != TO_TLS_RECORD_TYPE_CHANGE_CIPHER_SPEC && encryption) {
			__offset -= tls_ctx->connection_id_len;
		}
		if (_type == TO_TLS_RECORD_TYPE_HANDSHAKE) {
			frag_len = MIN(tls_ctx->fragment_max_size, to_send_len);
			len = frag_len + _TLS_HANDSHAKE_HEADER_SIZE;
		} else
		{
			frag_len = to_send_len;
			len = frag_len;
		}

		/* Protect buffer overflow */
		if (_offset + len > tls_ctx->txbuf_len) {
			TO_LOG_ERR("TX buffer too small, %lu bytes needed",
					(unsigned long int)(_offset + len));
			return TO_ERROR;
		}

		/* Write TLS header */
		SET_BE48(tls_ctx->sequence_number_up[epoch], tls_ctx->txbuf, __offset);
		++tls_ctx->sequence_number_up[epoch];
		if (_type != TO_TLS_RECORD_TYPE_CHANGE_CIPHER_SPEC && encryption && tls_ctx->connection_id_len > 0) {
			__offset += tls_ctx->connection_id_len;
			len++;
		}
		SET_BE16(len, tls_ctx->txbuf, __offset);

		if (_type == TO_TLS_RECORD_TYPE_HANDSHAKE) {
			uint32_t tmp32 = 0;

			if (frag_offset == 0) {
				/* Copy TLS handshake header */
#ifndef TO_DISABLE_DTLS_RETRANSMISSION
				TO_secure_memcpy
#else
				TO_secure_memmove
#endif
				(tls_ctx->txbuf + _offset, _data + TLS_FLIGHT_HEADER_SIZE, _TLS_HANDSHAKE_HEADER_SIZE);
			}

			/* Rewrite TLS handshake header */
			tmp32 = htobe32(frag_offset);
			TO_secure_memcpy(tls_ctx->txbuf + _offset + _TLS_HANDSHAKE_HEADER_SIZE - 3 * 2, ((uint8_t*)&tmp32) + 1, 3);
			tmp32 = htobe32(frag_len);
			TO_secure_memcpy(tls_ctx->txbuf + _offset + _TLS_HANDSHAKE_HEADER_SIZE - 3, ((uint8_t*)&tmp32) + 1, 3);

			/* Copy data */
#ifndef TO_DISABLE_DTLS_RETRANSMISSION
			TO_secure_memcpy
#else
			TO_secure_memmove
#endif
					(tls_ctx->txbuf + _offset + _TLS_HANDSHAKE_HEADER_SIZE,
					_data + TLS_FLIGHT_HEADER_SIZE + _TLS_HANDSHAKE_HEADER_SIZE + frag_offset,
					frag_len);
		} else
		{
			/* Copy data */
			TO_secure_memmove(tls_ctx->txbuf + _offset, _data + TLS_FLIGHT_HEADER_SIZE, len);
		}

		TO_LOG_DBG("Send buffer:",0);
		TO_LOG_DBG_BUF(tls_ctx->ctx->drv->log_ctx,tls_ctx->txbuf, _offset + len);

		if (encryption
		 && _type != TO_TLS_RECORD_TYPE_CHANGE_CIPHER_SPEC) {
			uint16_t tmp_len;
			/* Move data to allow using same buffer as source and destination */
			TO_secure_memmove(tls_ctx->txbuf + hdr_len + TO_AES_BLOCK_SIZE, tls_ctx->txbuf + hdr_len, len);
			TO_lib_ret_t ret = TO_ERROR;
			if (_type != TO_TLS_RECORD_TYPE_CHANGE_CIPHER_SPEC && tls_ctx->connection_id_len > 0) {
				/* Add real record type */
				*(tls_ctx->txbuf + hdr_len + TO_AES_BLOCK_SIZE + len - 1) = _type;
			}

			if ((ret2 = TOSE_tls_set_session(tls_ctx->ctx, tls_ctx->index)) != TORSP_SUCCESS) {
				if (tls_ctx->index == 0) {
					TO_LOG_WRN("Failed to set TLS session, trying to continue as it is first session",0);
				} else {
					TO_LOG_ERR("Failed to set TLS session",0);
					return TO_ERROR | ret2;
				}
			}

			if (_type == TO_TLS_RECORD_TYPE_APPLICATION_DATA) {
				switch (tls_ctx->encryption_type) {
					case TO_TLS_ENCRYPTION_AES_CBC:
#if !defined(TO_DISABLE_API_HELPER_TLS_SECURE_PAYLOAD_CBC)
						ret = TOSE_helper_tls_secure_payload_cbc(tls_ctx->ctx, tls_ctx->txbuf, hdr_len,
						                                       tls_ctx->txbuf + hdr_len + TO_AES_BLOCK_SIZE, len,
						                                       tls_ctx->txbuf + hdr_len,
						                                       tls_ctx->txbuf + hdr_len + tls_ctx->iv_len,
						                                       &tmp_len);
#else
						ret = TO_ERROR | TORSP_UNKNOWN_CMD;
#endif
						break;
					case TO_TLS_ENCRYPTION_AES_CCM:
					case TO_TLS_ENCRYPTION_AES_CCM_8:
					case TO_TLS_ENCRYPTION_AES_GCM:
#if !defined(TO_DISABLE_API_HELPER_TLS_SECURE_PAYLOAD_AEAD)
						ret = TOSE_helper_tls_secure_payload_aead(tls_ctx->ctx, tls_ctx->txbuf, hdr_len,
						                                        tls_ctx->txbuf + hdr_len + TO_AES_BLOCK_SIZE, len,
						                                        tls_ctx->txbuf + hdr_len,
						                                        tls_ctx->txbuf + hdr_len + tls_ctx->iv_len,
						                                        &tmp_len);
#else
						ret = TO_ERROR | TORSP_UNKNOWN_CMD;
#endif
						break;
					default:
						TO_LOG_ERR("Unsupported encryption type %u", tls_ctx->encryption_type);
						return TO_ERROR;
				}

				if (ret != TO_OK && TO_SE_ERRCODE(ret) != TORSP_UNKNOWN_CMD) {
					TO_LOG_ERR("Failed to secure message",0);
					return ret;
				}
			}
			if (ret != TO_OK) {
				/* Use old method for non-applicative messages and fallback */
				ret2 = TOSE_tls_secure_payload(tls_ctx->ctx, tls_ctx->txbuf, hdr_len,
				                            tls_ctx->txbuf + TO_AES_BLOCK_SIZE + hdr_len, len,
				                            tls_ctx->txbuf + hdr_len,
				                            &tmp_len);
				if (ret2 != TORSP_SUCCESS) {
					TO_LOG_ERR("Failed to secure message",0);
					return TO_ERROR | ret2;
				}

				len = tmp_len;
			} else {
				len = tls_ctx->iv_len + tmp_len;
			}
			/* Rewrite header */
			SET_BE16_NOINC(len, tls_ctx->txbuf, _offset - sizeof(uint16_t));

			TO_LOG_DBG("Encrypted buffer:",0);
			TO_LOG_DBG_BUF(tls_ctx->ctx->drv->log_ctx,tls_ctx->txbuf, hdr_len + len);
		}

		/* Send to network */
		_ret = tls_ctx->send_func(tls_ctx->priv_ctx, tls_ctx->txbuf, _offset + len);
		if (_ret != TO_OK) {
			TO_LOG_ERR("Failed to send %lu bytes",
					(unsigned long int)(_offset + len));
			return _ret;
		}

		frag_offset += frag_len;
		to_send_len -= frag_len;
	} while (to_send_len > 0);

	return TO_OK;
}
#endif

/**
 * @brief generate a protected TLS record and send it
 *
 * @param[in,out] tls_ctx TLS context
 * @param[in] type type of record (Application, Handshake, Alert, CipherSpecChange, etc.)
 * @param[in] data record's plain text content
 * @param[in] len record's plain text content length
 *
 * @retval TO_OK if the record has been sent to the network
 **/
static TO_lib_ret_t tls_send_record(TOSE_helper_tls_ctx_t *tls_ctx,
		TO_tls_record_type_t type, const uint8_t *data, uint32_t len)
{	TO_lib_ret_t ret = TO_OK;
	uint16_t hdr_len = _TLS_HEADER_SIZE;
	uint8_t *hdr = tls_ctx->txbuf;
	uint16_t record_content_len;
	uint8_t *record_content;

	/* generate header for plain text record */
	hdr[0] = type;
	hdr[1] = _TLS_MAJOR;
	hdr[2] = _TLS_MINOR;
	hdr[3] = len >> 8;
	hdr[4] = len;

	record_content = tls_ctx->txbuf + hdr_len;

	/* encrypt if necessary */
	if (tls_ctx->encryption) {
		TO_LOG_DBG("Send record content:",0);
		TO_LOG_DBG_BUF(data, len);
		ret = tls_ctx->secure_record(tls_ctx->cipher_ctx, hdr, hdr_len,
				data, len, &record_content, &record_content_len);
	} else {
		memmove(record_content, data, len);
		record_content_len = len;
	}

	if (ret == TO_OK) {
		/* update fragment length */
		hdr[3] = record_content_len >> 8;
		hdr[4] = record_content_len;

		/* send to the lower layer */
		if (tls_ctx->encryption) {
			TO_LOG_DBG("Send secured record:",0);
		} else {
			TO_LOG_DBG("Send plain text record:",0);
		}
		TO_LOG_DBG_BUF((record_content - hdr_len), hdr_len + record_content_len);
		ret = tls_ctx->send_func(tls_ctx->priv_ctx, record_content - hdr_len,
				hdr_len + record_content_len);
	}
	return ret;
}

/**
 * @brief generate an alert
 * @param[in,out] tls_ctx tls context
 * @param[in] level level of the alert, a FATAL level resets the context
 * @param[in] desc raison of the alert
 * @return TO_OK if the alert has been sent to the peer
 * */
static TO_lib_ret_t tls_alert(
		TOSE_helper_tls_ctx_t *tls_ctx,
		tls_alert_level_t level,
		tls_alert_desc_t desc
)
{
	TO_lib_ret_t ret = TO_OK;
	uint8_t msg[TLS_FLIGHT_HEADER_SIZE+2] = {
		[TLS_FLIGHT_HEADER_SIZE] = level,
		[TLS_FLIGHT_HEADER_SIZE+1] =  desc};

#ifdef TO_ENABLE_DTLS
	ret = _tls_send(tls_ctx, TO_TLS_RECORD_TYPE_ALERT, msg, (sizeof (msg)) - TLS_FLIGHT_HEADER_SIZE,
					tls_ctx->epoch,
					tls_ctx->encryption);
#else
	ret = tls_send_record(tls_ctx, TO_TLS_RECORD_TYPE_ALERT, msg, (sizeof (msg)) - TLS_FLIGHT_HEADER_SIZE);
#endif
	if (ret != TO_OK) {
		TO_LOG_ERR("Failed to send %u bytes", sizeof (msg));
		return ret;
	}

	return TO_OK;
}

#define TLS_CIPHER_UPDATE_SIZE (TLS_CAPI_MAX_UPDATE_SIZE & ~(TO_AES_BLOCK_SIZE-1))

/**
 * @brief decrypt and authenticate a protected record
 *
 * @param[in,out] ctx TLS context
 * @param[in] input protected record
 * @param[in] ilength protected record length
 * @param[out] output pointer to decrypted data
 * @param[out] olength length of decrypted data
 *
 * @retval TO_OK input has been authenticated and decrypted successfully, out parameters are updated
 * @retval TO_ERROR ORed with TO_se_ret_t error code: an error occured during authentification/decryption
 * 			out parameters are not updated
 **/
static TO_ret_t internal_unsecure_record(void *ctx,
		uint16_t header_length,
		uint8_t *input, uint16_t ilength,
		uint8_t **output, uint16_t *olength)
{
	TOSE_helper_tls_ctx_t *tls_ctx = ctx;
	TO_ret_t ret;
	uint16_t out_offset = 0;
	uint16_t olen = *olength;
	uint8_t *in = input;
	uint8_t *out = input + header_length; /* plain text output is decipered in place on cipherd input */

	if ((ret = TOSE_tls_set_session(tls_ctx->ctx, tls_ctx->index)) != TORSP_SUCCESS) {
		return TO_ERROR | ret;
	}
#ifdef TO_DISABLE_CAPI
	ret = TOSE_tls_unsecure_payload(tls_ctx->ctx,
				in, header_length,
				in + header_length, ilength - header_length,
				out, &olen);
#else /* CAPI ENABLED */
	uint16_t in_offset = header_length + tls_ctx->iv_len;
	/* INIT */
	if (tls_ctx->encryption_type == TO_TLS_ENCRYPTION_AES_CBC) {
		/* CBC */
		ret = TOSE_tls_unsecure_payload_init_cbc(tls_ctx->ctx,
				ilength - in_offset,
				in, header_length, in + header_length,
				in + ilength - 2 * TO_AES_BLOCK_SIZE,
				in + ilength - TO_AES_BLOCK_SIZE);
	} else {
		/* AEAD (GCM or CCM) */
		ret = TOSE_tls_unsecure_payload_init_aead(tls_ctx->ctx,
				ilength - in_offset, in, header_length, in + header_length);
	}
	if (ret != TORSP_SUCCESS) {
		return TO_ERROR | ret;
	}
	/* advance *in* to the ciphered content */
	in += in_offset;
	ilength -= in_offset;

	/* UPDATE */
	for (in_offset = out_offset = 0;
			(in_offset + TLS_CIPHER_UPDATE_SIZE) < ilength;
			in_offset += TLS_CIPHER_UPDATE_SIZE) {
		ret = TOSE_tls_unsecure_payload_update(tls_ctx->ctx,
				in + in_offset, TLS_CIPHER_UPDATE_SIZE,
				out + out_offset, &olen);
		if (ret != TORSP_SUCCESS) {
			return TO_ERROR | ret;
		}
		out_offset += olen;
	}

	/* FINAL */
	ret = TOSE_tls_unsecure_payload_update(tls_ctx->ctx,
			in + in_offset, ilength - in_offset,
			out + out_offset, &olen);
	if (ret != TORSP_SUCCESS) {
		return TO_ERROR | ret;
	}

	ret = TOSE_tls_unsecure_payload_final(tls_ctx->ctx);
#endif /* CAPI ENABLED */
	if (ret != TORSP_SUCCESS) {
		return TO_ERROR | ret;
	}
	/* OK, set the output */
	*output = out;
	*olength = out_offset + olen;
	return TO_OK;
}

/**
 * @brief encrypt a plain text record
 *
 * @param[in,out] ctx TLS context
 * @param[in] header plain text record's header (needed to generate authenticated data or HMAC)
 * @param[in] header_length plain text record's header length
 * @param[in] input plain text record's content
 * @param[in] ilength plain text record's content length
 * @param[out] output pointer to the buffer with the protected record
 * @param[out] olength length of the protected record
 *
 * @retval TO_OK out parameters are updated
 * @retval TO_ERROR ORed with TO_se_ret_t error code: an error occured during encryption,
 * 			out parameters are not updated
 **/
static TO_ret_t internal_secure_record(void *ctx,
		uint8_t *header, uint16_t header_length,
		const uint8_t *input, uint16_t ilength,
		uint8_t **output, uint16_t *olength)
{
	TOSE_helper_tls_ctx_t *tls_ctx = ctx;
	TO_ret_t ret;

	if ((ret = TOSE_tls_set_session(tls_ctx->ctx, tls_ctx->index))
			!= TORSP_SUCCESS) {
		return TO_ERROR | ret;
	}

#ifdef TO_DISABLE_CAPI
	ret = TOSE_tls_secure_payload(tls_ctx->ctx,
			header, header_length,
			input, ilength,
			*output, olength);
	if (ret != TORSP_SUCCESS) {
		return TO_ERROR | ret;
	}
#else /* CAPI ENABLED */
	uint8_t *out = *output;
	uint16_t offset;
	/* INIT */
	if (tls_ctx->encryption_type == TO_TLS_ENCRYPTION_AES_CBC) {
		/* CBC */
		ret = TOSE_tls_secure_payload_init_cbc(tls_ctx->ctx, header,
				header_length, out);
	} else {
		/* AEAD (GCM or CCM) */
		ret = TOSE_tls_secure_payload_init_aead(tls_ctx->ctx, header,
				header_length, out);
	}
	if (ret != TORSP_SUCCESS) {
		return TO_ERROR | ret;
	}
	out += tls_ctx->iv_len;

	/* UPDATE */
	for (offset = 0; (offset + TLS_CIPHER_UPDATE_SIZE) < ilength;
			offset += TLS_CIPHER_UPDATE_SIZE) {
		ret = TOSE_tls_secure_payload_update(tls_ctx->ctx, input + offset,
				TLS_CIPHER_UPDATE_SIZE, out + offset);
		if (ret != TORSP_SUCCESS) {
			return TO_ERROR | ret;
		}
	}

	/* FINAL */
	uint16_t last_length = (ilength - offset) & ~(TO_AES_BLOCK_SIZE - 1);
	if (last_length) {
		ret = TOSE_tls_secure_payload_update(tls_ctx->ctx, input + offset,
				last_length, out + offset);
		offset += last_length;
		if (ret != TORSP_SUCCESS) {
			return TO_ERROR | ret;
		}
	}
	last_length = ilength - offset;
	uint16_t olen;
	ret = TOSE_tls_secure_payload_final(tls_ctx->ctx, input + offset,
			last_length, out + offset, &olen);
	if (ret != TORSP_SUCCESS) {
		return TO_ERROR | ret;
	}
	*olength = tls_ctx->iv_len + offset + olen;
#endif /* CAPI_ENABLED */
	return TO_OK;
}

/**
 * @brief receive bytes from network into internal buffer.
 *
 * @param[in,out] tls_ctx tls context, with internal buffer updated on receive
 * @param[in] min_length minimum number of bytes required by the caller
 * @param[in] timeout_ms maximum time to wait for bytes available.
 *
 * @retval TO_OK at least min_length bytes has been received
 * @retval TO_AGAIN less than min_length bytes has been received
 * @retval TO_TIMEOUT timed out elapsed before any bytes were received
 * @retval TO_ERROR receive error
 * */
static TO_lib_ret_t receive_bytes(
		TOSE_helper_tls_ctx_t *tls_ctx,
		uint16_t min_length,
		int32_t timeout_ms)
{
	TO_lib_ret_t ret = TO_OK;
	if (min_length <= tls_ctx->rx_next_length) {
		/* needed data already received */
		return TO_OK;
	}
	/* adjust the min length to the amount of bytes missing */
	min_length -= tls_ctx->rx_next_length;
	uint16_t max_length = tls_ctx->rxbuf_len - tls_ctx->rx_next_length
		- (tls_ctx->rx_next_data - tls_ctx->rxbuf);

	/* rewind if not enough rooms in rxbuffer to receive needed data */
	if (min_length > max_length) {
		memmove(tls_ctx->rxbuf, tls_ctx->rx_next_data, tls_ctx->rx_next_length);
		tls_ctx->rx_next_data = tls_ctx->rxbuf;
		max_length = tls_ctx->rxbuf_len - tls_ctx->rx_next_length;
	}

	/* read */
	uint8_t *p = tls_ctx->rx_next_data + tls_ctx->rx_next_length;
	uint32_t len = max_length;
	ret = tls_ctx->receive_func(tls_ctx->priv_ctx, p, max_length, &len, timeout_ms);
	if (ret == TO_OK) {
		tls_ctx->rx_next_length += len;
		if (len < min_length) {
			TO_LOG_WRN("cannot receive all the needed data",0);
			ret = TO_AGAIN;
		}
	} else {
		TO_LOG_ERR("Failed to receive data",0);
	}
	return ret;
}

/**
 * @brief check record's header validity
 *
 * @param[in,out] tls_ctx tls context, the internal buffer is
 * updated with the data consumed (the header)
 *
 * @retval TO_OK header is valid
 * @retval TO_ERROR header is not valid
 * */
static TO_lib_ret_t validate_header(TOSE_helper_tls_ctx_t *tls_ctx)
{
	uint8_t *p = tls_ctx->rx_next_data;
	uint8_t type = p[0];
	uint8_t major = p[1];
	uint8_t minor = p[2];
	uint16_t length = (p[3] << 8) + p[4];
	uint16_t header_length = _TLS_HEADER_SIZE;

	if ((major != _TLS_MAJOR) || (minor != _TLS_MINOR)) {
		return TO_ERROR;
	}

	if (length > (tls_ctx->rxbuf_len - header_length)) {
		return TO_ERROR;
	}

	tls_ctx->rx_rec.type = type;
	tls_ctx->rx_rec.header_length = header_length;
	tls_ctx->rx_rec.length = length;
	return TO_OK;
}
/* validate_header() assumes a TLS header of 5 bytes */
COMPILE_ASSERT(_TLS_HEADER_SIZE == 5);

/**
 * @brief setup the cipher context in HANDSHAKE_ONLY mode
 *
 * This function shall be called only if the session is in
 * handshake mode (when the setup_cipher_ctx callback in the
 * context is set).
 *
 * @param[in,out] tls_ctx the TLS session context
 * @retval TO_OK if the cipher context is correctly setup
 * @retval TO_ERROR otherwise
 * */
static TO_lib_ret_t setup_cipher_ctx(TOSE_helper_tls_ctx_t *tls_ctx)
{
	TO_ret_t ret;
	uint8_t *key_block = NULL;
	uint8_t key_block_length = 0;
	uint16_t cipher_overhead_length = TO_TLS_RECORD_CIPHER_OVERHEAD_MAX;
	TOSE_helper_tls_unsecure_record unsecure_record;
	TOSE_helper_tls_secure_record secure_record;

	/* put negociated parameters to the upper layer, get the storage for
	 * derived keys, get callbacks for record encryption/decryption */
	ret = tls_ctx->setup_cipher_ctx(tls_ctx->cipher_ctx, tls_ctx->cipher_suite,
			&key_block, &key_block_length, &cipher_overhead_length,
			&unsecure_record, &secure_record);
	if ((ret != TO_OK) || !key_block || !unsecure_record || !secure_record) {
		return TO_ERROR;
	}

	/* adjust maximum plain text record size before encryption */
	tls_ctx->tx_ptrec_len_max = TOSE_HELPER_TLS_IO_BUFFER_SIZE
		- cipher_overhead_length;

	tls_ctx->unsecure_record = unsecure_record;
	tls_ctx->secure_record = secure_record;

	/* fill the upper layer's buffer with derived keys */
	if ((ret = TOSE_get_tls_master_secret_derived_keys(tls_ctx->ctx,
			key_block_length, key_block) != TORSP_SUCCESS)) {
		TO_LOG_ERR("Failed to retrieve derived keys from the Secure Element - ret %x",
				(unsigned) ret);
		return TO_ERROR;
	}
	return TO_OK;
}

/**
 * @brief decrypt a ciphered record
 *
 * @param[in,out] tls_ctx tls context, the internal buffer is
 * updated with the data decipered
 *
 * @retval TO_OK record is decrypted and authenticated
 * @retval TO_ERROR record failed to be decrypted or authenticated
 * */
static TO_lib_ret_t unsecure_record(TOSE_helper_tls_ctx_t *tls_ctx)
{
	TO_lib_ret_t ret;
	uint8_t *out;
	uint16_t out_length;
	uint8_t *in = tls_ctx->rx_next_data;
	uint16_t in_length = tls_ctx->rx_rec.header_length
			+ tls_ctx->rx_rec.length;

	ret = tls_ctx->unsecure_record(tls_ctx->cipher_ctx,
			tls_ctx->rx_rec.header_length,
			in, in_length,
			&out, &out_length);
	if (ret == TO_OK) {
		/* update record with plain text data */
		tls_ctx->rx_rec.length = out_length;
		tls_ctx->rx_rec.fragment = out;
		/* update reception buffer with consumed data */
		tls_ctx->rx_next_length -= in_length;
		tls_ctx->rx_next_data += in_length;
	}

	return ret;
}

/**
 * @brief receive, parse (and decrypt) a TLS record
 *
 * @param[in,out] tls_ctx TLS context
 * @param[in] timeout_ms timeout in milliseconds
 *
 * @retval TO_OK  if plain text content of the record is available
 * @retval TO_AGAIN if data received but not enough to cover a full record
 * @retval TO_TIMEOUT timeout elapsed before any bytes were received
 * @retval TO_ERROR data cannot be received, the connection shall be (re-)initialized
 * */
static TO_lib_ret_t tls_receive_record(
		TOSE_helper_tls_ctx_t *tls_ctx,
		int32_t timeout_ms)
{
	TO_lib_ret_t ret = TO_OK;
	uint16_t header_length = _TLS_HEADER_SIZE;

	/* check current record */
	if (tls_ctx->rx_rec.fragment) {
		if (tls_ctx->rx_rec.offset < tls_ctx->rx_rec.length) {
			/* the record is not entirely consumed */
			return TO_OK;
		} else {
			/* the record is entirely consumed,
			 * we prepare to get the next */
			memset(&tls_ctx->rx_rec, 0, sizeof tls_ctx->rx_rec);
		}
	}

	/* the minimum length of the record in order to be able to continue */
	uint16_t min_length = tls_ctx->rx_rec.length + header_length;

	ret = receive_bytes(tls_ctx, min_length, timeout_ms);
	if (ret != TO_OK) {
		return ret;
	}

	if (!tls_ctx->rx_rec.length) {
		/* validate the header of the next record */
		ret = validate_header(tls_ctx);
		if (ret != TO_OK) {
			tls_alert(tls_ctx, ALERT_LEVEL_FATAL, ALERT_DESC_DECODE_ERROR);
			return ret;
		}
	}

	uint16_t record_length = tls_ctx->rx_rec.header_length
				+ tls_ctx->rx_rec.length;
	if (tls_ctx->rx_next_length >= record_length) {

		/* we have a whole record */
		TO_LOG_DBG("Received record:",0);
		TO_LOG_DBG_BUF(tls_ctx->rx_next_data, record_length);

		if (tls_ctx->decryption) {
			ret = unsecure_record(tls_ctx);
			if (ret != TO_OK) {
				return ret;
			}
		} else {
			/* plain text is already available */
			tls_ctx->rx_rec.fragment = tls_ctx->rx_next_data
				+ tls_ctx->rx_rec.header_length;
			tls_ctx->rx_next_length -= record_length;
			tls_ctx->rx_next_data += record_length;
		}
		TO_LOG_DBG("Plain text record content:",0);
		TO_LOG_DBG_BUF(tls_ctx->rx_rec.fragment, tls_ctx->rx_rec.length);

		if (!tls_ctx->rx_next_length) {
			/* re-position the rx_next_data pointer at the start of the rxbuf
			 * to avoid useless memmoves (see receive_bytes()) */
			tls_ctx->rx_next_data = tls_ctx->rxbuf;
		}
	} else {
		/* if here we received the header but not the whole record */
		ret = TO_AGAIN;
	}
	return ret;
}

#ifdef TO_ENABLE_DTLS
/* max_len parameter is only for application data partial read */
static TO_lib_ret_t dtls_receive(
		TOSE_helper_tls_ctx_t *tls_ctx,
		TO_tls_record_type_t *_type,
		uint8_t *_data,
		uint32_t _data_size,
		uint32_t *_len,
		uint32_t max_len,
		uint8_t decryption,
		int32_t timeout
)
{
	TO_lib_ret_t ret = TO_OK;
	TO_se_ret_t ret2;
	uint8_t _offset = 0;
	int32_t _ret;
	uint32_t read_len;
	uint32_t total_read_len = 0;
	uint32_t len;
	uint16_t epoch;
	uint64_t seq = 0;

	if (tls_ctx->cache_len != 0
	 && *_type == tls_ctx->cache_type) {
		if (tls_ctx->cache_len > _data_size - _TLS_HEADER_SIZE) {
			TO_LOG_ERR("RX buffer too small, %lu bytes needed",
					(unsigned long int)(tls_ctx->cache_len));
			return TO_ERROR;
		}
		TO_secure_memmove(_data + _TLS_HEADER_SIZE, _data + tls_ctx->cache_offs, tls_ctx->cache_len);
		len = tls_ctx->cache_len;
		tls_ctx->cache_len = 0;
		_offset = _TLS_HEADER_SIZE;
		goto cache_check;
	}

	if (tls_ctx->record_cache_len != 0) {
		if (tls_ctx->record_cache_len > _data_size) {
			TO_LOG_ERR("RX buffer too small, %lu bytes needed",
					(unsigned long int)(tls_ctx->record_cache_len));
			return TO_ERROR;
		}
		TO_secure_memmove(_data, _data + tls_ctx->record_cache_offs, tls_ctx->record_cache_len);
		read_len = tls_ctx->record_cache_len;
		tls_ctx->record_cache_len = 0;
	} else
	{
		/**
		 * Read length is protocol dependent.
		 * Datagrams need to be read fully, and connected protocols as TCP can be
		 * read by chunks (header, then message).
		 * We assume that DTLS will be used with UDP, but it needs to be adapted
		 * if using another datagram protocol.
		 */
		read_len = tls_ctx->rxbuf_len;
		read_len = MIN(read_len, _data_size);

		/* Receive header from network */
		if ((_ret = tls_ctx->receive_func(tls_ctx->priv_ctx, _data, read_len, &read_len, timeout)) != TO_OK) {
			if (_ret == TO_TIMEOUT) {
				TO_LOG_DBG("Timed out",0);
			} else {
				TO_LOG_ERR("Failed to receive data",0);
			}
			return _ret;
		}
	}

	/* Check read length */
	if (read_len < _TLS_HEADER_SIZE) {
		TO_LOG_ERR("Failed to receive enough data",0);
		return TO_ERROR;
	}

	total_read_len = read_len - _TLS_HEADER_SIZE;

	/* Type */
	*_type = (TO_tls_record_type_t)_data[_offset++];

	/* HelloVerifyRequest(0x03) minor is always 255 */
	if (*_type == TO_TLS_RECORD_TYPE_HANDSHAKE && _data[_TLS_HEADER_SIZE] == 0x03) {
		_data[_offset + 1] = _TLS_MINOR;
	}

	/* Verify version */
	if (_data[_offset] != _TLS_MAJOR || _data[_offset + 1] != _TLS_MINOR) {
		TO_LOG_ERR("Bad TLS version %u:%u, expected %u:%u",
				_data[_offset], _data[_offset + 1], _TLS_MAJOR, _TLS_MINOR);
		ret = TO_ERROR;
	}
	_offset += 2 * sizeof(uint8_t);

	epoch = _data[_offset++] << 8;
	epoch += _data[_offset++];
	if (epoch > _TLS_EPOCH_MAX) {
		TO_LOG_ERR("Invalid epoch: %u, ignoring packet", (unsigned) epoch);
		return TO_ERROR;
	}
	seq += (uint64_t)(_data[_offset++]) << 40;
	seq += (uint64_t)(_data[_offset++]) << 32;
	seq += (uint64_t)(_data[_offset++]) << 24;
	seq += (uint64_t)(_data[_offset++]) << 16;
	seq += (uint64_t)(_data[_offset++]) << 8;
	seq += (uint64_t)(_data[_offset++]);

	/* Verify sequence */
	if (seq < tls_ctx->sequence_number_down[epoch]) {
		TO_LOG_WRN("Record sequence already past, not supported, ignoring packet",0);
		return TO_ERROR;
	} else if (seq > tls_ctx->sequence_number_down[epoch]) {
		TO_LOG_WRN("Sequence gap (%llu --> %llu), some packets have been lost",
				(long long unsigned int)tls_ctx->sequence_number_down[epoch],
				(long long unsigned int)seq);
	}
	tls_ctx->sequence_number_down[epoch] = seq + 1;

	/* Extract length */
	GET_BE16(_data, _offset, len);

	/* Protect buffer overflow */
	if (len + _TLS_HEADER_SIZE > _data_size) {
		TO_LOG_ERR("RX buffer too small, %lu bytes needed",
				(unsigned long int)(len + _TLS_HEADER_SIZE));
		return TO_ERROR;
	}

	/* Store next record in case of several records in the same datagram */
	if (len < total_read_len) {
		tls_ctx->record_cache_len = total_read_len - len;
		tls_ctx->record_cache_offs = (_data - tls_ctx->rxbuf) + _TLS_HEADER_SIZE + len;
	}

	while (total_read_len < len) {

		/* Receive from network */
		if ((_ret = tls_ctx->receive_func(tls_ctx->priv_ctx, _data + _TLS_HEADER_SIZE + total_read_len,
						len - total_read_len, &read_len, TOSE_HELPER_TLS_RECEIVE_TIMEOUT)) != TO_OK) {
			TO_LOG_ERR("Failed to receive data",0);
			return _ret;
		}
		total_read_len += read_len;
	}

	TO_LOG_DBG("Receive buffer:",0);
	TO_LOG_DBG_BUF(tls_ctx->ctx->drv->log_ctx,_data, _TLS_HEADER_SIZE + len);

	if (ret != TO_OK) {
		return ret;
	}

	if (decryption
	 && *_type != TO_TLS_RECORD_TYPE_CHANGE_CIPHER_SPEC) {
		uint16_t tmp_len;

		if ((ret2 = TOSE_tls_set_session(tls_ctx->ctx, tls_ctx->index)) != TORSP_SUCCESS) {
			if (tls_ctx->index == 0) {
				TO_LOG_WRN("Failed to set TLS session, trying to continue as it is first session",0);
			} else {
				TO_LOG_ERR("Failed to set TLS session",0);
				return TO_ERROR | ret2;
			}
		}

		ret = TO_ERROR;
		if (*_type == TO_TLS_RECORD_TYPE_APPLICATION_DATA) {
			switch (tls_ctx->encryption_type) {
				case TO_TLS_ENCRYPTION_AES_CBC:
#if !defined(TO_DISABLE_API_HELPER_TLS_UNSECURE_PAYLOAD_CBC)
					ret = TOSE_helper_tls_unsecure_payload_cbc(tls_ctx->ctx, _data, _TLS_HEADER_SIZE,
					                                         _data + _TLS_HEADER_SIZE,
					                                         _data + _TLS_HEADER_SIZE + tls_ctx->iv_len,
					                                         len - tls_ctx->iv_len,
					                                         _data + _TLS_HEADER_SIZE,
					                                         &tmp_len);
#else
					ret = TO_ERROR | TORSP_UNKNOWN_CMD;
#endif
					break;
				case TO_TLS_ENCRYPTION_AES_CCM:
				case TO_TLS_ENCRYPTION_AES_CCM_8:
				case TO_TLS_ENCRYPTION_AES_GCM:
#if !defined(TO_DISABLE_API_HELPER_TLS_UNSECURE_PAYLOAD_AEAD)
					ret = TOSE_helper_tls_unsecure_payload_aead(tls_ctx->ctx, _data, _TLS_HEADER_SIZE,
					                                         _data + _TLS_HEADER_SIZE,
					                                         _data + _TLS_HEADER_SIZE + tls_ctx->iv_len,
					                                         len - tls_ctx->iv_len,
					                                         _data + _TLS_HEADER_SIZE,
					                                         &tmp_len);
#else
					ret = TO_ERROR | TORSP_UNKNOWN_CMD;
#endif
					break;
				default:
					TO_LOG_ERR("Unsupported encryption type %u", tls_ctx->encryption_type);
					return TO_ERROR;
			}

			if (ret != TO_OK && TO_SE_ERRCODE(ret) != TORSP_UNKNOWN_CMD) {
				TO_LOG_ERR("Failed to unsecure message",0);
				return ret;
			}
		}
		if (ret != TO_OK) {
			TO_ret_t ret2;
			/* Use old method for non-applicative messages and fallback */
			ret2 = TOSE_tls_unsecure_payload(tls_ctx->ctx, _data, _TLS_HEADER_SIZE,
			                              _data + _TLS_HEADER_SIZE,
			                              len, _data + _TLS_HEADER_SIZE,
			                              &tmp_len);
			if (ret2 != TORSP_SUCCESS) {
				TO_LOG_ERR("Failed to unsecure message",0);
				return TO_ERROR | ret2;
			}
		}
		len = tmp_len;

		/* Rewrite header */
		SET_BE16_NOINC(len, _data, _offset - sizeof(uint16_t));

		TO_LOG_DBG("Decrypted buffer:",0);
		TO_LOG_DBG_BUF(tls_ctx->ctx->drv->log_ctx,_data, _TLS_HEADER_SIZE + len);
	}

cache_check:
	/* TLS handshake records can contains several messages */
	if (*_type == TO_TLS_RECORD_TYPE_HANDSHAKE) {
		uint32_t tmp_len = 0;

		/* Skip message type */
		++_offset;

		/* 24-bits big-endian length */
		tmp_len += _data[_offset++] << 16;
		tmp_len += _data[_offset++] << 8;
		tmp_len += _data[_offset++];

		/* Check several messages */
		if (tmp_len < len - _TLS_HANDSHAKE_HEADER_SIZE) {
			tls_ctx->cache_len = len - _TLS_HANDSHAKE_HEADER_SIZE - tmp_len;
			tls_ctx->cache_offs = (_data - tls_ctx->rxbuf) + _offset + tmp_len;
			tls_ctx->cache_type = TO_TLS_RECORD_TYPE_HANDSHAKE;
			len -= tls_ctx->cache_len;
		}
	} else if (*_type == TO_TLS_RECORD_TYPE_APPLICATION_DATA) {
		if (max_len < len) {
			tls_ctx->cache_len = len - max_len;
			tls_ctx->cache_offs = (_data - tls_ctx->rxbuf) + _offset + max_len;
			tls_ctx->cache_type = TO_TLS_RECORD_TYPE_APPLICATION_DATA;
			len -= tls_ctx->cache_len;
		}
	}

	*_len = len;

	return TO_OK;
}
#endif

#ifdef TO_ENABLE_DTLS
static TO_lib_ret_t _tls_receive_defrag(
		TOSE_helper_tls_ctx_t *tls_ctx,
		TO_tls_record_type_t *_type,
		uint8_t **_data,
		uint32_t *_len,
		uint8_t decryption
)
{
	TO_lib_ret_t ret;
	uint32_t offset = _TLS_HEADER_SIZE + _TLS_HANDSHAKE_HEADER_SIZE;
	uint32_t to_read_len = 0;
	uint32_t len;
	int32_t timeout = -1;
	uint16_t seq;

	do {
		uint16_t tmp16;
		uint32_t tmp32;
		uint16_t frag_seq;
		uint32_t frag_off;
		uint32_t frag_len;
		uint8_t save[_TLS_HEADER_SIZE + _TLS_HANDSHAKE_HEADER_SIZE];
#ifndef TO_DISABLE_DTLS_RETRANSMISSION
		timeout = tls_ctx->timeout;
#endif

		/* Save data which will be overwritten */
		TO_secure_memcpy(save, tls_ctx->rxbuf + offset - (_TLS_HEADER_SIZE + _TLS_HANDSHAKE_HEADER_SIZE), _TLS_HEADER_SIZE + _TLS_HANDSHAKE_HEADER_SIZE);

		if ((ret = dtls_receive(tls_ctx, _type, tls_ctx->rxbuf + offset - (_TLS_HEADER_SIZE + _TLS_HANDSHAKE_HEADER_SIZE),
		                        tls_ctx->rxbuf_len - (offset - (_TLS_HEADER_SIZE + _TLS_HANDSHAKE_HEADER_SIZE)),
		                        &len, 0, decryption, timeout)) != TO_OK) {
#if !defined(TO_DISABLE_DTLS_RETRANSMISSION)
			if (ret == TO_TIMEOUT) {
				/* Double timeout */
				tls_ctx->timeout *= 2;
				if (tls_ctx->timeout > tls_ctx->max_timeout) {
					TO_LOG_WRN("Timeout reached maximum",0);
					tls_ctx->timeout = tls_ctx->max_timeout;
				}
				TO_LOG_WRN("New timeout %u", tls_ctx->timeout);
			}
#endif
			return ret;
		}
#ifndef TO_DISABLE_DTLS_RETRANSMISSION
		tls_ctx->timeout = tls_ctx->min_timeout;
#endif

		if (*_type != TO_TLS_RECORD_TYPE_HANDSHAKE) {
			offset -= _TLS_HANDSHAKE_HEADER_SIZE;
			offset += len;
			break;
		}

		offset -= sizeof(uint16_t) + 3 * 2;

		/* Fragment sequence */
		GET_BE16(tls_ctx->rxbuf, offset, frag_seq);

		/* Fragment offset */
		GET_BE24(tls_ctx->rxbuf, offset, frag_off);

		/* Fragment length */
		GET_BE24(tls_ctx->rxbuf, offset, frag_len);

		if (offset > _TLS_HEADER_SIZE + _TLS_HANDSHAKE_HEADER_SIZE) {

			/* Check fragment sequence */
			if (frag_seq != seq) {
				TO_LOG_WRN("Bad sequence, retransmission needed",0);
				/* Return timeout to trigger retransmission */
				return TO_TIMEOUT;
			}

			/* Restore overwrote data */
			TO_secure_memcpy(tls_ctx->rxbuf + offset - (_TLS_HEADER_SIZE + _TLS_HANDSHAKE_HEADER_SIZE), save, _TLS_HEADER_SIZE + _TLS_HANDSHAKE_HEADER_SIZE);

			/* Update TLS record header */
			GET_BE16_NOINC(tls_ctx->rxbuf, _TLS_HEADER_SIZE - sizeof(uint16_t), tmp16);
			tmp16 += frag_len;
			SET_BE16_NOINC(tmp16, tls_ctx->rxbuf, _TLS_HEADER_SIZE - sizeof(uint16_t));

			/* Update TLS handshake header */
			GET_BE24_NOINC(tls_ctx->rxbuf, _TLS_HEADER_SIZE + _TLS_HANDSHAKE_HEADER_SIZE - 3, tmp32);
			tmp32 += frag_len;
			SET_BE24_NOINC(tmp32, tls_ctx->rxbuf, _TLS_HEADER_SIZE + _TLS_HANDSHAKE_HEADER_SIZE - 3);

		} else {
			/* Get total message length */
			GET_BE24_NOINC(tls_ctx->rxbuf, _TLS_HEADER_SIZE + sizeof(uint8_t), to_read_len);

			/* Set wanted sequence */
			seq = frag_seq;
		}

		/* Move data to right place */
		TO_secure_memmove(tls_ctx->rxbuf + _TLS_HEADER_SIZE + _TLS_HANDSHAKE_HEADER_SIZE + frag_off, tls_ctx->rxbuf + offset, frag_len);

		to_read_len -= frag_len;
		offset += frag_len;
	} while (to_read_len > 0);

	*_len = offset - _TLS_HEADER_SIZE;
	*_data = tls_ctx->rxbuf + _TLS_HEADER_SIZE;

	return TO_OK;
}
#endif

#if defined(TO_ENABLE_DTLS) && !defined(TO_DISABLE_DTLS_RETRANSMISSION)
static TO_lib_ret_t _tls_retransmit_last_flight(
		TOSE_helper_tls_ctx_t *tls_ctx
)
{
	uint32_t i;
	uint32_t _len;
	TO_lib_ret_t ret;

	TO_LOG_INF("Retransmission of last flight start\n",0);

	/* Resend last flight */
	for (i = 0; i < tls_ctx->flight_offset; i += TLS_FLIGHT_HEADER_SIZE + _len) {

		/* First bytes is header */
		_tls_flight_header_t *_flight_hdr = (_tls_flight_header_t*)(tls_ctx->flight_buf + i);

		if (_flight_hdr->type == TO_TLS_RECORD_TYPE_HANDSHAKE) {
			/* Read header length */
			_len = 0;
			TO_secure_memcpy(((uint8_t*)&_len) + 1, tls_ctx->flight_buf + i + TLS_FLIGHT_HEADER_SIZE + sizeof(uint8_t), 3);
			_len = _TLS_HANDSHAKE_HEADER_SIZE + be32toh(_len);
		} else {
			/* ChangeCipherSpec */
			_len = 1;
		}

		/* Retransmission */
		ret = _tls_send(tls_ctx, _flight_hdr->type, tls_ctx->flight_buf + i, _len,
				_flight_hdr->epoch, _flight_hdr->encryption);
		if (ret != TO_OK) {
			TO_LOG_ERR("Failed to send %u bytes", (uint32_t)_len);
		}
	}

	TO_LOG_INF("Last flight retransmitted\n",0);
	return TO_OK;
}
#endif

static TO_lib_ret_t _tls_set_types(
		TOSE_helper_tls_ctx_t *tls_ctx
)
{
	switch (tls_ctx->cipher_suite) {
		case TO_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
		case TO_TLS_ECDHE_ECDSA_WITH_AES_128_CCM:
		case TO_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8:
		case TO_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		case TO_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
		case TO_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
			tls_ctx->cipher_suite_type = TO_TLS_CIPHER_SUITE_ECDHE;
			break;
		case TO_TLS_PSK_WITH_AES_128_CBC_SHA256:
		case TO_TLS_PSK_WITH_AES_128_CCM:
		case TO_TLS_PSK_WITH_AES_128_CCM_8:
		case TO_TLS_PSK_WITH_AES_128_GCM_SHA256:
			tls_ctx->cipher_suite_type = TO_TLS_CIPHER_SUITE_PSK;
			break;
		default:
			TO_LOG_ERR("Unknown cipher suite %04x", tls_ctx->cipher_suite);
			return TO_ERROR;
	}

	switch (tls_ctx->cipher_suite) {
		case TO_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
		case TO_TLS_PSK_WITH_AES_128_CBC_SHA256:
		case TO_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
			tls_ctx->encryption_type = TO_TLS_ENCRYPTION_AES_CBC;
			tls_ctx->iv_len = TO_INITIALVECTOR_SIZE;
			break;
		case TO_TLS_PSK_WITH_AES_128_CCM:
		case TO_TLS_ECDHE_ECDSA_WITH_AES_128_CCM:
			tls_ctx->encryption_type = TO_TLS_ENCRYPTION_AES_CCM;
			tls_ctx->iv_len = TO_TLS_AEAD_EXPLICIT_NONCE_SIZE;
			break;
		case TO_TLS_PSK_WITH_AES_128_CCM_8:
		case TO_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8:
			tls_ctx->encryption_type = TO_TLS_ENCRYPTION_AES_CCM_8;
			tls_ctx->iv_len = TO_TLS_AEAD_EXPLICIT_NONCE_SIZE;
			break;
		case TO_TLS_PSK_WITH_AES_128_GCM_SHA256:
		case TO_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		case TO_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
			tls_ctx->encryption_type = TO_TLS_ENCRYPTION_AES_GCM;
			tls_ctx->iv_len = TO_TLS_AEAD_EXPLICIT_NONCE_SIZE;
			break;
		default:
			TO_LOG_ERR("Unknown cipher suite %04x", tls_ctx->cipher_suite);
			return TO_ERROR;
	}

	switch (tls_ctx->cipher_suite) {
		case TO_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
		case TO_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
			tls_ctx->is_rsa = 1;
			break;
		default:
			tls_ctx->is_rsa = 0;
			break;
	}

	return TO_OK;
}

TO_lib_ret_t TOSE_helper_tls_init_session(
		TOSE_ctx_t *ctx,
		TOSE_helper_tls_ctx_t **tls_ctx,
		const uint8_t session,
		void *priv_ctx,
		TOSE_helper_tls_send_func send_func,
		TOSE_helper_tls_receive_func receive_func
)
{
	TO_ret_t ret;
	TOSE_helper_tls_ctx_t *__tls_ctx = NULL;
	uint8_t i;

	/* Look for un-used session */
	for (i = 0; i < TO_TLS_SESSIONS_NB; ++i) {
		__tls_ctx = &_tls_ctx[i];

		if (!__tls_ctx->in_use) {
			break;
		}
	}

	/* Check if a session was available */
	if (i == TO_TLS_SESSIONS_NB) {
		TO_LOG_ERR("All sessions in use",0);
		return TO_ERROR;
	}

	TO_LOG_INF("Using session %u", session);

	if ((ret = TOSE_tls_set_session(ctx, session)) != TORSP_SUCCESS) {
		if (session == 0) {
			TO_LOG_WRN("Failed to set TLS session, trying to continue as it is first session",0);
		} else {
			TO_LOG_ERR("Failed to set TLS session",0);
			return TO_ERROR | ret;
		}
	}

	TO_secure_memset(__tls_ctx, 0, sizeof(TOSE_helper_tls_ctx_t));

	__tls_ctx->ctx = ctx;
	__tls_ctx->state = TO_TLS_STATE_FLIGHT_1;
#if !defined(TO_ENABLE_DTLS) || defined(TO_DISABLE_DTLS_RETRANSMISSION)
	__tls_ctx->flight_buf = __tls_ctx->buf + _TLS_HEADER_SIZE;
#endif
	__tls_ctx->rxbuf = __tls_ctx->buf;
	__tls_ctx->rxbuf_len = TOSE_HELPER_TLS_IO_BUFFER_SIZE;
	__tls_ctx->rx_next_data = __tls_ctx->rxbuf;
	__tls_ctx->txbuf = __tls_ctx->buf;
	__tls_ctx->txbuf_len = TOSE_HELPER_TLS_IO_BUFFER_SIZE;
	__tls_ctx->tx_ptrec_len_max = TOSE_HELPER_TLS_IO_BUFFER_SIZE
				- TO_TLS_RECORD_CIPHER_OVERHEAD_MAX;
#ifdef TO_ENABLE_DTLS
#ifndef TO_DISABLE_DTLS_RETRANSMISSION
	__tls_ctx->timeout = __tls_ctx->min_timeout = _TLS_TIMEOUT_MIN;
	__tls_ctx->max_timeout = _TLS_TIMEOUT_MAX;
	__tls_ctx->max_retransmissions = _TLS_RETRANSMISSIONS_MAX;
#endif
	__tls_ctx->fragment_max_size = _TLS_FRAGMENT_MAXSIZE;

	if (TOSE_tls_set_cid_ext_id(ctx, TO_TLS_EXTENSION_CONNECTION_ID) != TORSP_SUCCESS) {
		TO_LOG_WRN("Failed to set TLS connection ID extension ID",0);
	}

	uint8_t mode = TO_TLS_MODE_DTLS_1_2;
	ret = TOSE_tls_set_config(ctx, TO_TLS_CONFIG_ID_MODE, &mode, sizeof mode);
	if (ret != TORSP_SUCCESS)
	{
		TO_LOG_ERR("Failed to set TLS mode",0);
		return TO_ERROR | ret;
	}
#endif

	__tls_ctx->priv_ctx = priv_ctx;
	__tls_ctx->send_func = send_func;
	__tls_ctx->receive_func = receive_func;

	__tls_ctx->setup_cipher_ctx = NULL;
	__tls_ctx->unsecure_record = internal_unsecure_record;
	__tls_ctx->secure_record = internal_secure_record;
	__tls_ctx->cipher_ctx = __tls_ctx;

	__tls_ctx->in_use = 1;
	__tls_ctx->index = session;
	*tls_ctx = __tls_ctx;

	return TO_OK;
}

TO_lib_ret_t TOSE_helper_tls_close(
		TOSE_helper_tls_ctx_t *tls_ctx
)
{
#ifdef TO_ENABLE_DTLS
	uint16_t i;
#endif

	if (tls_alert(tls_ctx, ALERT_LEVEL_WARNING, ALERT_DESC_CLOSE_NOTIFY) != TO_OK) {
		TO_LOG_ERR("Failed to send close notify alert",0);
	}

	/* Reset */
	tls_ctx->rx = 0;
	tls_ctx->flight_offset = 0;
#if !defined(TO_ENABLE_DTLS) || defined(TO_DISABLE_DTLS_RETRANSMISSION)
	tls_ctx->flight_buf = tls_ctx->buf + _TLS_HEADER_SIZE;
#endif
	tls_ctx->pbuf = NULL;
	tls_ctx->cache_offs = 0;
	tls_ctx->cache_len = 0;
	tls_ctx->cache_type = 0;
	tls_ctx->encryption = 0;
	tls_ctx->decryption = 0;
	tls_ctx->auth_client = 0;
	tls_ctx->abbreviated_handshake = 0;
	tls_ctx->client_session_id_len = 0;
	tls_ctx->state = TO_TLS_STATE_FLIGHT_1;
	tls_ctx->rxbuf = tls_ctx->buf;
	tls_ctx->rxbuf_len = TOSE_HELPER_TLS_IO_BUFFER_SIZE;
	tls_ctx->rx_next_data = tls_ctx->rxbuf;
	tls_ctx->txbuf = tls_ctx->buf;
	tls_ctx->txbuf_len = TOSE_HELPER_TLS_IO_BUFFER_SIZE;
	tls_ctx->tx_ptrec_len_max = TOSE_HELPER_TLS_IO_BUFFER_SIZE
				- TO_TLS_RECORD_CIPHER_OVERHEAD_MAX;
#ifdef TO_ENABLE_DTLS
#ifndef TO_DISABLE_DTLS_RETRANSMISSION
	tls_ctx->timeout = tls_ctx->min_timeout;
	tls_ctx->retransmissions = 0;
#endif
	tls_ctx->epoch = 0;
	for (i = 0; i < _TLS_EPOCH_MAX + 1; ++i) {
		tls_ctx->sequence_number_up[i] = 0;
		tls_ctx->sequence_number_down[i] = 0;
	}
	tls_ctx->record_cache_offs = 0;
	tls_ctx->record_cache_len = 0;
	tls_ctx->connection_id_len = 0;
#endif

	return TO_OK;
}

TO_lib_ret_t TOSE_helper_tls_fini(
		TOSE_helper_tls_ctx_t *tls_ctx
)
{
	tls_ctx->in_use = 0;

	return TO_OK;
}

TO_lib_ret_t TOSE_helper_tls_cleanup(
		TOSE_helper_tls_ctx_t *tls_ctx
)
{
	TO_lib_ret_t ret;

	if ((ret = TOSE_helper_tls_close(tls_ctx)) != TO_OK) {
		TO_LOG_ERR("Failed to close TLS",0);
	}

	if ((ret = TOSE_helper_tls_fini(tls_ctx)) != TO_OK) {
		TO_LOG_ERR("Failed to finalize TLS\n",0);
	}

	return TO_OK;
}

#ifdef TO_ENABLE_DTLS
#ifndef TO_DISABLE_DTLS_RETRANSMISSION
TO_lib_ret_t TOSE_helper_tls_set_retransmission_timeout(
		TOSE_helper_tls_ctx_t *tls_ctx,
		const uint32_t min_timeout,
		const uint32_t max_timeout
)
{
	if (min_timeout > max_timeout) {
		TO_LOG_ERR("Bad range (%u > %u)", min_timeout, max_timeout);
		return TO_ERROR;
	}

	tls_ctx->timeout = MAX(tls_ctx->timeout, min_timeout);
	tls_ctx->timeout = MIN(tls_ctx->timeout, max_timeout);

	tls_ctx->min_timeout = min_timeout;
	tls_ctx->max_timeout = max_timeout;

	return TO_OK;
}

TO_lib_ret_t TOSE_helper_tls_set_retransmission_max(
		TOSE_helper_tls_ctx_t *tls_ctx,
		const uint32_t max_retransmissions
)
{
	tls_ctx->max_retransmissions = max_retransmissions;

	return TO_OK;
}
#endif

TO_lib_ret_t TOSE_helper_tls_set_fragment_max_size(
		TOSE_helper_tls_ctx_t *tls_ctx,
		const uint16_t max_size
)
{
	tls_ctx->fragment_max_size = max_size;

	return TO_OK;
}
#endif

#define TLS_HELPER_MAX_CIPHER_SUITE_COUNT 16
TO_lib_ret_t TOSE_helper_tls_set_cipher_suites(
		TOSE_helper_tls_ctx_t *tls_ctx,
		const uint16_t *cipher_suites,
		const uint16_t cipher_suites_cnt)
{
	TO_ret_t ret;
	uint16_t i;
	uint16_t _cipher_suites[TLS_HELPER_MAX_CIPHER_SUITE_COUNT];
	if (cipher_suites_cnt > TLS_HELPER_MAX_CIPHER_SUITE_COUNT) {
		TO_LOG_ERR("too many cipher suites provided.",0);

		return TO_ERROR;
	}

	if ((ret = TOSE_tls_set_session(tls_ctx->ctx, tls_ctx->index)) != TORSP_SUCCESS) {
		if (tls_ctx->index == 0) {
			TO_LOG_WRN("Failed to set TLS session, trying to continue as it is first session",0);
		} else {
			TO_LOG_ERR("Failed to set TLS session",0);

			return TO_ERROR | ret;
		}
	}

	for (i = 0; i < cipher_suites_cnt; ++i) {
		_cipher_suites[i] = htobe16(cipher_suites[i]);
	}

	ret = TOSE_tls_set_config(tls_ctx->ctx, TO_TLS_CONFIG_ID_CIPHER_SUITES,
	                        (uint8_t*)_cipher_suites,
	                        cipher_suites_cnt * sizeof(uint16_t));
	if (ret != TORSP_SUCCESS) {
		return TO_ERROR | ret;
	}

	return TO_OK;
}
TO_lib_ret_t TOSE_helper_tls_set_config_mode(TOSE_helper_tls_ctx_t *tls_ctx, TO_tls_mode_t mode)
{
	uint8_t data = mode;
	return TOSE_helper_tls_set_config(tls_ctx, TO_TLS_CONFIG_ID_MODE, &data, sizeof data);
}

TO_lib_ret_t TOSE_helper_tls_set_config_certificate_slot(TOSE_helper_tls_ctx_t *tls_ctx, uint8_t certificate_slot)
{
	return TOSE_helper_tls_set_config(tls_ctx, TO_TLS_CONFIG_ID_CERTIFICATE_SLOT, &certificate_slot, sizeof certificate_slot);
}

TO_lib_ret_t TOSE_helper_tls_set_config(
		TOSE_helper_tls_ctx_t *tls_ctx,
		const TO_tls_config_id_t config_id,
		const uint8_t *config,
		const uint16_t config_len)
{
	TO_ret_t ret;

	if ((ret = TOSE_tls_set_session(tls_ctx->ctx, tls_ctx->index)) != TORSP_SUCCESS) {
		if (tls_ctx->index == 0) {
			TO_LOG_WRN("Failed to set TLS session, trying to continue as it is first session",0);
		} else {
			TO_LOG_ERR("Failed to set TLS session",0);
			return TO_ERROR | ret;
		}
	}

	ret = TOSE_tls_set_config(tls_ctx->ctx, config_id, config, config_len);
	if (ret != TORSP_SUCCESS) {
		return TO_ERROR | ret;
	}

	return TO_OK;
}

static uint32_t get_max_ptrec_len(TOSE_helper_tls_ctx_t *tls_ctx)
{
	uint32_t max_len = tls_ctx->txbuf_len;

	switch (tls_ctx->encryption_type) {
	case TO_TLS_ENCRYPTION_AES_CBC:
	/* to compute the max_len, i.e the maximum length of data that can be
	 * copied inside the tx buffer, it assumed that the cipher suite is
	 * TLS_*_WITH_AES_128_CBC_SHA256 with minimal padding size */
		max_len -= TO_AES_BLOCK_SIZE;			/* the block for the IV */
		max_len -= TO_HMAC_SIZE;			/* the MAC after the data */
		max_len = max_len & ~(TO_AES_BLOCK_SIZE - 1);	/* the padding field */
		max_len -= 1;					/* the padding_length field */
		break;
	case TO_TLS_ENCRYPTION_AES_CCM_8:
		max_len -= tls_ctx->iv_len;		/* the nonce-explicit field max size */
		max_len -= TO_AESCCM_8_TAG_SIZE;
		break;
	case TO_TLS_ENCRYPTION_AES_CCM:
		max_len -= tls_ctx->iv_len;		/* the nonce-explicit field max size */
		max_len -= TO_AESCCM_TAG_SIZE;
		break;
	case TO_TLS_ENCRYPTION_AES_GCM:
		max_len -= tls_ctx->iv_len;		/* the nonce-explicit field max size */
		max_len -= TO_AESGCM_TAG_SIZE;
		break;
	default: /* unknown */
		max_len -= TO_TLS_RECORD_CIPHER_OVERHEAD_MAX;
		break;
	}
	return max_len;
}

/**
 * @brief consumes a single handshake message inside a handshake record
 * @param[in,out] tls_ctx tls context (tls_ctx->pbuf is set to the start of the message if TO_OK)
 * @param[out] len the length of the handshake message
 *
 * @retval TO_OK in case of success
 * @retval TO_ERROR in case of bad record
 * */
static TO_lib_ret_t tls_receive_handshake_message(TOSE_helper_tls_ctx_t *tls_ctx, uint32_t *len)
{
	uint8_t *pbuf = tls_ctx->rx_rec.fragment + tls_ctx->rx_rec.offset;
	uint16_t fragment_length = tls_ctx->rx_rec.length - tls_ctx->rx_rec.offset;
	if (fragment_length < _TLS_HANDSHAKE_HEADER_SIZE) {
		TO_LOG_ERR("invalid handshake message length(too short) %u\n", fragment_length);
		return TO_ERROR;
	}

	/* message length, including message header */
	uint32_t msg_len = _TLS_HANDSHAKE_HEADER_SIZE + (pbuf[1] << 16) + (pbuf[2] << 8) + pbuf[3];
	if (msg_len > fragment_length) {
		TO_LOG_ERR("invalid handshake message length(too long) %u\n", fragment_length);
		return TO_ERROR;
	}

	/* update context and len */
	tls_ctx->pbuf = pbuf;
	tls_ctx->rx_rec.offset += msg_len;
	*len = msg_len;

	return TO_OK;
}

TO_lib_ret_t TOSE_helper_tls_set_server_name(
		TOSE_helper_tls_ctx_t *tls_ctx,
		const char *server_name)
{
	uint32_t sni_len = 0;

	memset(tls_ctx->sni, 0, sizeof tls_ctx->sni);
	if (server_name) {
		sni_len = strlen(server_name);
	}
	if (sni_len > TO_TLS_SNI_LENGTH_MAX) {
		return TO_ERROR;
	}
	tls_ctx->sni_length = sni_len;
	if (sni_len > 0) {
		memcpy(tls_ctx->sni, server_name, sni_len);
	}
	return TO_OK;
}

#ifndef TOSE_HELPER_TLS_USE_DEFAULT_SETUP_CIPHER
void *default_cipher_ctx = NULL;
TOSE_helper_tls_setup_cipher_ctx default_setup_cipher_ctx = NULL;
#endif

TO_lib_ret_t TOSE_helper_tls_set_mode_handshake_only(
		TOSE_helper_tls_ctx_t *tls_ctx,
		void *cipher_ctx,
		TOSE_helper_tls_setup_cipher_ctx setup_cipher_ctx)
{
	TO_lib_ret_t ret;
	uint8_t mode = TO_TLS_MODE_TLS_1_2_HANDSHAKE_ONLY;
	ret = TOSE_helper_tls_set_config(tls_ctx, TO_TLS_CONFIG_ID_MODE, &mode, sizeof mode);
	if (ret != TO_OK) {
		return ret;
	}
	if (setup_cipher_ctx) {
		tls_ctx->cipher_ctx = cipher_ctx;
		tls_ctx->setup_cipher_ctx = setup_cipher_ctx;
	} else {
		/* fall back to default (if any) */
		tls_ctx->cipher_ctx = default_cipher_ctx;
		tls_ctx->setup_cipher_ctx = default_setup_cipher_ctx;
	}
	if (!tls_ctx->setup_cipher_ctx) {
		return TO_ERROR;
	}
	return TO_OK;
}
TO_lib_ret_t TOSE_helper_tls_do_handshake_step(
		TOSE_helper_tls_ctx_t *tls_ctx
)
{
	uint32_t len = 0;
	uint16_t len16;
	TO_ret_t ret;
	TO_lib_ret_t ret_lib = TO_OK;
	uint8_t timestamp[TO_TIMESTAMP_SIZE] = { 0x00, 0x00, 0x00, 0x00 };
	TO_tls_record_type_t type = TO_TLS_RECORD_TYPE_HANDSHAKE;
	uint8_t next_rx = tls_ctx->rx;

	if (tls_ctx->rx) {

		/* Receive mode */
#if defined(TO_ENABLE_DTLS)
		ret_lib = _tls_receive_defrag(tls_ctx, &type, &tls_ctx->pbuf, &len, tls_ctx->decryption);
#else
		ret_lib = tls_receive_record(tls_ctx, 10000);
		type = tls_ctx->rx_rec.type;
		len = tls_ctx->rx_rec.length;
		if (ret_lib == TO_OK) {
			if (type == TO_TLS_RECORD_TYPE_HANDSHAKE) {
				ret_lib = tls_receive_handshake_message(tls_ctx, &len);
			} else {
				tls_ctx->pbuf = tls_ctx->rx_rec.fragment;
				tls_ctx->rx_rec.offset = tls_ctx->rx_rec.length;
			}
		}
#endif
		if (ret_lib != TO_OK) {
#if defined(TO_ENABLE_DTLS) && !defined(TO_DISABLE_DTLS_RETRANSMISSION)
			if (ret_lib == TO_TIMEOUT) {
				if (++tls_ctx->retransmissions > tls_ctx->max_retransmissions) {
					TO_LOG_ERR("Retransmissions maximum reached, handshake aborted",0);
					return TO_ERROR;
				}
				TO_LOG_INF("Retransmission n°%u", tls_ctx->retransmissions);

				/* Retransmit last flight */
				_tls_retransmit_last_flight(tls_ctx);
			}
			return TO_AGAIN;
#else
			return ret_lib;
#endif
		}

#if defined(TO_ENABLE_DTLS) && !defined(TO_DISABLE_DTLS_RETRANSMISSION)
		tls_ctx->retransmissions = 0;
#endif

		if (type == TO_TLS_RECORD_TYPE_ALERT) {
			tls_handle_alert(tls_ctx, *tls_ctx->pbuf, *(tls_ctx->pbuf + 1));
			return TO_ERROR;
		}

		if ((tls_ctx->cipher_suite_type == TO_TLS_CIPHER_SUITE_ECDHE)
		 && (tls_ctx->state == TO_TLS_STATE_SERVER_CERTIFICATE_REQUEST)
		 && (*tls_ctx->pbuf == TO_TLS_HANDSHAKE_TYPE_SERVER_HELLO_DONE)) {
			TO_LOG_INF("Client authentication not requested\n",0);
			tls_ctx->state = TO_TLS_STATE_SERVER_HELLO_DONE;
		} else if ((tls_ctx->cipher_suite_type == TO_TLS_CIPHER_SUITE_PSK)
		 && (tls_ctx->state == TO_TLS_STATE_SERVER_KEY_EXCHANGE)
		 && (*tls_ctx->pbuf == TO_TLS_HANDSHAKE_TYPE_SERVER_HELLO_DONE)) {
			TO_LOG_INF("Server key exchange skipped\n",0);
			tls_ctx->state = TO_TLS_STATE_SERVER_HELLO_DONE;
		}
#ifdef TO_ENABLE_DTLS
		else if ((tls_ctx->state == TO_TLS_STATE_SERVER_HELLO_VERIFY_REQUEST)
		 && (*tls_ctx->pbuf == TO_TLS_HANDSHAKE_TYPE_SERVER_HELLO)
		 && (tls_ctx->client_session_id_len > 0)) {
			/* DTLS session resumption, no cookie exchange */
			TO_LOG_INF("Cookie exchange skipped\n",0);
			tls_ctx->state = TO_TLS_STATE_SERVER_HELLO;
		}

		uint8_t msg_type = tls_ctx->rxbuf[_TLS_HEADER_SIZE];

		/**
		 * Detect replayed flight by checking handshake message type.
		 * Server flight starting by ChangeCipherSpec will not be
		 * retransmitted to query last client flight as it is the last
		 * server flight.
		 */
		if (type == TO_TLS_RECORD_TYPE_HANDSHAKE && msg_type != (tls_ctx->state & 0xff)) {
#ifndef TO_DISABLE_DTLS_RETRANSMISSION
			/* Ignore in-flight messages, wait last or missing */
			if ((msg_type != TO_TLS_HANDSHAKE_TYPE_HELLO_VERIFY_REQUEST)
			 && (msg_type != TO_TLS_HANDSHAKE_TYPE_SERVER_HELLO_DONE)
			 && (msg_type != TO_TLS_HANDSHAKE_TYPE_FINISHED)) {
				TO_LOG_INF("Ignored in-flight handshake message type %02x\n", msg_type);
			} else {
				/* Retransmit last flight */
				_tls_retransmit_last_flight(tls_ctx);
			}
#endif

			return TO_AGAIN;
		}
#endif
	} else {
		tls_ctx->pbuf = tls_ctx->flight_buf + tls_ctx->flight_offset;
	}

	if ((ret = TOSE_tls_set_session(tls_ctx->ctx, tls_ctx->index)) != TORSP_SUCCESS) {
		if (tls_ctx->index == 0) {
			TO_LOG_WRN("Failed to set TLS session, trying to continue as it is first session",0);
		} else {
			TO_LOG_ERR("Failed to set TLS session",0);
			return TO_ERROR | ret;
		}
	}

	ret = TORSP_SUCCESS;

	switch (tls_ctx->state) {
		case TO_TLS_STATE_FLIGHT_1:
			TO_LOG_INF("*** Flight 1 ***",0);
#if defined(TO_ENABLE_DTLS) && !defined(TO_DISABLE_DTLS_RETRANSMISSION)
			tls_ctx->flight_offset = 0;
			tls_ctx->pbuf = tls_ctx->flight_buf;
#endif
			next_rx = 0;
			tls_ctx->state = TO_TLS_STATE_FLIGHT_1_INIT;
			FALL_THROUGH
		case TO_TLS_STATE_CLIENT_HELLO:
			TO_LOG_INF("SNI len : %d ",tls_ctx->sni_length);
			ret = TOSE_tls_get_client_hello_ext(tls_ctx->ctx,
					timestamp, tls_ctx->sni, tls_ctx->sni_length,
					tls_ctx->pbuf + TLS_FLIGHT_HEADER_SIZE, &len16);
			if (ret == TORSP_UNKNOWN_CMD) {
				/* fallback to previous version */
				ret = TOSE_tls_get_client_hello(tls_ctx->ctx, timestamp,
						tls_ctx->pbuf + TLS_FLIGHT_HEADER_SIZE, &len16);
			}
			if (ret != TORSP_SUCCESS) {
				break;
			}
			{
				uint8_t *p = tls_ctx->pbuf + TLS_FLIGHT_HEADER_SIZE + _TLS_HANDSHAKE_HEADER_SIZE + 2 * sizeof(uint8_t) + TO_TLS_RANDOM_SIZE;
				/* Save client session ID */
				tls_ctx->client_session_id_len = *(p++);
				TO_secure_memcpy(tls_ctx->client_session_id, p, tls_ctx->client_session_id_len);
				p += tls_ctx->client_session_id_len;
			}
			len = (uint32_t)len16;
			TO_LOG_INF("==> ClientHello",0);
#ifdef TO_ENABLE_DTLS
			tls_ctx->state = TO_TLS_STATE_FLIGHT_2;
			FALL_THROUGH
		case TO_TLS_STATE_FLIGHT_2:
			TO_LOG_INF("*** Flight 2 ***",0);
			next_rx = 1;
			tls_ctx->state = TO_TLS_STATE_FLIGHT_2_INIT;
			break;
		case TO_TLS_STATE_SERVER_HELLO_VERIFY_REQUEST:
			TO_LOG_INF("<== HelloVerifyRequest",0);
			ret = TOSE_tls_handle_hello_verify_request(tls_ctx->ctx, tls_ctx->pbuf, len);
			if (ret != TORSP_SUCCESS) { break; }
			tls_ctx->state = TO_TLS_STATE_FLIGHT_3;
			FALL_THROUGH
		case TO_TLS_STATE_FLIGHT_3:
			TO_LOG_INF("*** Flight 3 ***",0);
#if defined(TO_ENABLE_DTLS) && !defined(TO_DISABLE_DTLS_RETRANSMISSION)
			tls_ctx->flight_offset = 0;
			tls_ctx->pbuf = tls_ctx->flight_buf;
#endif
			next_rx = 0;
			tls_ctx->state = TO_TLS_STATE_FLIGHT_3_INIT;
			break;
		case TO_TLS_STATE_CLIENT_HELLO_WITH_COOKIE:
			ret = TOSE_tls_get_client_hello(tls_ctx->ctx, timestamp, tls_ctx->pbuf + TLS_FLIGHT_HEADER_SIZE, &len16);
			if (ret != TORSP_SUCCESS) { break; }
			TO_LOG_INF("==> ClientHello (with cookie",0);
			len = (uint32_t)len16;
#endif
			tls_ctx->state = TO_TLS_STATE_FLIGHT_4;
			FALL_THROUGH
		case TO_TLS_STATE_FLIGHT_4:
			TO_LOG_INF("*** Flight 4 ***",0);
			next_rx = 1;
			tls_ctx->state = TO_TLS_STATE_FLIGHT_4_INIT;
			break;
		case TO_TLS_STATE_SERVER_HELLO:
			{
				TO_LOG_INF("<== ServerHello",0);
				ret = TOSE_tls_handle_server_hello(tls_ctx->ctx, tls_ctx->pbuf, len);
				if (ret != TORSP_SUCCESS) {
					break;
				}

				uint8_t *p = tls_ctx->pbuf + _TLS_HANDSHAKE_HEADER_SIZE + 2 * sizeof(uint8_t) + TO_TLS_RANDOM_SIZE;
				uint16_t offset = 0;
				/* Check session ID */
				uint8_t session_id_len = p[offset++];
				uint16_t tmp16;
				if (session_id_len &&
						(session_id_len == tls_ctx->client_session_id_len) &&
						! TO_secure_memcmp(tls_ctx->client_session_id,
							p + offset,
							session_id_len)) {
					TO_LOG_INF("Session resumption detected",0);
					tls_ctx->abbreviated_handshake = 1;
					tls_ctx->state = TO_TLS_STATE_SERVER_CHANGE_CIPHER_SPEC;
				}
				offset += session_id_len;
				GET_BE16_NOINC(p, offset, tmp16);
				tls_ctx->cipher_suite = (TO_tls_cipher_suite_t)tmp16;
				ret_lib = _tls_set_types(tls_ctx);
				if (ret_lib != TO_OK) { break; }
				TO_LOG_INF("Detected cipher suite: %04x", tls_ctx->cipher_suite);
				offset += sizeof(uint16_t);
				/* Skip compression method */
				offset += sizeof(uint8_t);
				if (p + offset + sizeof(uint16_t) <= tls_ctx->pbuf + len) {
					/* Skip extensions length */
					offset += sizeof(uint16_t);
				}
				/* Parse extensions */
				while (p + offset + 2 * sizeof(uint16_t) < tls_ctx->pbuf + len) {
					uint16_t ext_id;
					uint16_t ext_len;
					GET_BE16(p, offset, ext_id);
					GET_BE16(p, offset, ext_len);
					switch (ext_id) {
#ifdef TO_ENABLE_DTLS
						case TO_TLS_EXTENSION_CONNECTION_ID:
							tls_ctx->connection_id_len = p[offset];
							TO_secure_memcpy(tls_ctx->connection_id, p + offset + sizeof(uint8_t), tls_ctx->connection_id_len);
							TO_LOG_INF("Detected ConnectionID (%u bytes):", tls_ctx->connection_id_len);
							TO_LOG_INF_HEX(tls_ctx->connection_id, tls_ctx->connection_id_len);
							break;
#endif
						default:
							break;
					}
					offset += ext_len;
				}
			}
			if (!tls_ctx->abbreviated_handshake) {
				switch (tls_ctx->cipher_suite_type) {
					case TO_TLS_CIPHER_SUITE_ECDHE:
						tls_ctx->state = TO_TLS_STATE_SERVER_CERTIFICATE;
						break;
					case TO_TLS_CIPHER_SUITE_PSK:
						tls_ctx->state = TO_TLS_STATE_SERVER_KEY_EXCHANGE;
						break;
					default:
						TO_LOG_ERR("No next state defined for cipher suite %04x",
								tls_ctx->cipher_suite);
						tls_ctx->state = TO_TLS_STATE_HANDSHAKE_FAILED;
				}
			}
			break;
		case TO_TLS_STATE_SERVER_CERTIFICATE:
			TO_LOG_INF("<== Certificate",0);
#ifndef TO_DISABLE_API_HELPER_TLS_HANDLE_SERVER_CERTIFICATE
			ret_lib = TOSE_helper_tls_handle_server_certificate(tls_ctx->ctx, tls_ctx->pbuf, len);
			if (ret_lib != TO_OK) {
				break;
			}
#else
			ret = TOSE_tls_handle_server_certificate(tls_ctx->ctx, tls_ctx->pbuf, len);
			if (ret != TORSP_SUCCESS) {
				break;
			}
#endif
			switch (tls_ctx->cipher_suite_type) {
				case TO_TLS_CIPHER_SUITE_ECDHE:
					tls_ctx->state = TO_TLS_STATE_SERVER_KEY_EXCHANGE;
					break;
				default:
					TO_LOG_ERR("No next state defined for cipher suite %04x",
							tls_ctx->cipher_suite);
					tls_ctx->state = TO_TLS_STATE_HANDSHAKE_FAILED;
			}
			break;
		case TO_TLS_STATE_SERVER_KEY_EXCHANGE:
			TO_LOG_INF("<== ServerKeyExchange",0);
#ifndef TO_DISABLE_API_HELPER_TLS_HANDLE_SERVER_KEY_EXCHANGE
			ret_lib = TO_ERROR | TORSP_UNKNOWN_CMD;
			if (tls_ctx->cipher_suite_type == TO_TLS_CIPHER_SUITE_ECDHE) {
				ret_lib = TOSE_helper_tls_handle_server_key_exchange(tls_ctx->ctx, tls_ctx->pbuf, len);
			}
			if (TO_SE_ERRCODE(ret_lib) == TORSP_UNKNOWN_CMD)
#endif
			{
				ret_lib = TO_OK;
				ret = TOSE_tls_handle_server_key_exchange(tls_ctx->ctx, tls_ctx->pbuf, len);
				if (ret != TORSP_SUCCESS) {
					break;
				}
			}
#ifndef TO_DISABLE_API_HELPER_TLS_HANDLE_SERVER_KEY_EXCHANGE
			else if (ret_lib != TO_OK) { break; }
#endif
			switch (tls_ctx->cipher_suite_type) {
				case TO_TLS_CIPHER_SUITE_ECDHE:
					tls_ctx->state = TO_TLS_STATE_SERVER_CERTIFICATE_REQUEST;
					break;
				case TO_TLS_CIPHER_SUITE_PSK:
					tls_ctx->state = TO_TLS_STATE_SERVER_HELLO_DONE;
					break;
				default:
					TO_LOG_ERR("No next state defined for cipher suite %04x",
							tls_ctx->cipher_suite);
					tls_ctx->state = TO_TLS_STATE_HANDSHAKE_FAILED;
			}
			break;
		case TO_TLS_STATE_SERVER_CERTIFICATE_REQUEST:
			TO_LOG_INF("<== CertificateRequest",0);
			ret = TOSE_tls_handle_certificate_request(tls_ctx->ctx, tls_ctx->pbuf, len);
			if (ret != TORSP_SUCCESS) {
				break;
			}
			tls_ctx->state = TO_TLS_STATE_SERVER_HELLO_DONE;
			tls_ctx->auth_client = 1;
			break;
		case TO_TLS_STATE_SERVER_HELLO_DONE:
			TO_LOG_INF("<== ServerHelloDone",0);
			ret = TOSE_tls_handle_server_hello_done(tls_ctx->ctx, tls_ctx->pbuf, len);
			if (ret != TORSP_SUCCESS) {
				break;
			}
#if !defined(TO_DISABLE_TLS_MEDIATOR)
			if (tls_ctx->is_rsa) {
				tls_ctx->state = TO_TLS_STATE_MEDIATOR_CERTIFICATE;
				break;
			}
			FALL_THROUGH
		case TO_TLS_STATE_MEDIATOR_CERTIFICATE:
			if (tls_ctx->is_rsa) {
				TO_LOG_INF("<== MediatorCertificate",0);
				ret = TOSE_tls_handle_mediator_certificate(tls_ctx->ctx, tls_ctx->pbuf, len);
				if (ret != TORSP_SUCCESS) {
					break;
				}
			}
#endif
			tls_ctx->state = TO_TLS_STATE_FLIGHT_5;
			FALL_THROUGH
		case TO_TLS_STATE_FLIGHT_5:
			TO_LOG_INF("*** Flight 5 ***",0);
#if defined(TO_ENABLE_DTLS)
#if !defined(TO_DISABLE_DTLS_RETRANSMISSION)
			tls_ctx->flight_offset = 0;
			tls_ctx->pbuf = tls_ctx->flight_buf;
#else
			tls_ctx->pbuf = tls_ctx->flight_buf = tls_ctx->buf + _TLS_HEADER_SIZE + tls_ctx->connection_id_len;
#endif
#endif
			next_rx = 0;
			if (tls_ctx->auth_client) {
				tls_ctx->state = TO_TLS_STATE_FLIGHT_5_INIT;
			} else {
				tls_ctx->state = TO_TLS_STATE_FLIGHT_5_INIT_NO_CLIENT_AUTH;
			}
			break;
		case TO_TLS_STATE_CLIENT_CERTIFICATE:
#ifndef TO_DISABLE_API_HELPER_TLS_GET_CERTIFICATE
			ret_lib = TOSE_helper_tls_get_certificate(tls_ctx->ctx, tls_ctx->pbuf + TLS_FLIGHT_HEADER_SIZE, &len16);
			if (TO_SE_ERRCODE(ret_lib) == TORSP_UNKNOWN_CMD)
#endif
			{
				ret_lib = TO_OK;
				/* Try to fallback on old method */
				ret = TOSE_tls_get_certificate(tls_ctx->ctx, tls_ctx->pbuf + TLS_FLIGHT_HEADER_SIZE, &len16);
				if (ret != TORSP_SUCCESS) {
					break;
				}
			}
#ifndef TO_DISABLE_API_HELPER_TLS_GET_CERTIFICATE
			else {
				if (ret_lib != TO_OK) {
					break;
				}
			}
#endif
			TO_LOG_INF("==> Certificate",0);
			len = (uint32_t)len16;
			tls_ctx->state = TO_TLS_STATE_CLIENT_KEY_EXCHANGE;
			break;
		case TO_TLS_STATE_CLIENT_KEY_EXCHANGE:
			ret = TOSE_tls_get_client_key_exchange(tls_ctx->ctx, tls_ctx->pbuf + TLS_FLIGHT_HEADER_SIZE, &len16);
			if (ret != TORSP_SUCCESS) {
				break;
			}
			TO_LOG_INF("==> ClientKeyExchange",0);
			len = (uint32_t)len16;
			switch (tls_ctx->cipher_suite_type) {
				case TO_TLS_CIPHER_SUITE_ECDHE:
					if (tls_ctx->auth_client) {
						tls_ctx->state = TO_TLS_STATE_CLIENT_CERTIFICATE_VERIFY;
					} else {
						tls_ctx->state = TO_TLS_STATE_CLIENT_CHANGE_CIPHER_SPEC;
					}
					break;
				case TO_TLS_CIPHER_SUITE_PSK:
					tls_ctx->state = TO_TLS_STATE_CLIENT_CHANGE_CIPHER_SPEC;
					break;
				default:
					TO_LOG_ERR("No next state defined for cipher suite %04x",
							tls_ctx->cipher_suite);
					tls_ctx->state = TO_TLS_STATE_HANDSHAKE_FAILED;
			}
			break;

		case TO_TLS_STATE_CLIENT_CERTIFICATE_VERIFY:
			ret = TOSE_tls_get_certificate_verify(tls_ctx->ctx, tls_ctx->pbuf + TLS_FLIGHT_HEADER_SIZE, &len16);
			if (ret != TORSP_SUCCESS) {
				break;
			}
			TO_LOG_INF("==> CertificateVerify",0);
			len = (uint32_t)len16;
			tls_ctx->state = TO_TLS_STATE_CLIENT_CHANGE_CIPHER_SPEC;
			break;

		case TO_TLS_STATE_CLIENT_CHANGE_CIPHER_SPEC:
			ret = TOSE_tls_get_change_cipher_spec(tls_ctx->ctx, tls_ctx->pbuf + TLS_FLIGHT_HEADER_SIZE, &len16);
			if (ret != TORSP_SUCCESS) {
				break;
			}
			TO_LOG_INF("==> ChangeCipherSpec",0);
			if ((!tls_ctx->abbreviated_handshake)
					&& (tls_ctx->setup_cipher_ctx)){
				/* give negociated parameters and derived keys
				 * to the upper layer's cipher_ctx */
				ret_lib = setup_cipher_ctx(tls_ctx);
			}
			type = TO_TLS_RECORD_TYPE_CHANGE_CIPHER_SPEC;
			len = (uint32_t)len16;
			tls_ctx->state = TO_TLS_STATE_CLIENT_FINISHED;
			break;

		case TO_TLS_STATE_CLIENT_FINISHED:
			tls_ctx->encryption = 1;
#ifdef TO_ENABLE_DTLS
			++tls_ctx->epoch;
#else
			tls_ctx->pbuf += tls_ctx->iv_len;
#endif
			ret = TOSE_tls_get_finished(tls_ctx->ctx, tls_ctx->pbuf + TLS_FLIGHT_HEADER_SIZE, &len16);
			if (ret != TORSP_SUCCESS) { break; }
			TO_LOG_INF("==> Finished",0);
			len = (uint32_t)len16;
			if (tls_ctx->abbreviated_handshake) {
				tls_ctx->state = TO_TLS_STATE_HANDSHAKE_DONE;
				break;
			} else {
				tls_ctx->state = TO_TLS_STATE_FLIGHT_6;
			}
			FALL_THROUGH
		case TO_TLS_STATE_FLIGHT_6:
			TO_LOG_INF("*** Flight 6 ***",0);
			next_rx = 1;
			tls_ctx->state = TO_TLS_STATE_FLIGHT_6_INIT;
			break;
		case TO_TLS_STATE_SERVER_CHANGE_CIPHER_SPEC:
			TO_LOG_INF("<== ChangeCipherSpec",0);
			ret = TOSE_tls_handle_change_cipher_spec(tls_ctx->ctx, tls_ctx->pbuf, len);
			if (ret != TORSP_SUCCESS) {
				break;
			}
			if ((tls_ctx->abbreviated_handshake)
					&& (tls_ctx->setup_cipher_ctx)){
				/* give negociated parameters and derived keys
				 * to the upper layer's cipher_ctx */
				ret_lib = setup_cipher_ctx(tls_ctx);
			}
			tls_ctx->decryption = 1;
			tls_ctx->state = TO_TLS_STATE_SERVER_FINISHED;
			break;
		case TO_TLS_STATE_SERVER_FINISHED:
			TO_LOG_INF("<== Finished",0);
			ret = TOSE_tls_handle_finished(tls_ctx->ctx, tls_ctx->pbuf, len);
			if (ret != TORSP_SUCCESS) {
				break;
			}
			if (tls_ctx->abbreviated_handshake) {
				tls_ctx->state = TO_TLS_STATE_CLIENT_CHANGE_CIPHER_SPEC;
#if defined(TO_ENABLE_DTLS)
#if !defined(TO_DISABLE_DTLS_RETRANSMISSION)
				tls_ctx->flight_offset = 0;
				tls_ctx->pbuf = tls_ctx->flight_buf;
#else
				tls_ctx->pbuf = tls_ctx->flight_buf = tls_ctx->buf + _TLS_HEADER_SIZE + tls_ctx->connection_id_len;
#endif
#endif
				next_rx = 0;
			} else {
				tls_ctx->state = TO_TLS_STATE_HANDSHAKE_DONE;
			}
			break;
		default:
			TO_LOG_ERR("Unknown state %u\n", tls_ctx->state);
			break;
	}

	if (ret != TORSP_SUCCESS || ret_lib != TO_OK) {
		ret_lib = (ret == TORSP_SUCCESS) ? ret_lib : (ret | TO_ERROR);
		TO_LOG_ERR("TO call failed (state: %04x, ret: %02x)", tls_ctx->state, ret_lib);
		tls_alert(tls_ctx, ALERT_LEVEL_FATAL, ALERT_DESC_HANDSHAKE_FAILURE);
		return ret_lib;
	}

	if (!tls_ctx->rx) {

		/* Handle buffer overflow */
		if (tls_ctx->pbuf + len > tls_ctx->flight_buf + TOSE_HELPER_TLS_FLIGHT_BUFFER_SIZE) {
			TO_LOG_ERR("flight buffer overflow, %lu bytes needed",
					(unsigned long int)((tls_ctx->pbuf - tls_ctx->flight_buf) + len));
			return TO_ERROR;
		}

#ifdef TO_ENABLE_DTLS
		ret_lib = _tls_send(tls_ctx, type, tls_ctx->pbuf, len,
				tls_ctx->epoch,
				tls_ctx->encryption);
#else
		ret_lib = tls_send_record(tls_ctx, type, tls_ctx->pbuf, len);
#endif
		if (ret_lib != TO_OK) {
			TO_LOG_ERR("Failed to send %u bytes", (uint32_t)len);
			return ret_lib;
		}
#if defined(TO_ENABLE_DTLS) && !defined(TO_DISABLE_DTLS_RETRANSMISSION)
		tls_ctx->flight_offset += TLS_FLIGHT_HEADER_SIZE + len;
#endif
	}

	tls_ctx->rx = next_rx;

	if (tls_ctx->state != TO_TLS_STATE_HANDSHAKE_DONE) {
		return TO_AGAIN;
	}

#ifdef TO_DISABLE_TLS_FULL_DUPLEX
	/* handshake is OK, split the I/O buffer to enable full duplex */
	tls_ctx->rxbuf = tls_ctx->buf;
	tls_ctx->rxbuf_len = TOSE_HELPER_TLS_RX_BUFFER_SIZE;
	tls_ctx->txbuf = tls_ctx->buf + TOSE_HELPER_TLS_TX_BUFFER_OFFSET;
	tls_ctx->txbuf_len = TOSE_HELPER_TLS_TX_BUFFER_SIZE;
#endif

	tls_ctx->tx_ptrec_len_max = get_max_ptrec_len(tls_ctx);

	return TO_OK;
}

TO_lib_ret_t TOSE_helper_tls_do_handshake(
		TOSE_helper_tls_ctx_t *tls_ctx
)
{
	TO_lib_ret_t ret;

	while ((ret = TOSE_helper_tls_do_handshake_step(tls_ctx)) == TO_AGAIN);

	if (ret != TO_OK) {
		TO_LOG_ERR("TOSE_helper_tls_do_handshake_step() failed",0);
		return ret;
	}

	return ret;
}

TO_lib_ret_t TOSE_helper_tls_get_certificate_slot(
		TOSE_helper_tls_ctx_t *tls_ctx,
		uint8_t *slot
)
{
	TO_ret_t ret;

	if ((ret = TOSE_tls_set_session(tls_ctx->ctx, tls_ctx->index)) != TORSP_SUCCESS) {
		if (tls_ctx->index == 0) {
			TO_LOG_WRN("Failed to set TLS session, trying to continue as it is first session",0);
		} else {
			TO_LOG_ERR("Failed to set TLS session",0);
			return TO_ERROR | ret;
		}
	}

	ret = TOSE_tls_get_certificate_slot(tls_ctx->ctx, slot);
	if (ret != TORSP_SUCCESS) {
		return TO_ERROR | ret;
	}

	return TO_OK;
}

TO_lib_ret_t TOSE_helper_tls_send(
		TOSE_helper_tls_ctx_t *tls_ctx,
		const uint8_t *msg,
		const uint32_t msg_len
)
{
	TO_lib_ret_t ret;

	if (tls_ctx->state != TO_TLS_STATE_HANDSHAKE_DONE) {
		/* application data cannot be sent if handshake is not done */
		return TO_ERROR;
	}

	uint32_t hdr_len = _TLS_HEADER_SIZE;
	uint32_t max_fragment_len, sent_len = 0;
#ifdef TO_ENABLE_DTLS
	if (tls_ctx->connection_id_len > 0) {
		hdr_len += tls_ctx->connection_id_len + 1;
	}
#endif
	max_fragment_len = tls_ctx->tx_ptrec_len_max
		- hdr_len - TLS_FLIGHT_HEADER_SIZE;
	/* max length is bound to 2**14 in TLS protocol */
	max_fragment_len = MIN(max_fragment_len, TO_TLS_RECORD_MAX_SIZE);

	while (sent_len < msg_len) {
		uint32_t fragment_len = MIN(msg_len - sent_len, max_fragment_len);
#ifdef TO_ENABLE_DTLS
		TO_secure_memcpy(tls_ctx->txbuf + hdr_len + TLS_FLIGHT_HEADER_SIZE,
				msg + sent_len, fragment_len);
		ret = _tls_send(tls_ctx, TO_TLS_RECORD_TYPE_APPLICATION_DATA,
						tls_ctx->txbuf + hdr_len, fragment_len,
						tls_ctx->epoch, 1);
#else
		ret = tls_send_record(tls_ctx, TO_TLS_RECORD_TYPE_APPLICATION_DATA,
						msg + sent_len, fragment_len);
#endif
		if (ret != TO_OK) {
			return ret;
		}
		sent_len += fragment_len;

	}
	return TO_OK;
}

TO_lib_ret_t TOSE_helper_tls_receive(
		TOSE_helper_tls_ctx_t *tls_ctx,
		uint8_t *msg,
		uint32_t max_msg_len,
		uint32_t *msg_len,
		int32_t timeout
)
{
	TO_lib_ret_t ret;
#ifdef TO_ENABLE_DTLS
	TO_tls_record_type_t type = TO_TLS_RECORD_TYPE_APPLICATION_DATA;

	do {
		if ((ret = dtls_receive(tls_ctx, &type, tls_ctx->rxbuf, tls_ctx->rxbuf_len, msg_len, max_msg_len, 1, timeout)) != TO_OK) {
			return ret;
		}
		if (max_msg_len < *msg_len) {
			TO_LOG_ERR("Message too long for given buffer (%u > %u)", max_msg_len, *msg_len);
			return TO_ERROR;
		}
		if (type != TO_TLS_RECORD_TYPE_APPLICATION_DATA) {
			if (type == TO_TLS_RECORD_TYPE_ALERT) {
				uint8_t *p = tls_ctx->rxbuf + _TLS_HEADER_SIZE;
				tls_handle_alert(tls_ctx, p[0], p[1]);
			} else {
				TO_LOG_WRN("Bad record type %02x, %02x expected",
						type, TO_TLS_RECORD_TYPE_APPLICATION_DATA);
			}
		}
	} while (type != TO_TLS_RECORD_TYPE_APPLICATION_DATA);
	TO_secure_memcpy(msg, tls_ctx->rxbuf + _TLS_HEADER_SIZE, *msg_len);
	return TO_OK;
#else
	do {
		ret = TOSE_helper_tls_recv(tls_ctx, msg, max_msg_len, msg_len, timeout);
	} while (ret == TO_AGAIN);
	return ret;
#endif
}

TO_lib_ret_t TOSE_helper_tls_recv(
		TOSE_helper_tls_ctx_t *tls_ctx,
		uint8_t *msg,
		uint32_t max_msg_len,
		uint32_t *msg_len,
		int32_t timeout_ms
)
{
#ifdef TO_ENABLE_DTLS
	return TOSE_helper_tls_receive(tls_ctx, msg, max_msg_len, msg_len, timout_ms);
#else
	TO_lib_ret_t ret = TO_OK;
	struct record *record = &tls_ctx->rx_rec;
	uint32_t rec_len;

	if (tls_ctx->state != TO_TLS_STATE_HANDSHAKE_DONE) {
		/* application data cannot be received if handshake is not done */
		return TO_ERROR;
	}
	if ((ret = tls_receive_record(tls_ctx, timeout_ms)) != TO_OK) {
		return ret;
	}
	switch (record->type) {
	case TO_TLS_RECORD_TYPE_APPLICATION_DATA:
		/* give back the maximum data to the upper layer */
		rec_len = record->length - record->offset;
		*msg_len = (rec_len > max_msg_len) ? max_msg_len : rec_len;
		TO_secure_memcpy(msg, record->fragment + record->offset, *msg_len);
		record->offset += *msg_len; /* update record with consumed data */
		break;
	case TO_TLS_RECORD_TYPE_ALERT:
		tls_handle_alert(tls_ctx, record->fragment[0], record->fragment[1]);
		if (tls_ctx->state == TO_TLS_STATE_HANDSHAKE_DONE) {
			record->offset = record->length; /* update record with consumed data */
			ret = TO_AGAIN; /* the alert is not fatal, but we still have no data */
		} else {
			ret = TO_ERROR;
		}
		break;
	default:
		/* unexpected record */
		tls_alert(tls_ctx, ALERT_LEVEL_FATAL, ALERT_DESC_UNEXPECTED_MESSAGE);
		ret = TO_ERROR;
		break;
	}
	return ret;
#endif
}
#endif // TO_DISABLE_TLS_STACK

#endif //TO_DISABLE_TLS_HELPER
