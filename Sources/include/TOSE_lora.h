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
 * @file TOSE_lora.h
 * @brief
 */

#ifndef _TOSE_LORA_H_
#define _TOSE_LORA_H_

#ifndef TOSE_LORA_API
#ifdef __linux__
#define TOSE_LORA_API
#elif _WIN32
#define TOSE_LORA_API __declspec(dllexport)
#else
#define TOSE_LORA_API
#endif /* __LINUX__ */
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include "TO_defs.h"

/** @addtogroup lora
 * @{ */

/**
 * @brief Computes the LoRaMAC frame MIC field
 * @param[in] ctx Pointer to the SE context
 * @param[in] data Data buffer
 * @param[in] data_length Data buffer size
 * @param[in] address Device address
 * @param[in] direction: Frame direction [0: uplink, 1 downlink]
 * @param[in] seq_counter Frame sequence counter
 * @param[out] mic Computed MIC field
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_*: for any error occurred while handling command
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR: generic error
 */
TOSE_LORA_API TO_ret_t TOSE_lora_compute_mic(TOSE_ctx_t *ctx, const uint8_t *data, uint16_t data_length,
		uint32_t address, uint8_t direction, uint32_t seq_counter,
		uint8_t mic[TO_LORA_MIC_SIZE]);

/**
 * @brief Computes the LoRaMAC payload encryption
 * @param[in] ctx Pointer to the SE context
 * @param[in] data Data buffer
 * @param[in] data_length Data buffer size
 * @param[in] fport Frame port (as pointer to keep retrocompatibility)
 * @param[in] address Device address
 * @param[in] direction: Frame direction [0: uplink, 1 downlink]
 * @param[in] seq_counter Frame sequence counter
 * @param[out] enc_buffer Encrypted buffer
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_*: for any error occurred while handling command
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR: generic error
 */
TOSE_LORA_API TO_ret_t TOSE_lora_encrypt_payload(TOSE_ctx_t *ctx, const uint8_t *data,
		uint16_t data_length, const uint8_t *fport,
		uint32_t address, uint8_t direction, uint32_t seq_counter,
		uint8_t *enc_buffer);

/**
 * @brief Computes the LoRaMAC Join Request frame
 * MIC field
 * @param[in] ctx Pointer to the SE context
 * @param[in] data Data buffer
 * @param[in] data_length Data buffer size
 * @param[out] mic Computed MIC field
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_*: for any error occurred while handling command
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR: generic error
 */
TOSE_LORA_API TO_ret_t TOSE_lora_join_compute_mic(TOSE_ctx_t *ctx, const uint8_t *data,
		uint16_t data_length, uint8_t mic[TO_LORA_MIC_SIZE]);

/**
 * @brief Computes the LoRaMAC join-accept frame decryption
 * MIC field
 * @param[in] ctx Pointer to the SE context
 * @param[in] data Data buffer
 * @param[in] data_length Data buffer size
 * @param[out] dec_buffer Decrypted buffer
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_*: for any error occurred while handling command
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR: generic error
 */
TOSE_LORA_API TO_ret_t TOSE_lora_decrypt_join(TOSE_ctx_t *ctx, const uint8_t *data, uint16_t data_length,
		uint8_t *dec_buffer);

/**
 * @brief Computes the LoRaMAC secret keys NwkSkey and AppSKey
 * @param[in] ctx Pointer to the SE context
 * @param[in] app_nonce Application nonce
 * @param[in] net_id Network ID
 * @param[in] dev_nonce Device nonce
 *
 * The keys are safely stored in the Secure Element and can’t be extracted.
 * They will be used in LoRaWAN Secure Element’s functions.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_*: for any error occurred while handling command
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR: generic error
 */
TOSE_LORA_API TO_ret_t TOSE_lora_compute_shared_keys(TOSE_ctx_t *ctx, const uint8_t *app_nonce,
		const uint8_t *net_id, uint16_t dev_nonce);

/** @} */

/** @addtogroup loracommon
 * @{ */

/**
 * @brief Get AppEUI
 * @param[in] ctx Pointer to the SE context
 * @param[out] app_eui Application EUI (big endian)
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_*: for any error occurred while handling command
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR: generic error
 */
TOSE_LORA_API TO_ret_t TOSE_lora_get_app_eui(TOSE_ctx_t *ctx, uint8_t app_eui[TO_LORA_APPEUI_SIZE]);

/**
 * @brief Get DevEUI
 * @param[in] ctx Pointer to the SE context
 * @param[out] dev_eui Device EUI (big endian)
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_*: for any error occurred while handling command
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR: generic error
 */
TOSE_LORA_API TO_ret_t TOSE_lora_get_dev_eui(TOSE_ctx_t *ctx, uint8_t dev_eui[TO_LORA_DEVEUI_SIZE]);

/**
 * @brief Get DevAddr
 * @param[in] ctx Pointer to the SE context
 * @param[out] dev_addr Device address (little endian)
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_*: for any error occurred while handling command
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR: generic error
 */
TOSE_LORA_API TO_ret_t TOSE_lora_get_dev_addr(TOSE_ctx_t *ctx, uint8_t dev_addr[TO_LORA_DEVADDR_SIZE]);

/** @} */

/** @addtogroup loraoptim
 * @{ */

/**
 * @brief Get encrypted join request payload
 * @param[in] ctx Pointer to the SE context
 * @param[out] data Join request payload
 *
 * The returned LoRaWAN "Join-Request" payload can be sent directly to the Radio
 * transceiver.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_*: for any error occurred while handling command
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR: generic error
 */
TOSE_LORA_API TO_ret_t TOSE_lora_get_join_request_phypayload(TOSE_ctx_t *ctx,
		uint8_t data[TO_LORA_JOINREQUEST_SIZE]);

/**
 * @brief Handle encrypted join accept
 * payload
 * @param[in] ctx Pointer to the SE context
 * @param[in] data Join accept payload (MHDR + payload + MIC)
 * @param[in] data_length Join accept payload size
 * @param[out] dec_buffer Decrypted join accept payload
 *
 * Decrypt LoRaWAN "Join Accept" frame and verify MIC. If verification succeeds,
 * compute NwkSKey and AppSKey, and return decrypted data.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_*: for any error occurred while handling command
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR: generic error
 */
TOSE_LORA_API TO_ret_t TOSE_lora_handle_join_accept_phypayload(TOSE_ctx_t *ctx, const uint8_t *data,
		const uint16_t data_length,
		uint8_t dec_buffer[TO_LORA_JOINACCEPT_CLEAR_MAXSIZE]);

/**
 * @brief Encrypt PHYPayload
 * @param[in] ctx Pointer to the SE context
 * @param[in] mhdr MHDR
 * @param[in] fctrl Frame control
 * @param[in] fopts Frame options (optional, FCtrl FOptsLen part must be 0 if
 * missing)
 * @param[in] fport  Frame port (optional, must be present if payload_size > 0)
 * @param[in] payload  payload to encrypt (optional)
 * @param[in] payload_size  payload size (must be 0 if payload is null)
 * @param[out] enc_buffer: Encrypted PHYPayload (size TO_LORA_MHDR_SIZE +
 *              TO_LORA_DEVADDR_SIZE + TO_LORA_FCTRL_SIZE +
 *              TO_LORA_FCNT_SIZE / 2 + FOptLen + (payload_size ?
 *              payload_size + 1 : 0) + TO_LORA_MIC_SIZE)
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_*: for any error occurred while handling command
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR: generic error
 */
TOSE_LORA_API TO_ret_t TOSE_lora_secure_phypayload(TOSE_ctx_t *ctx, const uint8_t mhdr,
		const uint8_t fctrl, const uint8_t *fopts, const uint8_t fport,
		const uint8_t *payload, const int payload_size,
		uint8_t *enc_buffer);

/**
 * @brief Decrypt PHYPayload
 * @param[in] ctx Pointer to the SE context
 * @param[in] data PHYPayload to decrypt
 * @param[in] data_length PHYPayload size
 * @param[out] dec_buffer: Decrypted PHYPayload (size data_length -
 * TO_LORA_MIC_SIZE)
 *
 * Verify MIC and decrypt (if verified) FRMPayload.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_*: for any error occurred while handling command
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR: generic error
 */
TOSE_LORA_API TO_ret_t TOSE_lora_unsecure_phypayload(TOSE_ctx_t *ctx, const uint8_t *data,
		const uint16_t data_length, uint8_t *dec_buffer);

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* _TOSE_LORA_H_ */

