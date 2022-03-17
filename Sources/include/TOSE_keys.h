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
 * @file TOSE_keys.h
 * @brief
 */

#ifndef _TOSE_KEYS_H_
#define _TOSE_KEYS_H_

#ifndef TOSE_KEYS_API
#ifdef __linux__
#define TOSE_KEYS_API
#elif _WIN32
#define TOSE_KEYS_API __declspec(dllexport)
#else
#define TOSE_KEYS_API
#endif /* __LINUX__ */
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include "TO_defs.h"

/** @addtogroup keys
 * @{ */

/**
 * @brief Set remote public key
 * @param[in] ctx Pointer to the SE context
 * @param[in] key_index Index of the key to be set, starting from 0
 * @param[in] public_key Key to set
 * @param[in] signature Public key signature with the certificate previously sent
 * with verify_certificate_and_store()
 *
 * This command requests the Secure Element to store, at the given index, a
 * public key to be used in the ECIES process.
 *
 * A signature is attached to the new public key and must be verified with the
 * certificate previously sent using TOSE_verify_certificate_and_store().
 * This command is disabled if public key is configured as non-writable during
 * (pre-)personalization.
 *
 * A CA signed certificate is first sent to the Secure Element using
 * TOSE_verify_certificate_and_store(), TOSE_get_challenge_and_store(), and
 * TOSE_verify_challenge_signature() commands (remote authentication).  If the
 * Certificate Authority signature of the certificate is validated, the public
 * key of the certificate is stored. Then, this certificate is used to verify
 * the signature of any ephemeral public key sent using
 * TOSE_set_remote_public_key().  The signature is calculated on all bytes of the
 * New Remote Public Key.  If the signature verification failed, Secure Element
 * will not store the public key.  Please refer to Secure Element Datasheet -
 * “Chain of Trust between Authentication and Secure Messaging” chapter for
 * more details.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_BAD_SIGNATURE: invalid signature
 * - TORSP_ARG_OUT_OF_RANGE: invalid key index
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR: generic error
 */
TOSE_KEYS_API TO_ret_t TOSE_set_remote_public_key(TOSE_ctx_t *ctx, const uint8_t key_index,
		const uint8_t public_key[TO_ECC_PUB_KEYSIZE],
		const uint8_t signature[TO_SIGNATURE_SIZE]);

/**
 * @brief Renew ECC keys pair
 * @param[in] ctx Pointer to the SE context
 * @param[in] key_index Index of the ECC key pair to renew, starting from 0
 *
 * Renews Elliptic Curve key pair for the corresponding index.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_ARG_OUT_OF_RANGE: invalid key index
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TOSE_KEYS_API TO_ret_t TOSE_renew_ecc_keys(TOSE_ctx_t *ctx, const uint8_t key_index);

/**
 * @brief Get the public key corresponding to the given index, and the
 * signature of this public key.
 * @param[in] ctx Pointer to the SE context
 * @param[in] key_index Public key index
 * @param[out] public_key The requested public key
 * @param[out] signature Public key signature, can be verified using the public key
 * of the certificate returned by TOSE_get_certificate()
 *
 * Signature can be verified using the public key of the certificate returned
 * by TOSE_get_certificate().
 *
 * This signature is calculated on all bytes of the Public Key in the TO
 * response.
 * Key pair used to generate and verify this signature is the one associated to
 * certificate sent by the Secure Element in get_certificate() or
 * get_certificate_and_sign() commands.
 * Please refer to Secure Element Datasheet - “Chain of Trust between
 * Authentication and Secure Messaging” chapter for more details.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_ARG_OUT_OF_RANGE: invalid key index
 * - TO_INVALID_RESPONSE_LENGTH: invalid response length
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR: generic error
 */
TOSE_KEYS_API TO_ret_t TOSE_get_public_key(TOSE_ctx_t *ctx, const uint8_t key_index,
		uint8_t public_key[TO_ECC_PUB_KEYSIZE],
		uint8_t signature[TO_SIGNATURE_SIZE]);

/**
 * @brief Get the public key corresponding to the given index.
 * @param[in] ctx Pointer to the SE context
 * @param[in] key_index Public key index
 * @param[out] public_key The requested public key
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_ARG_OUT_OF_RANGE: invalid key index
 * - TO_INVALID_RESPONSE_LENGTH: invalid response length
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR: generic error
 */
TOSE_KEYS_API TO_ret_t TOSE_get_unsigned_public_key(TOSE_ctx_t *ctx, const uint8_t key_index,
		uint8_t public_key[TO_ECC_PUB_KEYSIZE]);

/**
 * @brief Renew shared keys
 * @param[in] ctx Pointer to the SE context
 * @param[in] key_index Index of the Secure Element ephemeral public/private key
 * pair, starting from 0
 * @param[in] public_key_index Index where the remote public key is stored in the
 * Secure Element, starting from 0.
 *
 * Renews shared keys (AES and HMAC), stored at the same index as Secure
 * Element ephemeral public/private key pair.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_ARG_OUT_OF_RANGE: invalid key index
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TOSE_KEYS_API TO_ret_t TOSE_renew_shared_keys(TOSE_ctx_t *ctx, const uint8_t key_index,
		const uint8_t public_key_index);

/**
 * @brief Get key fingerprint
 * @param[in] ctx Pointer to the SE context
 * @param[in] key_type Type of key
 * @param[in] key_index Index of the key for given type starting from 0
 * @param[in] fingerprint 3 bytes fingerprint of the key
 *
 * Retrieve the 3 bytes fingerprint of the key corresponding to given type and
 * index.
 *
 * See `Keys fingerprints` chapter for defails about fingerprint computation.
 *
 * This function is available only for fixed keys.
 *
 * Note: keys indexes starts from 0 for each key type. For example, first AES
 * key and first Public Key have both index 0.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_ARG_OUT_OF_RANGE: invalid key type and/or key index
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TOSE_KEYS_API TO_ret_t TOSE_get_key_fingerprint(TOSE_ctx_t *ctx, TO_key_type_t key_type,
		uint8_t key_index,
		uint8_t* fingerprint[TO_KEY_FINGERPRINT_SIZE]);

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* _TOSE_KEYS_H_ */

