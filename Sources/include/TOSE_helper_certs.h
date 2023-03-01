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
 * @file TOSE_helper_certs.h
 * @brief
 */

#ifndef _TOSE_HELPER_CERTS_H_
#define _TOSE_HELPER_CERTS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "TO_defs.h"
#include "TO_retcodes.h"

/** @addtogroup helper_certs
 * @{ */

/**
 * @brief Handle certificate chain at once
 * @param[in] ctx Pointer to the SE context
 * @param[in] ca_key_index CA key index (use TO_CA_IDX_AUTO to enable Authority Key
 *                     Identifier based CA detection)
 * @param[in] chain_certificate Certificate chain
 * @param[in] chain_certificate_length Certificate chain length
 *
 * Certificates must be in X509 DER (binary) format.
 * Certificates must be ordered as following:
 * - Final certificate
 * - Intermediate CA certificates (if any)
 * - Root CA certificate (optional as it must already be trusted by the
 *   Secure Element)
 *
 * Each certificate must be signed by the next.
 *
 * @return TO_OK if data has been sent successfully, else TO_ERROR
 */
extern TO_lib_ret_t TOSE_helper_verify_chain_certificate_and_store(TOSE_ctx_t *ctx,
		const uint8_t ca_key_index,
		const uint8_t *chain_certificate,
		const uint16_t chain_certificate_length);

/**
 * @brief Handle CA certificate chain at once
 * @param[in] ctx Pointer to the SE context
 * @param[in] ca_key_index CA key index (use TO_CA_IDX_AUTO to enable Authority Key
 *                     Identifier based CA detection)
 * @param[in] subca_key_index subCA index to store subCA
 * @param[in] chain_certificate Certificate chain
 * @param[in] chain_certificate_length Certificate chain length
 *
 * Certificates must be in X509 DER (binary) format.
 * Certificates must be ordered as following:
 * - Intermediate CA certificates
 * - Root CA certificate (optional as it must already be trusted by the
 *   Secure Element)
 *
 * Each certificate must be signed by the next.
 *
 * @return TO_OK if data has been sent successfully, else TO_ERROR
 */
extern TO_lib_ret_t TOSE_helper_verify_chain_ca_certificate_and_store(TOSE_ctx_t *ctx,
		const uint8_t ca_key_index,
		const uint8_t subca_key_index,
		const uint8_t *chain_certificate,
		const uint16_t chain_certificate_length);


/**
 * @brief Set new certificate from previously generated CSR
 * @param[in] ctx Pointer to the SE context
 * @param[in] certificate_index Requested certificate index
 * @param[in] certificate New certificate data (x509 DER formated)
 * @param[in] size New certificate size
 *
 * Set a x509 DER formated certificate according to the given index.
 * The new certificate must be signed by a CA trusted by the Secure Element.
 * Secure Element certificate size cannot exceed TO_CERT_X509_MAXSIZE.
 *
 * @return TO_OK if certificate has been sent successfully, else TO_ERROR
 */
extern TO_lib_ret_t TOSE_helper_set_certificate_x509(
		TOSE_ctx_t *ctx,
		const uint8_t certificate_index,
		const uint8_t* certificate,
		const uint16_t size);

/**
 * @brief Returns one of the Secure Element x509 DER formated certificates, and
 * optionnaly a challenge signed with the certificate private key
 * @param[in,out] ctx SE context
 * @param[in] certificate_index Index of the certificate to return, starting from 0
 * @param[in] challenge Challenge to be signed, NULL if nothing to sign
 * @param[in] challenge_length Length of the challenge to be signed, 0 if nothing to sign
 * @param[out] certificate Returned certificate data, this buffer should be at least
 * TO_CERT_X509_MAXSIZE
 * @param[in,out] size	input: the certificate's buffer size,
 * 			output: the certificate's real size
 * @param[out] signature Returned signature, NULL if nothing to sign
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_INVALID_LEN: wrong length
 * - TORSP_NOT_AVAILABLE: certificate Format not supported
 * - TORSP_ARG_OUT_OF_RANGE: invalid Certificate Number
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR: generic error
 */
extern TO_lib_ret_t TOSE_helper_get_certificate_x509_and_sign(
		TOSE_ctx_t *ctx, const uint8_t certificate_index,
		const uint8_t *challenge, const uint16_t challenge_length,
		uint8_t *certificate, uint16_t *size, uint8_t signature[TO_SIGNATURE_SIZE]);
/* @} */

#ifdef __cplusplus
}
#endif

#endif /* _TOSE_HELPER_CERTS_H_ */

