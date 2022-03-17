/*
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (C) 2019-2021 Trusted Objects. All rights reserved.
 */

/**
 * @file TOSE_auth.h
 * @brief
 */

#ifndef _TOSE_AUTH_H_
#define _TOSE_AUTH_H_

#ifndef TOSE_AUTH_API
#ifdef __linux__
#define TOSE_AUTH_API
#elif _WIN32
#define TOSE_AUTH_API __declspec(dllexport)
#else
#define TOSE_AUTH_API
#endif /* __LINUX__ */
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include "TO_defs.h"

/** @addtogroup auth
 * @{ */

/**
 * @brief Returns the Elliptic Curve Digital Signature of the given data
 * @param[in] ctx Pointer to the SE contex
 * @param[in] key_index Key index to use for signature
 * @param[in] challenge Challenge to be signed
 * @param[in] challenge_length Challenge length (maximum 512)
 * @param[out] signature Returned challenge signature (64 bytes)
 *
 * Note that calling this function is equivalent to calling `TOSE_sha256()`
 * followed by `TOSE_sign_hash()`.
 *
 * Signature Size is twice the size of the ECC key in bytes.
 * With a 256 bits key, signature is 64 bytes.
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
TOSE_AUTH_API TO_ret_t TOSE_sign(TOSE_ctx_t *ctx, const uint8_t key_index,
		const uint8_t* challenge, const uint16_t challenge_length,
		uint8_t* signature);

/**
 * @brief Verifies the given Elliptic Curve Digital Signature of the
 * given data
 * @param[in] ctx Pointer to the SE context
 * @param[in] key_index Remote Public Key index to use for verification
 * @param[in] data Data to verify signature on
 * @param[in] data_length Data length (maximum 512)
 * @param[in] signature Expected data signature (64 bytes)
 *
 * The public key used for the signature verification must be previously
 * provided using the TOSE_set_remote_public_key() call.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_ARG_OUT_OF_RANGE: invalid key index
 * - TORSP_BAD_SIGNATURE: invalid signature
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TOSE_AUTH_API TO_ret_t TOSE_verify(TOSE_ctx_t *ctx, const uint8_t key_index,
		const uint8_t* data, const uint16_t data_length,
		const uint8_t* signature);

/**
 * @brief Returns the Elliptic Curve Digital Signature of the given
 * hash
 * @param[in] ctx Pointer to the SE context
 * @param[in] key_index Key index to use for signature
 * @param[in] hash Hash to be signed
 * @param[out] signature Returned hash signature
 *
 * Signature Size is twice the size of the ECC key in bytes.
 * With a 256 bits key, signature is 64 bytes.
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
TOSE_AUTH_API TO_ret_t TOSE_sign_hash(TOSE_ctx_t *ctx, const uint8_t key_index,
		const uint8_t hash[TO_HASH_SIZE], uint8_t* signature);

/**
 * @brief Verifies the given Elliptic Curve Digital
 * Signature of the data that generates the given hash
 * @param[in] ctx Pointer to the SE context
 * @param[in] key_index Remote Public Key index to use for verification
 * @param[in] hash Hash to verify signature on (32 bytes)
 * @param[in] signature Expected hash signature (64 bytes)
 *
 * The public key used for the signature verification must be previously
 * provided using the TOSE_set_remote_public_key() call.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_ARG_OUT_OF_RANGE: invalid key index
 * - TORSP_BAD_SIGNATURE: invalid signature
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TOSE_AUTH_API TO_ret_t TOSE_verify_hash_signature(TOSE_ctx_t *ctx, const uint8_t key_index,
		const uint8_t hash[TO_HASH_SIZE], const uint8_t* signature);

/**
 * @brief Returns subject common name of one of the Secure Element certificates
 * @param[in] ctx Pointer to the SE context
 * @param[in] certificate_index Requested certificate index
 * @param[out] subject_cn Returned certificate subject common name null terminated
 * string
 *
 * Request a certificate subject common name to Secure Element according to the
 * given index.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_NOT_AVAILABLE: certificate Format not supported
 * - TORSP_ARG_OUT_OF_RANGE: invalid Certificate Number
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TOSE_AUTH_API TO_ret_t TOSE_get_certificate_subject_cn(TOSE_ctx_t *ctx, const uint8_t certificate_index,
		char subject_cn[TO_CERT_SUBJECT_CN_MAXSIZE + 1]);

/**
 * @brief Set CSR distinguished name
 * @param[in] ctx Pointer to the SE context
 * @param[in] certificate_index Certificate index
 * @param[in] csr_dn CSR distinguished name (without main sequence tag & length)
 * @param[in] csr_dn_len CSR distinguished name length
 *
 * Set certificate distinguished name which will be used in next CSR.
 *
 * openssl can be used to generate a fake CSR and extract the Distinguished Name
 * sequence in DER format, like:
 * - openssl ecparam -out acme.key -name prime256v1 -genkey
 * - openssl req -new -key acme.key -out acme.csr -subj "/CN=*.ACME.com/O=ACME/OU=Security Services"
 * - openssl asn1parse -in acme.csr
 * Note the number of the first “SEQUENCE” with depth=2; in example above, this
 * is item number 9
 * - openssl asn1parse -in acme.csr -strparse 9 -out extract_acme_DN.der
 * and the file extract_acme_DN.der contains the Distinguished Name in DER format,
 * that can be used as parameter to TOSE_set_certificate_signing_request_dn()
 * Double-check that Distinguished Name size (check *extract_acme_DN.der* file
 * size on the disk) does not exceed TO_CERT_DN_MAXSIZE; else this will be
 * rejected by libTO.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_ARG_OUT_OF_RANGE: invalid Certificate Number
 * - TORSP_INVALID_LEN: invalid Distinguished Name length (> TO_CERT_DN_MAXSIZE)
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TOSE_AUTH_API TO_ret_t TOSE_set_certificate_signing_request_dn(
		TOSE_ctx_t *ctx, const uint8_t certificate_index,
		const uint8_t csr_dn[TO_CERT_DN_MAXSIZE],
		const uint16_t csr_dn_len);

/**
 * @brief Get new certificate signing request
 * @param[in] ctx Pointer to the SE context
 * @param[in] certificate_index Certificate index to renew
 * @param[out] csr Returned CSR data (can be NULL to determine needed buffer size)
 * @param[out] size Returned CSR real size
 *
 * Request a x509 DER formated certificate signing request according to the
 * given index.
 * CSR distinguished name can be set with
 * TOSE_set_certificate_signing_request_dn(), otherwise existing certificate DN
 * will be used (if any).
 * Secure Element CSR size will not exceed TO_CERT_X509_MAXSIZE.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_ARG_OUT_OF_RANGE: invalid Certificate Number
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TOSE_AUTH_API TO_ret_t TOSE_get_certificate_signing_request(
		TOSE_ctx_t *ctx, const uint8_t certificate_index,
		uint8_t* csr, uint16_t* size);

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
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_NOT_AVAILABLE: certificate Format not supported
 * - TORSP_ARG_OUT_OF_RANGE: invalid Certificate Number
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TOSE_AUTH_API TO_ret_t TOSE_set_certificate_x509(
		TOSE_ctx_t *ctx, const uint8_t certificate_index,
		const uint8_t* certificate, const uint16_t size);

/**
 * @brief Initialize to set new certificate from previously generated CSR
 * @param[in] ctx Pointer to the SE context
 * @param[in] certificate_index Requested certificate index
 *
 * See TOSE_set_certificate_x509
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_NOT_AVAILABLE: certificate Format not supported
 * - TORSP_ARG_OUT_OF_RANGE: invalid Certificate Number
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TOSE_AUTH_API TO_ret_t TOSE_set_certificate_x509_init(
		TOSE_ctx_t *ctx,
		const uint8_t certificate_index);

/**
 * @brief Update to set new certificate from previously generated CSR
 * @param[in] ctx Pointer to the SE context
 * @param[in] certificate New certificate partial data (from x509 DER formated)
 * @param[in] size New certificate partial data size
 *
 * See TOSE_set_certificate_x509
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_NOT_AVAILABLE: certificate Format not supported
 * - TORSP_ARG_OUT_OF_RANGE: invalid Certificate Number
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TOSE_AUTH_API TO_ret_t TOSE_set_certificate_x509_update(
		TOSE_ctx_t *ctx,
		const uint8_t* certificate,
		const uint16_t size);

/**
 * @brief Finalize to set new certificate from previously generated CSR
 * @param[in] ctx Pointer to the SE context
 *
 * See TOSE_set_certificate_x509
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_NOT_AVAILABLE: certificate Format not supported
 * - TORSP_ARG_OUT_OF_RANGE: invalid Certificate Number
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TOSE_AUTH_API TO_ret_t TOSE_set_certificate_x509_final(
		TOSE_ctx_t *ctx);

/**
 * @brief Returns one of the Secure Element certificates
 * @param[in] ctx Pointer to the SE context
 * @param[in] certificate_index Requested certificate index
 * @param[in] format Requested certificate format
 * @param[out] certificate Certificate, size depends on the certificate type (see
 * TO_cert_*_t)
 *
 * Request a certificate to Secure Element according to the given index and
 * format.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_NOT_AVAILABLE: certificate Format not supported
 * - TORSP_ARG_OUT_OF_RANGE: invalid Certificate Number
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TOSE_AUTH_API TO_ret_t TOSE_get_certificate(TOSE_ctx_t *ctx, const uint8_t certificate_index,
		const TO_certificate_format_t format, uint8_t* certificate);

/**
 * @brief Returns one of the certificates, x509 DER formated
 * @param[in] ctx Pointer to the SE context
 * @param[in] certificate_index Requested certificate index
 * @param[out] certificate Returned certificate data (can be NULL to determine needed
 *                    buffer size)
 * @param[out] size Returned certificate real size
 *
 * Request a x509 DER formated certificate according to the given index.
 * Secure Element certificate size will not exceed TO_CERT_X509_MAXSIZE.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_NOT_AVAILABLE: certificate Format not supported
 * - TORSP_ARG_OUT_OF_RANGE: invalid Certificate Number
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TOSE_AUTH_API TO_ret_t TOSE_get_certificate_x509(TOSE_ctx_t *ctx, const uint8_t certificate_index,
		uint8_t* certificate, uint16_t* size);

/**
 * @brief Requests to verify signature of the given subCA certificate; if
 * verification succeeds, this certificate is stored into Secure Element
 * CA slot.
 * @param[in] ctx Pointer to the SE context
 * @param[in] ca_key_index index of the CA slot used to verify subCA
 * @param[in] subca_key_index subCA index to store certificate
 * @param[in] certificate Certificate to be verified and stored
 * @param[in] certificate_len Certificate length
 *
 * Note: the only supported certificate format for this command is DER X509.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_ARG_OUT_OF_RANGE: invalid CA Key index
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TOSE_AUTH_API TO_ret_t TOSE_verify_ca_certificate_and_store(TOSE_ctx_t *ctx, const uint8_t ca_key_index,
		const uint8_t subca_key_index, const uint8_t *certificate,
		const uint16_t certificate_len);

/**
 * @brief Returns a challenge (random number of fixed
 * length) and store it into Secure Element memory.
 * @param[in] ctx Pointer to the SE context
 * @param[out] challenge Returned challenge
 *
 * This command must be called before TOSE_verify_challenge_signature().
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TOSE_AUTH_API TO_ret_t TOSE_get_challenge_and_store(TOSE_ctx_t *ctx,
		uint8_t challenge[TO_CHALLENGE_SIZE]);

/** @} */

/** @addtogroup ecies
 * @{ */

/**
 * @brief Returns one of the Secure Element certificates, and a challenge
 * signed with the certificate private key
 * @param[in] ctx Pointer to the SE context
 * @param[in] certificate_index Index of the certificate to return, starting from 0
 * @param[in] format Format of the Secure Element’s certificate, read the Secure
 * Element Datasheet, "Certificates description" chapter
 * @param[in] challenge Challenge to be signed
 * @param[in] challenge_length Length of the challenge to be signed
 * @param[in] certificate Certificate, size depends on the certificate type (see
 * TO_cert_*_t)
 * @param[out] signature Returned signature
 *
 * This command is equivalent to calling `TOSE_get_certificate` and `TOSE_sign`
 * functions in only one function call.
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
TOSE_AUTH_API TO_ret_t TOSE_get_certificate_and_sign(TOSE_ctx_t *ctx, const uint8_t certificate_index,
		const TO_certificate_format_t format,
		const uint8_t* challenge, const uint16_t challenge_length,
		uint8_t* certificate, uint8_t* signature);

/**
 * @brief Returns one of the Secure Element x509 DER formated certificates, and
 * a challenge signed with the certificate private key
 * @param[in] ctx Pointer to the SE context
 * @param[in] certificate_index Index of the certificate to return, starting from 0
 * @param[in] challenge Challenge to be signed
 * @param[in] challenge_length Length of the challenge to be signed
 * @param[out] certificate Returned certificate data, this buffer must be at least
 * TO_CERT_X509_MAXSIZE
 * @param[out] size Returned certificate real size (which is less or equal to 512
 * bytes)
 * @param[out] signature Returned signature
 *
 * This command is equivalent to TOSE_get_certificate() and TOSE_sign() commands
 * in only 1 call.
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
TOSE_AUTH_API TO_ret_t TOSE_get_certificate_x509_and_sign(TOSE_ctx_t *ctx, const uint8_t certificate_index,
		const uint8_t* challenge, const uint16_t challenge_length,
		uint8_t* certificate, uint16_t* size, uint8_t* signature);

/**
 * @brief CAPI version of TOSE_get_certificate_x509_and_sign(), initialization
 * @param ctx SE context
 * @param certificate_index Index of the certificate to return, starting from 0
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
TOSE_AUTH_API TO_ret_t TOSE_get_certificate_x509_init(
		TOSE_ctx_t *ctx,
		const uint8_t certificate_index
);

/**
 * @brief CAPI version of TOSE_get_certificate_x509_and_sign(), update
 * @param ctx SE context
 * @param certificate Returned certificate data
 * @param size input: the size of the certificate buffer
 * 	       output: the size of the certificate data copied in the buffer
 * 	       If output size is lower than input size then the end of the
 * 	       certificate has been reached.
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_INVALID_LEN: wrong length
 * - TORSP_NOT_AVAILABLE: certificate Format not supported
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR: generic error
 */
TOSE_AUTH_API TO_ret_t TOSE_get_certificate_x509_update(
		TOSE_ctx_t *ctx,
		uint8_t* certificate,
		uint16_t* size
);

/**
 * @brief CAPI version of TOSE_get_certificate_x509_and_sign(), Finalization
 * @param ctx SE context
 * @param challenge Challenge to be signed
 * @param challenge_length Length of the challenge to be signed
 * @param signature Returned signature
 *
 * @note This function must be called even if a signed challenge is not required
 * in order to release the CAPI context, if signature is unneeded then
 * challenge, challenge_length and signature shall be set to null, to improve
 * response time.
 *
 * */
TOSE_AUTH_API TO_ret_t TOSE_get_certificate_x509_final(
		TOSE_ctx_t *ctx,
		const uint8_t* challenge,
		const uint16_t challenge_length,
		uint8_t* signature
);

/**
 * @brief Requests to verify Certificate
 * Authority Signature of the given certificate, if verification succeeds, this
 * certificate is stored into Secure Element Memory.
 * @param[in] ctx Pointer to the SE context
 * @param[in] ca_key_id Index of the Certificate Authority public Key
 * @param[in] format Format of the certificate
 * @param[in] certificate Certificate to be verified and stored
 *
 * This command is required before using TOSE_get_challenge_and_store() and
 * TOSE_verify_challenge_signature().
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_NOT_AVAILABLE: certificate Format not supported
 * - TORSP_ARG_OUT_OF_RANGE: invalid CA Key index
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TOSE_AUTH_API TO_ret_t TOSE_verify_certificate_and_store(TOSE_ctx_t *ctx, const uint8_t ca_key_id,
		const TO_certificate_format_t format, const uint8_t* certificate);

/**
 * @brief Verifies if the given signature matches
 * with the signature of the challenge previously sent by
 * TOSE_get_challenge_and_store(), using the public key of the certificate
 * previously sent by TOSE_verify_certificate_and_store().
 * @param[in] ctx Pointer to the SE context
 * @param[in] signature Challenge signature to verify. The challenge was previously
 * sent by the Secure Element on call to TOSE_get_challenge_and_store().
 *
 * Note: TOSE_verify_certificate_and_store() must be called before this command.
 * TOSE_get_challenge_and_store() must be called before this command.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_BAD_SIGNATURE: verification failed
 * - TORSP_COND_OF_USE_NOT_SATISFIED: TOSE_verify_certificate_and_store() and
 *      TOSE_get_challenge_and_store() were not called before this command
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TOSE_AUTH_API TO_ret_t TOSE_verify_challenge_signature(TOSE_ctx_t *ctx,
		const uint8_t signature[TO_SIGNATURE_SIZE]);

/**
 * @brief Initialize certificate chain verification
 * @param[in] ctx Pointer to the SE context
 * @param[in] ca_key_index CA key index (use TO_CA_IDX_AUTO to enable Authority Key
 *                     Identifier based CA detection)
 *
 * This command is required before using
 * TOSE_verify_chain_certificate_and_store_update().
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TOSE_AUTH_API TO_ret_t TOSE_verify_chain_certificate_and_store_init(TOSE_ctx_t *ctx,
		const uint8_t ca_key_index);

/**
 * @brief Update certificate chain verification with certificate chain data.
 * @param[in] ctx Pointer to the SE context
 * @param[in] chain_certificate Chain certificate
 * @param[in] chain_certificate_length Chain certificate length
 *
 * This command must be used after
 * TOSE_verify_chain_certificate_and_store_update_init() and is required before
 * using TOSE_verify_chain_certificate_and_store_update_final() and can be
 * repeated to deal with certificate chains longer than 512 bytes.
 *
 * Certificates must be in X509 DER (binary) format.
 * Certificates must be ordered as following:
 * - Final certificate
 * - Intermediate CA certificates (if any)
 * - Root CA certificate (optional as it must already be trusted by the
 *   Secure Element)
 *
 * Certificate chain can be cut anywhere.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_BAD_SIGNATURE: invalid signature
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TOSE_AUTH_API TO_ret_t TOSE_verify_chain_certificate_and_store_update(TOSE_ctx_t *ctx,
		const uint8_t *chain_certificate,
		const uint16_t chain_certificate_length);

/**
 * @brief Finalize certificate chain verification.
 * @param[in] ctx Pointer to the SE context
 *
 * This command must be used after
 * TOSE_verify_chain_certificate_and_store_update_update() to verify last
 * certificate and store final certificate.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_BAD_SIGNATURE: invalid signature
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TOSE_AUTH_API TO_ret_t TOSE_verify_chain_certificate_and_store_final(TOSE_ctx_t *ctx);

/**
 * @brief Initialize CA certificate chain verification
 * @param[in] ctx Pointer to the SE context
 * @param[in] ca_key_index CA key index (use TO_CA_IDX_AUTO to enable Authority Key
 *                     Identifier based CA detection)
 * @param[in] subca_key_index subCA index to store subCA
 *
 * This command is required before using
 * TOSE_verify_chain_ca_certificate_and_store_update().
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TOSE_AUTH_API TO_ret_t TOSE_verify_chain_ca_certificate_and_store_init(TOSE_ctx_t *ctx,
		const uint8_t ca_key_index, const uint8_t subca_key_index);

/**
 * @brief Update CA certificate chain verification with certificate chain data.
 * @param[in] ctx Pointer to the SE context
 * @param[in] chain_certificate Chain certificate
 * @param[in] chain_certificate_length Chain certificate length
 *
 * This command must be used after
 * TOSE_verify_chain_ca_certificate_and_store_update_init() and is required
 * before using TOSE_verify_chain_ca_certificate_and_store_update_final() and
 * can be repeated to deal with certificate chains longer than 512 bytes.
 *
 * Certificates must be in X509 DER (binary) format.
 * Certificates must be ordered as following:
 * - Intermediate CA certificates
 * - Root CA certificate (optional as it must already be trusted by the
 *   Secure Element)
 *
 * Certificate chain can be cut anywhere.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_BAD_SIGNATURE: invalid signature
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TOSE_AUTH_API TO_ret_t TOSE_verify_chain_ca_certificate_and_store_update(TOSE_ctx_t *ctx,
		const uint8_t *chain_certificate,
		const uint16_t chain_certificate_length);

/**
 * @brief Finalize certificate chain verification.
 * @param[in] ctx Pointer to the SE context
 *
 * This command must be used after
 * TOSE_verify_chain_ca_certificate_and_store_update_update() to verify last
 * certificate and store first intermediate CA certificate.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_BAD_SIGNATURE: invalid signature
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TOSE_AUTH_API TO_ret_t TOSE_verify_chain_ca_certificate_and_store_final(TOSE_ctx_t *ctx);

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* _TOSE_AUTH_H_ */

