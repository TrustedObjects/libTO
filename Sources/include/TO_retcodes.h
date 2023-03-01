/*
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (C) 2019-2022 Trusted Objects. All rights reserved.
 */

/**
 * @file TO_retcodes.h
 * @brief Secure Element return codes.
 */

#ifndef _TO_RETCODES_H_
#define _TO_RETCODES_H_

#include "TO_utils.h"

/** @addtogroup lib_codes
 * Error codes
 * @{ */

/*
 * Library error codes.
 * Note: the LSB is left empty because it is reserved for Secure Element device
 * error codes, then it is possible to return Secure Element and library error
 * codes in one single variable.
 */
typedef enum TO_lib_ret_e {
	TO_OK = 0x0000,
	TO_MEMORY_ERROR = 0x0100,
	TO_DEVICE_WRITE_ERROR = 0x0200,
	TO_DEVICE_READ_ERROR = 0x0400,
	TO_INVALID_CA_ID = 0x1000,
	TO_INVALID_CERTIFICATE_FORMAT = 0x1100,
	TO_INVALID_CERTIFICATE_NUMBER = 0x1200,
	TO_INVALID_RESPONSE_LENGTH = 0x2000,
	TO_SECLINK_ERROR = 0x2100,
	TO_TIMEOUT = 0x2200,
	TO_AGAIN = 0x2400,
	TO_INVALID_PARAM = 0x4000,
	TO_NOT_IMPLEMENTED = 0x8000,
	TO_ERROR = 0xF000,
} PACKED TO_lib_ret_t;

/** @} */

COMPILE_ASSERT(sizeof(TO_lib_ret_t) == sizeof(uint16_t));

/** @addtogroup se_codes
 * @{ */

/**
 * @brief Secure Element response codes
 * @details These return codes are common to all TO Secure elements, including
 * the TO-136 and TO-Protect. Therefore, some of these return values may have
 * a different meaning depending on the SE you are using, and the context you
 * are receiving it. Refer yourself to the called function to have a more
 * precise information.
 */
typedef enum TO_se_ret_e {
        /** Indicates that the SE does not know how to handle this command */
	TORSP_UNKNOWN_CMD = 0x01,

        /** The digital signature is wrong */
	TORSP_BAD_SIGNATURE = 0x66,

	/** The provided length is wrong */
	TORSP_INVALID_LEN = 0x67,

        /** The requested data cannot be retrieved */
	TORSP_NOT_AVAILABLE = 0x68,

        /** The expected padding is not respected */
	TORSP_INVALID_PADDING = 0x69,

        /** A communication error has occurred */
	TORSP_COM_ERROR = 0x72,

        /** Deprecated, use TORSP_COM_ERROR instead */
	TO136RSP_COM_ERROR = TORSP_COM_ERROR,

        /** An authentication process has to be conduced to pursue */
	TORSP_NEED_AUTHENTICATION = 0x80,

        /** This command cannot be used in this context */
	TORSP_COND_OF_USE_NOT_SATISFIED = 0x85,

        /** An argument is not in the expected range */
	TORSP_ARG_OUT_OF_RANGE = 0x88,

        /** The Command's execution has been conduced correctly */
	TORSP_SUCCESS = 0x90,

        /** No valid secure storage found */
	TORSP_NO_VALID_SECURE_STORAGE_FOUND = 0xD0,

        /** Inconsistent secure storages */
	TORSP_INCONSISTENT_SECURE_STORAGES = 0xD1,

        /** Secure Storage's version is wrong */
	TORSP_WRONG_SECURE_STORAGE_VERSION = 0xD2,

	/** Wrong code integrity */
	TORSP_WRONG_INSTALLATION = 0xD3,

        /** The SecLink key has to be renewed */
	TORSP_SECLINK_RENEW_KEY = 0xFD,

        /** An internal error has occurred. It may be the proof that
         * something unexpected has happened (for instance, a fault has
         * been detected).
        */
	TORSP_INTERNAL_ERROR = 0xFE,
} PACKED TO_se_ret_t;

/** @} */

COMPILE_ASSERT(sizeof(TO_se_ret_t) == sizeof(uint8_t));

/** @addtogroup error_codes
 * @{ */

/*
 * Concatenation of TO_lib_ret_t and TO_se_ret_t.
 */
typedef uint16_t TO_ret_t;

/** Mask error code to extract library error */
#define TO_LIB_ERRCODE(errcode) ((errcode) & 0xFF00)

/** Mask error code to extract SE error */
#define TO_SE_ERRCODE(errcode) ((errcode) & 0x00FF)

/** @} */

COMPILE_ASSERT(sizeof(TO_ret_t) == sizeof(uint16_t));

#endif /* _TO_RETCODES_H_ */

