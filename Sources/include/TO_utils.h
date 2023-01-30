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
 * @file TO_utils.h
 * @brief Secure Element utilities.
 */

#ifndef _TO_UTILS_H_
#define _TO_UTILS_H_

#include "TO_endian.h"
#include "TO_stdint.h"
#include "TO_portability.h"

#include <string.h>

#ifndef COMPILE_ASSERT
#define _COMPILE_ASSERT_NAME(counter) __check_ ## counter
#define _COMPILE_ASSERT(cond, counter) extern char _COMPILE_ASSERT_NAME(counter)[1 - 2*!(cond)]
#define COMPILE_ASSERT(cond) _COMPILE_ASSERT(cond, __COUNTER__)
#endif /* COMPILE_ASSERT */

#ifndef PACKED
#if defined(__GNUC__)
#define PACKED __attribute__ ((packed))
#else
#define PACKED
#endif /* __GNUC__ */
#endif /* PACKED */

#ifndef FALL_THROUGH
#if defined(__GNUC__) && __GNUC__ >= 7
#define FALL_THROUGH __attribute__ ((fallthrough));
#else
#define FALL_THROUGH
#endif /* __GNUC__ >= 7 */
#endif /* FALL_THROUGH */

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

#ifndef MAX
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif

/**
 * @brief Transforms a data from a host representation to Big-Endian (Most significant Byte First)
 * @param[in] val Value to be transformed
 * @param[out] data Destination buffer
 * @param[in] offset Offset at which we will write the result
 */
#define SET_BE16_NOINC(val, data, offset) \
    TO_safewrite_beuint16((void*)((uint8_t *)(data) + (offset)),(val));

/**
 * @brief Transforms a data from a host representation to Big-Endian (Most significant Byte First)
 * @param[in] val Value to be transformed
 * @param[out] data Destination buffer
 * @param[in] offset Offset at which we will write the result
 */
#define SET_BE24_NOINC(val, data, offset) \
    TO_safewrite_beuint24((void*)((uint8_t *)(data) + (offset)),(val));

/**
 * @brief Transforms a data from a host representation to Big-Endian (Most significant Byte First)
 * @param[in] val Value to be transformed
 * @param[out] data Destination buffer
 * @param[in] offset Offset at which we will write the result
 */
#define SET_BE32_NOINC(val, data, offset) \
    TO_safewrite_beuint32((void*)((uint8_t *)(data) + (offset)),(val));

/**
 * @brief Transforms a data from a host representation to Big-Endian (Most significant Byte First)
 * @param[in] val Value to be transformed
 * @param[out] data Destination buffer
 * @param[in] offset Offset at which we will write the result
 */
#define SET_BE48_NOINC(val, data, offset) \
    TO_safewrite_beuint48((void*)((uint8_t *)(data) + (offset)),(val));

/**
 * @brief Transforms a data from a host representation to Big-Endian (Most significant Byte First)
 * @param[in] val Value to be transformed
 * @param[out] data Destination buffer
 * @param[in] offset Offset at which we will write the result
 */
#define SET_BE64_NOINC(val, data, offset) \
    TO_safewrite_beuint64((void*)((uint8_t *)(data) + (offset)),(val));

/**
 * @brief Transforms a data from a Big-Endian (Most significant Byte First) to a host representation
 * @param[in] data Source buffer
 * @param[in] offset Offset at which we will read the data
 * @param[out] val Destination data
 */
#define GET_BE16_NOINC(data, offset, val) \
    (val) = TO_saferead_beuint16((void*)((uint8_t *)(data) + (offset)));

/**
 * @brief Transforms a data from a Big-Endian (Most significant Byte First) to a host representation
 * @param[in] data Source buffer
 * @param[in] offset Offset at which we will read the data
 * @param[out] val Destination data
 */
#define GET_BE24_NOINC(data, offset, val) \
    (val) = TO_saferead_beuint24((void*)((uint8_t *)(data) + (offset)));

/**
 * @brief Transforms a data from a Big-Endian (Most significant Byte First) to a host representation
 * @param[in] data Source buffer
 * @param[in] offset Offset at which we will read the data
 * @param[out] val Destination data
 */
#define GET_BE32_NOINC(data, offset, val) \
    (val) = TO_saferead_beuint32((void*)((uint8_t *)(data) + (offset)));

/**
 * @brief Transforms a data from a Big-Endian (Most significant Byte First) to a host representation
 * @param[in] data Source buffer
 * @param[in] offset Offset at which we will read the data
 * @param[out] val Destination data
 */
#define GET_BE48_NOINC(data, offset, val) \
    (val) = TO_saferead_beuint48((void*)((uint8_t *)(data) + (offset)));

/**
 * @brief Transforms a data from a Big-Endian (Most significant Byte First) to a host representation
 * @param[in] data Source buffer
 * @param[in] offset Offset at which we will read the data
 * @param[out] val Destination data
 */
#define GET_BE64_NOINC(data, offset, val) \
    (val) = TO_saferead_beuint64((void*)((uint8_t *)(data) + (offset)));

/**
 * @brief Transforms a data from a host representation to Big-Endian (Most significant Byte First).
 * Increments the Offset depending on the data size.
 * @param[in] val Value to be transformed
 * @param[out] data Destination buffer
 * @param[in] offset Offset at which we will write the result
 */
#define SET_BE16(val, data, offset)                                            \
{                                                                              \
    SET_BE16_NOINC(val, data, offset);                                         \
    (offset) += sizeof(uint16_t);                                              \
}

/**
 * @brief Transforms a data from a host representation to Big-Endian (Most significant Byte First).
 * Increments the Offset depending on the data size.
 * @param[in] val Value to be transformed
 * @param[out] data Destination buffer
 * @param[in] offset Offset at which we will write the result
 */
#define SET_BE24(val, data, offset)                                            \
{                                                                              \
    SET_BE24_NOINC(val, data, offset);                                         \
    (offset) += 3;                                                             \
}

/**
 * @brief Transforms a data from a host representation to Big-Endian (Most significant Byte First).
 * Increments the Offset depending on the data size.
 * @param[in] val Value to be transformed
 * @param[out] data Destination buffer
 * @param[in] offset Offset at which we will write the result
 */
#define SET_BE32(val, data, offset)                                            \
{                                                                              \
    SET_BE32_NOINC(val, data, offset);                                         \
    (offset) += sizeof(uint32_t);                                              \
}

/**
 * @brief Transforms a data from a host representation to Big-Endian (Most significant Byte First).
 * Increments the Offset depending on the data size.
 * @param[in] val Value to be transformed
 * @param[out] data Destination buffer
 * @param[out] offset Offset at which we will write the result
 */
#define SET_BE48(val, data, offset)                                            \
{                                                                              \
    SET_BE48_NOINC(val, data, offset);                                         \
    (offset) += 6;                                                             \
}

/**
 * @brief Transforms a data from a host representation to Big-Endian (Most significant Byte First).
 * Increments the Offset depending on the data size.
 * @param[in] val Value to be transformed
 * @param[out] data Destination buffer
 * @param[in] offset Offset at which we will write the result
 */
#define SET_BE64(val, data, offset)                                            \
{                                                                              \
    SET_BE64_NOINC(val, data, offset);                                         \
    (offset) += sizeof(uint64_t);                                              \
}

/**
 * @brief Transforms a data from a Big-Endian (Most significant Byte First) to a host representation
 * Increments the Offset depending on the data size.
 * @param[in] data Source buffer
 * @param[in] offset Offset at which we will read the data
 * @param[out] val Destination data
 */
#define GET_BE16(data, offset, val)                                            \
{                                                                              \
    GET_BE16_NOINC(data, offset, val);                                         \
    (offset) += sizeof(uint16_t);                                              \
}

/**
 * @brief Transforms a data from a Big-Endian (Most significant Byte First) to a host representation
 * Increments the Offset depending on the data size.
 * @param[in] data Source buffer
 * @param[in] offset Offset at which we will read the data
 * @param[out] val Destination data
 */
#define GET_BE24(data, offset, val)                                            \
{                                                                              \
    GET_BE24_NOINC(data, offset, val);                                         \
    (offset) += 3;                                                             \
}

/**
 * @brief Transforms a data from a Big-Endian (Most significant Byte First) to a host representation
 * Increments the Offset depending on the data size.
 * @param[in] data Source buffer
 * @param[in] offset Offset at which we will read the data
 * @param[in] val Destination data
 */
#define GET_BE32(data, offset, val)                                            \
{                                                                              \
    GET_BE32_NOINC(data, offset, val);                                         \
    (offset) += sizeof(uint32_t);                                              \
}

/**
 * @brief Transforms a data from a Big-Endian (Most significant Byte First) to a host representation
 * Increments the Offset depending on the data size.
 * @param[in] data Source buffer
 * @param[in] offset Offset at which we will read the data
 * @param[out] val Destination data
 */
#define GET_BE48(data, offset, val)                                            \
{                                                                              \
    GET_BE48_NOINC(data, offset, val);                                         \
    (offset) += 6;                                                             \
}

/**
 * @brief Transforms a data from a Big-Endian (Most significant Byte First) to a host representation
 * Increments the Offset depending on the data size.
 * @param[in] data Source buffer
 * @param[in] offset Offset at which we will read the data
 * @param[out] val Destination data
 */
#define GET_BE64(data, offset, val)                                            \
{                                                                              \
    GET_BE64_NOINC(data, offset, val);                                         \
    (offset) += sizeof(uint64_t);                                              \
}

/**
 * @brief Transforms a data from a host representation to Little-Endian (Least significant Byte First)
 * @param[in] val Value to be transformed
 * @param[out] data Destination buffer
 * @param[in] offset Offset at which we will write the result
 */
#define SET_LE16_NOINC(val, data, offset) \
    TO_safewrite_leuint16((void*)((uint8_t *)(data) + (offset)),(val));

/**
 * @brief Transforms a data from a host representation to Little-Endian (Least significant Byte First)
 * @param[in] val Value to be transformed
 * @param[out] data Destination buffer
 * @param[in] offset Offset at which we will write the result
 */
#define SET_LE24_NOINC(val, data, offset) \
    TO_safewrite_leuint24((void*)((uint8_t *)(data) + (offset)),(val));

/**
 * @brief Transforms a data from a host representation to Little-Endian (Least significant Byte First)
 * @param[in] val Value to be transformed
 * @param[out] data Destination buffer
 * @param[in] offset Offset at which we will write the result
 */
#define SET_LE32_NOINC(val, data, offset) \
    TO_safewrite_leuint32((void*)((uint8_t *)(data) + (offset)),(val));

/**
 * @brief Transforms a data from a host representation to Little-Endian (Least significant Byte First)
 * @param[in] val Value to be transformed
 * @param[out] data Destination buffer
 * @param[in] offset Offset at which we will write the result
 */
#define SET_LE48_NOINC(val, data, offset) \
    TO_safewrite_leuint48((void*)((uint8_t *)(data) + (offset)),(val));

/**
 * @brief Transforms a data from a host representation to Little-Endian (Least significant Byte First)
 * @param[in] val Value to be transformed
 * @param[out] data Destination buffer
 * @param[in] offset Offset at which we will write the result
 */
#define SET_LE64_NOINC(val, data, offset) \
    TO_safewrite_leuint64((void*)((uint8_t *)(data) + (offset)),(val));

/**
 * @brief Transforms a data from a Little-Endian (Least significant Byte First) to a host representation
 * @param[in] data Source buffer
 * @param[in] offset Offset at which we will read the data
 * @param[out] val Destination data
 */
#define GET_LE16_NOINC(data, offset, val) \
    (val) = TO_saferead_leuint16((void*)((uint8_t *)(data) + (offset)));

/**
 * @brief Transforms a data from a Little-Endian (Least significant Byte First) to a host representation
 * @param[in] data Source buffer
 * @param[in] offset Offset at which we will read the data
 * @param[out] val Destination data
 */
#define GET_LE24_NOINC(data, offset, val) \
    (val) = TO_saferead_leuint24((void*)((uint8_t *)(data) + (offset)));

/**
 * @brief Transforms a data from a Little-Endian (Least significant Byte First) to a host representation
 * @param[in] data Source buffer
 * @param[in] offset Offset at which we will read the data
 * @param[out] val Destination data
 */
#define GET_LE32_NOINC(data, offset, val) \
    (val) = TO_saferead_leuint32((void*)((uint8_t *)(data) + (offset)));

/**
 * @brief Transforms a data from a Little-Endian (Least significant Byte First) to a host representation
 * @param[in] data Source buffer
 * @param[in] offset Offset at which we will read the data
 * @param[out] val Destination data
 */
#define GET_LE48_NOINC(data, offset, val) \
    (val) = TO_saferead_leuint48((void*)((uint8_t *)(data) + (offset)));

/**
 * @brief Transforms a data from a Little-Endian (Least significant Byte First) to a host representation
 * @param[in] data Source buffer
 * @param[in] offset Offset at which we will read the data
 * @param[out] val Destination data
 */
#define GET_LE64_NOINC(data, offset, val) \
    (val) = TO_saferead_leuint64((void*)((uint8_t *)(data) + (offset)));

/**
 * @brief Transforms a data from a host representation to Little-Endian (Least significant Byte First)
 * Increments the Offset depending on the data size.
 * @param[in] val Value to be transformed
 * @param[out] data Destination buffer
 * @param[in] offset Offset at which we will write the result
 */
#define SET_LE16(val, data, offset)                                            \
{                                                                              \
    SET_LE16_NOINC(val, data, offset);                                         \
    (offset) += sizeof(uint16_t);                                              \
}

/**
 * @brief Transforms a data from a host representation to Little-Endian (Least significant Byte First)
 * Increments the Offset depending on the data size.
 * @param[in] val Value to be transformed
 * @param[out] data Destination buffer
 * @param[in] offset Offset at which we will write the result
 */
#define SET_LE24(val, data, offset)                                            \
{                                                                              \
    SET_LE24_NOINC(val, data, offset);                                         \
    (offset) += 3;                                                             \
}

/**
 * @brief Transforms a data from a host representation to Little-Endian (Least significant Byte First)
 * Increments the Offset depending on the data size.
 * @param[in] val Value to be transformed
 * @param[out] data Destination buffer
 * @param[in] offset Offset at which we will write the result
 */
#define SET_LE32(val, data, offset)                                            \
{                                                                              \
    SET_LE32_NOINC(val, data, offset);                                         \
    (offset) += sizeof(uint32_t);                                              \
}

/**
 * @brief Transforms a data from a host representation to Little-Endian (Least significant Byte First)
 * Increments the Offset depending on the data size.
 * @param[in] val Value to be transformed
 * @param[out] data Destination buffer
 * @param[in] offset Offset at which we will write the result
 */
#define SET_LE48(val, data, offset)                                            \
{                                                                              \
    SET_LE48_NOINC(val, data, offset);                                         \
    (offset) += 6;                                                             \
}

/**
 * @brief Transforms a data from a host representation to Little-Endian (Least significant Byte First)
 * Increments the Offset depending on the data size.
 * @param[in] val Value to be transformed
 * @param[out] data Destination buffer
 * @param[in] offset Offset at which we will write the result
 */
#define SET_LE64(val, data, offset)                                            \
{                                                                              \
    SET_LE64_NOINC(val, data, offset);                                         \
    (offset) += sizeof(uint64_t);                                              \
}

/**
 * @brief Transforms a data from a Little-Endian (Least significant Byte First) to a host representation
 * Increments the Offset depending on the data size.
 * @param[in] data Source buffer
 * @param[in] offset Offset at which we will read the data
 * @param[out] val Destination data
 */
#define GET_LE16(data, offset, val)                                            \
{                                                                              \
    GET_LE16_NOINC(data, offset, val);                                         \
    (offset) += sizeof(uint16_t);                                              \
}

/**
 * @brief Transforms a data from a Little-Endian (Least significant Byte First) to a host representation
 * Increments the Offset depending on the data size.
 * @param[in] data Source buffer
 * @param[in] offset Offset at which we will read the data
 * @param[out] val Destination data
 */
#define GET_LE24(data, offset, val)                                            \
{                                                                              \
    GET_LE24_NOINC(data, offset, val);                                         \
    (offset) += 3;                                                             \
}

/**
 * @brief Transforms a data from a Little-Endian (Least significant Byte First) to a host representation
 * Increments the Offset depending on the data size.
 * @param[in] data Source buffer
 * @param[in] offset Offset at which we will read the data
 * @param[out] val Destination data
 */
#define GET_LE32(data, offset, val)                                            \
{                                                                              \
    GET_LE32_NOINC(data, offset, val);                                         \
    (offset) += sizeof(uint32_t);                                              \
}

/**
 * @brief Transforms a data from a Little-Endian (Least significant Byte First) to a host representation
 * Increments the Offset depending on the data size.
 * @param[in] data Source buffer
 * @param[in] offset Offset at which we will read the data
 * @param[out] val Destination data
 */
#define GET_LE48(data, offset, val)                                            \
{                                                                              \
    GET_LE48_NOINC(data, offset, val);                                         \
    (offset) += 6;                                                             \
}

/**
 * @brief Transforms a data from a Little-Endian (Least significant Byte First) to a host representation
 * Increments the Offset depending on the data size.
 * @param[in] data Source buffer
 * @param[in] offset Offset at which we will read the data
 * @param[out] val Destination data
 */
#define GET_LE64(data, offset, val)                                            \
{                                                                              \
    GET_LE64_NOINC(data, offset, val);                                         \
    (offset) += sizeof(uint64_t);                                              \
}

#ifdef __GNUC__
#define DO_PRAGMA_(x) _Pragma (#x)
#define GCC_PRAGMA(x) DO_PRAGMA_(GCC x)
#else
#define GCC_PRAGMA(x)
#endif

/**
 * @brief Performs memory areas comparisons in constant time
 * @param[in] s1 First memory area
 * @param[in] s2 Second memory area
 * @param[in] n Size to compare in bytes
 *
 * Performs s1 and s2 comparisons in constant time (not related to the number
 * of equal bytes).
 *
 * @return value is zero only if s1 and s2 bytes are matching. If n is zero
 * then zero is returned.
 */
extern int TO_secure_memcmp(const void *s1, const void *s2, unsigned int n);

/**
 * @brief Copy memory area into another safer than memcpy()
 * @param[out] dest Destination memory area
 * @param[in] src Source memory area
 * @param[in] n Size to copy in bytes
 *
 * Copy src to dest after the following checks:
 * - dest and src are not NULL
 * - no overlap between dest and src
 *
 * @return a pointer to dest or NULL on error
 */
extern void *TO_secure_memcpy(void *dest, const void *src, unsigned int n);

/**
 * @brief Move memory area into another safer than memmove()
 * @param[out] dest Destination memory area
 * @param[in] src Source memory area
 * @param[in] n Size to move in bytes
 *
 * Move src to dest after the following checks:
 * - dest and src are not NULL
 * - overlap determines moving from start or from end
 *
 * @return a pointer to dest or NULL on error
 */
extern void *TO_secure_memmove(void *dest, const void *src, unsigned int n);

/**
 * @brief Secure memory area set
 * @param[out] s Memory area to set
 * @param[in] c Value to set for each byte of memory area s
 * @param[in] n Length to set
 *
 * Set all bytes of s to c, and prevent this operation to be optimized by
 * compiler.
 * Return immediately if s is NULL.
 *
 * @return s
 */
extern void *TO_secure_memset(void *s, int c, unsigned int n);

/**
 * @brief initial value to give to TO_crc16_ccitt_29b1()
 * */
#define TO_CRC16_SEED 0xFFFFu

/**
 * @brief Compute CRC16 CCITT 29B1.
 * @param[in] crc Initial value
 * @param[in] data Data to compute on
 * @param[in] len Data length
 * @param[in] reflect Reflect data bytes and output CRC if not 0
 *
 * @return Computed CRC value.
 */
extern uint16_t TO_crc16_ccitt_29b1(uint16_t crc,
		const uint8_t *data, int len, int reflect);

#endif /* _TO_UTILS_H_ */