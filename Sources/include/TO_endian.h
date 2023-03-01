/*
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (C) 2017 Trusted Objects. All rights reserved.
 */

/**
 * @file TO_endian.h
 * @brief Endianness.
 */

#ifndef _TO_ENDIAN_H_
#define _TO_ENDIAN_H_

#if HAVE_ENDIAN_H
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
#include <endian.h>
#endif

#if defined(__BYTE_ORDER__) \
	&& !defined(TO_BIG_ENDIAN) && !defined(TO_LITTLE_ENDIAN)
	#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
		#define TO_LITTLE_ENDIAN
	#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
		#define TO_BIG_ENDIAN
	#else
		#error "Unsupported byte order"
	#endif
#else
	#error "Unspecified byte order"
#endif

#if HAVE_BYTESWAP_H
	#include <byteswap.h>
#else
#if defined(__GNUC__) && !defined(__ARMCC_VERSION)
#include <sys/types.h>
#endif
#if defined(__bswap16)
	#define bswap_16 __bswap16
#else
	#define bswap_16(value) \
		((((value) & 0xff) << 8) | ((value) >> 8))
#endif
#if defined(__bswap32)
	#define bswap_32 __bswap32
#else
	#define bswap_32(value) \
		(((uint32_t)bswap_16((uint16_t)((value) & 0xffff)) \
		  << 16) | (uint32_t)bswap_16((uint16_t)((value) >> 16)))
#endif
#if defined(__bswap64)
	#define bswap_64 __bswap64
#else
	#define bswap_64(value) \
		(((uint64_t)bswap_32((uint32_t)((value) & 0xffffffff)) \
		  << 32) | (uint64_t)bswap_32((uint32_t)((value) >> 32)))
#endif
#endif

#ifdef TO_LITTLE_ENDIAN
#ifndef htobe16
	#define htobe16(x) bswap_16(x)
#endif
#ifndef htobe32
	#define htobe32(x) bswap_32(x)
#endif
#ifndef htobe64
	#define htobe64(x) bswap_64(x)
#endif
#ifndef be16toh
	#define be16toh(x) bswap_16(x)
#endif
#ifndef be32toh
	#define be32toh(x) bswap_32(x)
#endif
#ifndef be64toh
	#define be64toh(x) bswap_64(x)
#endif
#ifndef htole16
	#define htole16(x) (x)
#endif
#ifndef htole32
	#define htole32(x) (x)
#endif
#ifndef htole64
	#define htole64(x) (x)
#endif
#ifndef le16toh
	#define le16toh(x) (x)
#endif
#ifndef le32toh
	#define le32toh(x) (x)
#endif
#ifndef le64toh
	#define le64toh(x) (x)
#endif
#elif defined(TO_BIG_ENDIAN)
#ifndef htobe16
	#define htobe16(x) (x)
#endif
#ifndef htobe32
	#define htobe32(x) (x)
#endif
#ifndef htobe64
	#define htobe64(x) (x)
#endif
#ifndef be16toh
	#define be16toh(x) (x)
#endif
#ifndef be32toh
	#define be32toh(x) (x)
#endif
#ifndef be64toh
	#define be64toh(x) (x)
#endif
#ifndef htole16
	#define htole16(x) bswap_16(x)
#endif
#ifndef htole32
	#define htole32(x) bswap_32(x)
#endif
#ifndef htole64
	#define htole64(x) bswap_64(x)
#endif
#ifndef le16toh
	#define le16toh(x) bswap_16(x)
#endif
#ifndef le32toh
	#define le32toh(x) bswap_32(x)
#endif
#ifndef le64toh
	#define le64toh(x) bswap_64(x)
#endif
#else
	/* Runtime detection is needed */
	#define TO_ENDIAN_RUNTIME_DETECT
	#define TO_BYTE_ORDER_LITTLE_ENDIAN 0
	#define TO_BYTE_ORDER_BIG_ENDIAN 1
	extern int TO_byte_order;
	#define htobe16(x) (TO_byte_order ? x : bswap_16(x))
	#define htobe32(x) (TO_byte_order ? x : bswap_32(x))
	#define htobe64(x) (TO_byte_order ? x : bswap_64(x))
	#define be16toh(x) (TO_byte_order ? x : bswap_16(x))
	#define be32toh(x) (TO_byte_order ? x : bswap_32(x))
	#define be64toh(x) (TO_byte_order ? x : bswap_64(x))
	#define htole16(x) (TO_byte_order ? bswap_16(x) : x)
	#define htole32(x) (TO_byte_order ? bswap_32(x) : x)
	#define htole64(x) (TO_byte_order ? bswap_64(x) : x)
	#define le16toh(x) (TO_byte_order ? bswap_16(x) : x)
	#define le32toh(x) (TO_byte_order ? bswap_32(x) : x)
	#define le64toh(x) (TO_byte_order ? bswap_64(x) : x)
#endif

#endif /* _TO_ENDIAN_H_ */

