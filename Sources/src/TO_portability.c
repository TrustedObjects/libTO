/*
 *
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (C) 2022 Trusted Objects. All rights reserved.
 */

#include "TO_portability.h"
#include "TO_endian.h"

uint8_t TO_saferead_uint8(const void* adr)
{

	// On Xtensa architecture, depending on the location of
	// the byte to read, it may be mandatory to read it this way.
	// Else, an exception will be raised.
#ifdef __XTENSA__
	uint32_t *ptr32bits = (uint32_t *)(((uint32_t)adr) & 0xfffffffc);
	uint32_t offset = ((uint32_t)adr) & 0x3;
	uint32_t data;

	data = *ptr32bits;

	return (uint8_t)(data >> (offset * 8));
#else
	return *((uint8_t*)adr);
#endif
}

uint16_t TO_saferead_leuint16(const void* adr)
{
	union {
		uint16_t data;
		uint8_t  bytes[2];
	} convert;

	convert.bytes[0] = TO_saferead_uint8(adr);
	convert.bytes[1] = TO_saferead_uint8((uint8_t *)adr + 1);
	
	return le16toh(convert.data);
}

uint32_t TO_saferead_leuint24(const void* adr)
{
	union {
		uint32_t data;
		uint8_t  bytes[4];
	} convert;

	convert.data = 0;
	convert.bytes[0] = TO_saferead_uint8(adr);
	convert.bytes[1] = TO_saferead_uint8((uint8_t *)adr + 1);
	convert.bytes[2] = TO_saferead_uint8((uint8_t *)adr + 2);
	
	return le32toh(convert.data) & ((1 << 24) - 1);
}

uint32_t TO_saferead_leuint32(const void* adr)
{
	union {
		uint32_t data;
		uint8_t  bytes[4];
	} convert;

	convert.bytes[0] = TO_saferead_uint8(adr);
	convert.bytes[1] = TO_saferead_uint8((uint8_t *)adr + 1);
	convert.bytes[2] = TO_saferead_uint8((uint8_t *)adr + 2);
	convert.bytes[3] = TO_saferead_uint8((uint8_t *)adr + 3);
	
	return le32toh(convert.data);
}

uint64_t TO_saferead_leuint40(const void* adr)
{
	union {
		uint64_t data;
		uint8_t  bytes[8];
	} convert;

	convert.data = 0;
	convert.bytes[0] = TO_saferead_uint8(adr);
	convert.bytes[1] = TO_saferead_uint8((uint8_t *)adr + 1);
	convert.bytes[2] = TO_saferead_uint8((uint8_t *)adr + 2);
	convert.bytes[3] = TO_saferead_uint8((uint8_t *)adr + 3);
	convert.bytes[4] = TO_saferead_uint8((uint8_t *)adr + 4);
	
	return le64toh(convert.data) & (((uint64_t)1 << 40) - 1);
}

uint64_t TO_saferead_leuint48(const void* adr)
{
	union {
		uint64_t data;
		uint8_t  bytes[8];
	} convert;

	convert.data = 0;
	convert.bytes[0] = TO_saferead_uint8(adr);
	convert.bytes[1] = TO_saferead_uint8((uint8_t *)adr + 1);
	convert.bytes[2] = TO_saferead_uint8((uint8_t *)adr + 2);
	convert.bytes[3] = TO_saferead_uint8((uint8_t *)adr + 3);
	convert.bytes[4] = TO_saferead_uint8((uint8_t *)adr + 4);
	convert.bytes[5] = TO_saferead_uint8((uint8_t *)adr + 5);
	
	return le64toh(convert.data) & (((uint64_t)1 << 48) - 1);
}

uint64_t TO_saferead_leuint56(const void* adr)
{
	union {
		uint64_t data;
		uint8_t  bytes[8];
	} convert;

	convert.data = 0;
	convert.bytes[0] = TO_saferead_uint8(adr);
	convert.bytes[1] = TO_saferead_uint8((uint8_t *)adr + 1);
	convert.bytes[2] = TO_saferead_uint8((uint8_t *)adr + 2);
	convert.bytes[3] = TO_saferead_uint8((uint8_t *)adr + 3);
	convert.bytes[4] = TO_saferead_uint8((uint8_t *)adr + 4);
	convert.bytes[5] = TO_saferead_uint8((uint8_t *)adr + 5);
	convert.bytes[6] = TO_saferead_uint8((uint8_t *)adr + 6);
	
	return le64toh(convert.data) & (((uint64_t)1 << 56) - 1);
}

uint64_t TO_saferead_leuint64(const void* adr)
{
	union {
		uint64_t data;
		uint8_t  bytes[8];
	} convert;

	convert.data = 0;
	convert.bytes[0] = TO_saferead_uint8(adr);
	convert.bytes[1] = TO_saferead_uint8((uint8_t *)adr + 1);
	convert.bytes[2] = TO_saferead_uint8((uint8_t *)adr + 2);
	convert.bytes[3] = TO_saferead_uint8((uint8_t *)adr + 3);
	convert.bytes[4] = TO_saferead_uint8((uint8_t *)adr + 4);
	convert.bytes[5] = TO_saferead_uint8((uint8_t *)adr + 5);
	convert.bytes[6] = TO_saferead_uint8((uint8_t *)adr + 6);
	convert.bytes[7] = TO_saferead_uint8((uint8_t *)adr + 7);
	
	return le64toh(convert.data);
}

uint16_t TO_saferead_beuint16(const void* adr)
{
	union {
		uint16_t data;
		uint8_t  bytes[2];
	} convert;

	convert.bytes[0] = TO_saferead_uint8(adr);
	convert.bytes[1] = TO_saferead_uint8((uint8_t *)adr + 1);
	
	return be16toh(convert.data);
}

uint32_t TO_saferead_beuint24(const void* adr)
{
	union {
		uint32_t data;
		uint8_t  bytes[4];
	} convert;

	convert.data = 0;
	convert.bytes[1] = TO_saferead_uint8(adr);
	convert.bytes[2] = TO_saferead_uint8((uint8_t *)adr + 1);
	convert.bytes[3] = TO_saferead_uint8((uint8_t *)adr + 2);
	
	return be32toh(convert.data) & 0xffffff;
}

uint32_t TO_saferead_beuint32(const void* adr)
{
	union {
		uint32_t data;
		uint8_t  bytes[4];
	} convert;

	convert.bytes[0] = TO_saferead_uint8(adr);
	convert.bytes[1] = TO_saferead_uint8((uint8_t *)adr + 1);
	convert.bytes[2] = TO_saferead_uint8((uint8_t *)adr + 2);
	convert.bytes[3] = TO_saferead_uint8((uint8_t *)adr + 3);
	
	return be32toh(convert.data);
}

uint64_t TO_saferead_beuint40(const void* adr)
{
	union {
		uint64_t data;
		uint8_t  bytes[8];
	} convert;

	convert.data = 0;
	convert.bytes[3] = TO_saferead_uint8(adr);
	convert.bytes[4] = TO_saferead_uint8((uint8_t *)adr + 1);
	convert.bytes[5] = TO_saferead_uint8((uint8_t *)adr + 2);
	convert.bytes[6] = TO_saferead_uint8((uint8_t *)adr + 3);
	convert.bytes[7] = TO_saferead_uint8((uint8_t *)adr + 4);
	
	return be64toh(convert.data) & (((uint64_t)1 << 40) - 1);
}

uint64_t TO_saferead_beuint48(const void* adr)
{
	union {
		uint64_t data;
		uint8_t  bytes[8];
	} convert;

	convert.data = 0;
	convert.bytes[2] = TO_saferead_uint8(adr);
	convert.bytes[3] = TO_saferead_uint8((uint8_t *)adr + 1);
	convert.bytes[4] = TO_saferead_uint8((uint8_t *)adr + 2);
	convert.bytes[5] = TO_saferead_uint8((uint8_t *)adr + 3);
	convert.bytes[6] = TO_saferead_uint8((uint8_t *)adr + 4);
	convert.bytes[7] = TO_saferead_uint8((uint8_t *)adr + 5);
	
	return be64toh(convert.data) & (((uint64_t)1 << 48) - 1);
}

uint64_t TO_saferead_beuint56(const void* adr)
{
	union {
		uint64_t data;
		uint8_t  bytes[8];
	} convert;

	convert.data = 0;
	convert.bytes[1] = TO_saferead_uint8(adr);
	convert.bytes[2] = TO_saferead_uint8((uint8_t *)adr + 1);
	convert.bytes[3] = TO_saferead_uint8((uint8_t *)adr + 2);
	convert.bytes[4] = TO_saferead_uint8((uint8_t *)adr + 3);
	convert.bytes[5] = TO_saferead_uint8((uint8_t *)adr + 4);
	convert.bytes[6] = TO_saferead_uint8((uint8_t *)adr + 5);
	convert.bytes[7] = TO_saferead_uint8((uint8_t *)adr + 6);
	
	return be64toh(convert.data) & (((uint64_t)1 << 56) - 1);
}

uint64_t TO_saferead_beuint64(const void* adr)
{
	union {
		uint64_t data;
		uint8_t  bytes[8];
	} convert;

	convert.bytes[0] = TO_saferead_uint8(adr);
	convert.bytes[1] = TO_saferead_uint8((uint8_t *)adr + 1);
	convert.bytes[2] = TO_saferead_uint8((uint8_t *)adr + 2);
	convert.bytes[3] = TO_saferead_uint8((uint8_t *)adr + 3);
	convert.bytes[4] = TO_saferead_uint8((uint8_t *)adr + 4);
	convert.bytes[5] = TO_saferead_uint8((uint8_t *)adr + 5);
	convert.bytes[6] = TO_saferead_uint8((uint8_t *)adr + 6);
	convert.bytes[7] = TO_saferead_uint8((uint8_t *)adr + 7);
	
	return be64toh(convert.data);
}

void TO_safewrite_uint8(void* adr, uint8_t data)
{
#ifdef __CORTEXM0__
	uint32_t *ptr32bits = (uint32_t *)(((uint32_t)adr) & 0xfffffffc);
	uint32_t offset = ((uint32_t)adr) & 0x3;
	uint32_t data_original;

	data_original = *ptr32bits;
	data_original &= ~(0xff >> (offset * 8))
	data_original |= (data >> (offset * 8))

	*ptr32bits = data_original;
#else
	*(uint8_t*)adr = data;
#endif
}

void TO_safewrite_leuint16(void* adr, uint16_t data)
{
	union {
		uint16_t data;
		uint8_t  bytes[2];
	} convert;

	convert.data = htole16(data);
	TO_safewrite_uint8(                  adr     ,convert.bytes[0] & 0xff);
	TO_safewrite_uint8((void*)((uint8_t*)adr + 1),convert.bytes[1] & 0xff);
}

void TO_safewrite_leuint24(void* adr, uint32_t data)
{
	union {
		uint32_t data;
		uint8_t  bytes[4];
	} convert;

	convert.data = htole32(data);
	TO_safewrite_uint8(                  adr     ,convert.bytes[0] & 0xff);
	TO_safewrite_uint8((void*)((uint8_t*)adr + 1),convert.bytes[1] & 0xff);
	TO_safewrite_uint8((void*)((uint8_t*)adr + 2),convert.bytes[2] & 0xff);
}

void TO_safewrite_leuint32(void* adr, uint32_t data)
{
	union {
		uint32_t data;
		uint8_t  bytes[4];
	} convert;

	convert.data = htole32(data);
	TO_safewrite_uint8(                  adr     ,convert.bytes[0] & 0xff);
	TO_safewrite_uint8((void*)((uint8_t*)adr + 1),convert.bytes[1] & 0xff);
	TO_safewrite_uint8((void*)((uint8_t*)adr + 2),convert.bytes[2] & 0xff);
	TO_safewrite_uint8((void*)((uint8_t*)adr + 3),convert.bytes[3] & 0xff);
}

void TO_safewrite_leuint40(void* adr, uint64_t data)
{
	union {
		uint64_t data;
		uint8_t  bytes[8];
	} convert;

	convert.data = htole64(data);
	TO_safewrite_uint8(                  adr     ,convert.bytes[0] & 0xff);
	TO_safewrite_uint8((void*)((uint8_t*)adr + 1),convert.bytes[1] & 0xff);
	TO_safewrite_uint8((void*)((uint8_t*)adr + 2),convert.bytes[2] & 0xff);
	TO_safewrite_uint8((void*)((uint8_t*)adr + 3),convert.bytes[3] & 0xff);
	TO_safewrite_uint8((void*)((uint8_t*)adr + 4),convert.bytes[4] & 0xff);
}

void TO_safewrite_leuint48(void* adr, uint64_t data)
{
	union {
		uint64_t data;
		uint8_t  bytes[8];
	} convert;

	convert.data = htole64(data);
	TO_safewrite_uint8(                  adr     ,convert.bytes[0] & 0xff);
	TO_safewrite_uint8((void*)((uint8_t*)adr + 1),convert.bytes[1] & 0xff);
	TO_safewrite_uint8((void*)((uint8_t*)adr + 2),convert.bytes[2] & 0xff);
	TO_safewrite_uint8((void*)((uint8_t*)adr + 3),convert.bytes[3] & 0xff);
	TO_safewrite_uint8((void*)((uint8_t*)adr + 4),convert.bytes[4] & 0xff);
	TO_safewrite_uint8((void*)((uint8_t*)adr + 5),convert.bytes[5] & 0xff);
}

void TO_safewrite_leuint56(void* adr, uint64_t data)
{
	union {
		uint64_t data;
		uint8_t  bytes[8];
	} convert;

	convert.data = htole64(data);
	TO_safewrite_uint8(                  adr     ,convert.bytes[0] & 0xff);
	TO_safewrite_uint8((void*)((uint8_t*)adr + 1),convert.bytes[1] & 0xff);
	TO_safewrite_uint8((void*)((uint8_t*)adr + 2),convert.bytes[2] & 0xff);
	TO_safewrite_uint8((void*)((uint8_t*)adr + 3),convert.bytes[3] & 0xff);
	TO_safewrite_uint8((void*)((uint8_t*)adr + 4),convert.bytes[4] & 0xff);
	TO_safewrite_uint8((void*)((uint8_t*)adr + 5),convert.bytes[5] & 0xff);
	TO_safewrite_uint8((void*)((uint8_t*)adr + 6),convert.bytes[6] & 0xff);
}

void TO_safewrite_leuint64(void* adr, uint64_t data)
{
	union {
		uint64_t data;
		uint8_t  bytes[8];
	} convert;

	convert.data = htole64(data);
	TO_safewrite_uint8(                  adr     ,convert.bytes[0] & 0xff);
	TO_safewrite_uint8((void*)((uint8_t*)adr + 1),convert.bytes[1] & 0xff);
	TO_safewrite_uint8((void*)((uint8_t*)adr + 2),convert.bytes[2] & 0xff);
	TO_safewrite_uint8((void*)((uint8_t*)adr + 3),convert.bytes[3] & 0xff);
	TO_safewrite_uint8((void*)((uint8_t*)adr + 4),convert.bytes[4] & 0xff);
	TO_safewrite_uint8((void*)((uint8_t*)adr + 5),convert.bytes[5] & 0xff);
	TO_safewrite_uint8((void*)((uint8_t*)adr + 6),convert.bytes[6] & 0xff);
	TO_safewrite_uint8((void*)((uint8_t*)adr + 7),convert.bytes[7] & 0xff);
}

void TO_safewrite_beuint16(void* adr, uint16_t data)
{
	union {
		uint16_t data;
		uint8_t  bytes[2];
	} convert;

	convert.data = htobe16(data);
	TO_safewrite_uint8(                  adr     ,convert.bytes[0] & 0xff);
	TO_safewrite_uint8((void*)((uint8_t*)adr + 1),convert.bytes[1] & 0xff);
}

void TO_safewrite_beuint24(void* adr, uint32_t data)
{
	union {
		uint32_t data;
		uint8_t  bytes[4];
	} convert;

	convert.data = htobe32(data);
	TO_safewrite_uint8(                  adr     ,convert.bytes[1] & 0xff);
	TO_safewrite_uint8((void*)((uint8_t*)adr + 1),convert.bytes[2] & 0xff);
	TO_safewrite_uint8((void*)((uint8_t*)adr + 2),convert.bytes[3] & 0xff);
}

void TO_safewrite_beuint32(void* adr, uint32_t data)
{
	union {
		uint32_t data;
		uint8_t  bytes[4];
	} convert;

	convert.data = htobe32(data);
	TO_safewrite_uint8(                  adr     ,convert.bytes[0] & 0xff);
	TO_safewrite_uint8((void*)((uint8_t*)adr + 1),convert.bytes[1] & 0xff);
	TO_safewrite_uint8((void*)((uint8_t*)adr + 2),convert.bytes[2] & 0xff);
	TO_safewrite_uint8((void*)((uint8_t*)adr + 3),convert.bytes[3] & 0xff);
}

void TO_safewrite_beuint40(void* adr, uint64_t data)
{
	union {
		uint64_t data;
		uint8_t  bytes[8];
	} convert;

	convert.data = htobe64(data);
	TO_safewrite_uint8(                  adr     ,convert.bytes[3] & 0xff);
	TO_safewrite_uint8((void*)((uint8_t*)adr + 1),convert.bytes[4] & 0xff);
	TO_safewrite_uint8((void*)((uint8_t*)adr + 2),convert.bytes[5] & 0xff);
	TO_safewrite_uint8((void*)((uint8_t*)adr + 3),convert.bytes[6] & 0xff);
	TO_safewrite_uint8((void*)((uint8_t*)adr + 4),convert.bytes[7] & 0xff);
}

void TO_safewrite_beuint48(void* adr, uint64_t data)
{
	union {
		uint64_t data;
		uint8_t  bytes[8];
	} convert;

	convert.data = htobe64(data);
	TO_safewrite_uint8(                  adr     ,convert.bytes[2] & 0xff);
	TO_safewrite_uint8((void*)((uint8_t*)adr + 1),convert.bytes[3] & 0xff);
	TO_safewrite_uint8((void*)((uint8_t*)adr + 2),convert.bytes[4] & 0xff);
	TO_safewrite_uint8((void*)((uint8_t*)adr + 3),convert.bytes[5] & 0xff);
	TO_safewrite_uint8((void*)((uint8_t*)adr + 4),convert.bytes[6] & 0xff);
	TO_safewrite_uint8((void*)((uint8_t*)adr + 5),convert.bytes[7] & 0xff);
}

void TO_safewrite_beuint56(void* adr, uint64_t data)
{
	union {
		uint64_t data;
		uint8_t  bytes[8];
	} convert;

	convert.data = htobe64(data);
	TO_safewrite_uint8(                  adr     ,convert.bytes[1] & 0xff);
	TO_safewrite_uint8((void*)((uint8_t*)adr + 1),convert.bytes[2] & 0xff);
	TO_safewrite_uint8((void*)((uint8_t*)adr + 2),convert.bytes[3] & 0xff);
	TO_safewrite_uint8((void*)((uint8_t*)adr + 3),convert.bytes[4] & 0xff);
	TO_safewrite_uint8((void*)((uint8_t*)adr + 4),convert.bytes[5] & 0xff);
	TO_safewrite_uint8((void*)((uint8_t*)adr + 5),convert.bytes[6] & 0xff);
	TO_safewrite_uint8((void*)((uint8_t*)adr + 6),convert.bytes[7] & 0xff);
}

void TO_safewrite_beuint64(void* adr, uint64_t data)
{
	union {
		uint64_t data;
		uint8_t  bytes[8];
	} convert;

	convert.data = htobe64(data);
	TO_safewrite_uint8(                  adr     ,convert.bytes[0] & 0xff);
	TO_safewrite_uint8((void*)((uint8_t*)adr + 1),convert.bytes[1] & 0xff);
	TO_safewrite_uint8((void*)((uint8_t*)adr + 2),convert.bytes[2] & 0xff);
	TO_safewrite_uint8((void*)((uint8_t*)adr + 3),convert.bytes[3] & 0xff);
	TO_safewrite_uint8((void*)((uint8_t*)adr + 4),convert.bytes[4] & 0xff);
	TO_safewrite_uint8((void*)((uint8_t*)adr + 5),convert.bytes[5] & 0xff);
	TO_safewrite_uint8((void*)((uint8_t*)adr + 6),convert.bytes[6] & 0xff);
	TO_safewrite_uint8((void*)((uint8_t*)adr + 7),convert.bytes[7] & 0xff);
}

void *TO_safe_memcpy(void *dst, const void * src,size_t size)
{
#ifdef __XTENSA__
	uint8_t *source = (uint8_t *)src;
	uint8_t *destination = (uint8_t *)dst;
	char car = TO_saferead_uint8(source++);

	while (size) {
		*(destination++) = car;
		car = TO_saferead_uint8(source++);
		size--;
	}
	return dst;
#else
	return memcpy(dst,src,size);
#endif
}

char *TO_safe_strcpy(char * dst, const char * src)
{
#ifdef __XTENSA__
	uint8_t *source = (uint8_t *)src;
	char car = TO_saferead_uint8(source++);

	do {
		*(dst++) = car;
		car = TO_saferead_uint8(source++);
	} while (car);
	*dst = '\x0';

	return dst;
#else
	return strcpy(dst,src);
#endif
}

char *TO_safe_strncpy(char * dst, const char * src, size_t num)
{
#ifdef __XTENSA__
	uint8_t *source = (uint8_t *)src;
	char car = TO_saferead_uint8(source++);
	size_t len = 0;

	do {
		*(dst++) = car;
		car = TO_saferead_uint8(source++);
		if (len >= num - 1)
			break;
		num++;
	} while (car);
	*dst = '\x0';

	return dst;
#else
	return strncpy(dst,src,num);
#endif
}

int TO_safe_memcmp( const void * ptr1, const void * ptr2, size_t num )
{
#ifdef __XTENSA__
	uint8_t *pointer1 = (uint8_t *)ptr1;
	uint8_t *pointer2 = (uint8_t *)ptr2;
	int diff;

	while (num--) {
		diff = TO_saferead_uint8(pointer1++) - TO_saferead_uint8(pointer2++);
		if (diff)
			return diff;
	};

	return 0;
#else
	return memcmp(ptr1,ptr2,num);
#endif
}
