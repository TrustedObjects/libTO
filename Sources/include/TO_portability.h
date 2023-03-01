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

#ifndef __TOP_PORTABILITY_H__
#define __TOP_PORTABILITY_H__

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "TO_endian.h"
#include "TO_portability.h"

/**
 * @brief Generic uint8_t read function, available whatever the architecture.
 * @details Enables reading of a 8-bits integer whatever its alignment.
 * This function is usefull on architectures needing special care (Cortex-M0, lx6, etc).
 * It performs a one-byte read by reading the 32-bits word, aligned on a 32-bits boundary and
 * extracting the right byte from it.
 * @param[in] adr Address where the uint8 is located.
 * @return uint8_t The read value.
 */
extern uint8_t TO_saferead_uint8(const void* adr);

/**
 * @brief Generic uint16_t (little endian) read function, available whatever the architecture.
 * @details Enables reading of a 16-bits integer whatever its alignment.
 * This function is usefull on architectures needing special care (Cortex-M0, lx6, etc).
 * It converts the data from a little-endian representation to a host-one
 * @param[in] adr Address where the uint16 is located.
 * @return uint16_t The read value.
 */
extern uint16_t TO_saferead_leuint16(const void* adr);

/**
 * @brief Generic uint24_t (little endian) read function, available whatever the architecture.
 * @details Enables reading of a 24-bits integer whatever its alignment.
 * This function is usefull on architectures needing special care (Cortex-M0, lx6, etc).
 * @param[in] adr Address where the uint24 is located.
 * @return uint16_t The read value.
 */
extern uint32_t TO_saferead_leuint24(const void* adr);

/**
 * @brief Generic uint32_t (little endian) read function, available whatever the architecture.
 * @details Enables reading of a 32-bits integer whatever its alignment.
 * This function is usefull on architectures needing special care (Cortex-M0, lx6, etc).
 * @param[in] adr Address where the uint32 is located.
 * @return uint16_t The read value.
 */
extern uint32_t TO_saferead_leuint32(const void* adr);

/**
 * @brief Generic uint40_t (little endian) read function, available whatever the architecture.
 * @details Enables reading of a 40-bits integer whatever its alignment.
 * This function is usefull on architectures needing special care (Cortex-M0, lx6, etc).
 * @param[in] adr Address where the uint40 is located.
 * @return uint64_t The read value.
 */
extern uint64_t TO_saferead_leuint40(const void* adr);

/**
 * @brief Generic uint48_t (little endian) read function, available whatever the architecture.
 * @details Enables reading of a 48-bits integer whatever its alignment.
 * This function is usefull on architectures needing special care (Cortex-M0, lx6, etc).
 * @param[in] adr Address where the uint48 is located.
 * @return uint64_t The read value.
 */
extern uint64_t TO_saferead_leuint48(const void* adr);

/**
 * @brief Generic uint56_t (little endian) read function, available whatever the architecture.
 * @details Enables reading of a 56-bits integer whatever its alignment.
 * This function is usefull on architectures needing special care (Cortex-M0, lx6, etc).
 * @param[in] adr Address where the uint56 is located.
 * @return uint64_t The read value.
 */
extern uint64_t TO_saferead_leuint56(const void* adr);

/**
 * @brief Generic uint64_t (little endian) read function, available whatever the architecture.
 * @details Enables reading of a 64-bits integer whatever its alignment.
 * This function is usefull on architectures needing special care (Cortex-M0, lx6, etc).
 * @param[in] adr Address where the uint64 is located.
 * @return uint64_t The read value.
 */
extern uint64_t TO_saferead_leuint64(const void* adr);

/**
 * @brief Generic uint16_t (big endian) read function, available whatever the architecture.
 * @details Enables reading of a 16-bits integer whatever its alignment.
 * This function is usefull on architectures needing special care (Cortex-M0, lx6, etc).
 * @param[in] adr Address where the uint16 is located.
 * @return uint16_t The read value.
 */
extern uint16_t TO_saferead_beuint16(const void* adr);

/**
 * @brief Generic uint24_t (big endian) read function, available whatever the architecture.
 * @details Enables reading of a 24-bits integer whatever its alignment.
 * This function is usefull on architectures needing special care (Cortex-M0, lx6, etc).
 * @param[in] adr Address where the uint24 is located.
 * @return uint16_t The read value.
 */
extern uint32_t TO_saferead_beuint24(const void* adr);

/**
 * @brief Generic uint32_t (big endian) read function, available whatever the architecture.
 * @details Enables reading of a 32-bits integer whatever its alignment.
 * This function is usefull on architectures needing special care (Cortex-M0, lx6, etc).
 * @param[in] adr Address where the uint32 is located.
 * @return uint16_t The read value.
 */
extern uint32_t TO_saferead_beuint32(const void* adr);

/**
 * @brief Generic uint40_t (big endian) read function, available whatever the architecture.
 * @details Enables reading of a 40-bits integer whatever its alignment.
 * This function is usefull on architectures needing special care (Cortex-M0, lx6, etc).
 * @param[in] adr Address where the uint40 is located.
 * @return uint64_t The read value.
 */
extern uint64_t TO_saferead_beuint40(const void* adr);

/**
 * @brief Generic uint48_t (big endian) read function, available whatever the architecture.
 * @details Enables reading of a 48-bits integer whatever its alignment.
 * This function is usefull on architectures needing special care (Cortex-M0, lx6, etc).
 * @param[in] adr Address where the uint48 is located.
 * @return uint64_t The read value.
 */
extern uint64_t TO_saferead_beuint48(const void* adr);

/**
 * @brief Generic uint56_t (big endian) read function, available whatever the architecture.
 * @details Enables reading of a 56-bits integer whatever its alignment.
 * This function is usefull on architectures needing special care (Cortex-M0, lx6, etc).
 * @param[in] adr Address where the uint56 is located.
 * @return uint64_t The read value.
 */
extern uint64_t TO_saferead_beuint56(const void* adr);

/**
 * @brief Generic uint64_t (big endian) read function, available whatever the architecture.
 * @details Enables reading of a 64-bits integer whatever its alignment.
 * This function is usefull on architectures needing special care (Cortex-M0, lx6, etc).
 * @param[in] adr Address where the uint64 is located.
 * @return uint64_t The read value.
 */
extern uint64_t TO_saferead_beuint64(const void* adr);

/**
 * @brief Generic uint8_t data write function, available whatever the architecture.
 * @details Enables writing of a 8-bits integer whatever its alignment.
 * This function is usefull on architectures needing special care (Cortex-M0, lx6, etc)
 * @param[in/out] adr Address where to write to.
 * @param[in] data uint8_t value to write.
 */
extern void TO_safewrite_uint8(void* adr, uint8_t data);

/**
 * @brief Generic uint16_t (little endian) data write function, available whatever the architecture.
 * @details Enables writing of a 16-bits integer whatever its alignment.
 * This function is usefull on architectures needing special care (Cortex-M0, lx6, etc)
 * @param[in/out] adr Address where to write to.
 * @param[in] data uint16_t value to write.
 */
extern void TO_safewrite_leuint16(void* adr, uint16_t data);

/**
 * @brief Generic uint24_t (little endian) data write function, available whatever the architecture.
 * @details Enables writing of a 24-bits integer whatever its alignment.
 * This function is usefull on architectures needing special care (Cortex-M0, lx6, etc)
 * @param[in/out] adr Address where to write to.
 * @param[in] data uint32_t value to write.
 */
extern void TO_safewrite_leuint24(void* adr, uint32_t data);

/**
 * @brief Generic uint32_t (little endian) data write function, available whatever the architecture.
 * @details Enables writing of a 32-bits integer whatever its alignment.
 * This function is usefull on architectures needing special care (Cortex-M0, lx6, etc)
 * @param[in/out] adr Address where to write to.
 * @param[in] data uint32_t value to write.
 */
extern void TO_safewrite_leuint32(void* adr, uint32_t data);

/**
 * @brief Generic uint40_t (little endian) data write function, available whatever the architecture.
 * @details Enables writing of a 40-bits integer whatever its alignment.
 * This function is usefull on architectures needing special care (Cortex-M0, lx6, etc)
 * @param[in/out] adr Address where to write to.
 * @param[in] data uint64_t value to write.
 */
extern void TO_safewrite_leuint40(void* adr, uint64_t data);

/**
 * @brief Generic uint48_t (little endian) data write function, available whatever the architecture.
 * @details Enables writing of a 48-bits integer whatever its alignment.
 * This function is usefull on architectures needing special care (Cortex-M0, lx6, etc)
 * @param[in/out] adr Address where to write to.
 * @param[in] data uint64_t value to write.
 */
extern void TO_safewrite_leuint48(void* adr, uint64_t data);

/**
 * @brief Generic uint56_t (little endian) data write function, available whatever the architecture.
 * @details Enables writing of a 56-bits integer whatever its alignment.
 * This function is usefull on architectures needing special care (Cortex-M0, lx6, etc)
 * @param[in/out] adr Address where to write to.
 * @param[in] data uint64_t value to write.
 */
extern void TO_safewrite_leuint56(void* adr, uint64_t data);

/**
 * @brief Generic uint64_t (little endian) data write function, available whatever the architecture.
 * @details Enables writing of a 64-bits integer whatever its alignment.
 * This function is usefull on architectures needing special care (Cortex-M0, lx6, etc)
 * @param[in/out] adr Address where to write to.
 * @param[in] data uint64_t value to write.
 */
extern void TO_safewrite_leuint64(void* adr, uint64_t data);

/**
 * @brief Generic uint16_t (big endian) data write function, available whatever the architecture.
 * @details Enables writing of a 16-bits integer whatever its alignment.
 * This function is usefull on architectures needing special care (Cortex-M0, lx6, etc)
 * @param[in/out] adr Address where to write to.
 * @param[in] data uint16_t value to write.
 */
extern void TO_safewrite_beuint16(void* adr, uint16_t data);

/**
 * @brief Generic uint24_t (big endian) data write function, available whatever the architecture.
 * @details Enables writing of a 24-bits integer whatever its alignment.
 * This function is usefull on architectures needing special care (Cortex-M0, lx6, etc)
 * @param[in/out] adr Address where to write to.
 * @param[in] data uint32_t value to write.
 */
extern void TO_safewrite_beuint24(void* adr, uint32_t data);

/**
 * @brief Generic uint32_t (big endian) data write function, available whatever the architecture.
 * @details Enables writing of a 32-bits integer whatever its alignment.
 * This function is usefull on architectures needing special care (Cortex-M0, lx6, etc)
 * @param[in/out] adr Address where to write to.
 * @param[in] data uint32_t value to write.
 */
extern void TO_safewrite_beuint32(void* adr, uint32_t data);

/**
 * @brief Generic uint40_t (big endian) data write function, available whatever the architecture.
 * @details Enables writing of a 40-bits integer whatever its alignment.
 * This function is usefull on architectures needing special care (Cortex-M0, lx6, etc)
 * @param[in/out] adr Address where to write to.
 * @param[in] data uint64_t value to write.
 */
extern void TO_safewrite_beuint40(void* adr, uint64_t data);

/**
 * @brief Generic uint48_t (big endian) data write function, available whatever the architecture.
 * @details Enables writing of a 48-bits integer whatever its alignment.
 * This function is usefull on architectures needing special care (Cortex-M0, lx6, etc)
 * @param[in/out] adr Address where to write to.
 * @param[in] data uint64_t value to write.
 */
extern void TO_safewrite_beuint48(void* adr, uint64_t data);

/**
 * @brief Generic uint56_t (big endian) data write function, available whatever the architecture.
 * @details Enables writing of a 56-bits integer whatever its alignment.
 * This function is usefull on architectures needing special care (Cortex-M0, lx6, etc)
 * @param[in/out] adr Address where to write to.
 * @param[in] data uint64_t value to write.
 */
extern void TO_safewrite_beuint56(void* adr, uint64_t data);

/**
 * @brief Generic uint64_t (big endian) data write function, available whatever the architecture.
 * @details Enables writing of a 64-bits integer whatever its alignment.
 * This function is usefull on architectures needing special care (Cortex-M0, lx6, etc)
 * @param[in/out] adr Address where to write to.
 * @param[in] data uint64_t value to write.
 */
extern void TO_safewrite_beuint64(void* adr, uint64_t data);

/**
 * @brief Safe memcpy function, available whatever the architecture.
 * Enables reading of a bytes buffer integer whatever its alignment.
 * This function is usefull on architectures needing special care (Cortex-M0, lx6, etc).
 * @warning The architecture's capability may be taken into account differently in input and output.
 * @param dst Destination buffer
 * @param src Source buffer
 * @param size Buffer size (bytes)
 * @return void* The destination buffer's address
 */
extern void *TO_safe_memcpy(void *dst, const void * src,size_t size);

/**
 * @brief Safe strcpy function, available whatever the architecture.
 * Enables reading of a bytes buffer integer whatever its alignment.
 * This function is usefull on architectures needing special care (Cortex-M0, lx6, etc).
 * @warning The architecture's capability may be taken into account differently in input and output.
 * @param dst Pointer to the destination array where the content is to be copied.
 * @param src C string to be copied.
 * @return char* Destination string
 */
extern char *TO_safe_strcpy(char * dst, const char * src);

/**
 * @brief Safe strncpy function, available whatever the architecture.
 * Enables reading of a bytes buffer integer whatever its alignment.
 * This function is usefull on architectures needing special care (Cortex-M0, lx6, etc).
 * @warning The architecture's capability may be taken into account differently in input and output.
 * @param dst Pointer to the destination array where the content is to be copied.
 * @param src C string to be copied.
 * @param num Maximum number of characters to be copied from source
 * @return char* Destination string
 */
extern char *TO_safe_strncpy(char * dst, const char * src, size_t num);


/**
 * @brief Safe memcmp function, available whatever the architecture.
 * Enables reading of a bytes buffer integer whatever its alignment.
 * This function is usefull on architectures needing special care (Cortex-M0, lx6, etc).
 * @param ptr1 Buffer 1 to be compared with
 * @param ptr2 Buffer 2 to be compared with
 * @param num Number of bytes to compare on
 * @return int 
 */
extern int TO_safe_memcmp( const void * ptr1, const void * ptr2, size_t num );

/**
 * @brief This macro is used to access constants at their current place
 * whereas their access is made using an absolute address, and not a relative one.
 * 
 */
#ifdef __XTENSA__
#define TO_RELATIVE_CONST(adr,base)	(void *)((uint8_t *)(adr) + (base))
#else
#define TO_RELATIVE_CONST(adr,base)	(void *)((uint8_t *)(adr))
#endif

#endif // __TOP_PORTABILITY_H__