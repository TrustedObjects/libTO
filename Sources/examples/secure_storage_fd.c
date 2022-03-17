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
 * @file secure_storage.c
 * @brief Secure storage file based example.
 */
#include "TO.h"
#include "TOP.h"
#include "TODRV_SSE_cfg.h"

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

static int open_fd(void)
{
	int fd;
	fd = open("fake_nvm", O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);

	if (ftruncate(fd, TOP_SECURE_STORAGE_NVM_FOOTPRINT) < 0) {
		perror("ftruncate");
		return -1;
	}

	return fd;
}

TO_lib_ret_t TODRV_SSE_secure_storage_read(uint8_t *data, const void *address, const uint32_t size)
{
	ssize_t len;
	int fd;

	if ((fd = open_fd()) < 0) {
		return TO_ERROR;
	}

	if (lseek(fd, (off_t)address, SEEK_SET) < 0) {
		perror("lseek");
		close(fd);
		return TO_ERROR;
	}

	if ((len = read(fd, data, size)) < 0) {
		perror("read");
		close(fd);
		return TO_ERROR;
	}

	if (len != size) {
		printf("%ld bytes read instead of %u\n", len, size);
		close(fd);
		return TO_ERROR;
	}

	close(fd);
	return TO_OK;
}

TO_lib_ret_t TODRV_SSE_secure_storage_write(void *address, const uint8_t *data, const uint32_t size)
{
	TO_lib_ret_t ret;
	uint8_t _data[size];
	int fd;
	uint32_t i;

	if ((fd = open_fd()) < 0) {
		return TO_ERROR;
	}

	if ((ret = TODRV_SSE_secure_storage_read(_data, address, size)) != TO_OK) {
		close(fd);
		return ret;
	}

	for (i = 0; i < size; ++i) {
		if (_data[i] != 0xff) {
			printf("Cannot write not erased byte at address %lx\n",
					(unsigned long)(address) + i);
			close(fd);
			return TO_ERROR;
		}
	}

	if (lseek(fd, (off_t)address, SEEK_SET) < 0) {
		perror("lseek");
		close(fd);
		return TO_ERROR;
	}

	if (write(fd, data, size) != size) {
		perror("write");
		close(fd);
		return TO_ERROR;
	}

	if (fsync(fd) < 0) {
		perror("fsync");
		close(fd);
		return TO_ERROR;
	}

	close(fd);
	return TO_OK;
}

TO_lib_ret_t TODRV_SSE_secure_storage_erase(void *address, uint32_t size)
{
	long unsigned int i;
	const uint8_t ff = 0xff;
	int fd;

	if ((fd = open_fd()) < 0) {
		return TO_ERROR;
	}

	if (lseek(fd, (off_t)address, SEEK_SET) < 0) {
		perror("lseek");
		close(fd);
		return TO_ERROR;
	}

	for (i = (long unsigned int)address; i < (long unsigned int)address + size; ++i) {
		if (write(fd, &ff, sizeof(ff)) != sizeof(ff)) {
			perror("write");
			close(fd);
			return TO_ERROR;
		}
	}

	if (fsync(fd) < 0) {
		perror("fsync");
		close(fd);
		return TO_ERROR;
	}

	close(fd);
	return TO_OK;
}

