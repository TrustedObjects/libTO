/*
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright 2016 Trusted Objects
 */

/**
 * @file get_sn
 * @brief Example getting and printing Secure Element serial number.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include "TO.h"
#ifdef TOSE_DRIVER_SSE
#include "TOP.h"
#endif

void print_usage(char *bin_name)
{
	fprintf(stderr, "Usage: %s <certificate_index> <output DER file>\n"
			"\tcertificate index range is 0..255\n", bin_name);
}

int main(int argc, char *argv[])
{
	unsigned int i;
	int ret;
	uint8_t index;
	uint8_t certificate[TOP_CERT_X509_MAXSIZE];
	uint16_t size;
	char *output_file;
	FILE *f;

	if (argc != 3) {
		print_usage(argv[0]);
		ret = -1;
		goto err;
	}
	index = atoi(argv[1]);
	output_file = argv[2];

	if (TO_init() != TO_OK) {
		fprintf(stderr, "Unable to initialize Secure Element\n");
		ret = -2;
		goto err;
	}
	printf("Secure Element initialized\n");

	if (TO_get_certificate_x509(index, certificate, &size)
			!= TORSP_SUCCESS) {
		fprintf(stderr, "Unable to get certificate %d\n", index);
		ret = -3;
		goto err;
	}
	printf("Secure Element certificate %d:", index);
	for (i = 0; i < size; i++)
		printf(" %02X", certificate[i]);
	printf("\n");

	f = fopen(output_file, "wb");
	if (f == NULL) {
		fprintf(stderr, "Unable to open %s: %s\n",
				output_file, strerror(errno));
		ret = -4;
		goto err;
	}
	if (fwrite(certificate, sizeof(uint8_t), size, f) != size) {
		fprintf(stderr, "Unable to write %s\n", output_file);
		fclose(f);
		ret = -5;
		goto err;
	}
	fclose(f);
	printf("Certificate written to %s.\n", output_file);

	ret = 0;
err:
	TO_fini();
	return ret;
}

