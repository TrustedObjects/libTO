/*
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright 2016-2021 Trusted Objects
 */

/**
 * @file multi_driver
 * @brief Example using both HSE and SSE Secure Elements at the same time.
 */

#include "TO.h"
#include "TO_helper.h"
#include "TO_driver.h"
#include "TO_retcodes.h"

void print_log_function(const TO_log_level_t level, const char *log)
{
	switch (level & TO_LOG_LEVEL_MASK) {
		case TO_LOG_LEVEL_ERR:
			fprintf(stderr,log);
			break;
	
		case TO_LOG_LEVEL_DBG:
		case TO_LOG_LEVEL_INF:
		case TO_LOG_LEVEL_WRN:
			fprintf(stdout,log);
			break;
	
		default:
			break;
	}
}

void printhex(const char* label, uint8_t *data, uint16_t size)
{
	uint16_t i;

	printf("%s: ", label);
	for (i = 0; i < size; i++) {
		printf("%02X ", data[i]);
	}
	printf("\n");
}

int main(void)
{
	int ret;
	uint8_t pn[TO_PN_SIZE + 1];
	TOSE_ctx_t *sse_ctx;
	TOSE_ctx_t *hse_ctx;
	uint8_t challenge[TO_CHALLENGE_SIZE];
	uint8_t certificate[1024];
	uint16_t size;
	uint8_t signature[TO_SIGNATURE_SIZE];

	sse_ctx = TODRV_SSE_get_ctx();
	hse_ctx = TODRV_HSE_get_ctx();
	if (TOSE_init(sse_ctx) != TO_OK) {
		fprintf(stderr, "Unable to initialize SSE\n");
		ret = -1;
		goto err;
	}
	if (TOSE_init(hse_ctx) != TO_OK) {
		fprintf(stderr, "Unable to initialize HSE\n");
		ret = -1;
		goto err;
	}
	printf("Secure Elements initialized\n");

	pn[TO_PN_SIZE] = '\0';
	if (TOSE_get_product_number(sse_ctx, pn) != TORSP_SUCCESS) {
		fprintf(stderr, "Unable to get SSE PN\n");
		ret = -2;
		goto err;
	}
	printf("SSE PN: %s\n", pn);
	if (TOSE_get_product_number(hse_ctx, pn) != TORSP_SUCCESS) {
		fprintf(stderr, "Unable to get HSE PN\n");
		ret = -2;
		goto err;
	}
	printf("HSE PN: %s\n", pn);

#ifndef TO_DISABLE_CERTS_HELPER
	size = sizeof(certificate);
	ret = TOSE_helper_get_certificate_x509_and_sign(sse_ctx, 0,
			challenge, TO_CHALLENGE_SIZE,
			certificate, &size, signature);
	if (ret != TO_OK) {
		fprintf(stderr, "Unable to get SSE x509 certificate, error %X\n", ret);
		ret = -3;
		goto err;
	}
	printhex("Certificate", certificate, size);
	printhex("\tSignature", signature, TO_SIGNATURE_SIZE);

	size = sizeof(certificate);
	ret = TOSE_helper_get_certificate_x509_and_sign(hse_ctx, 0,
			challenge, TO_CHALLENGE_SIZE,
			certificate, &size, signature);
	if (ret != TO_OK) {
		fprintf(stderr, "Unable to get x509 certificate, error %X\n", ret);
		ret = -3;
		goto err;
	}
	printhex("Certificate", certificate, size);
	printhex("\tSignature", signature, TO_SIGNATURE_SIZE);
#endif

	ret = 0;
err:
	TOSE_fini(sse_ctx);
	TOSE_fini(hse_ctx);
	return ret;
}

