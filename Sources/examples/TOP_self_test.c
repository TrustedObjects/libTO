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
 * @file TOP_self_test.c
 * @brief Example self-testing TO-Protect
 */
#include "TO.h"
#include "TODRV_SSE.h"
#include "TO_log.h"

#ifndef ENABLE_X86_PLATFORM
// This log function will have to be overridden by a better one, depending on the
// running platform (eg. printf(), serial_printf(), etc)
void print_log_function(const TO_log_level_t level, const char * log)
{
	(void)level;
	(void)log;
}
#endif

int main(void)
{
	TO_lib_ret_t ret;

	if ((ret = TODRV_SSE_nvm_self_test(TO_log_get_ctx())) != TO_OK) {
		printf("NVM self-test failed with error %04x\n", ret);
		return 1;
	}

	if ((ret = TODRV_SSE_top_self_test(TO_log_get_ctx())) != TO_OK) {
		printf("TO-Protect self-test failed with error %04x\n", ret);
		return 1;
	}

	printf("Self-tests succeed\n");

	return 0;
}

