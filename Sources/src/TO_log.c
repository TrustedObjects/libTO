/*
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (C) 2016-2023 Trusted Objects. All rights reserved.
 */

#include "TO_cfg.h"
#include "TO_defs.h"
#include "TO_utils.h"
#include "TO_portability.h"
#include "TO_log.h"

#include <stdarg.h>
#include <stdio.h>

#define HEX_DISP_NB_COL 16
#define MAX_LOG_SIZE 200
#define MAX_LOG_FORMAT_SIZE 100
#define MAX_LOG_FUNC_NAME_SIZE 100

/**
 * @brief Print log function.
 * @details This function will have to be implemented using the correct method to send
 * the logs away.
 * This default implementation simply writes the log message to stdout. It may be
 * enough for most applications, but feel free to re-implement it to fit your particular
 * needs.
 * @param[in] level This is the log level (Error, Warning, Info, Debug)
 * @param[in] log This is the log string to be sent.
 */
__attribute__ ((weak)) void print_log_function(const TO_log_level_t level, const char *log)
{
	(void)level;
	puts(log);
}

/**
 * @brief Process a standard log output with formatting
 * @details This function expects a variable arguments list, including :
 *  - A mandatory function name (already provided by the invoking macro)
 *  - Parameters required by the formatting.
 * @param[in] level Log level (Error, Warning ...)
 * @param[in] format Display format to be used (printf)
 * @param[in] args Variable arguments list
 */
static void TO_log_string(const TO_log_level_t level,
		char* format,
		va_list args)
{
#ifdef __XTENSA__
	char str_format[MAX_LOG_FORMAT_SIZE];
#else
	char *str_format;
#endif
	char *func_name;
	char log[MAX_LOG_SIZE];
	size_t len;

	// Search for the next args and convert the strings
	func_name = va_arg(args,char *);

#ifdef __XTENSA__
	// Copy those constants supposingly coming from the code to the RAM data space
	TO_safe_strcpy(log,func_name);
	TO_safe_strcpy(str_format,format);
#else
	strcpy(log, func_name);
	str_format = format;
#endif

	// Concat the ":"
	strcat(log,": ");
	len = strlen(log);
	len = vsnprintf(log + len, sizeof(log) - len, str_format, args);

	// Make it appear wherever
	print_log_function(level, log);
}

/**
 * @brief Log function used to dump a buffer in hexadecimal
 * @details This function does not requires the buffer to be in the data memory space.
 * In Xtensa architecture, it takes care of accessing the data the correct way.
 * The result is an hexadecimal dump, without the ascii correspondance.
 * @param[in] level Log level (Error, Warning ...)
 * @param[in] _data Pointer to the data to be dumped
 * @param[in] size Size of the data area to be dumped (bytes)
 */
static void TO_log_hex_disp(const TO_log_level_t level,
		void *_data,
		unsigned int size)
{
	char log[HEX_DISP_NB_COL * 3 + 2];
	uint16_t log_len = 0;
	unsigned int i;
#ifdef __XTENSA__
	uint8_t the_data[HEX_DISP_NB_COL];
#else
	uint8_t *the_data;
#endif

	// Looping over data
	for(i = 0; i < size; i++) {
		if ((i) && (!(i % HEX_DISP_NB_COL))) {
			log[log_len++] = '\0';
			print_log_function(level, log);
			log_len = 0;
		}
		if (i % HEX_DISP_NB_COL == 0) {
#ifdef __XTENSA__

			// Recopy the data from Code to data using the right method
			TO_safe_memcpy(the_data,((uint8_t *)_data) + i, HEX_DISP_NB_COL);
#else
			the_data = ((uint8_t *)_data) + i;
#endif
		}
		log_len += snprintf(log + log_len, sizeof(log) - log_len, "%02X ", the_data[i % HEX_DISP_NB_COL]);
	}
	log[log_len++] = '\0';
	print_log_function(level, log);
}

/**
 * @brief Log function used to dump a buffer in hexadecimal
 * @details This function does not requires the buffer to be in the data memory space.
 * In Xtensa architecture, it takes care of accessing the data the correct way.
 * The result is an hexadecimal dump, with the ascii correspondance.
 * @param[in] level Log level (Error, Warning ...)
 * @param[in] _data Pointer to the data to be dumped
 * @param[in] size Size of the data area to be dumped (bytes)
 */
static void TO_log_dump_buffer(const TO_log_level_t level,
		void *_data,
		unsigned int size)
{
	char log[20 + HEX_DISP_NB_COL * 3 + 2 + HEX_DISP_NB_COL + 3];
	char ascii[HEX_DISP_NB_COL + 1];
	uint16_t log_len = 0;
	unsigned int i;
	uint8_t the_data[HEX_DISP_NB_COL];

	memset(ascii, 0, HEX_DISP_NB_COL + 1);

	// Looping over data
	for (i = 0; i < size; ++i) {
		if (!(i % HEX_DISP_NB_COL)) {
			if (i) {

				// Every 16 bytes
				log[log_len++] = '\0';
				strcat(log, "  ");
				strcat(log, ascii);
				print_log_function(level, log);
				memset(ascii, 0, HEX_DISP_NB_COL + 1);
				log_len = 0;
			}
			if (i % HEX_DISP_NB_COL == 0) {

				// Recopy the data from Code to data using the right method
				TO_safe_memcpy(the_data,((uint8_t *)_data) + i, HEX_DISP_NB_COL);
			}
			log_len += snprintf(log + log_len, sizeof(log) - log_len, "%04x: ", (unsigned int)i);
		}
		log_len += snprintf(log + log_len, sizeof(log) - log_len, "%02x ", the_data[i % HEX_DISP_NB_COL]);
		if ((the_data[i % HEX_DISP_NB_COL] >= 32) && (the_data[i % HEX_DISP_NB_COL] < 127)) {
			ascii[i % HEX_DISP_NB_COL] = the_data[i % HEX_DISP_NB_COL];
		} else {
			ascii[i % HEX_DISP_NB_COL] = '.';
		}
	}
	if (log_len > 0) {
		// Excluding the silly case where we have 16 bytes already dumped
		if (i % HEX_DISP_NB_COL) {
			// Fill missing bytes with space
			for (int j = (i % HEX_DISP_NB_COL);j < HEX_DISP_NB_COL; j++) {
				strcat(log,"   ");
			}
		}
		strcat(log, "  ");
		strcat(log, ascii);
		print_log_function(level, log);
	}
}

/**
 * @brief Generates a log message when entering a function
 *
 * @param[in] fct Function's name
 */
static void TO_log_enter(char * fct)
{
	char log[MAX_LOG_SIZE];
	char fct_name[MAX_LOG_FUNC_NAME_SIZE];

	TO_safe_strncpy(fct_name, fct, sizeof(fct_name));
	sprintf(log, ">>> %s", fct_name);
	print_log_function(TO_LOG_LEVEL_DBG, log);
}

/**
 * @brief Generates a log message when exiting a function
 *
 * @param[in] fct Function's name
 */
static void TO_log_exit(char * fct)
{
	char log[MAX_LOG_SIZE];
	char fct_name[MAX_LOG_FUNC_NAME_SIZE];

	TO_safe_strncpy(fct_name, fct, sizeof(fct_name));
	sprintf(log,"<<< %s", fct_name);
	print_log_function(TO_LOG_LEVEL_DBG, log);
}

/**
 * @brief Generates a log message when returning a value from a function
 *
 * @param[in] fct Function's name
 * @param[in] ret Returned value
 * @param[in] line Line number
 *
 */
static void TO_log_return(char * fct, unsigned short ret, int line)
{
	char log[MAX_LOG_SIZE];
	char fct_name[MAX_LOG_FUNC_NAME_SIZE];

	TO_safe_strncpy(fct_name, fct, sizeof(fct_name));
	sprintf(log, "<<< %s (%04X) @(%d)", fct_name, ret, line);
	print_log_function(TO_LOG_LEVEL_DBG, log);
}

void TO_set_log_level(TO_log_ctx_t *log_ctx,
		const TO_log_level_t level,
		TO_log_func_t* log_function)
{
	log_ctx->log_level = level;
	log_ctx->log_function = log_function;
}

void TO_log(TO_log_ctx_t *log_ctx, const TO_log_level_t level, void * ptr, ...)
{
	va_list vl;
	unsigned int size;
	unsigned short ret;
	int line;

	// Filter the requested level
	if ((level & TO_LOG_LEVEL_MASK) > log_ctx->log_level) {
		return;
	}

	// ptr is the last argument we know for sure
	va_start(vl,ptr);

	switch (level) {
		case TO_LOG_STRING_ERR:
		case TO_LOG_STRING_WRN:
		case TO_LOG_STRING_INF:
		case TO_LOG_STRING_DBG:

			// Forward to the other function
			TO_log_string(level & TO_LOG_LEVEL_MASK, (char *)ptr, vl);
			break;

		case TO_LOG_BUFFER_ERR:
		case TO_LOG_BUFFER_WRN:
		case TO_LOG_BUFFER_INF:
		case TO_LOG_BUFFER_DBG:

			// Get the 2 arguments and go !
			size = va_arg(vl,unsigned int);
			TO_log_dump_buffer(level & TO_LOG_LEVEL_MASK, ptr, size);
			break;

		case TO_LOG_HEX_DISP_ERR:
		case TO_LOG_HEX_DISP_WRN:
		case TO_LOG_HEX_DISP_INF:
		case TO_LOG_HEX_DISP_DBG:

			// Get the 2 arguments and go !
			size = va_arg(vl,unsigned int);
			TO_log_hex_disp(level & TO_LOG_LEVEL_MASK, ptr, size);
			break;

		case TO_LOG_ENTER:
			TO_log_enter((char *)ptr);
			break;

		case TO_LOG_RETURN:
			ret = va_arg(vl,int);
			line = va_arg(vl,int);
			TO_log_return((char *)ptr,ret,line);
			break;

		case TO_LOG_EXIT:
			TO_log_exit((char *)ptr);
			break;

		default:
			break;
	}

	// Clean-up
	va_end(vl);
}

/**
 * @brief Default log context
 *
 */
TO_log_ctx_t log_ctx = {
	.log_function = &TO_log,   	// By default
	.log_level = TO_LOG_LEVEL_MAX,	// By default, no LOGs (as we ignore the log function)
};

TO_log_ctx_t* TO_log_get_ctx(void)
{
	return (TO_log_ctx_t*)&log_ctx;
}
