
#include "TO_cfg.h"
#include "TO_defs.h"

#include <stdarg.h>
#include <stdio.h>

#define HEX_DISP_NB_COL 16

static void TO_log_string(const TO_log_level_t level,
		const char* format,
		va_list args)
{
	uint16_t len;
	va_list copy;

	// Keep the var args safe
	va_copy(copy,args);

	// Make a first attempt to guess the number of bytes to be allocated
	len = vsnprintf(NULL, 0, format, copy);

	// Then, allocate the string the right size
	char log[len + 1];

	// Generate the message
	va_copy(copy,args);
	vsnprintf(log, sizeof(log), format, copy);

	// Make it appear wherever
	print_log_function(level, log);
}

static void TO_log_hex_disp(const TO_log_level_t level,
		void *_data,
		unsigned int size)
{
	char log[HEX_DISP_NB_COL * 3 + 2];
	uint16_t log_len = 0;
	unsigned int i;
	uint8_t *data = (uint8_t *)_data;

	for(i = 0; i < size; i++) {
		if ((i) && (!(i%HEX_DISP_NB_COL))) {
			log[log_len++] = '\n';
			log[log_len++] = '\0';
			print_log_function(level, log);
			log_len = 0;
		}
		log_len += snprintf(log + log_len, sizeof(log) - log_len, "%02X ", data[i]);
	}
	log[log_len++] = '\n';
	log[log_len++] = '\0';
	print_log_function(level, log);
}

static void TO_log_dump_buffer(const TO_log_level_t level,
		void *_buf,
		unsigned int size)
{
	char log[10 + HEX_DISP_NB_COL * 3 + 2];
	uint16_t log_len = 0;
	unsigned int i;
	uint8_t * buf = (uint8_t *)_buf;

	for (i = 0; i < size; ++i) {
		if (!(i % HEX_DISP_NB_COL)) {
			if (i) {
				log[log_len++] = '\n';
				log[log_len++] = '\0';
				print_log_function(level, log);
				log_len = 0;
			}
			log_len += snprintf(log + log_len, sizeof(log) - log_len, "%08x: ", (unsigned int)i);
		}
		log_len += snprintf(log + log_len, sizeof(log) - log_len, "%02x ", buf[i]);
	}
	log[log_len++] = '\n';
	log[log_len++] = '\0';
	print_log_function(level, log);
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

	(void)log_ctx;

	// ptr is the last argument we know for sure
	va_start(vl,ptr);

	switch (level) {
		case TO_LOG_STRING_ERR:
		case TO_LOG_STRING_WRN:
		case TO_LOG_STRING_INF:
		case TO_LOG_STRING_DBG:

			// Forward to the other function
			TO_log_string(level & TO_LOG_LEVEL_MASK, (const char *)ptr, vl);
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

		default:
			break;
	}

	// Clean-up
	va_end(vl);
}

__attribute__ ((weak)) void print_log_function(const TO_log_level_t level, const char *log)
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

__attribute__ ((weak)) TO_log_ctx_t* TO_log_get_ctx(void)
{ 
	static TO_log_ctx_t log_ctx = {.log_function = TO_log,.log_level = TO_LOG_LEVEL_MAX};

	return & log_ctx;
}
