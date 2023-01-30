
#include "TO_cfg.h"
#include "TO_defs.h"
#include "TO_utils.h"
#include "TO_portability.h"
#include "TO_log.h"

#include <stdarg.h>
#include <stdio.h>

#define HEX_DISP_NB_COL 16
#define MAX_LOG_SIZE 500
#define MAX_LOG_FORMAT_SIZE 100
#define MAX_LOG_FUNC_NAME_SIZE 100

__attribute__ ((weak)) void print_log_function(const TO_log_level_t level, const char *log)
{
	(void)level;
	puts(log);
}

static void TO_log_string(const TO_log_level_t level,
		char* format,
		va_list args)
{
	char log[MAX_LOG_SIZE];
	char str_format[MAX_LOG_FORMAT_SIZE];
	char *func_name;
	size_t len;

	// Search for the next args and convert the strings
	func_name = va_arg(args,char *);
	TO_safe_strcpy(log,func_name);
	TO_safe_strcpy(str_format,format);

	// Concat the ":"
	strcat(log,": ");
	len = strlen(log);
	len = vsnprintf(log + len, sizeof(log) - len, str_format, args);

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
	uint8_t the_data[size];

	// Recopy the data from Code to data using the right method
	TO_safe_memcpy(the_data,(uint8_t *)_data,size);

	// Looping over data
	for(i = 0; i < size; i++) {
		if ((i) && (!(i%HEX_DISP_NB_COL))) {
			log[log_len++] = '\0';
			print_log_function(level, log);
			log_len = 0;
		}
		log_len += snprintf(log + log_len, sizeof(log) - log_len, "%02X ", the_data[i]);
	}
	log[log_len++] = '\0';
	print_log_function(level, log);
}

static void TO_log_dump_buffer(const TO_log_level_t level,
		void *_buf,
		unsigned int size)
{
	char log[20 + HEX_DISP_NB_COL * 3 + 2 + HEX_DISP_NB_COL + 3];
	char ascii[HEX_DISP_NB_COL + 1];
	uint16_t log_len = 0;
	unsigned int i;
	uint8_t the_buf[size];

	// Recopy the data from Code to data using the right method
	TO_safe_memcpy(the_buf,(uint8_t *)_buf,size);
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
			log_len += snprintf(log + log_len, sizeof(log) - log_len, "%04x: ", (unsigned int)i);
		}
		log_len += snprintf(log + log_len, sizeof(log) - log_len, "%02x ", the_buf[i]);
		if ((the_buf[i] >= 32) && (the_buf[i] < 127)) {
			ascii[i % HEX_DISP_NB_COL] = the_buf[i];
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

static void TO_log_enter(char * fct)
{
	char log[110];
	char fct_name[100];

	TO_safe_strncpy(fct_name,fct,sizeof(fct_name));
	sprintf(log,">>> %s",fct_name);
	print_log_function(TO_LOG_LEVEL_DBG,log);
}

static void TO_log_exit(char * fct)
{
	char log[110];
	char fct_name[100];

	TO_safe_strncpy(fct_name,fct,sizeof(fct_name));
	sprintf(log,"<<< %s",fct_name);
	print_log_function(TO_LOG_LEVEL_DBG,log);
}

static void TO_log_return(char * fct,unsigned short ret,int line)
{
	char log[130];
	char fct_name[100];

	TO_safe_strncpy(fct_name,fct,sizeof(fct_name));
	sprintf(log,"<<< %s (%04X) @(%d)",fct_name,ret,line);
	print_log_function(TO_LOG_LEVEL_DBG,log);
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

	(void)log_ctx;

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

TO_log_ctx_t log_ctx = {
	.log_function = &TO_log,   		// By default
	.log_level = TO_LOG_LEVEL_MAX,	// By default, no LOGs (as we ignore the log function)
};

TO_log_ctx_t* TO_log_get_ctx(void)
{ 
	return (TO_log_ctx_t*)&log_ctx;
}
