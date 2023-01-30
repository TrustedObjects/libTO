/**
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright 2018 Trusted Objects
 *
 * @file arduino.cpp
 * @brief I2C wrapper for Arduino
 */

#include "TO_cfg.h"
#ifndef TODRV_HSE_DRIVER_DISABLE

#include "TO.h"

#include "Arduino.h"
#include "Wire.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "utility/twi.h"

#include "TODRV_HSE_i2c_wrapper.h"

#define TODRV_HSE_I2C_ADDR 0x50
#define TODRV_HSE_I2C_BITRATE 400 // kHz
#define TODRV_HSE_I2C_TIMEOUT 6000 // ms

static unsigned char i2c_addr = TODRV_HSE_I2C_ADDR;

TO_lib_ret_t TO_data_init(void)
{
#ifdef TO_POWER_PIN
	pinMode(TO_POWER_PIN, OUTPUT);
	digitalWrite(TO_POWER_PIN, LOW);
#endif
	/* Wait boot time */
	delay(1);
	twi_setFrequency(TODRV_HSE_I2C_BITRATE * 1000);
	twi_init();
	return TO_OK;
}

TO_lib_ret_t TO_data_fini(void)
{
#ifdef TO_POWER_PIN
	digitalWrite(TO_POWER_PIN, HIGH);
#endif
	return TO_OK;
}

TO_lib_ret_t TO_data_config(const TO_i2c_config_t *config)
{
	i2c_addr = config->i2c_addr;
	return TO_OK;
}

TO_lib_ret_t TO_data_read(void *data, unsigned int length)
{
	uint8_t _len;
	unsigned int len;
	unsigned int total_len = 0;

	do {
		_len = min(min(BUFFER_LENGTH, length - total_len), UINT8_MAX);
		len = twi_readFrom((uint8_t)i2c_addr, (uint8_t*)data + total_len, (uint8_t)_len, (uint8_t)(_len < BUFFER_LENGTH));
		total_len += len;
	} while (len == _len && total_len < length);

	return total_len ? TO_OK : TO_ERROR;
}

TO_lib_ret_t TO_data_write(const void *data, unsigned int length)
{
	uint8_t _len;
	unsigned int total_len = 0;

	do {
		_len = min(BUFFER_LENGTH, length - total_len);
		if (twi_writeTo((uint8_t)i2c_addr, (const uint8_t*)data + total_len, _len, 1, _len + total_len == length)) {
			break;
		}
		total_len += _len;
	} while (total_len < length);

	return (total_len == length) ? TO_OK : TO_ERROR;
}

TO_lib_ret_t TO_data_last_command_duration(unsigned int *duration)
{
	return TO_NOT_IMPLEMENTED;
}

#ifdef __cplusplus
}
#endif

#endif /* TODRV_HSE_DRIVER_DISABLE */

