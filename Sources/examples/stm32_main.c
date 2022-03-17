/*
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (C) 2016-2018 Trusted Objects. All rights reserved.
 */

/**
 * @file stm32_main.c
 * @brief Main example on STM32.
 */

#if (defined(STM32L072xx) && !defined(STM32L0))
#define STM32L0
#endif

#if (defined (STM32L0) || defined(USE_STM32L0XX_NUCLEO))
#include "stm32l0xx_hal.h"
#include "stm32l0xx_hal_flash_ex.h"
#elif (defined (STM32L1) || defined(USE_STM32L1XX_NUCLEO))
#include "stm32l1xx_hal.h"
#include "stm32l1xx_hal_flash_ex.h"
#elif (defined (STM32L4) || defined(USE_STM32L4XX_NUCLEO))
#include "stm32l4xx_hal.h"
#include "stm32l4xx_hal_flash_ex.h"
#elif (defined (STM32F4) || defined(USE_STM32F4XX_NUCLEO))
#include "stm32f4xx_hal.h"
#include "stm32f4xx_hal_flash_ex.h"
#else
#define PLATFORM_NOT_SUPPORTED
#endif

#if !defined(PLATFORM_NOT_SUPPORTED)

#include "stm32_vcom.h"

#include "TO.h"

int main( void )
{
	HAL_StatusTypeDef hal_ret;
	const uint8_t wapp_eui[TO_LORA_APPEUI_SIZE] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
	uint8_t rapp_eui[TO_LORA_APPEUI_SIZE];
	TO_lib_ret_t ret;
	TO_ret_t ret2;

	/* Initialize HAL */
	if ((hal_ret = HAL_Init()) != HAL_OK) {
		return -1;
	}

	/* Enable clock */
	__HAL_RCC_PWR_CLK_ENABLE();

	/* Initialize serial logs */
	vcom_Init();

	/* Initialize libTO */
	if ((ret = TO_init()) != TO_OK) {
		PRINTF("TO_init failed with error %x\n", ret);
		return -1;
	}

	if ((ret2 = TO_lora_get_app_eui(rapp_eui)) != TORSP_SUCCESS) {
		PRINTF("TO_lora_set_app_eui failed with error %x\n", ret2);
		return -1;
	}

	if (memcmp(wapp_eui, rapp_eui, TO_LORA_APPEUI_SIZE)) {
		PRINTF("AppEUI badly re-read\n");
	} else {
		PRINTF("AppEUI re-read correctly\n");
	}

	if ((ret = TO_fini()) != TO_OK) {
		PRINTF("TO_fini failed with error %x\n", ret);
		return -1;
	}

	vcom_DeInit();

	__HAL_RCC_PWR_CLK_DISABLE();

	if ((hal_ret = HAL_DeInit()) != HAL_OK) {
		return -1;
	}

	return 0;
}
#else
#error "Platform not supported"
#endif
