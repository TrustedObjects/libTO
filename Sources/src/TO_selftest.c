/*
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (C) 2019 Trusted Objects. All rights reserved.
 */

#include "TO_cfg.h"
#ifndef TODRV_SSE_DRIVER_DISABLE

#include "TODRV_SSE_cfg.h"
#include "TO_retcodes.h"
#include "TOP.h"
#include "TO_defs.h"
#include "TO_utils.h"

#include "TODRV_SSE.h"
#include "TOP_storage.h"

#include "TO_sse_driver.h"

#ifdef TODRV_SSE_ENABLE_SELF_TESTS

// Those functions have no need to be imported normaly.
extern TO_lib_ret_t TOP_data_load(zone_id_t zone_id,
		const void *dst);
extern TO_lib_ret_t TOP_data_store(zone_id_t zone_id,
		const void *src);


#define TO_SELFTEST_STAGE_BEFORE_LOAD		0
#define TO_SELFTEST_STAGE_BEFORE_STORE		1
#define TO_SELFTEST_STAGE_BEFORE_CHECK		2
#define TO_SELFTEST_STAGE_BEFORE_STORE_11       3
#define TO_SELFTEST_STAGE_BEFORE_STORE_22       4
#define TO_SELFTEST_STAGE_BEFORE_STORE_33       5
#define TO_SELFTEST_STAGE_BEFORE_STORE_AA       6
#define TO_SELFTEST_STAGE_BEFORE_STORE_55       7
#define TO_SELFTEST_STAGE_BEFORE_CHECK_55	8
#define TO_SELFTEST_STAGE_BEFORE_CHECK_AA	9

#define TO_SELFTEST_STAGE_TEST_ZONE_0		0
#define TO_SELFTEST_STAGE_TEST_ZONE_1		20

#define TO_SELFTEST_FAILURE_DURING_LOAD		0
#define TO_SELFTEST_FAILURE_DURING_STORE	1
#define TO_SELFTEST_FAILURE_DURING_CHECK	2

/**
 * @brief It checks whether a given memory buffer contains <len> bytes all being <value>
 *
 * @param ptr Pointer to the area to be checked
 * @param value Byte value to be checked
 * @param len Length of the buffer to be checked
 * @return int return value
 * @retval 0 The buffer is effectivelly containing <len> bytes <value>
 * @retval 1 The buffer is not as requested
 */
static int memchk(uint8_t *ptr, uint8_t value, size_t len)
{
	for (size_t i = 0; i < len; i++) {
		if (*ptr++ != value) {
			return 1;
		}
	}

	return 0;
}

/**
 * @brief Self test function for the NVm (part 2)
 * @details This function is meant to test that it is possible to load/store into zone
 * individually without any interference from the writting of the other one.
 * It performs :
 * - Writting Zone 0 with all 0x11
 * - Reading & Checking The Zone 0 content (0x11 ... 0x11)
 * - Writting Zone 1 with all 0x22
 * - Reading & Checking The Zone 1 content (0x22 ... 0x22)
 * - Reading & Checking The Zone 0 content (0x11 ... 0x11)
 * - Writting Zone 0 with all 0x33
 * - Reading & Checking The Zone 0 content (0x33 ... 0x33)
 * - Reading & Checking The Zone 1 content (0x22 ... 0x22)
 * @param ram_buffer The Ram buffer allocated to perform the NVM writes
 * @param stage The execution stage (to guess where the fail occured)
 * @param reason_code The precise reason of the failure
 * @return TO_lib_ret_t return code
 * @retval TO_OK If everything is fine
 * @retval TO_ERROR If an error has been detected
 */
static TO_lib_ret_t nvm_selftest_two_zones(uint8_t *ram_buffer,
		int *stage,
		int *reason_code)
{
	TO_lib_ret_t ret;

	TO_LOG_INF("Testing the load/store for the two zones.", 0);

	// First Store (11) into the Zone 0
	*stage = TO_SELFTEST_STAGE_BEFORE_STORE_11 + TO_SELFTEST_STAGE_TEST_ZONE_0;
	memset(ram_buffer, 0x11, TOP_SECURE_STORAGE_NVM_FOOTPRINT);
	ret = TOP_data_store(TEARING_ZONE_0, ram_buffer);
	if (ret != TO_OK) {
		TO_LOG_ERR("Failure during the store of Zone 0 (%d).", ret);
		*reason_code = TO_SELFTEST_FAILURE_DURING_STORE;

		return TO_ERROR;
	}

	// Checking Zone 0 (Check it has been correctly written)
	*stage = TO_SELFTEST_STAGE_BEFORE_LOAD + TO_SELFTEST_STAGE_TEST_ZONE_0;
	memset(ram_buffer, 0, TOP_SECURE_STORAGE_NVM_FOOTPRINT);
	ret = TOP_data_load(TEARING_ZONE_0, ram_buffer);
	if (ret != TO_OK) {
		TO_LOG_ERR("Failure during the load of Zone 0 (%d).", ret);
		*reason_code = TO_SELFTEST_FAILURE_DURING_LOAD;

		return TO_ERROR;
	}
	*stage = TO_SELFTEST_FAILURE_DURING_CHECK + TO_SELFTEST_STAGE_TEST_ZONE_0;
	if (memchk(ram_buffer, 0x11, TOP_SECURE_STORAGE_NVM_FOOTPRINT)) {
		TO_LOG_ERR("Failure when checking the written value.", 0);
		*reason_code = TO_SELFTEST_FAILURE_DURING_CHECK;

		return TO_ERROR;
	}

	// Writting Zone 1
	*stage = TO_SELFTEST_STAGE_BEFORE_STORE_22 + TO_SELFTEST_STAGE_TEST_ZONE_0;
	memset(ram_buffer, 0x22, TOP_SECURE_STORAGE_NVM_FOOTPRINT);
	ret = TOP_data_store(TEARING_ZONE_1, ram_buffer);
	if (ret != TO_OK) {
		TO_LOG_ERR("Failure during the store of Zone 0 (%d).", ret);
		*reason_code = TO_SELFTEST_FAILURE_DURING_STORE;

		return TO_ERROR;
	}

	// Checking Zone 0 (check it has not been over-written by Zone 1)
	*stage = TO_SELFTEST_STAGE_BEFORE_LOAD + TO_SELFTEST_STAGE_TEST_ZONE_0;
	ret = TOP_data_load(TEARING_ZONE_0, ram_buffer);
	if (ret != TO_OK) {
		TO_LOG_ERR("Failure during the load of Zone 0 (%d).", ret);
		*reason_code = TO_SELFTEST_FAILURE_DURING_LOAD;

		return TO_ERROR;
	}
	*stage = TO_SELFTEST_FAILURE_DURING_CHECK + TO_SELFTEST_STAGE_TEST_ZONE_0;
	if (memchk(ram_buffer, 0x11, TOP_SECURE_STORAGE_NVM_FOOTPRINT)) {
		TO_LOG_ERR("Failure when checking the written value.", 0);
		*reason_code = TO_SELFTEST_FAILURE_DURING_CHECK;

		return TO_ERROR;
	}

	// Checking Zone 1 (Check it has been correctly written)
	*stage = TO_SELFTEST_FAILURE_DURING_LOAD + TO_SELFTEST_STAGE_TEST_ZONE_1;
	ret = TOP_data_load(TEARING_ZONE_1, ram_buffer);
	if (ret != TO_OK) {
		TO_LOG_ERR("Failure during the load of Zone 1 (%d).", ret);
		*reason_code = TO_SELFTEST_FAILURE_DURING_LOAD;

		return TO_ERROR;
	}
	*stage = TO_SELFTEST_FAILURE_DURING_CHECK + TO_SELFTEST_STAGE_TEST_ZONE_1;
	if (memchk(ram_buffer, 0x22, TOP_SECURE_STORAGE_NVM_FOOTPRINT)) {
		TO_LOG_ERR("Failure when checking the written value.", 0);
		*reason_code = TO_SELFTEST_FAILURE_DURING_CHECK;

		return TO_ERROR;
	}

	// Writting Zone 0
	*stage = TO_SELFTEST_STAGE_BEFORE_STORE_33;
	memset(ram_buffer, 0x33, TOP_SECURE_STORAGE_NVM_FOOTPRINT);
	ret = TOP_data_store(TEARING_ZONE_0, ram_buffer);
	if (ret != TO_OK) {
		TO_LOG_ERR("Failure during the store of Zone 0 (%d).", ret);
		*reason_code = TO_SELFTEST_FAILURE_DURING_STORE;

		return TO_ERROR;
	}

	// Checking Zone 1 (check it has not been over-written by Zone 0)
	*stage = TO_SELFTEST_FAILURE_DURING_LOAD + TO_SELFTEST_STAGE_TEST_ZONE_0;
	ret = TOP_data_load(TEARING_ZONE_1, ram_buffer);
	if (ret != TO_OK) {
		TO_LOG_ERR("Failure during the load of Zone 1 (%d).", ret);
		*reason_code = TO_SELFTEST_FAILURE_DURING_LOAD;

		return TO_ERROR;
	}
	*stage = TO_SELFTEST_FAILURE_DURING_LOAD + TO_SELFTEST_STAGE_TEST_ZONE_1;
	if (memchk(ram_buffer, 0x22, TOP_SECURE_STORAGE_NVM_FOOTPRINT)) {
		TO_LOG_ERR("Failure when checking the written value.", 0);
		*reason_code = TO_SELFTEST_FAILURE_DURING_CHECK;

		return TO_ERROR;
	}

	// Checking Zone 0 (Check it has been correctly written)
	*stage = TO_SELFTEST_FAILURE_DURING_LOAD + TO_SELFTEST_STAGE_TEST_ZONE_0;
	ret = TOP_data_load(TEARING_ZONE_0, ram_buffer);
	if (ret != TO_OK) {
		TO_LOG_ERR("Failure during the load of Zone 0 (%d).", ret);
		*reason_code = TO_SELFTEST_FAILURE_DURING_LOAD;

		return TO_ERROR;
	}
	*stage = TO_SELFTEST_FAILURE_DURING_CHECK + TO_SELFTEST_STAGE_TEST_ZONE_0;
	if (memchk(ram_buffer, 0x33, TOP_SECURE_STORAGE_NVM_FOOTPRINT)) {
		TO_LOG_ERR("Failure when checking the written value.", 0);
		*reason_code = TO_SELFTEST_FAILURE_DURING_CHECK;

		return TO_ERROR;
	}

	return TO_OK;
}

/**
 * @brief Performs a test of the capability of writing the secure storage through
 * the customer-provided API.
 * @details This function is meant to test that it is possible to load/store into each zone
 * individually. The tests run here are quite basic, but hopefully will help setting-up
 * the NVM-access routines. It performs as follows :
 * - Load the Zone (no check of the obtained value)
 * - Store bytes to 0xAA into the targetted Zone
 * - Load the Zone , and check the resulting value (0xAA ... 0xAA)
 * - Store bytes to 0x55 into the targetted Zone
 * - Load the Zone , and check the resulting value (0x55 ... 0x55)
 * @param zone_id The zone to be written (0 or 1)
 * @param ram_buffer The Ram buffer allocated to perform the NVM writes
 * @param stage The execution stage (to guess where the fail occured)
 * @param reason_code The precise reason of the failure
 * @return TO_lib_ret_t return code
 * @retval TO_OK If everything is fine
 * @retval TO_ERROR If an error has been detected
 */
static TO_lib_ret_t nvm_selftest_one_zone(zone_id_t zone_id,
		uint8_t *ram_buffer,
		int * stage,
		int *reason_code)
{
	TO_lib_ret_t ret;
	TO_LOG_INF("Testing the load/store into Zone %d.", zone_id);

	// First Read of the Zone
	*stage = TO_SELFTEST_STAGE_BEFORE_LOAD + TO_SELFTEST_STAGE_TEST_ZONE_1 * zone_id;
	ret = TOP_data_load(TEARING_ZONE_0, ram_buffer);
	if (ret != TO_OK) {
		TO_LOG_ERR("Failure during the load of Zone %d (%d).", zone_id, ret);
		*reason_code = TO_SELFTEST_FAILURE_DURING_LOAD;

		return TO_ERROR;
	}

	// First Store (AA) into the Zone
	*stage = TO_SELFTEST_STAGE_BEFORE_STORE_AA + TO_SELFTEST_STAGE_TEST_ZONE_1 * zone_id;
	memset(ram_buffer, 0xAA, TOP_SECURE_STORAGE_NVM_FOOTPRINT);
	ret = TOP_data_store(TEARING_ZONE_0, ram_buffer);
	if (ret != TO_OK) {
		TO_LOG_ERR("Failure during the store of Zone %d (%d).", zone_id, ret);
		*reason_code = TO_SELFTEST_FAILURE_DURING_STORE;

		return TO_ERROR;
	}

	// Checking the value we've just written
	*stage = TO_SELFTEST_STAGE_BEFORE_CHECK_AA + TO_SELFTEST_STAGE_TEST_ZONE_1 * zone_id;
	memset(ram_buffer, 0x00, TOP_SECURE_STORAGE_NVM_FOOTPRINT);
	ret = TOP_data_load(TEARING_ZONE_0, ram_buffer);
	if (ret != TO_OK) {
		TO_LOG_ERR("Failure during the load of Zone %d (%d).", zone_id, ret);
		*reason_code = TO_SELFTEST_FAILURE_DURING_LOAD;

		return TO_ERROR;
	}
	*stage = TO_SELFTEST_STAGE_BEFORE_CHECK_AA + TO_SELFTEST_STAGE_TEST_ZONE_1 * zone_id;
	if (memchk(ram_buffer, 0xAA, TOP_SECURE_STORAGE_NVM_FOOTPRINT)) {
		TO_LOG_ERR("Failure when checking the written value.", 0);
		*reason_code = TO_SELFTEST_FAILURE_DURING_CHECK;

		return TO_ERROR;
	}

	// Second Store (55) into the Zone
	*stage = TO_SELFTEST_STAGE_BEFORE_STORE_55 + TO_SELFTEST_STAGE_TEST_ZONE_1 * zone_id;
	memset(ram_buffer, 0x55, TOP_SECURE_STORAGE_NVM_FOOTPRINT);
	ret = TOP_data_store(TEARING_ZONE_0, ram_buffer);
	if (ret != TO_OK) {
		TO_LOG_ERR("Failure during the store of Zone %d (%d).", zone_id, ret);
		*reason_code = TO_SELFTEST_FAILURE_DURING_STORE;

		return TO_ERROR;
	}

	// Checking the value we've just written
	*stage = TO_SELFTEST_STAGE_BEFORE_LOAD + TO_SELFTEST_STAGE_TEST_ZONE_1 * zone_id;
	memset(ram_buffer, 0x00, TOP_SECURE_STORAGE_NVM_FOOTPRINT);
	ret = TOP_data_load(TEARING_ZONE_0, ram_buffer);
	if (ret != TO_OK) {
		TO_LOG_ERR("Failure during the load of Zone %d (%d).", zone_id, ret);
		*reason_code = TO_SELFTEST_FAILURE_DURING_LOAD;

		return TO_ERROR;
	}
	*stage = TO_SELFTEST_STAGE_BEFORE_CHECK_55 + TO_SELFTEST_STAGE_TEST_ZONE_1 * zone_id;
	if (memchk(ram_buffer, 0x55, TOP_SECURE_STORAGE_NVM_FOOTPRINT)) {
		TO_LOG_ERR("Failure when checking the written value.", 0);
		*reason_code = TO_SELFTEST_FAILURE_DURING_CHECK;

		return TO_ERROR;
	}

	return TO_OK;
}


static uint8_t nvm_content[TOP_SECURE_STORAGE_NVM_FOOTPRINT * 2];

TO_lib_ret_t TODRV_SSE_nvm_self_test(void)
{
	// Getting the TO-Protect's context
	TOSE_ctx_t *ctx = TODRV_SSE_get_ctx();
	TO_lib_ret_t ret;
	uint8_t *ram_buffer = (uint8_t *)(((TOP_ext_ctx_t*)ctx->drv->priv_ctx)->secure_storage->storage.raw_ram_buffer);
	int stage;
	int reason_code;

	TO_LOG_INF("Starting the NVM Selftest", 0);

	// Start by saving the secure storages into RAM for a non-destructive test
	// BTW, be aware that this test, although non destructive if successful will
	// wear the NVM.
	ret = TOP_data_load(TEARING_ZONE_0, nvm_content);
	ret = TOP_data_load(TEARING_ZONE_1, nvm_content + TOP_SECURE_STORAGE_NVM_FOOTPRINT);

	ret = nvm_selftest_one_zone(TEARING_ZONE_0, ram_buffer, &stage, &reason_code);
	if (ret != TO_OK) {
		TO_LOG_ERR("Abnormal end of the load/store test of Zone 0.", 0);
		TO_LOG_ERR("The fail occurred during nvm_selftest_one_zone(), "
				"at stage %d, with reason code %d.",
				stage,
				reason_code);

		return ret;
	}
	ret = nvm_selftest_one_zone(TEARING_ZONE_1, ram_buffer, &stage, &reason_code);
	if (ret != TO_OK) {
		TO_LOG_ERR("Abnormal end of the load/store test of Zone 1.", 0);
		TO_LOG_ERR("The fail occurred during nvm_selftest_one_zone(), "
				"at stage %d, with reason code %d.",
				stage,
				reason_code);

		return ret;
	}
	ret = nvm_selftest_two_zones(ram_buffer, &stage, &reason_code);
	if (ret != TO_OK) {
		TO_LOG_ERR("Abnormal end of the load/store test of both zones.", 0);
		TO_LOG_ERR("The fail occurred during nvm_selftest_two_zones(), "
				"at stage %d, with reason code %d.",
				stage,
				reason_code);

		return ret;
	}
	TO_LOG_INF("Successful execution of the NVM Selftest !", 0);

	// Restore the nvm content
	ret = TOP_data_store(TEARING_ZONE_0, nvm_content);
	ret = TOP_data_store(TEARING_ZONE_1, nvm_content + TOP_SECURE_STORAGE_NVM_FOOTPRINT);



	return TO_OK;
}

/**
 * @brief All this implementation has been inspired from running pycrc.
 * @details python pycrc.py --poly=0x1021 --xor-out=0 --xor-in=0 --width=16 --reflect-in=true --reflect-out=true --generate=c --algorithm=tbl
 * It is using 0x1021 as a polynomial in reflected mode
 *
 */
static uint16_t crctbl[256] = {
	0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf,
	0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7,
	0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e,
	0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876,
	0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
	0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5,
	0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c,
	0xbdcb, 0xac42, 0x9ed9, 0x8f50, 0xfbef, 0xea66, 0xd8fd, 0xc974,
	0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb,
	0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
	0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a,
	0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72,
	0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9,
	0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3, 0x8a78, 0x9bf1,
	0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738,
	0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70,
	0x8408, 0x9581, 0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7,
	0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff,
	0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036,
	0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
	0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5,
	0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd,
	0xb58b, 0xa402, 0x9699, 0x8710, 0xf3af, 0xe226, 0xd0bd, 0xc134,
	0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c,
	0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
	0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb,
	0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232,
	0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a,
	0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1,
	0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,
	0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330,
	0x7bc7, 0x6a4e, 0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78};

/**
 * @brief CRC-16 computation routine, able to read in safe way the code
 *
 * @param seed CRC seed
 * @param data Pointer to the data to be CRCed
 * @param len Length of the data to be CRCed
 * @return uint16_t CRC
 */
static uint16_t crc16_ccitt_29b1_code(const uint16_t seed, const uint8_t *data, const int len)
{
	const unsigned char *d = (const unsigned char *)data;
	uint16_t crc = seed;
	unsigned int tbl_idx;
	int data_len = len;

	while (data_len--) {
		tbl_idx = (crc ^ TO_saferead_uint8(d)) & 0xff;
		crc = (TO_saferead_leuint16(crctbl + tbl_idx) ^ (crc >> 8)) & 0xffff;
		d++;
	}

	return crc & 0xffff;
}

TO_lib_ret_t TODRV_SSE_top_self_test(void)
{
	uint16_t crc;
	TOSE_ctx_t *ctx = TODRV_SSE_get_ctx();

	TO_LOG_INF("TO-Protect self-test started",0);
	TO_LOG_INF("TO-Protect configuration:",0);
	TO_LOG_INF(" - TO-Protect address : %p", ctx->drv->api);
	TO_LOG_INF(" - TO-Protect size    : %08x", TO_saferead_leuint32((void *)&ctx->drv->api->binary_size) +
			TO_saferead_leuint16((void *)&ctx->drv->api->binary_offset));

	// Check the provided API
	if ((TO_saferead_uint8((void *)&ctx->drv->api->api_version.major) == TODRV_API_MAJOR) &&
			(TO_saferead_uint8((void *)&ctx->drv->api->api_version.minor) == TODRV_API_MINOR) &&
			(TO_saferead_leuint16((void *)&ctx->drv->api->api_version.rfu) == 0)) {
		TO_LOG_INF(" - API Major is OK     : %02x",
				TO_saferead_uint8((void *)&ctx->drv->api->api_version.major));
		TO_LOG_INF(" - API Minor is OK     : %02x",
				TO_saferead_uint8((void *)&ctx->drv->api->api_version.minor));
		TO_LOG_INF(" - rfu field is OK     : %04x",
				TO_saferead_leuint16((void *)&ctx->drv->api->api_version.rfu));
	} else {
		if (TO_saferead_uint8((void *)&ctx->drv->api->api_version.major) != TODRV_API_MAJOR) {
			TO_LOG_INF(" - API Major is wrong %02x (expected %02x)",
					TO_saferead_uint8((void *)&ctx->drv->api->api_version.major),
					TODRV_API_MAJOR);
		}
		if (TO_saferead_uint8((void *)&ctx->drv->api->api_version.minor) != TODRV_API_MINOR) {
			TO_LOG_INF(" - API Minor is wrong %02x (expected %02x)",
					TO_saferead_uint8((void *)&ctx->drv->api->api_version.minor),
					TODRV_API_MINOR);
		}
		TO_LOG_ERR("TO-protect is not correctly loaded at the expected address (%p) !",
				ctx->drv->api);

		return TO_ERROR;
	}

	// Check the crc
	crc = crc16_ccitt_29b1_code(0xffff,
			((uint8_t *)ctx->drv->api) + TO_saferead_leuint16(&ctx->drv->api->binary_offset),
			TO_saferead_leuint32(&ctx->drv->api->binary_size));
	if (TO_saferead_leuint16(&ctx->drv->api->binary_crc) != crc) {
		TO_LOG_INF("TO-protect's integrity is wrong : %04x (expected %04x) !",
				crc,
				TO_saferead_leuint16(&ctx->drv->api->binary_crc));
		TO_LOG_ERR("TO-protect is not correctly loaded at the expected address (%p) !",
				ctx->drv->api);

		return TO_ERROR;
	}

	TO_LOG_INF("TO-protect seems to have been correctly flashed at the expected address !",0);

	return TO_OK;
}

#endif /* TODRV_SSE_ENABLE_SELF_TESTS */
#endif /* TODRV_SSE_DRIVER_DISABLE */
