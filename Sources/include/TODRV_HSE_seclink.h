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

/**
 * @file TODRV_HSE_seclink.h
 * @brief
 */

#include "TO_cfg.h"
#ifndef TODRV_HSE_DRIVER_DISABLE

#ifndef _TODRV_HSE_SECLINK_H_
#define _TODRV_HSE_SECLINK_H_

#include "TO_retcodes.h"

#ifndef TO_SECLINKAPI
#ifdef __linux__
#define TO_SECLINKAPI
#elif _WIN32
#define TO_SECLINKAPI __declspec(dllexport)
#else
#define TO_SECLINKAPI
#endif /* __LINUX__ */
#endif

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup seclink_defs
 * @{ */

/**
 * @brief Secure link callback prototype to store keys.
 * @param data New keys to save, data format depends on the used secure link
 * protocol.
 *
 * Callback prototype for an user function to be called in case of secure link
 * keys renewal.
 * This function is expected to store the new keys persistently, in replacement
 * of the old ones.
 * The storage method depends on the user environment, and is to be implemented
 * according to it.
 *
 * @warning Do not do libTO functions calls from this callback.
 *
 * See TODRV_HSE_seclink_set_store_keys_cb().
 *
 * @return TO_OK on success
 */
typedef TO_lib_ret_t (*TODRV_HSE_seclink_store_keys_cb)(void *data);

/**
 * @brief Secure link callback to load keys.
 * @param data Pre-allocated to return loaded keys, data format depends on the
 * used secure link protocol.
 *
 * Callback prototype for an user function to be called by the library when it
 * needs keys to use secure link.
 * It may be called by the library on every Secure Element function call.
 * This function is expected to read the keys from an user persistent storage.
 *
 * @warning Do not do libTO functions calls from this callback.
 *
 * See TODRV_HSE_seclink_set_load_keys_cb().
 *
 * @return TO_OK on success
 */
typedef TO_lib_ret_t (*TODRV_HSE_seclink_load_keys_cb)(void *data);

/** @} */

/** @addtogroup seclink
 * @{ */

/**
 * @brief Reset secure link.
 *
 * This function can be used to initialize secure link, after each
 * successful TO_init() calls.
 * If not called manually after TO_init(), it is automatically called on
 * first command.
 *
 * According to secure link protocol, this function may reset some internal
 * state, request an initial vector from Secure Element, etc...
 *
 * @return TO_OK on reset success, secure link is ready to be used.
 */
TO_SECLINKAPI TO_lib_ret_t TODRV_HSE_seclink_reset(void);


/**
 * @brief Set secure link keys storage callback.
 * @param cb Callback function pointer, see TODRV_HSE_seclink_store_keys_cb.
 *
 * This function is used to set secure link keys storage callback. The callback
 * function will be used by the library to allow user to store new keys in
 * remplacement of the old ones in cases of a secure link keys renewal
 * procedure.
 *
 * This function has to be called just after TO_init() if secure link is used
 * by the project with a keys renewal mechanism enabled.
 * In this case, do not use Secure Element APIs before having defined and set
 * this callback, or you may miss keys storage notifications if a keys renewal
 * procedure occurs.
 */
TO_SECLINKAPI void TODRV_HSE_seclink_set_store_keys_cb(TODRV_HSE_seclink_store_keys_cb cb);

/**
 * @brief Set secure link callback to load keys.
 * @param cb Callback function pointer, see TODRV_HSE_seclink_load_keys_cb.
 *
 * This function is used to set secure link callback used by the library to
 * load keys.
 * The callback function will be called later by the library.
 *
 * This function has to be called just after TO_init().
 */
TO_SECLINKAPI void TODRV_HSE_seclink_set_load_keys_cb(TODRV_HSE_seclink_load_keys_cb cb);

/**
 * @brief Get secure link renewed keys.
 *
 * This function can only be used if you have the old keys.
 * When using this function, it calls the configured secure link key renewal
 * callback, allowing user to store the new key.
 *
 * See TODRV_HSE_seclink_set_key_renewal_cb() and TODRV_HSE_seclink_keys_renewal_cb.
 */
TO_SECLINKAPI TO_lib_ret_t TODRV_HSE_seclink_request_renewed_keys(void);

/**
 * @brief Bypass Secure Element secure link and use clear text
 * ones.
 * @param bypass Set to 1 to bypass secure link, set to 0 to use secure
 * commands.
 *
 * If called just after TO_init(), TODRV_HSE_seclink_reset() will not be called
 * automatically.
 * According to Secure Element settings, bypassing secure link may be
 * impossible.
 *
 * @return Previous secure link bypassing state.
 */
TO_SECLINKAPI int TODRV_HSE_seclink_bypass(int bypass);

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* _TODRV_HSE_SECLINK_H_ */

#endif /* TODRV_HSE_DRIVER_DISABLE */

