/* include/TOP_cfg.h.  Generated from TOP_cfg.h.in by configure.  */
/*
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (C) 2016-2022 Trusted Objects. All rights reserved.
 */

/**
 * @file TOP_cfg.h
 * @brief This file provides a way to configure TO-Protect build.
 *
 * Please read the library configuration documentation chapter before modifying
 * this file.
 */

#ifndef _TOP_CFG_H_
#define _TOP_CFG_H_

/*
 * -----------------------------
 * Global settings
 * -----------------------------
 */

#ifndef TOP_LOG_LEVEL_MAX
/* log level max for TO-Protect */
#define TOP_LOG_LEVEL_MAX -1
#endif

#ifndef TOX_LOG_LEVEL_MAX
/* log level max for the secure storage */
#define TOX_LOG_LEVEL_MAX -1
#endif

#ifndef TOC_LOG_LEVEL_MAX
/* log level max for libto-crypto */
#define TOC_LOG_LEVEL_MAX -1
#endif

#ifndef TOP_DISABLE_MEASURES
/* disable measures */
#define TOP_DISABLE_MEASURES 1
#endif

#ifndef TOSEC_ADMIN_CNT
/* Number of Adminstration key slots */
#define TOSEC_ADMIN_CNT 5
#endif

#ifndef TOSEC_CA_CNT
/* Number of CA public-key slots */
#define TOSEC_CA_CNT 4
#endif

#ifndef TOSEC_CERT_CNT
/* Number of certificates slots */
#define TOSEC_CERT_CNT 3
#endif

#ifndef TOSEC_ECIES_CNT
/* Number of ECIES key slots */
#define TOSEC_ECIES_CNT 6
#endif

#ifndef TOSEC_PSK_CNT
/* Number of PSK slots */
#define TOSEC_PSK_CNT 3
#endif

#ifndef TOSEC_REMOTE_KPUB_CNT
/* Number of remote public-key slots */
#define TOSEC_REMOTE_KPUB_CNT 6
#endif

#ifndef TOSEC_TLS_CNT
/* Number of TLS session slots */
#define TOSEC_TLS_CNT 3
#endif

#ifndef TO_ENABLE_EVALUATION
/* Evaluation version enabled */
#define TO_ENABLE_EVALUATION 1
#endif

#endif /* _TOP_CFG_H_ */
