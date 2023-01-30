/* include/TOSE_helper_cfg.h.  Generated from TOSE_helper_cfg.h.in by configure.  */
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
 * @file TOSE_helper_cfg.h
 * @brief This file provides a way to configure libTO helpers.
 *
 * Please read the library configuration documentation chapter before modifying
 * this file.
 */

#ifndef _TOSE_HELPER_CFG_H_
#define _TOSE_HELPER_CFG_H_

/*
 * ---------------
 * Helpers options
 * ---------------
 */

#ifndef TO_DISABLE_CERTS_HELPER
/* disable certificates helper */
/* #undef TO_DISABLE_CERTS_HELPER */
#endif

#ifndef TO_DISABLE_ECIES_HELPER
/* disable ECIES helper */
#define TO_DISABLE_ECIES_HELPER 1
#endif

#ifndef TO_DISABLE_SECURE_PAYLOAD_HELPER
/* disable secure payload helper */
#define TO_DISABLE_SECURE_PAYLOAD_HELPER 1
#endif

#ifndef TO_DISABLE_SEC_MSG_HELPER
/* disable secure messaging helper */
#define TO_DISABLE_SEC_MSG_HELPER 1
#endif

#ifndef TO_DISABLE_TLS_HELPER
/* disable TLS helper */
/* #undef TO_DISABLE_TLS_HELPER */
#endif

#ifndef TO_DISABLE_TLS_STACK
/* disable TLS stack */
/* #undef TO_DISABLE_TLS_STACK */
#endif

#ifndef TO_DISABLE_TLS_MEDIATOR
/* disable TLS mediator */
#define TO_DISABLE_TLS_MEDIATOR 1
#endif

#ifndef TO_ENABLE_DTLS
/* enable DTLS */
/* #undef TO_ENABLE_DTLS */
#endif

#ifndef TO_DISABLE_DTLS_RETRANSMISSION
/* disable DTLS retransmission */
/* #undef TO_DISABLE_DTLS_RETRANSMISSION */
#endif

#ifndef TO_TLS_SESSIONS_NB
/* TLS sessions number */
#define TO_TLS_SESSIONS_NB 2
#endif

#ifndef TO_DISABLE_LOADER_HELPER
/* disable loader helper */
#define TO_DISABLE_LOADER_HELPER 1
#endif

#ifdef TO_DISABLE_CAPI
#define TO_DISABLE_SECURE_PAYLOAD_HELPER 1
#define TO_DISABLE_SEC_MSG_HELPER 1
#endif

/*
 * --------------
 * Expert options
 * --------------
 */

/*
 * /!\ EXPERT
 * Customize internal TLS I/O buffer size
 */
#ifndef TOSE_HELPER_TLS_IO_BUFFER_SIZE
#define TOSE_HELPER_TLS_IO_BUFFER_SIZE 2048
#endif

/*
 * /!\ EXPERT
 * Customize internal TLS RX I/O buffer size (for full duplex)
 */
#ifndef TOSE_HELPER_TLS_RX_BUFFER_SIZE
#define TOSE_HELPER_TLS_RX_BUFFER_SIZE 1024
#endif

/*
 * /!\ EXPERT
 * Customize internal TLS flight buffer size
 */
#ifndef TOSE_HELPER_TLS_FLIGHT_BUFFER_SIZE
#define TOSE_HELPER_TLS_FLIGHT_BUFFER_SIZE 2048
#endif

/*
 * /!\ EXPERT
 * Customize internal TLS receive timeout
 */
#ifndef TOSE_HELPER_TLS_RECEIVE_TIMEOUT
#define TOSE_HELPER_TLS_RECEIVE_TIMEOUT 1000
#endif

/*
 * Enable default cipher suite for TLS_HANDSHAKE_ONLY mode
 * */
#ifndef TOSE_HELPER_TLS_USE_DEFAULT_SETUP_CIPHER
#define TOSE_HELPER_TLS_USE_DEFAULT_SETUP_CIPHER yes
#endif

#endif /* _TOSE_HELPER_CFG_H_ */
