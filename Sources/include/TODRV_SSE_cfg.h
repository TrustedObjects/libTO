/* include/TODRV_SSE_cfg.h.  Generated from TODRV_SSE_cfg.h.in by configure.  */
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
 * @file TODRV_SSE_cfg.h
 * @brief This file provides a way to configure libTO-driver-SSE build.
 *
 * Please read the library configuration documentation chapter before modifying
 * this file.
 */

#ifndef _TODRV_SSE_CFG_H_
#define _TODRV_SSE_CFG_H_

/*
 * -----------------------------
 * Global settings
 * -----------------------------
 */

#ifndef TODRV_SSE_TOP_ADDRESS
/* TO-Protect vector table start address */
/* #undef TODRV_SSE_TOP_ADDRESS */
#endif

#ifndef TODRV_SSE_ENABLE_SELF_TESTS
/* TO-Protect & NVM self tests */
#define TODRV_SSE_ENABLE_SELF_TESTS 1
#endif

#endif /* _TODRV_SSE_CFG_H_ */
