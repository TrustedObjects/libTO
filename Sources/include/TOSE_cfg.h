/* include/TOSE_cfg.h.  Generated from TOSE_cfg.h.in by configure.  */
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
 * @file TOSE_cfg.h
 * @brief This file provides a way to configure libTO.
 *
 * Please read the library configuration documentation chapter before modifying
 * this file.
 */

#ifndef _TOSE_CFG_H_
#define _TOSE_CFG_H_

#include "TO_cfg.h"

/*
 * --------------
 * Driver options
 * --------------
 */

#ifndef TOSE_DRIVER_HSE
/* enable HSE driver */
#define TOSE_DRIVER_HSE 1
#endif

#ifndef TOSE_DRIVER_SSE
/* enable SSE driver */
#define TOSE_DRIVER_SSE 1
#endif

#endif /* _TOSE_CFG_H_ */
