/* include/TODRV_HSE_cfg.h.  Generated from TODRV_HSE_cfg.h.in by configure.  */
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
 * @file TODRV_HSE_cfg.h
 * @brief This file provides a way to configure libTO-driver-HSE build.
 *
 * Please read the library configuration documentation chapter before modifying
 * this file.
 */

#ifndef _TODRV_HSE_CFG_H_
#define _TODRV_HSE_CFG_H_

#include "TO_cfg.h"

/*
 * -----------------------------
 * Global settings
 * -----------------------------
 */

#ifndef TODRV_HSE_ENABLE_SECLINK_AESHMAC
/* AES/HMAC secure link protocol */
/* #undef TODRV_HSE_ENABLE_SECLINK_AESHMAC */
#endif

#ifndef TODRV_HSE_ENABLE_SECLINK_ARC4
/* ARC4 secure link protocol */
/* #undef TODRV_HSE_ENABLE_SECLINK_ARC4 */
#endif

#ifndef TODRV_HSE_I2C_WRAPPER
/* I2C wrapper name */
#define TODRV_HSE_I2C_WRAPPER "net_bridge"
#endif

#ifndef TODRV_HSE_SERIAL_DEVICE
/* wrapper serial device to use */
/* #undef TODRV_HSE_SERIAL_DEVICE */
#endif

#ifndef TODRV_HSE_SERIAL_SPEED
/* wrapper serial speed to use */
/* #undef TODRV_HSE_SERIAL_SPEED */
#endif

#ifndef TODRV_HSE_I2C_DEVICE
/* wrapper Linux I2C device to use */
/* #undef TODRV_HSE_I2C_DEVICE */
#endif

#ifndef TODRV_HSE_I2C_WRAPPER_CONFIG
/* wrapper accepts I2C configuration */
#define TODRV_HSE_I2C_WRAPPER_CONFIG 1
#endif

#ifndef TODRV_HSE_I2C_WRAPPER_LAST_COMMAND_DURATION
/* wrapper accepts I2C last command duration */
#define TODRV_HSE_I2C_WRAPPER_LAST_COMMAND_DURATION 1
#endif

#ifndef TODRV_HSE_ENABLE_I2C_NET_BRIDGE_TLS
/* I2C net_bridge TLS enabled */
#define TODRV_HSE_ENABLE_I2C_NET_BRIDGE_TLS 1
#endif

#ifndef TODRV_HSE_ENABLE_I2C_PIPE
/* Fake I2C on pipes enabled */
/* #undef TODRV_HSE_ENABLE_I2C_PIPE */
#endif

#ifndef TODRV_HSE_ENABLE_I2C_SERIAL
/* Fake I2C on serial port enabled */
/* #undef TODRV_HSE_ENABLE_I2C_SERIAL */
#endif

/*
 * --------------
 * Expert options
 * --------------
 */

/*
 * /!\ EXPERT
 * Customize MAX data size
 */
#ifndef TODRV_HSE_MAXSIZE
/* maximum data size */
#define TODRV_HSE_MAXSIZE 512
#endif

/*
 * /!\ EXPERT
 * Customize internal I/O buffer size
 */
#ifndef TODRV_HSE_LIB_INTERNAL_IO_BUFFER_SIZE
/* internal I/O buffer size */
#define TODRV_HSE_LIB_INTERNAL_IO_BUFFER_SIZE 640
#endif
#if (!defined(TODRV_HSE_ENABLE_I2C_PIPE) && !defined(TODRV_HSE_ENABLE_I2C_SERIAL)) && TODRV_HSE_LIB_INTERNAL_IO_BUFFER_SIZE > 640
#error "Internal I/O buffer cannot exceed 640 bytes due to SE limitations"
#endif

/*
 * /!\ EXPERT
 * Customize maximum number of parameters taken by commands, for internal
 * library use
 */
#ifndef TODRV_HSE_CMD_MAX_PARAMS
/* command max. parameters number */
#define TODRV_HSE_CMD_MAX_PARAMS 10
#endif

#endif /* _TODRV_HSE_CFG_H_ */
