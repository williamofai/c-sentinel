/*
 * C-Sentinel - Semantic Observability for UNIX Systems
 * Copyright (c) 2025 William Murray
 *
 * Licensed under the MIT License.
 * See LICENSE file for details.
 *
 * https://github.com/williamofai/c-sentinel
 *
 * platform.h - Platform detection and abstraction layer
 *
 * This header provides cross-platform support for Linux, macOS, and BSD.
 * It detects the current platform at compile time and includes the
 * appropriate system headers.
 */

#ifndef PLATFORM_H
#define PLATFORM_H

/* ============================================================
 * Platform Detection
 * ============================================================ */

#if defined(__APPLE__) && defined(__MACH__)
    #define PLATFORM_MACOS 1
    #define PLATFORM_NAME "macOS"
#elif defined(__linux__)
    #define PLATFORM_LINUX 1
    #define PLATFORM_NAME "Linux"
#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
    #define PLATFORM_BSD 1
    #define PLATFORM_NAME "BSD"
#else
    #error "Unsupported platform. C-Sentinel requires Linux, macOS, or BSD."
#endif

/* ============================================================
 * Platform-Specific Headers
 * ============================================================ */

#ifdef PLATFORM_LINUX
    #include <sys/sysinfo.h>
    /* Linux uses /proc filesystem - no special headers needed */
#endif

#ifdef PLATFORM_MACOS
    #include <sys/sysctl.h>
    #include <sys/proc_info.h>
    #include <libproc.h>
    #include <mach/mach.h>
    #include <mach/mach_host.h>
    #include <mach/vm_statistics.h>
    #include <mach/host_info.h>
#endif

#ifdef PLATFORM_BSD
    #include <sys/sysctl.h>
    #include <sys/user.h>
    #include <kvm.h>
#endif

/* ============================================================
 * Common Headers (All Platforms)
 * ============================================================ */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

/* ============================================================
 * Platform-Specific Constants
 * ============================================================ */

#ifdef PLATFORM_MACOS
    /* macOS process states (from sys/proc.h) */
    #define PROC_STATE_RUNNING  'R'
    #define PROC_STATE_SLEEPING 'S'
    #define PROC_STATE_DISK     'D'
    #define PROC_STATE_ZOMBIE   'Z'
    #define PROC_STATE_STOPPED  'T'
    #define PROC_STATE_IDLE     'I'
#endif

/* ============================================================
 * Portable getloadavg()
 * ============================================================
 * getloadavg() is available on macOS, Linux (glibc), and BSD.
 * On older Linux systems without glibc, we fall back to /proc/loadavg.
 */

#ifndef HAVE_GETLOADAVG
    #if defined(PLATFORM_MACOS) || defined(PLATFORM_BSD) || defined(_GNU_SOURCE)
        #define HAVE_GETLOADAVG 1
    #endif
#endif

#endif /* PLATFORM_H */
