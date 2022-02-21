/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "klog.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include "securec.h"
#include "hilog/log.h"

// dmesg
#define UNUSED(x) \
    do { \
        (void)(x) \
    } while (0)

#define MAX_LOG_SIZE 1024
#define BASE_YEAR 1900
#define UNLIKELY(x)    __builtin_expect(!!(x), 0)

static int g_fd_klog = -1;

void KLogOpenLogDevice(void)
{
#ifdef _CLOEXEC_
    int fd = open("/dev/kmsg", O_WRONLY | O_CLOEXEC, S_IRUSR | S_IWUSR | S_IRGRP | S_IRGRP);
#else
    int fd = open("/dev/kmsg", O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP | S_IRGRP);
#endif
    if (fd >= 0) {
        g_fd_klog = fd;
    }
    return;
}

void KLogEnableDevKmsg(void)
{
    /* printk_devkmsg default value is ratelimit, We need to set "on" and remove the restrictions */
#ifdef _CLOEXEC_
    int fd = open("/proc/sys/kernel/printk_devkmsg", O_WRONLY | O_CLOEXEC, S_IRUSR | S_IWUSR | S_IRGRP | S_IRGRP);
#else
    int fd = open("/proc/sys/kernel/printk_devkmsg", O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP | S_IRGRP);
#endif
    if (fd < 0) {
        return;
    }
    char kmsgStatus[] = "on";
    write(fd, kmsgStatus, strlen(kmsgStatus) + 1);
    close(fd);
    fd = -1;
    return;
}

void kMsgLog(const char* fileName, int line, const char* kLevel,
    const char* fmt, ...)
{
    if (UNLIKELY(g_fd_klog < 0)) {
        KLogOpenLogDevice();
        if (g_fd_klog < 0) {
            return;
        }
    }
    va_list vargs;
    va_start(vargs, fmt);
    char tmpFmt[MAX_LOG_SIZE];
    if (vsnprintf_s(tmpFmt, MAX_LOG_SIZE, MAX_LOG_SIZE - 1, fmt, vargs) == -1) {
        va_end(vargs);
        close(g_fd_klog);
        g_fd_klog = -1;
        return;
    }

    char logInfo[MAX_LOG_SIZE];
    if (snprintf_s(logInfo, MAX_LOG_SIZE, MAX_LOG_SIZE - 1,
        "%s[dm=%08X][pid=%d][%s:%d][%s][%s] %s",
        kLevel, 0x0D002800, getpid(), fileName, line, "klog", "info", tmpFmt) == -1) {
        va_end(vargs);
        close(g_fd_klog);
        g_fd_klog = -1;
        return;
    }
    va_end(vargs);

    if (write(g_fd_klog, logInfo, strlen(logInfo)) < 0) {
        close(g_fd_klog);
        g_fd_klog = -1;
    }
    return;
}

// #endif // OHOS_BUILD_MMI_DEBUG
