/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "klog.h"
#include <fcntl.h>
#include <unistd.h>

#include "securec.h"

namespace OHOS {
namespace MMI {
#define UNUSED(x) \
    do { \
        (void)(x) \
    } while (0)

#define UNLIKELY(x) __builtin_expect(!!(x), 0)

static int g_fd = -1;

constexpr int32_t MAX_LOG_SIZE = 1024;

void KLogOpenLogDevice(void)
{
#ifdef _CLOEXEC_
    int fd = open("/dev/kmsg", O_WRONLY | O_CLOEXEC, S_IRUSR | S_IWUSR | S_IRGRP | S_IRGRP);
#else
    int fd = open("/dev/kmsg", O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP | S_IRGRP);
#endif
    if (fd >= 0) {
        g_fd = fd;
    }
    return;
}

void kMsgLog(const char* fileName, int line, const char* kLevel,
    const char* fmt, ...)
{
    if (UNLIKELY(g_fd < 0)) {
        KLogOpenLogDevice();
        if (g_fd < 0) {
            return;
        }
    }
    va_list vargs;
    va_start(vargs, fmt);
    char tmpFmt[MAX_LOG_SIZE];
    if (vsnprintf_s(tmpFmt, MAX_LOG_SIZE, MAX_LOG_SIZE - 1, fmt, vargs) == -1) {
        va_end(vargs);
        close(g_fd);
        g_fd = -1;
        return;
    }

    char logInfo[MAX_LOG_SIZE];
    if (snprintf_s(logInfo, MAX_LOG_SIZE, MAX_LOG_SIZE - 1,
        "%s[dm=%08X][pid=%d][%s:%d][%s][%s] %s",
        kLevel, 0x0D002800, getpid(), fileName, line, "klog", "info", tmpFmt) == -1) {
        va_end(vargs);
        close(g_fd);
        g_fd = -1;
        return;
    }
    va_end(vargs);

    if (write(g_fd, logInfo, strlen(logInfo)) < 0) {
        close(g_fd);
        g_fd = -1;
    }
    return;
}
} // namespace MMI
} // namespace OHOS
