/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef COMMON_H
#define COMMON_H

#include <atomic>
#include <cstdint>
#include <stdarg.h>
#include <stdio.h>

#include <linux/input.h>

#include "mmi_log.h"

namespace OHOS {
namespace MMI {

struct EventRecord {
    uint32_t deviceId;
    input_event event;
};

// Global shutdown flag for event recorder tool use
extern std::atomic<bool> g_shutdown;

// Print functions in place of Logger
inline void PrintWithPrefix(const char* prefix, const char* format, va_list args)
{
    if (prefix && *prefix) {
        printf("%s", prefix); // Only print prefix if it's not empty
    }
    vprintf(format, args);
    printf("\n");
}

inline void PrintDebug(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    PrintWithPrefix("", format, args);
    va_end(args);
}

inline void PrintInfo(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    PrintWithPrefix("", format, args);
    va_end(args);
}

inline void PrintWarning(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    PrintWithPrefix("[WARNING] ", format, args);
    va_end(args);
}

inline void PrintError(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    PrintWithPrefix("[ERROR] ", format, args);
    va_end(args);
}

inline void TrimString(std::string& str)
{
    size_t start = str.find_first_not_of(" \t");
    if (start == std::string::npos) {
        str.clear();
        return;
    }
    size_t end = str.find_last_not_of(" \t");
    str = str.substr(start, end - start + 1);
}

inline bool RemovePrefix(std::string& str, const std::string& prefix)
{
    if (str.find(prefix) == 0) {
        str.erase(0, prefix.length());
        TrimString(str);
        return true;
    }
    return false;
}
} // namespace MMI
} // namespace OHOS
#endif // COMMON_H