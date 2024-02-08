/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#ifndef MMI_LOG_H
#define MMI_LOG_H

#include <cstdarg>
#include <cstdio>

namespace OHOS {
namespace HiviewDFX {
struct HiLogLabel {
    int32_t log;
    int32_t domain;
    const char* tag;
};
} // namespace HiviewDFX
} // namespace OHOS

inline void ReplaceAll(std::string& str, const std::string& what, const std::string& with)
{
    for (size_t pos = 0; str.npos != (pos = str.find(what, pos)); pos += with.size()) {
        str.replace(pos, what.size(), with);
    }
}

inline void PrintLog(const OHOS::HiviewDFX::HiLogLabel& label, const char* type, const char* fmt, ...)
{
    std::string fmts{fmt};
    ReplaceAll(fmts, "{public}", "");
    ReplaceAll(fmts, "{private}", "");
    fmts.append("\n");
    va_list args;
    va_start(args, fmt);
    std::printf("%s/%s: ", label.tag, type);
    std::vprintf(fmts.c_str(), args);
    va_end(args);
}

#define MMI_HILOGD(fmt, ...) PrintLog(LABEL, "D", fmt, ##__VA_ARGS__)
#define MMI_HILOGI(fmt, ...) PrintLog(LABEL, "I", fmt, ##__VA_ARGS__)
#define MMI_HILOGW(fmt, ...) PrintLog(LABEL, "W", fmt, ##__VA_ARGS__)
#define MMI_HILOGE(fmt, ...) PrintLog(LABEL, "E", fmt, ##__VA_ARGS__)
#define MMI_HILOGF(fmt, ...) PrintLog(LABEL, "F", fmt, ##__VA_ARGS__)
#define MMI_HILOGDK(fmt, ...) PrintLog(LABEL, "D", fmt, ##__VA_ARGS__)
#define MMI_HILOGIK(fmt, ...) PrintLog(LABEL, "I", fmt, ##__VA_ARGS__)
#define MMI_HILOGWK(fmt, ...) PrintLog(LABEL, "W", fmt, ##__VA_ARGS__)
#define MMI_HILOGEK(fmt, ...) PrintLog(LABEL, "E", fmt, ##__VA_ARGS__)
#define MMI_HILOGFK(fmt, ...) PrintLog(LABEL, "F", fmt, ##__VA_ARGS__)
#define CALL_DEBUG_ENTER (void)LABEL
#define CALL_INFO_TRACE (void)LABEL
#define CALL_TEST_DEBUG (void)LABEL

constexpr int32_t LOG_CORE = 0;
namespace OHOS {
namespace MMI {
constexpr int32_t MMI_LOG_DOMAIN = 0;
} // namespace MMI
} // namespace OHOS
#endif // MMI_LOG_H
