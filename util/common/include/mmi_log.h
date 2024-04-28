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
 
#ifndef MMI_LOG_H
#define MMI_LOG_H

#include <cinttypes>
#include <functional>
#include <future>
#include <string>
#include <sstream>

#include "hilog/log.h"

#include "util.h"
#include "klog.h"

#ifdef MMI_LOG_DOMAIN
#undef MMI_LOG_DOMAIN
#endif
#define MMI_LOG_DOMAIN 0XD002800

#ifndef MMI_FUNC_FMT
#define MMI_FUNC_FMT "in %{public}s, "
#endif

#ifndef MMI_FUNC_INFO
#define MMI_FUNC_INFO __FUNCTION__
#endif

#ifndef MMI_FILE_NAME
#define MMI_FILE_NAME   (strrchr((__FILE__), '/') ? strrchr((__FILE__), '/') + 1 : (__FILE__))
#endif

#ifndef MMI_LINE_INFO
#define MMI_LINE_INFO   MMI_FILE_NAME, __LINE__
#endif

#define MMI_HILOGD(fmt, ...) do { \
    if (HiLogIsLoggable(MMI_LOG_DOMAIN, MMI_LOG_TAG, LOG_DEBUG)) { \
        HILOG_IMPL(LOG_CORE, LOG_DEBUG, MMI_LOG_DOMAIN, MMI_LOG_TAG, MMI_FUNC_FMT fmt, MMI_FUNC_INFO, ##__VA_ARGS__); \
    } \
} while (0)
#define MMI_HILOGI(fmt, ...) do { \
    HILOG_IMPL(LOG_CORE, LOG_INFO, MMI_LOG_DOMAIN, MMI_LOG_TAG, MMI_FUNC_FMT fmt, MMI_FUNC_INFO, ##__VA_ARGS__); \
} while (0)
#define MMI_HILOGW(fmt, ...) do { \
    HILOG_IMPL(LOG_CORE, LOG_WARN, MMI_LOG_DOMAIN, MMI_LOG_TAG, MMI_FUNC_FMT fmt, MMI_FUNC_INFO, ##__VA_ARGS__); \
} while (0)
#define MMI_HILOGE(fmt, ...) do { \
    HILOG_IMPL(LOG_CORE, LOG_ERROR, MMI_LOG_DOMAIN, MMI_LOG_TAG, MMI_FUNC_FMT fmt, MMI_FUNC_INFO, ##__VA_ARGS__); \
} while (0)
#define MMI_HILOGF(fmt, ...) do { \
    HILOG_IMPL(LOG_CORE, LOG_FATAL, MMI_LOG_DOMAIN, MMI_LOG_TAG, MMI_FUNC_FMT fmt, MMI_FUNC_INFO, ##__VA_ARGS__); \
} while (0)

#define MMI_HILOGDK(fmt, ...) do { \
    KMSG_LOGD(fmt, ##__VA_ARGS__); \
    MMI_HILOGD(fmt, ##__VA_ARGS__); \
} while (0)

#define MMI_HILOGIK(fmt, ...) do { \
    KMSG_LOGI(fmt, ##__VA_ARGS__); \
    MMI_HILOGI(fmt, ##__VA_ARGS__); \
} while (0)

#define MMI_HILOGWK(fmt, ...) do { \
    KMSG_LOGW(fmt, ##__VA_ARGS__); \
    MMI_HILOGW(fmt, ##__VA_ARGS__); \
} while (0)

#define MMI_HILOGEK(fmt, ...) do { \
    KMSG_LOGE(fmt, ##__VA_ARGS__); \
    MMI_HILOGE(fmt, ##__VA_ARGS__); \
} while (0)

#define MMI_HILOGFK(fmt, ...) do { \
    KMSG_LOGF(fmt, ##__VA_ARGS__); \
    MMI_HILOGF(fmt, ##__VA_ARGS__); \
} while (0)

namespace OHOS {
namespace MMI {
inline constexpr int32_t EVENT_TYPE_POINTER { 0X00020000 };
inline constexpr int32_t TIMEOUT { 100000 };
inline constexpr int32_t POINTER_ACTION_UP { 4 };
inline constexpr int32_t POINTER_ACTION_MOVE { 3 };
inline constexpr int32_t FINAL_FINGER { 1 };

class InnerFunctionTracer {
public:
    InnerFunctionTracer(LogLevel level, const char* tag, const char* logfn)
        : level_ { level }, tag_ { tag }, logfn_ { logfn }
    {
        if (HiLogIsLoggable(MMI_LOG_DOMAIN, tag_, level_)) {
            if (logfn_ != nullptr) {
                HILOG_IMPL(LOG_CORE, level_, MMI_LOG_DOMAIN, tag_, "in %{public}s, enter", logfn_);
            }
        }
    }
    ~InnerFunctionTracer()
    {
        if (HiLogIsLoggable(MMI_LOG_DOMAIN, tag_, level_)) {
            if (logfn_ != nullptr) {
                HILOG_IMPL(LOG_CORE, level_, MMI_LOG_DOMAIN, tag_, "in %{public}s, leave", logfn_);
            }
        }
    }
private:
    LogLevel level_ { LOG_LEVEL_MIN };
    const char* tag_ { nullptr };
    const char* logfn_ { nullptr };
};
} // namespace MMI
} // namespace OHOS

#define CALL_DEBUG_ENTER ::OHOS::MMI::InnerFunctionTracer __innerFuncTracer_Debug___ \
    { LOG_DEBUG, MMI_LOG_TAG, __FUNCTION__ }
#define CALL_INFO_TRACE ::OHOS::MMI::InnerFunctionTracer ___innerFuncTracer_Info___ \
    { LOG_INFO, MMI_LOG_TAG, __FUNCTION__ }
#define CALL_TEST_DEBUG ::OHOS::MMI::InnerFunctionTracer ___innerFuncTracer_Info___ \
    { LOG_DEBUG, MMI_LOG_TAG, test_info_ == nullptr ? "TestBody" : test_info_->name() }
#endif // MMI_LOG_H
