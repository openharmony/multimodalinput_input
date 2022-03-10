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
#ifndef MMI_LOG_H
#define MMI_LOG_H

#include <future>
#include <string>

#include "hilog/log.h"

#include "util.h"
#include "klog.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr uint32_t MMI_LOG_DOMAIN = 0xD002800;
} // namespace
} // namespace MMI
} // namespace OHOS

#ifndef MMI_FUNC_FMT
#define MMI_FUNC_FMT "in %{public}s, #%{public}d, "
#endif

#ifndef MMI_FUNC_INFO
#define MMI_FUNC_INFO __FUNCTION__, __LINE__
#endif

#ifndef MMI_FILE_NAME
#define MMI_FILE_NAME   (strrchr((__FILE__), '/') ? strrchr((__FILE__), '/') + 1 : (__FILE__))
#endif

#ifndef MMI_LINE_INFO
#define MMI_LINE_INFO   MMI_FILE_NAME, __LINE__
#endif

#define MMI_LOGT(fmt, ...) do { \
    OHOS::HiviewDFX::HiLog::Debug(LABEL, MMI_FUNC_FMT fmt, MMI_FUNC_INFO, ##__VA_ARGS__); \
} while (0)
#define MMI_LOGD(fmt, ...) do { \
    OHOS::HiviewDFX::HiLog::Debug(LABEL, MMI_FUNC_FMT fmt, MMI_FUNC_INFO, ##__VA_ARGS__); \
} while (0)
#define MMI_LOGI(fmt, ...) do { \
    OHOS::HiviewDFX::HiLog::Info(LABEL, MMI_FUNC_FMT fmt, MMI_FUNC_INFO, ##__VA_ARGS__); \
} while (0)
#define MMI_LOGW(fmt, ...) do { \
    OHOS::HiviewDFX::HiLog::Warn(LABEL, MMI_FUNC_FMT fmt, MMI_FUNC_INFO, ##__VA_ARGS__); \
} while (0)
#define MMI_LOGE(fmt, ...) do { \
    OHOS::HiviewDFX::HiLog::Error(LABEL, MMI_FUNC_FMT fmt, MMI_FUNC_INFO, ##__VA_ARGS__); \
} while (0)
#define MMI_LOGA(fmt, ...) do { \
    OHOS::HiviewDFX::HiLog::Error(LABEL, MMI_FUNC_FMT fmt, MMI_FUNC_INFO, ##__VA_ARGS__); \
} while (0)
#define MMI_LOGF(fmt, ...) do { \
    OHOS::HiviewDFX::HiLog::Fatal(LABEL, MMI_FUNC_FMT fmt, MMI_FUNC_INFO, ##__VA_ARGS__); \
} while (0)

#define MMI_LOGTK(fmt, ...) do { \
    KMSG_LOGT(fmt, ##__VA_ARGS__); \
    MMI_LOGT(fmt, ##__VA_ARGS__); \
} while (0)

#define MMI_LOGDK(fmt, ...) do { \
    KMSG_LOGD(fmt, ##__VA_ARGS__); \
    MMI_LOGD(fmt, ##__VA_ARGS__); \
} while (0)

#define MMI_LOGIK(fmt, ...) do { \
    KMSG_LOGI(fmt, ##__VA_ARGS__); \
    MMI_LOGI(fmt, ##__VA_ARGS__); \
} while (0)

#define MMI_LOGWK(fmt, ...) do { \
    KMSG_LOGW(fmt, ##__VA_ARGS__); \
    MMI_LOGW(fmt, ##__VA_ARGS__); \
} while (0)

#define MMI_LOGEK(fmt, ...) do { \
    KMSG_LOGE(fmt, ##__VA_ARGS__); \
    MMI_LOGE(fmt, ##__VA_ARGS__); \
} while (0)

#define MMI_LOGAK(fmt, ...) do { \
    KMSG_LOGA(fmt, ##__VA_ARGS__); \
    MMI_LOGA(fmt, ##__VA_ARGS__); \
} while (0)

#define MMI_LOGFK(fmt, ...) do { \
    KMSG_LOGF(fmt, ##__VA_ARGS__); \
    MMI_LOGF(fmt, ##__VA_ARGS__); \
} while (0)

namespace OHOS {
namespace MMI {
class InnerFunctionTracer {
public:
    InnerFunctionTracer(const OHOS::HiviewDFX::HiLogLabel& label, const char *func)
        : label_ { label }, func_ { func }
    {
        OHOS::HiviewDFX::HiLog::Debug(label_, "in %{public}s, enter", func_);
    }
    ~InnerFunctionTracer()
    {
        OHOS::HiviewDFX::HiLog::Debug(label_, "in %{public}s, leave", func_);
    }
private:
    const OHOS::HiviewDFX::HiLogLabel& label_;
    const char* func_ { nullptr };
};
} // namespace MMI
} // namespace OHOS

#define CALL_LOG_ENTER   InnerFunctionTracer ___innerFuncTracer___ { LABEL, __FUNCTION__ }
#endif // MMI_LOG_H