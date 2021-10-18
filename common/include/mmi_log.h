/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef OHOS_MMI_LOG_H
#define OHOS_MMI_LOG_H

#include <string>
#include "hilog/log.h"

namespace OHOS {
namespace {
    constexpr uint32_t COMMON = 0xD002800;
}
static constexpr HiviewDFX::HiLogLabel MMI_COMMON_LABEL = { LOG_CORE, COMMON, "MMI" };
const std::string DOUBLE_COLON = "::";
#if defined(DEBUG)
#define MMI_LOGD(fmt, ...) \
    OHOS::HiviewDFX::HiLog::Debug(MMI_COMMON_LABEL, "File:%{public}s, Line:%{public}d, Function:%{public}s" fmt, \
                                                           __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)
#define MMI_LOGI(fmt, ...) \
    OHOS::HiviewDFX::HiLog::Info(MMI_COMMON_LABEL, "File:%{public}s, Line:%{public}d, Function:%{public}s" fmt, \
                                                          __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)
#define MMI_LOGW(fmt, ...) \
    OHOS::HiviewDFX::HiLog::Warn(MMI_COMMON_LABEL, "File:%{public}s, Line:%{public}d, Function:%{public}s" fmt, \
                                                          __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)
#define MMI_LOGE(fmt, ...) \
    OHOS::HiviewDFX::HiLog::Error(MMI_COMMON_LABEL, "File:%{public}s, Line:%{public}d, Function:%{public}s" fmt, \
                                                           __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)
#define MMI_LOGF(fmt, ...) \
    OHOS::HiviewDFX::HiLog::Fatal(MMI_COMMON_LABEL, "File:%{public}s, Line:%{public}d, Function:%{public}s" fmt, \
                                                           __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)
#else
#define MMI_LOGD(fmt, ...) \
    OHOS::HiviewDFX::HiLog::Debug(MMI_COMMON_LABEL, "%{public}s: " fmt, __FUNCTION__, ##__VA_ARGS__)
#define MMI_LOGI(fmt, ...) \
    OHOS::HiviewDFX::HiLog::Info(MMI_COMMON_LABEL, "%{public}s: " fmt, __FUNCTION__, ##__VA_ARGS__)
#define MMI_LOGW(fmt, ...) \
    OHOS::HiviewDFX::HiLog::Warn(MMI_COMMON_LABEL, "%{public}s: " fmt, __FUNCTION__, ##__VA_ARGS__)
#define MMI_LOGE(fmt, ...) \
    OHOS::HiviewDFX::HiLog::Error(MMI_COMMON_LABEL, "%{public}s: " fmt, __FUNCTION__, ##__VA_ARGS__)
#define MMI_LOGF(fmt, ...) \
    OHOS::HiviewDFX::HiLog::Fatal(MMI_COMMON_LABEL, "%{public}s: " fmt, __FUNCTION__, ##__VA_ARGS__)
#endif
}  // namespace OHOS

#endif  // OHOS_MMI_LOG_H
