/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
    HiviewDFX::HiLog::Debug(MMI_COMMON_LABEL, "File:%{public}s, Line:%{public}d, Function:%{public}s " fmt,\
                                                           __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)

#define MMI_LOGI(fmt, ...) \
    HiviewDFX::HiLog::Info(MMI_COMMON_LABEL, "File:%{public}s, Line:%{public}d, Function:%{public}s " fmt,\
                                                          __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)

#define MMI_LOGW(fmt, ...) \
    HiviewDFX::HiLog::Warn(MMI_COMMON_LABEL, "File:%{public}s, Line:%{public}d, Function:%{public}s " fmt,\
                                                          __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)

#define MMI_LOGE(fmt, ...) \
    HiviewDFX::HiLog::Error(MMI_COMMON_LABEL, "File:%{public}s, Line:%{public}d, Function:%{public}s " fmt,\
                                                           __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)

#define MMI_LOGF(fmt, ...) \
    HiviewDFX::HiLog::Fatal(MMI_COMMON_LABEL, "File:%{public}s, Line:%{public}d, Function:%{public}s " fmt,\
                                                           __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)
#else

static const char* _FuncName(std::string &&funcName)
{
    auto pos = funcName.find('(');
    if (pos != std::string::npos) {
        funcName.erase(funcName.begin() + pos, funcName.end());
    }

    pos = funcName.find(DOUBLE_COLON);
    if (pos != std::string::npos) {
        funcName.erase(funcName.begin(), funcName.begin() + pos + DOUBLE_COLON.size());  // need wrap "::" symbol
    }

    return funcName.c_str();
}

#define CLASS_FUNCTION _FuncName(std::string(__PRETTY_FUNCTION__))

#define MMI_LOGD(fmt, ...) \
    HiviewDFX::HiLog::Debug(MMI_COMMON_LABEL, "%{public}s: " fmt, CLASS_FUNCTION, ##__VA_ARGS__)

#define MMI_LOGI(fmt, ...) \
    HiviewDFX::HiLog::Info(MMI_COMMON_LABEL, "%{public}s: " fmt, CLASS_FUNCTION, ##__VA_ARGS__)

#define MMI_LOGW(fmt, ...) \
    HiviewDFX::HiLog::Warn(MMI_COMMON_LABEL, "%{public}s: " fmt, CLASS_FUNCTION, ##__VA_ARGS__)

#define MMI_LOGE(fmt, ...) \
    HiviewDFX::HiLog::Error(MMI_COMMON_LABEL, "%{public}s: " fmt, CLASS_FUNCTION, ##__VA_ARGS__)

#define MMI_LOGF(fmt, ...) \
    HiviewDFX::HiLog::Fatal(MMI_COMMON_LABEL, "%{public}s: " fmt, CLASS_FUNCTION, ##__VA_ARGS__)
#endif
}  // namespace OHOS

#endif  // MMI_LOG_H
