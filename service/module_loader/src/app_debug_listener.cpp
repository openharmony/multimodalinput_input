/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "app_debug_listener.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "AppDebugListener"

namespace OHOS {
namespace MMI {
AppDebugListener *AppDebugListener::instance_ = new (std::nothrow) AppDebugListener();
AppDebugListener *AppDebugListener::GetInstance()
{
    return instance_;
}

void AppDebugListener::OnAppDebugStarted(const std::vector<AppExecFwk::AppDebugInfo> &debugInfos)
{
    CALL_DEBUG_ENTER;
    for (const auto &debugInfo : debugInfos) {
        appDebugPid_ = debugInfo.pid;
        MMI_HILOGD("appDebugPid_ : %{public}d", appDebugPid_);
    }
}

void AppDebugListener::OnAppDebugStoped(const std::vector<AppExecFwk::AppDebugInfo> &debugInfos)
{
    CALL_DEBUG_ENTER;
    for (const auto &debugInfo : debugInfos) {
        if (appDebugPid_ == debugInfo.pid) {
            appDebugPid_ = -1;
        }
    }
}

int32_t AppDebugListener::GetAppDebugPid()
{
    MMI_HILOGD("appDebugPid_ : %{public}d", appDebugPid_);
    return appDebugPid_;
}
} // namespace MMI
} // namespace OHOS
