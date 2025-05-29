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

#ifndef APP_DEBUG_LISTENER_H
#define APP_DEBUG_LISTENER_H

#include "app_debug_listener_stub.h"

namespace OHOS {
namespace MMI {
class AppDebugListener : public AppExecFwk::AppDebugListenerStub {
public:
    static AppDebugListener *GetInstance();
    ~AppDebugListener() = default;

    ErrCode OnAppDebugStarted(const std::vector<AppExecFwk::AppDebugInfo> &debugInfos) override;
    ErrCode OnAppDebugStoped(const std::vector<AppExecFwk::AppDebugInfo> &debugInfos) override;

    int32_t GetAppDebugPid();

private:
    static AppDebugListener *instance_;
    int32_t appDebugPid_ { -1 };
};
} // namespace MMI
} // namespace OHOS
#endif // APP_DEBUG_LISTENER_H