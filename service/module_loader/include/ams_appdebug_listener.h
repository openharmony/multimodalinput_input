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

#ifndef AMS_APPDEBUG_LISTENER_H
#define AMS_APPDEBUG_LISTENER_H

#include "app_debug_info.h"
#include "app_debug_listener_interface.h"

namespace OHOS {
namespace MMI {

class AmsAppDebugListener : public AppExecFwk::IAppDebugListener {
public:
    static AmsAppDebugListener *GetInstance();
    ~AmsAppDebugListener() = default;

    /**
     * @brief Notification of application information registered in listening and debugging mode.
     * @param tokens The app info of app running record.
     */
    void OnAppDebugStarted(const std::vector<AppExecFwk::AppDebugInfo> &debugInfos) override;

    /**
     * @brief Notification of application information registered in listening and remove debug mode.
     * @param tokens The app info of app running record.
     */
    void OnAppDebugStoped(const std::vector<AppExecFwk::AppDebugInfo> &debugInfos) override;

    sptr<IRemoteObject> AsObject() override;

    bool isDebugMode();

private:
    static AmsAppDebugListener *instance_;
    bool isDebugMode_ { false };
};
} // namespace MMI
} // namespace OHOS
#endif // AMS_APPDEBUG_LISTENER_H