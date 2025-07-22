/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_APP_STATE_OBSERVER_H
#define OHOS_APP_STATE_OBSERVER_H

#include "singleton.h"

#include "app_mgr_interface.h"
#include "application_state_observer_stub.h"
#include "iservice_registry.h"
#include "mmi_log.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace MMI {
class ApplicationStateObserver : public AppExecFwk::ApplicationStateObserverStub {
public:
    ApplicationStateObserver() {};
    ~ApplicationStateObserver() = default;
    void OnProcessStateChanged(const AppExecFwk::ProcessData &processData) override;
    std::vector<AppExecFwk::AppStateData> GetForegroundAppData();
private:
    sptr<AppExecFwk::IAppMgr> appManager_ = nullptr;
    OHOS::sptr<OHOS::AppExecFwk::IAppMgr> GetAppMgr();
    int32_t GetForegroundApplicationInfo(std::vector<AppExecFwk::AppStateData> &list);
};

class AppObserverManager final {
    DECLARE_DELAYED_SINGLETON(AppObserverManager);
public:
    DISALLOW_COPY_AND_MOVE(AppObserverManager);
    void InitAppStateObserver();
    void SetForegroundAppData(const std::vector<AppExecFwk::AppStateData> &list);
    std::vector<AppExecFwk::AppStateData> GetForegroundAppData();
private:
    bool hasInit_ { false };
    std::vector<AppExecFwk::AppStateData> foregroundAppData_ {};
};

#define APP_OBSERVER_MGR ::OHOS::DelayedSingleton<AppObserverManager>::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // OHOS_APP_STATE_OBSERVER_H
