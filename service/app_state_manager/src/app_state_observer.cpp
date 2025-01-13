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

#include "app_state_observer.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_SERVER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "AppStateObserver"

namespace OHOS {
namespace MMI {
namespace {
std::mutex mutex_;
} // namespace
AppObserverManager::AppObserverManager() {}
AppObserverManager::~AppObserverManager() {}

void ApplicationStateObserver::OnProcessStateChanged(const AppExecFwk::ProcessData &processData)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    MMI_HILOGD("Process state change app name:%{public}s, uid:%{public}d, state:%{public}d",
        processData.bundleName.c_str(),
        processData.uid,
        processData.state);
    std::vector<AppExecFwk::AppStateData> list {};
    GetForegroundApplicationInfo(list);
}

OHOS::sptr<OHOS::AppExecFwk::IAppMgr> ApplicationStateObserver::GetAppMgr()
{
    if (appManager_) {
        return appManager_;
    }

    OHOS::sptr<ISystemAbilityManager> systemAbilityManager =
        OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemAbilityManager) {
        MMI_HILOGE("Get system ability manager failed");
        return nullptr;
    }
    OHOS::sptr<OHOS::IRemoteObject> object = systemAbilityManager->CheckSystemAbility(OHOS::APP_MGR_SERVICE_ID);
    appManager_ = OHOS::iface_cast<OHOS::AppExecFwk::IAppMgr>(object);
    return appManager_;
}

int32_t ApplicationStateObserver::GetForegroundApplicationInfo(std::vector<AppExecFwk::AppStateData> &list)
{
    CALL_DEBUG_ENTER;
    auto appMgr = GetAppMgr();
    CHKPR(appMgr, RET_ERR);
    int32_t ret = appMgr->GetForegroundApplications(list);
    if (ret == RET_OK) {
        MMI_HILOGD("GetForegroundApplications success");
        APP_OBSERVER_MGR->SetForegroundAppData(list);
    }
    return ret;
}

std::vector<AppExecFwk::AppStateData> AppObserverManager::GetForegroundAppData()
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    MMI_HILOGD("The foregroundAppData_.size():%{public}zu", foregroundAppData_.size());
    return foregroundAppData_;
}

void AppObserverManager::SetForegroundAppData(std::vector<AppExecFwk::AppStateData> list)
{
    CALL_DEBUG_ENTER;
    foregroundAppData_ = list;
    MMI_HILOGD("The foregroundAppData_.size():%{public}zu", foregroundAppData_.size());
}

void AppObserverManager::InitAppStateObserver()
{
    CALL_DEBUG_ENTER;
    if (hasInit_) {
        MMI_HILOGI("App state observer has init");
        return;
    }
    OHOS::sptr<ISystemAbilityManager> systemAbilityManager =
        OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemAbilityManager) {
        MMI_HILOGE("Get system ability manager failed");
        return;
    }
    OHOS::sptr<OHOS::IRemoteObject> object = systemAbilityManager->CheckSystemAbility(OHOS::APP_MGR_SERVICE_ID);
    CHKPV(object);
    sptr<AppExecFwk::IAppMgr> appMgr = OHOS::iface_cast<OHOS::AppExecFwk::IAppMgr>(object);
    CHKPV(appMgr);
    int32_t ret = appMgr->RegisterApplicationStateObserver(new ApplicationStateObserver());
    if (ret == RET_OK) {
        hasInit_ = true;
        MMI_HILOGI("Register app success");
    }
}
} // namespace MMI
} // namespace OHOS