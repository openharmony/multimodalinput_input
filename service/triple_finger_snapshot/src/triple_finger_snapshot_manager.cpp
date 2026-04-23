/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "triple_finger_snapshot_manager.h"
#include <string>
#include "dlfcn.h"
#include "account_manager.h"
#include "mmi_log.h"
#include "ability_launcher.h"
#include "parameters.h"
#include "setting_datashare.h"
#include "setting_observer.h"
#include "bundle_name_parser.h"
#include "system_ability_definition.h"
#include "i_input_windows_manager.h"
#include "window_info.h"
#include "util_ex.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TripleFingerSnapshotManager"

namespace {
static const std::string TRIPLE_FINGER_SNAPSHOT_LIB = "libmmi_triple_finger_snapshot.z.so";
const std::string EXTENSION_ABILITY = "extensionAbility";
const std::string TRIPLE_FINGER_SNAPSHOT_SWITCH_KEY { "sceneboard.navigation.triple_finger_type" };
constexpr int32_t CAST_INPUT_DEVICEID { 0xAAAAAAFF };
constexpr int32_t CAST_SCREEN_DEVICEID { 0xAAAAAAFE };
const std::string DATASHARE_BASE_URI =
    "datashare:///com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_SECURE_";
const std::string ENABLE_TRIPLE_FINGER_SNAPSHOT = "1";
const std::string DISABLE_TRIPLE_FINGER_SNAPSHOT = "0";
}

namespace OHOS {
namespace MMI {
TripleFingerSnapshotManager &TripleFingerSnapshotManager::GetInstance()
{
    static TripleFingerSnapshotManager instance;
    return instance;
}

bool TripleFingerSnapshotManager::Init()
{
    MMI_HILOGI("TripleFingerSnapshotManager::Init");
    return true;
}

bool TripleFingerSnapshotManager::HandleTouchEvent(std::shared_ptr<PointerEvent> event)
{
    if (event == nullptr) {
        MMI_HILOGE("event is null");
        return false;
    }
    if (event->GetFixedMode() == PointerEvent::FixedMode::AUTO) {
        return false;
    }
    PointerEvent::PointerItem item;
    if (event->GetPointerItem(event->GetPointerId(), item)) {
        if (item.GetToolType() != PointerEvent::TOOL_TYPE_FINGER) {
            return false;
        }
    }
    if (event->GetDeviceId() == CAST_INPUT_DEVICEID ||
        event->GetDeviceId() == CAST_SCREEN_DEVICEID) {
        return false;
    }
    auto impl = GetImpl();
    if (impl == nullptr) {
        return false;
    }
    return impl->HandleTouchEvent(event);
}

bool TripleFingerSnapshotManager::Enable()
{
    auto impl = Load();
    if (impl == nullptr) {
        MMI_HILOGE("impl is null");
        return false;
    }
    auto delegateProxy = GetDelegateProxy();
    if (delegateProxy == nullptr) {
        MMI_HILOGE("delegateProxy is nullptr");
        return false;
    }
    bool isAllAppsEnabled = true;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        isAllAppsEnabled = CheckAllAppsEnabled();
    }
    delegateProxy->OnPostSyncTask([this, impl, isAllAppsEnabled] {
        impl->Enable();
        impl->UpdateAppsEnable(isAllAppsEnabled);
        // 获取并初始化显示信息
        auto displayInfo = WIN_MGR->GetDefaultDisplayInfo();
        if (displayInfo != nullptr) {
            auto direction = WIN_MGR->GetDisplayDirection(displayInfo);
            UpdateDisplayInfo(displayInfo->validWidth, displayInfo->validHeight, direction);
            MMI_HILOGI("Initialized display info: width:%{public}d, height=%{public}d, direction=%{public}d",
                displayInfo->validWidth, displayInfo->validHeight, direction);
        } else {
            MMI_HILOGW("Failed to get default display info");
        }
        return RET_OK;
    });
    {
        std::lock_guard<std::mutex> lock(mutex_);
        enabled_ = true;
    }
    MMI_HILOGI("Triple finger snapshot enabled");
    return true;
}

bool TripleFingerSnapshotManager::Disable()
{
    auto impl = GetImpl();
    if (impl == nullptr) {
        MMI_HILOGE("impl is null");
        return false;
    }
    auto delegateProxy = GetDelegateProxy();
    if (delegateProxy == nullptr) {
        MMI_HILOGE("delegateProxy is nullptr");
        return false;
    }
    delegateProxy->OnPostSyncTask([this, impl] {
        impl->Disable();
        return RET_OK;
    });
    Unload();
    {
        std::lock_guard<std::mutex> lock(mutex_);
        enabled_ = false;
    }
    MMI_HILOGI("Triple finger snapshot disabled");
    return true;
}

void TripleFingerSnapshotManager::UpdateDisplayInfo(int32_t displayWidth, int32_t displayHeight, int32_t direction)
{
    auto impl = GetImpl();
    if (impl == nullptr) {
        return;
    }
    impl->UpdateDisplayInfo(displayWidth, displayHeight, direction);
}

void TripleFingerSnapshotManager::Dump(int32_t fd)
{
    auto impl = GetImpl();
    if (impl == nullptr) {
        return;
    }
    auto delegateProxy = GetDelegateProxy();
    if (delegateProxy == nullptr) {
        MMI_HILOGE("delegateProxy is nullptr");
        return;
    }
    delegateProxy->OnPostSyncTask([this, impl, fd] {
        mprintf(fd, "Triple Finger Snapshot Info:\t");
        for (const auto& [uid, enabled] : appPermissions_) {
            mprintf(fd, "App uid:%d, enabled:%s\t", uid, enabled ? "true" : "false");
        }
        impl->Dump(fd);
        return RET_OK;
    });
}

void TripleFingerSnapshotManager::SetDelegateProxy(std::shared_ptr<IDelegateInterface> proxy)
{
    std::lock_guard<std::mutex> lock(mutex_);
    delegateProxy_ = proxy;
}

std::shared_ptr<IDelegateInterface> TripleFingerSnapshotManager::GetDelegateProxy()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return delegateProxy_;
}

void TripleFingerSnapshotManager::UpdateAppPermission(int32_t uid, bool enable)
{
    MMI_HILOGI("UpdateAppPermission, uid:%{public}d, enable:%{public}s", uid, enable ? "true" : "false");
    bool allEnabled = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        appPermissions_[uid] = enable;
        // 检查是否所有应用都已启用
        allEnabled = CheckAllAppsEnabled();
    }
    auto impl = GetImpl();
    if (impl != nullptr) {
        impl->UpdateAppsEnable(allEnabled);
        MMI_HILOGI("UpdateAppsEnable called with allEnabled:%{public}s", allEnabled ? "true" : "false");
    } else {
        MMI_HILOGE("impl is null, cannot update permission");
    }
}

void TripleFingerSnapshotManager::SetDatashareReady(int32_t userId)
{
    isDataShareReady_.store(true); 
    RegisterSwitchObserver(userId);
    MMI_HILOGI("datashare is ready");
}

bool TripleFingerSnapshotManager::RegisterSwitchObserver(int32_t userId)
{
    MMI_HILOGI("RegisterSwitchObserver, userId:%{public}d", userId);
    if (userId == -1) {
        MMI_HILOGW("userId is -1");
        return false;
    }
    if (!isDataShareReady_.load() ||
        !SettingDataShare::GetInstance(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID).CheckIfSettingsDataReady()) {
        MMI_HILOGW("datashare is not ready");
        return false;
    }
    if (IsObserverRegistered(userId)) {
        MMI_HILOGI("Observer already registered for userId:%{public}d", userId);
        return true;
    }

    int32_t oldUserId = -1;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        oldUserId = currentAccountId_;
        currentAccountId_ = userId;
    }

    // 用户切换场景：先注销旧用户的 observer
    if (oldUserId != -1 && oldUserId != userId) {
        UnregisterObserverForUser(oldUserId);
    }

    // 为新用户注册 observer
    return CreateAndRegisterObserver(userId);
}

bool TripleFingerSnapshotManager::IsObserverRegistered(int32_t userId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    return currentAccountId_ == userId && switchObserver_ != nullptr;
}

void TripleFingerSnapshotManager::UnregisterObserverForUser(int32_t userId)
{
    std::string oldUri = DATASHARE_BASE_URI + std::to_string(userId) + "?Proxy=true";
    MMI_HILOGI("Unregister observer for userId:%{public}d", userId);
    std::lock_guard<std::mutex> lock(mutex_);
    if (switchObserver_ != nullptr) {
        SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
            .UnregisterObserver(switchObserver_, oldUri);
        switchObserver_ = nullptr;
    }
}

bool TripleFingerSnapshotManager::CreateAndRegisterObserver(int32_t userId)
{
    std::string uri = DATASHARE_BASE_URI + std::to_string(userId) + "?Proxy=true";
    SettingObserver::UpdateFunc updateFunc = [this, uri](const std::string& key) {
        std::string value;
        auto ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
            .GetStringValue(key, value, uri);
        if (ret != RET_OK) {
            value = system::GetParameter("const.sceneboard.triple_finger_type", DISABLE_TRIPLE_FINGER_SNAPSHOT);
            MMI_HILOGW("Get value from setting data fail:%{public}d, value:%{public}s", ret, value.c_str());
        }
        if (value == ENABLE_TRIPLE_FINGER_SNAPSHOT) {
            this->OnSwitchChanged(true);
        }
        if (value == DISABLE_TRIPLE_FINGER_SNAPSHOT) {
            this->OnSwitchChanged(false);
        }
    };

    sptr<SettingObserver> statusObserver = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
        .CreateObserver(TRIPLE_FINGER_SNAPSHOT_SWITCH_KEY, updateFunc);
    if (statusObserver == nullptr) {
        MMI_HILOGE("Create observer failed");
        return false;
    }

    ErrCode ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
        .RegisterObserver(statusObserver, uri);
    if (ret != ERR_OK) {
        MMI_HILOGE("Register setting observer failed, ret:%{public}d", ret);
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    switchObserver_ = statusObserver;
    MMI_HILOGI("Successfully registered switch observer for userId:%{public}d", userId);
    return true;
}

void TripleFingerSnapshotManager::OnSwitchChanged(bool enabled)
{
    MMI_HILOGI("OnSwitchChanged, enabled: %{public}s", enabled ? "true" : "false");

    if (enabled) {
        Enable();
    } else {
        Disable();
    }
}

bool TripleFingerSnapshotManager::CheckAllAppsEnabled()
{
    // 如果没有任何应用设置权限，默认返回 true
    if (appPermissions_.empty()) {
        return true;
    }

    // 检查是否所有应用都已启用
    for (const auto& [uid, enabled] : appPermissions_) {
        if (!enabled) {
            MMI_HILOGI("App uid:%{public}d has disabled triple finger snapshot", uid);
            return false;
        }
    }

    return true;
}

std::shared_ptr<ITripleFingerSnapshot> TripleFingerSnapshotManager::GetImpl()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return impl_;
}

std::shared_ptr<ITripleFingerSnapshot> TripleFingerSnapshotManager::Load()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (impl_ != nullptr) {
        return impl_;
    }

    if (!LoadLibrary()) {
        return nullptr;
    }
    
    if (!LoadSymbols()) {
        CleanupOnError();
        return nullptr;
    }
    
    if (!CreateImpl()) {
        CleanupOnError();
        return nullptr;
    }

    return impl_;
}

void TripleFingerSnapshotManager::Unload()
{
    std::lock_guard<std::mutex> lock(mutex_);
    create_ = nullptr;
    destroy_ = nullptr;
    impl_.reset();

    if (handle_ != nullptr) {
        ::dlclose(handle_);
        handle_ = nullptr;
    }

    MMI_HILOGI("Successfully unloaded triple finger snapshot plugin");
}

void TripleFingerSnapshotManager::CleanupOnError()
{
    create_ = nullptr;
    destroy_ = nullptr;
    impl_.reset();
    
    if (handle_ != nullptr) {
        ::dlclose(handle_);
        handle_ = nullptr;
    }
}

bool TripleFingerSnapshotManager::LoadLibrary()
{
    if (handle_ != nullptr) {
        return true;
    }
    
    handle_ = ::dlopen(TRIPLE_FINGER_SNAPSHOT_LIB.c_str(), RTLD_LAZY);
    if (handle_ == nullptr) {
        MMI_HILOGE("dlopen %{public}s failed: %{public}s",
            TRIPLE_FINGER_SNAPSHOT_LIB.c_str(), ::dlerror());
        return false;
    }
    return true;
}

bool TripleFingerSnapshotManager::LoadSymbols()
{
    create_ = reinterpret_cast<GetTripleFingerSnapshotFunc>(
        ::dlsym(handle_, "GetTripleFingerSnapshot"));
    if (create_ == nullptr) {
        MMI_HILOGE("dlsym GetTripleFingerSnapshot failed: %{public}s", ::dlerror());
        return false;
    }

    destroy_ = reinterpret_cast<DestroyTripleFingerSnapshotFunc>(
        ::dlsym(handle_, "DestroyTripleFingerSnapshot"));
    if (destroy_ == nullptr) {
        MMI_HILOGE("dlsym DestroyTripleFingerSnapshot failed: %{public}s", ::dlerror());
        return false;
    }
    return true;
}

bool TripleFingerSnapshotManager::CreateImpl()
{
    auto context = std::make_shared<TripleFingerSnapshotContext>();
    if (context == nullptr) {
        MMI_HILOGE("Failed to create TripleFingerSnapshotContext");
        return false;
    }
    impl_ = std::shared_ptr<ITripleFingerSnapshot>(create_(context), [this](ITripleFingerSnapshot* ptr) {
        if (destroy_ != nullptr) {
            destroy_(ptr);
        }
    });
    if (impl_ == nullptr) {
        MMI_HILOGE("Failed to create TripleFingerSnapshot");
        return false;
    }
    return true;
}

void TripleFingerSnapshotContext::TriggerScreenshot()
{
    // 获取截屏服务的 bundleName 和 abilityName
    std::string bundleName = BUNDLE_NAME_PARSER.GetBundleName("SCREENSHOT_BUNDLE_NAME");
    std::string abilityName = BUNDLE_NAME_PARSER.GetBundleName("SCREENSHOT_ABILITY_NAME");

    if (bundleName.empty() || abilityName.empty()) {
        MMI_HILOGE("Failed to get screenshot bundle info, bundleName:%{public}s, abilityName:%{public}s",
                   bundleName.c_str(), abilityName.c_str());
        return;
    }
    // 启动截屏 Ability
    Ability ability;
    ability.bundleName = bundleName;
    ability.abilityName = abilityName;
    ability.abilityType = EXTENSION_ABILITY;
    ability.params.emplace(std::make_pair("shot_type", "normal_type"));
    ability.params.emplace(std::make_pair("trigger_type", "triple_finger_swipe"));

    // 使用 LAUNCHER_ABILITY 启动截屏服务
    LAUNCHER_ABILITY->LaunchAbility(ability);

    MMI_HILOGI("Launching screenshot ability, bundleName:%{public}s, abilityName:%{public}s",
               bundleName.c_str(), abilityName.c_str());
}

void TripleFingerSnapshotContext::TriggerAncoTripleFingerSnapshot()
{
#ifdef OHOS_BUILD_ENABLE_ANCO
    TriggerAncoTripleFingerSnapshotExt();
#endif // OHOS_BUILD_ENABLE_ANCO
}
} // namespace MMI
} // namespace OHOS