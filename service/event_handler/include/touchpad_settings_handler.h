/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#ifndef TOUCHPAD_SETTINGS_HANDLER_H
#define TOUCHPAD_SETTINGS_HANDLER_H

#include <dlfcn.h>
#include <atomic>
#include "setting_observer.h"

namespace OHOS {
namespace MMI {
class TouchpadSettingsObserver {
public:
static std::shared_ptr<TouchpadSettingsObserver> GetInstance();
    TouchpadSettingsObserver();
    ~TouchpadSettingsObserver();
    bool RegisterTpObserver(const int32_t accountId);
    bool UnregisterTpObserver(const int32_t accountId);
    void RegisterUpdateFunc();
    void SyncTouchpadSettingsData();
    void SetCommonEventReady();
    bool GetCommonEventStatus();
private:
    static std::shared_ptr<TouchpadSettingsObserver> instance_;
    static std::mutex mutex_;
    std::mutex lock_;
    SettingObserver::UpdateFunc updateFunc_ = nullptr;
    bool hasRegistered_ = false;
    std::atomic<bool> isCommonEventReady_ {false};
    int32_t currentAccountId_ = -1;
    sptr<SettingObserver> pressureObserver_ {nullptr};
    sptr<SettingObserver> vibrationObserver_ {nullptr};
    sptr<SettingObserver> touchpadSwitchesObserver_ {nullptr};
    sptr<SettingObserver> knuckleSwitchesObserver_ {nullptr};
    std::string datashareUri_ = "";
};
#define TOUCHPAD_MGR ::OHOS::MMI::TouchpadSettingsObserver::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif