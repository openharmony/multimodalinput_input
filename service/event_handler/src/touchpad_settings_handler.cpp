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
#include "touchpad_settings_handler.h"
#include "mmi_log.h"
#include <system_ability_definition.h>

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TouchpadSettingsObserver"

namespace OHOS {
namespace MMI {
namespace {
static bool g_hasRegistered = false;
} // namespace

TouchpadSettingsObserver::TouchpadSettingsObserver() {}

TouchpadSettingsObserver::~TouchpadSettingsObserver() {}

void TouchpadSettingsObserver::RegisterUpdateFunc()
{
    const std::string datashareUri = datashareUri_;
    const std::string libthpPath = libthpPath_;
    const std::map<std::string, int> keyToCmd = keyToCmd_;

    SettingObserver::UpdateFunc UpdateFunc = [datashareUri, libthpPath, keyToCmd](const std::string& key) {
        typedef const char* (*ThpExtraRunCommandFunc)(const char* command, const char* parameters);
        const char* (*ThpExtraRunCommand)(const char* command, const char* parameters) {};
        MMI_HILOGD("Update func");
        std::string value;
        auto ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID).GetStringValue(key, value, datashareUri);
        if (ret != 0) {
            MMI_HILOGE("Get value from setting data fail");
            return;
        }
        auto iter = keyToCmd.find(key);
        if (iter != keyToCmd.end()) {
            MMI_HILOGE("Invalid key");
            return;
        }
        MMI_HILOGD("Get value: %{public}s", value.c_str());
        void *handle = nullptr;
        handle = dlopen(libthpPath.c_str(), RTLD_LAZY);
        if (handle == nullptr) {
            MMI_HILOGE("Handle is null");
            return;
        }
        ThpExtraRunCommand = reinterpret_cast<ThpExtraRunCommandFunc>(dlsym(handle, "ThpExtraRunCommand"));
        if (ThpExtraRunCommand == nullptr) {
            MMI_HILOGE("ThpExtraRunCommand is null");
            return;
        }
        const std::string param =
            std::string("#").append(std::to_string(iter->second)).append("#").append(value);
        ThpExtraRunCommand("THP_TouchpadStatusChange", param.c_str());
        MMI_HILOGD("Update func success");
    };
    updateFunc_ = UpdateFunc;
    return;
}

void TouchpadSettingsObserver::RegisterTpObserver()
{
    if (g_hasRegistered) {
        return;
    }
    std::unique_lock<std::mutex> lock(mutex_);
    MMI_HILOGD("create touchpad settings observer");
    ErrCode ret = 0;
    RegisterUpdateFunc();
    if (updateFunc_ == nullptr) {
        MMI_HILOGE("updateFunc_ is null");
        return;
    }

    sptr<SettingObserver> pressureObserver = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
        .CreateObserver(pressureKey_, updateFunc_);
    ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
        .RegisterObserver(pressureObserver, datashareUri_);
    
    sptr<SettingObserver> vibrationObserver = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
        .CreateObserver(vibrationKey_, updateFunc_);
    ret = ret || SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
        .RegisterObserver(vibrationObserver, datashareUri_);
    
    sptr<SettingObserver> touchpadSwitchesObserver = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
        .CreateObserver(touchpadSwitchesKey_, updateFunc_);
    ret = ret || SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
        .RegisterObserver(touchpadSwitchesObserver, datashareUri_);
    
    sptr<SettingObserver> knuckleSwitchesObserver = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
        .CreateObserver(knuckleSwitchesKey_, updateFunc_);
    ret = ret || SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
        .RegisterObserver(knuckleSwitchesObserver, datashareUri_);
    if (ret) {
        MMI_HILOGE("Register setting observer failed, ret = %{public}d", ret);
        pressureObserver = nullptr;
        vibrationObserver = nullptr;
        touchpadSwitchesObserver = nullptr;
        knuckleSwitchesObserver = nullptr;
        return;
    }
    updateFunc_(pressureKey_);
    updateFunc_(vibrationKey_);
    updateFunc_(touchpadSwitchesKey_);
    updateFunc_(knuckleSwitchesKey_);
    MMI_HILOGD("register touchpad observer end");
    g_hasRegistered = true;
}
} // namespace MMI
} // namespace OHOS
