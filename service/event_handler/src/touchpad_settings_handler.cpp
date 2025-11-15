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
#include <system_ability_definition.h>
#include "setting_datashare.h"
#include "touchpad_settings_handler.h"
#include "mmi_log.h"
#include "account_manager.h"
#include "input_device_manager.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TouchpadSettingsObserver"

#define TP_CHECK_FALSE_RETURN(cond, ret, fmt, ...)  \
    if (!(cond)) {                                  \
        MMI_HILOGE(fmt, ##__VA_ARGS__);             \
        return ret;                                 \
    }

namespace OHOS {
namespace MMI {
namespace {
const std::string g_volumeSwitchesKey {"settings.trackpad.right_volume_switches"};
const std::string g_brightnessSwitchesKey {"settings.trackpad.left_brightness_switches"};
const std::string g_pressureKey {"settings.trackpad.press_level"};
const std::string g_vibrationKey {"settings.trackpad.shock_level"};
const std::string g_touchpadSwitchesKey {"settings.trackpad.touchpad_switches"};
const std::string g_touchpadMasterSwitchesKey {"settings.trackpad.touchpad_master_switches"};
const std::string g_keepTouchpadEnableSwitchesKey {"settings.trackpad.keep_touchpad_enable_switches"};
const std::string g_knuckleSwitchesKey {"settings.trackpad.touchpad_switches"};
const std::string g_datashareBaseUri =
    "datashare:///com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_";
const std::string g_libthpPath {"/system/lib64/libthp_extra_innerapi.z.so"};
const std::string g_switchStateOpen { "1" };
const std::string g_switchStateClose { "0" };
const std::map<std::string, int> g_keyToCmd = {
    {g_volumeSwitchesKey, 111}, // right volume gesture cmd 111
    {g_brightnessSwitchesKey, 110}, // left brightness gesture cmd 110
    {g_pressureKey, 103}, // pressure cmd 103
    {g_vibrationKey, 104}, // vibration cmd 104
    {g_touchpadSwitchesKey, 108}, // touchpad switches cmd 108
    {g_knuckleSwitchesKey, 109} // knuckle switches cmd 109
};
const std::map<std::string, std::string> g_defaultValue = {
    {g_volumeSwitchesKey, "1"}, // default gesture on
    {g_brightnessSwitchesKey, "1"}, // default gesture on
    {g_pressureKey, "2"}, // default pressure value 2
    {g_vibrationKey, "2"}, // default vibration value 2
    {g_touchpadSwitchesKey, "1"}, // tdefault touchpad on
    {g_knuckleSwitchesKey, "0"} // default knuckle off
};
} // namespace

std::mutex TouchpadSettingsObserver::mutex_;
std::shared_ptr<TouchpadSettingsObserver> TouchpadSettingsObserver::instance_ = nullptr;

TouchpadSettingsObserver::TouchpadSettingsObserver() {}

TouchpadSettingsObserver::~TouchpadSettingsObserver() {}

std::shared_ptr<TouchpadSettingsObserver> TouchpadSettingsObserver::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (instance_ == nullptr) {
            instance_ = std::make_shared<TouchpadSettingsObserver>();
        }
    }
    return instance_;
}

void TouchpadSettingsObserver::RegisterUpdateFunc()
{
    updateFunc_ = nullptr;
    const std::string datashareUri = datashareUri_;
    const std::string libthpPath = g_libthpPath;
    const std::map<std::string, int> keyToCmd = g_keyToCmd;
    const std::map<std::string, std::string> defaultValue = g_defaultValue;

    SettingObserver::UpdateFunc UpdateFunc =
        [datashareUri, libthpPath, keyToCmd, defaultValue](const std::string& key) {
        MMI_HILOGI("Touchpad settings change: %{public}s", key.c_str());
        typedef const char* (*ThpExtraRunCommandFunc)(const char* command, const char* parameters);
        const char* (*ThpExtraRunCommand)(const char* command, const char* parameters) {};
        std::string value;

        auto ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID).GetStringValue(key, value, datashareUri);
        if (ret != 0) {
            auto valueIter = defaultValue.find(key);
            if (valueIter == defaultValue.end()) {
                MMI_HILOGE("Invalid value key");
                return;
            }
            value = valueIter->second;
        }
        MMI_HILOGI("Get value: %{public}s", value.c_str());

        auto cmdIter = keyToCmd.find(key);
        if (cmdIter == keyToCmd.end()) {
            MMI_HILOGE("Invalid command key");
            return;
        }

        void *handle = nullptr;
        handle = dlopen(libthpPath.c_str(), RTLD_LAZY);
        if (handle == nullptr) {
            MMI_HILOGE("Handle is null");
            return;
        }

        ThpExtraRunCommand = reinterpret_cast<ThpExtraRunCommandFunc>(dlsym(handle, "ThpExtraRunCommand"));
        if (ThpExtraRunCommand == nullptr) {
            MMI_HILOGE("ThpExtraRunCommand is null");
            dlclose(handle);
            return;
        }
        const std::string param = std::string("#").append(std::to_string(cmdIter->second)).append("#").append(value);
        ThpExtraRunCommand("THP_TouchpadStatusChange", param.c_str());
        dlclose(handle);
    };
    MMI_HILOGI("Update function register end");
    updateFunc_ = UpdateFunc;
    return;
}

void TouchpadSettingsObserver::RegisterTouchpadSwitchUpdateFunc()
{
    updateTouchpadSwitchFunc_ = nullptr;
    const std::string datashareUri = datashareUri_;

    SettingObserver::UpdateFunc UpdateFunc = [datashareUri](const std::string& key) {
        MMI_HILOGI("Touchpad switch settings change: %{public}s", key.c_str());
        TOUCHPAD_MGR->OnUpdateTouchpadSwitch();
    };
    MMI_HILOGI("Update touchpad switch function register end");
    updateTouchpadSwitchFunc_  = UpdateFunc;
    return;
}

sptr<SettingObserver> TouchpadSettingsObserver::RegisterDatashareObserver(
    const std::string key, SettingObserver::UpdateFunc onUpdate)
{
    ErrCode ret = 0;
    if (key.empty() || datashareUri_.empty() || onUpdate == nullptr) {
        MMI_HILOGE("Invalid input parameter");
        return nullptr;
    }

    auto &settingHelper = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID);
    sptr<SettingObserver> settingObserver = settingHelper.CreateObserver(key, onUpdate);
    if (settingObserver == nullptr) {
        MMI_HILOGE("CreateObserver fail");
        return nullptr;
    }

    ret = settingHelper.RegisterObserver(settingObserver, datashareUri_);
    if (ret != ERR_OK) {
        MMI_HILOGE("RegisterObserver failed");
        return nullptr;
    }
    return settingObserver;
}

bool TouchpadSettingsObserver::RegisterTpObserver(const int32_t accountId)
{
    if (!isCommonEventReady_.load() || hasRegistered_) { return false; }
    std::lock_guard<std::mutex> lock(lock_);
    currentAccountId_ = accountId;
    TP_CHECK_FALSE_RETURN(currentAccountId_ >= 0, false, "Get account info fail");

    datashareUri_ = g_datashareBaseUri + std::to_string(currentAccountId_) + "?Proxy=true";
    RegisterUpdateFunc();
    TP_CHECK_FALSE_RETURN(updateFunc_ != nullptr, false, "Update function is null");
    RegisterTouchpadSwitchUpdateFunc();
    TP_CHECK_FALSE_RETURN(updateTouchpadSwitchFunc_ != nullptr, false, "Update switch function is null");

    if (volumeSwitchesObserver_ == nullptr) {
        volumeSwitchesObserver_ = RegisterDatashareObserver(g_volumeSwitchesKey, updateFunc_);
    }
    if (brightnessSwitchesObserver_ == nullptr) {
        brightnessSwitchesObserver_ = RegisterDatashareObserver(g_brightnessSwitchesKey, updateFunc_);
    }
    if (pressureObserver_ == nullptr) {
        pressureObserver_ = RegisterDatashareObserver(g_pressureKey, updateFunc_);
    }
    if (vibrationObserver_ == nullptr) {
        vibrationObserver_ = RegisterDatashareObserver(g_vibrationKey, updateFunc_);
    }
    if (touchpadSwitchesObserver_ == nullptr) {
        touchpadSwitchesObserver_ = RegisterDatashareObserver(g_touchpadSwitchesKey, updateFunc_);
    }
    if (touchpadMasterSwitchesObserver_ == nullptr) {
        touchpadMasterSwitchesObserver_ = RegisterDatashareObserver(g_touchpadMasterSwitchesKey,
            updateTouchpadSwitchFunc_);
    }
    if (keepTouchpadEnableSwitchesObserver_ == nullptr) {
        keepTouchpadEnableSwitchesObserver_ = RegisterDatashareObserver(g_keepTouchpadEnableSwitchesKey,
            updateTouchpadSwitchFunc_);
    }
    if (knuckleSwitchesObserver_ == nullptr) {
        knuckleSwitchesObserver_ = RegisterDatashareObserver(g_knuckleSwitchesKey, updateFunc_);
    }
    if (volumeSwitchesObserver_ == nullptr || brightnessSwitchesObserver_ == nullptr || pressureObserver_ == nullptr ||
        vibrationObserver_ == nullptr ||touchpadSwitchesObserver_ == nullptr || knuckleSwitchesObserver_ == nullptr ||
        touchpadMasterSwitchesObserver_ == nullptr || keepTouchpadEnableSwitchesObserver_ == nullptr) {
        MMI_HILOGE("Register setting observer fail");
        return false;
    }
    MMI_HILOGI("Register touchpad observer");
    hasRegistered_ = true;
    return true;
}

bool TouchpadSettingsObserver::UnregisterTpObserver(const int32_t accountId)
{
    if (!hasRegistered_ || accountId == currentAccountId_) { return false; }
    std::lock_guard<std::mutex> lock { lock_ };
    ErrCode ret = 0;

    auto &settingHelper = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID);
    if (volumeSwitchesObserver_ != nullptr) {
        ret = settingHelper.UnregisterObserver(volumeSwitchesObserver_, datashareUri_);
        TP_CHECK_FALSE_RETURN(ret == 0, false, "Unregister volumeSwitchesObserver fail");
        volumeSwitchesObserver_ = nullptr;
    }
    if (brightnessSwitchesObserver_ != nullptr) {
        ret = settingHelper.UnregisterObserver(brightnessSwitchesObserver_, datashareUri_);
        TP_CHECK_FALSE_RETURN(ret == 0, false, "Unregister brightnessSwitchesObserver fail");
        brightnessSwitchesObserver_ = nullptr;
    }
    if (pressureObserver_ != nullptr) {
        ret = settingHelper.UnregisterObserver(pressureObserver_, datashareUri_);
        TP_CHECK_FALSE_RETURN(ret == 0, false, "Unregister pressureObserver fail");
        pressureObserver_ = nullptr;
    }
    if (vibrationObserver_ != nullptr) {
        ret = settingHelper.UnregisterObserver(vibrationObserver_, datashareUri_);
        TP_CHECK_FALSE_RETURN(ret == 0, false, "Unregister vibrationObserver fail");
        vibrationObserver_ = nullptr;
    }
    if (touchpadSwitchesObserver_ != nullptr) {
        ret = settingHelper.UnregisterObserver(touchpadSwitchesObserver_, datashareUri_);
        TP_CHECK_FALSE_RETURN(ret == 0, false, "Unregister touchpadSwitchesObserver fail");
        touchpadSwitchesObserver_ = nullptr;
    }
    if (touchpadMasterSwitchesObserver_ != nullptr) {
        ret = settingHelper.UnregisterObserver(touchpadMasterSwitchesObserver_, datashareUri_);
        TP_CHECK_FALSE_RETURN(ret == 0, false, "Unregister touchpadMasterSwitchesObserver fail");
        touchpadMasterSwitchesObserver_ = nullptr;
    }
    if (keepTouchpadEnableSwitchesObserver_ != nullptr) {
        ret = settingHelper.UnregisterObserver(keepTouchpadEnableSwitchesObserver_, datashareUri_);
        TP_CHECK_FALSE_RETURN(ret == 0, false, "Unregister keepTouchpadEnableSwitchesObserver fail");
        keepTouchpadEnableSwitchesObserver_ = nullptr;
    }
    if (knuckleSwitchesObserver_ != nullptr) {
        ret = settingHelper.UnregisterObserver(knuckleSwitchesObserver_, datashareUri_);
        TP_CHECK_FALSE_RETURN(ret == 0, false, "Unregister knuckleSwitchesObserver fail");
        knuckleSwitchesObserver_ = nullptr;
    }

    hasRegistered_ = false;
    MMI_HILOGI("Unregister touchpad observer");
    return true;
}

void TouchpadSettingsObserver::SyncTouchpadSettingsData()
{
    if (!isCommonEventReady_.load()) {
        return;
    }
    if (!hasRegistered_) {
        RegisterTpObserver(ACCOUNT_MGR->GetCurrentAccountSetting().GetAccountId());
        return;
    }
    std::lock_guard<std::mutex> lock { lock_ };
    if (updateFunc_ == nullptr || updateTouchpadSwitchFunc_ == nullptr) {
        return;
    }
    updateFunc_(g_volumeSwitchesKey);
    updateFunc_(g_brightnessSwitchesKey);
    updateFunc_(g_pressureKey);
    updateFunc_(g_vibrationKey);
    updateFunc_(g_touchpadSwitchesKey);
    updateFunc_(g_knuckleSwitchesKey);
    LoadSwitchState();
    SetTouchpadState();
    MMI_HILOGI("Sync touchpad settings end");
}

void TouchpadSettingsObserver::SetCommonEventReady()
{
    isCommonEventReady_.store(true);
}

bool TouchpadSettingsObserver::GetCommonEventStatus()
{
    return isCommonEventReady_.load();
}

void TouchpadSettingsObserver::SetDefaultState(const std::string &key, std::string &value)
{
    if (key == g_keepTouchpadEnableSwitchesKey) {
        value = g_switchStateOpen;
    } else if (key == g_touchpadMasterSwitchesKey) {
        auto &settingHelper = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID);
        auto ret = settingHelper.GetStringValue(g_touchpadSwitchesKey, value, datashareUri_);
        MMI_HILOGI("current switch key:%{public}s, value:%{public}s", g_touchpadSwitchesKey.c_str(), value.c_str());
        if (ret != ERR_OK) {
            value = g_switchStateOpen;
        }
    } else {
        MMI_HILOGE("invalid key");
    }
    MMI_HILOGI("set default key:%{public}s, value:%{public}s", key.c_str(), value.c_str());
}

void TouchpadSettingsObserver::LoadSwitchState()
{
    std::string key = g_touchpadMasterSwitchesKey;
    std::string value;
    auto &settingHelper = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID);
    auto ret = settingHelper.GetStringValue(key, value, datashareUri_);
    MMI_HILOGI("get key:%{public}s, value:%{public}s", key.c_str(), value.c_str());
    if (ret != ERR_OK) {
        SetDefaultState(key, value);
    }
    touchpadMasterSwitches_ = (value == g_switchStateOpen);
    key = g_keepTouchpadEnableSwitchesKey;
    ret = settingHelper.GetStringValue(key, value, datashareUri_);
    MMI_HILOGI("get key:%{public}s, value:%{public}s", key.c_str(), value.c_str());
    if (ret != ERR_OK) {
        SetDefaultState(key, value);
    }
    keepTouchpadEnableSwitches_ = (value == g_switchStateOpen);
}

int32_t TouchpadSettingsObserver::SetTouchpadState()
{
    bool status = true;
    if (!touchpadMasterSwitches_) {                         // 总开关关闭，实际开关关闭
        status = false;
    } else if (keepTouchpadEnableSwitchesObserver_) {       // 总开关开启，子开关开启，实际开关开启
        status = true;
    } else {
        status = !INPUT_DEV_MGR->HasLocalMouseDevice();     // 总开关开启，子开关关闭，根据是否有鼠标决定
    }
    std::string value = (status ? g_switchStateOpen : g_switchStateClose);
    auto &settingHelper = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID);
    auto ret = settingHelper.PutStringValue(g_touchpadSwitchesKey, value, true, datashareUri_);
    MMI_HILOGI("put key:%{public}s, value:%{public}s", g_touchpadSwitchesKey.c_str(), value.c_str());
    if (ret != ERR_OK) {
        MMI_HILOGE("put switch value failed, ret:%{public}d", ret);
        return RET_ERR;
    }
    return RET_OK;
}

void TouchpadSettingsObserver::OnUpdateTouchpadSwitch()
{
    ffrt::submit([this] {
        std::lock_guard<ffrt::mutex> lock(ffrtMtx_);
        LoadSwitchState();
        SetTouchpadState();
    });
}
} // namespace MMI
} // namespace OHOS
