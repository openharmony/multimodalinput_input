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

#include "setting_datashare.h"
#include <dlfcn.h>

namespace OHOS {
namespace MMI {
class TouchpadSettingsObserver {
public:
    TouchpadSettingsObserver();
    ~TouchpadSettingsObserver();
    void RegisterTpObserver();
    void RegisterUpdateFunc();
private:
    const std::string pressureKey_ {"settings.trackpad.press_level"};
    const std::string vibrationKey_ {"settings.trackpad.shock_level"};
    const std::string touchpadSwitchesKey_ {"settings.trackpad.touchpad_switches"};
    const std::string knuckleSwitchesKey_ {"settings.trackpad.touchpad_switches"};
    const std::string datashareUri_ =
        "datashare:///com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_100?Proxy=true";
    const std::string libthpPath_ {"/system/lib64/libthp_extra_innerapi.z.so"};
    const std::map<std::string, int> keyToCmd_ = {
        {pressureKey_, 103}, //pressure cmd 103
        {vibrationKey_, 104}, // vibration cmd 104
        {touchpadSwitchesKey_, 108}, // touchpad switches cmd 108
        {knuckleSwitchesKey_, 109} // knuckle switches cmd 109
    };
    SettingObserver::UpdateFunc updateFunc_ = nullptr;
    std::mutex mutex_;
};
} // namespace MMI
} // namespace OHOS
#endif