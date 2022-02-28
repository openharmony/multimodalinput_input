/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "get_device_object.h"
#include <chrono>
#include <thread>

using namespace OHOS::MMI;

namespace {
    static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "GetDeviceObject" };
}

DeviceBase* GetDeviceObject::CreateDeviceObject(const std::string deviceName)
{
    DeviceBase* deviceBasePtr = nullptr;
    if (deviceName == "finger") {
        deviceBasePtr = new ProcessingFingerDevice();
    } else if (deviceName == "pen") {
        deviceBasePtr = new ProcessingPenDevice();
    } else if (deviceName == "pad") {
        deviceBasePtr = new ProcessingPadDevice();
    } else if (deviceName == "touch") {
        deviceBasePtr = new ProcessingTouchScreenDevice();
    } else if (deviceName == "gamePad") {
        deviceBasePtr = new ProcessingGamePadDevice();
    } else if (deviceName == "joystick") {
        deviceBasePtr = new ProcessingJoystickDevice();
    } else if ((deviceName == "keyboard model1") || (deviceName == "keyboard model2")
               || (deviceName == "keyboard model3")) {
        deviceBasePtr = new ProcessingKeyboardDevice();
    } else if ((deviceName == "mouse") || (deviceName == "trackball")) {
        deviceBasePtr = new ProcessingMouseDevice();
    } else if (deviceName == "remoteControl") {
        deviceBasePtr = new ProcessingKeyboardDevice();
    } else if ((deviceName == "knob model1") || (deviceName == "knob model2") || (deviceName == "knob model3")
               || (deviceName == "trackpad model1") || (deviceName == "trackpad model2")) {
        deviceBasePtr = new ProcessingMouseDevice();
    } else {
        MMI_LOGI("Not create device object from deviceName:%s", deviceName.c_str());
    }

    return deviceBasePtr;
}
