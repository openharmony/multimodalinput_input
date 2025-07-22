/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "get_device_object.h"

#include <chrono>
#include <regex>
#include <thread>

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "GetDeviceObject"

namespace OHOS {
namespace MMI {
namespace {
bool IsKeyboardDevice(const std::string &deviceName)
{
    std::regex regExp("keyboard model[1-3]");
    return std::regex_match(deviceName, regExp);
}

bool IsMouseDevice(const std::string &deviceName)
{
    std::regex regExp("(knob model[1-3])|(trackpad model[1-2])");
    return std::regex_match(deviceName, regExp);
}
} // namespace

DeviceBase* GetDeviceObject::CreateDeviceObject(const std::string &deviceName)
{
    DeviceBase* deviceBasePtr = nullptr;
    if (deviceName == "finger") {
        deviceBasePtr = new (std::nothrow) ProcessingFingerDevice();
    } else if (deviceName == "pen") {
        deviceBasePtr = new (std::nothrow) ProcessingPenDevice();
    } else if (deviceName == "pad") {
        deviceBasePtr = new (std::nothrow) ProcessingPadDevice();
    } else if (deviceName == "touch") {
        deviceBasePtr = new (std::nothrow) ProcessingTouchScreenDevice();
    } else if (deviceName == "gamePad") {
        deviceBasePtr = new (std::nothrow) ProcessingGamePadDevice();
    } else if (deviceName == "joystick") {
        deviceBasePtr = new (std::nothrow) ProcessingJoystickDevice();
    } else if (IsKeyboardDevice(deviceName)) {
        deviceBasePtr = new (std::nothrow) ProcessingKeyboardDevice();
    } else if ((deviceName == "mouse") || (deviceName == "trackball")) {
        deviceBasePtr = new (std::nothrow) ProcessingMouseDevice();
    } else if (deviceName == "remoteControl") {
        deviceBasePtr = new (std::nothrow) ProcessingKeyboardDevice();
    } else if (IsMouseDevice(deviceName)) {
        deviceBasePtr = new (std::nothrow) ProcessingMouseDevice();
    } else {
        MMI_HILOGI("Not supported device :%s", deviceName.c_str());
    }
    CHKPP(deviceBasePtr);
    return deviceBasePtr;
}
} // namespace MMI
} // namespace OHOS
