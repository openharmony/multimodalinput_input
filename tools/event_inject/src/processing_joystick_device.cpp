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

#include "processing_joystick_device.h"

using namespace OHOS::MMI;

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "ProcessingJoystickDevice" };
constexpr int32_t DEFAULT_ABSX_VALUE = 8188;
constexpr int32_t DEFAULT_ABSY_VALUE = 8192;
constexpr int32_t DEFAULT_ABSZ_VALUE = 125;
} // namespace

int32_t ProcessingJoystickDevice::TransformJsonDataToInputData(const DeviceItem& originalEvent,
    InputEventArray& inputEventArray)
{
    CALL_DEBUG_ENTER;
    if (originalEvent.events.empty()) {
        MMI_HILOGE("Manage joystick array failed, inputData is empty");
        return RET_ERR;
    }
    std::vector<DeviceEvent> inputData = originalEvent.events;
    if (inputData.empty()) {
        MMI_HILOGE("Manage finger array failed, inputData is empty");
        return RET_ERR;
    }
    TransformPadEventToInputEvent(inputData, inputEventArray);
    return RET_OK;
}

void ProcessingJoystickDevice::TransformPadEventToInputEvent(const std::vector<DeviceEvent>& inputData,
                                                             InputEventArray& inputEventArray)
{
    for (const auto &item : inputData) {
        if (item.eventType.empty()) {
            MMI_HILOGW("Not find eventType");
            return;
        }
        if (item.eventType == "KEY_EVENT_PRESS") {
            TransformKeyPressEvent(item, inputEventArray);
        } else if (item.eventType == "KEY_EVENT_RELEASE") {
            TransformKeyReleaseEvent(item, inputEventArray);
        } else if (item.eventType == "KEY_EVENT_CLICK") {
            TransformKeyClickEvent(item, inputEventArray);
        } else if (item.eventType == "DIRECTION_KEY") {
            TransformDirectionKeyEvent(item, inputEventArray);
        } else if (item.eventType == "ROCKER_1") {
            TransformRocker1Event(item, inputEventArray);
        } else if (item.eventType == "THROTTLE") {
            TransformThrottle1Event(item, inputEventArray);
        } else {
            MMI_HILOGW("Unknown eventType type");
        }
    }
}

void ProcessingJoystickDevice::TransformKeyPressEvent(const DeviceEvent& joystickEvent,
                                                      InputEventArray& inputEventArray)
{
    uint16_t keyValue = static_cast<uint16_t>(joystickEvent.keyValue);
    SetKeyPressEvent(inputEventArray, joystickEvent.blockTime, keyValue);
    SetSynReport(inputEventArray);
}

void ProcessingJoystickDevice::TransformKeyReleaseEvent(const DeviceEvent& joystickEvent,
                                                        InputEventArray& inputEventArray)
{
    uint16_t keyValue = static_cast<uint16_t>(joystickEvent.keyValue);
    SetKeyReleaseEvent(inputEventArray, joystickEvent.blockTime, keyValue);
    SetSynReport(inputEventArray);
}

void ProcessingJoystickDevice::TransformKeyClickEvent(const DeviceEvent& joystickEvent,
                                                      InputEventArray& inputEventArray)
{
    uint16_t keyValue = static_cast<uint16_t>(joystickEvent.keyValue);
    SetKeyPressEvent(inputEventArray, joystickEvent.blockTime, keyValue);
    SetSynReport(inputEventArray);
    SetKeyReleaseEvent(inputEventArray, joystickEvent.blockTime, keyValue);
    SetSynReport(inputEventArray);
}

void ProcessingJoystickDevice::TransformRocker1Event(const DeviceEvent& joystickEvent,
                                                     InputEventArray& inputEventArray)
{
    if (joystickEvent.direction.empty()) {
        MMI_HILOGW("Not find direction");
        return;
    }
    if (joystickEvent.event.empty()) {
        MMI_HILOGW("Not find event");
        return;
    }
    std::string direction = joystickEvent.direction;
    for (const auto &item : joystickEvent.event) {
        if ((direction == "left")||(direction == "right")) {
            SetEvAbsX(inputEventArray, 0, item);
        } else if ((direction == "up") || (direction == "down")) {
            SetEvAbsY(inputEventArray, 0, item);
        } else if (direction == "lt") {
            SetEvAbsRz(inputEventArray, 0, item);
        } else {
            MMI_HILOGW("Unknown direction move type");
        }
        SetSynReport(inputEventArray);
    }

    if ((direction == "left") || (direction == "right")) {
        SetEvAbsX(inputEventArray, 0, DEFAULT_ABSX_VALUE);
    } else if ((direction == "up") || (direction == "down")) {
        SetEvAbsY(inputEventArray, 0, DEFAULT_ABSY_VALUE);
    } else if (direction == "lt") {
        SetEvAbsRz(inputEventArray, 0, DEFAULT_ABSZ_VALUE);
    } else {
        MMI_HILOGW("Unknown direction type");
    }
    SetSynReport(inputEventArray);
}


void ProcessingJoystickDevice::TransformDirectionKeyEvent(const DeviceEvent& joystickEvent,
                                                          InputEventArray& inputEventArray)
{
    if (joystickEvent.direction.empty()) {
        MMI_HILOGW("Not find direction");
        return;
    }
    std::string direction = joystickEvent.direction;
    if (direction == "left") {
        SetEvAbsHat0X(inputEventArray, 0, -1);
        SetSynReport(inputEventArray);
        SetEvAbsHat0X(inputEventArray, 0, 0);
        SetSynReport(inputEventArray);
    } else if (direction == "right") {
        SetEvAbsHat0X(inputEventArray, 0, 1);
        SetSynReport(inputEventArray);
        SetEvAbsHat0X(inputEventArray, 0, 0);
        SetSynReport(inputEventArray);
    } else if (direction == "up") {
        SetEvAbsHat0Y(inputEventArray, 0, -1);
        SetSynReport(inputEventArray);
        SetEvAbsHat0Y(inputEventArray, 0, 0);
        SetSynReport(inputEventArray);
    } else if (direction == "down") {
        SetEvAbsHat0Y(inputEventArray, 0, 1);
        SetSynReport(inputEventArray);
        SetEvAbsHat0Y(inputEventArray, 0, 0);
        SetSynReport(inputEventArray);
    }  else {
        MMI_HILOGW("Unknown direction type");
    }
}

void ProcessingJoystickDevice::TransformThrottle1Event(const DeviceEvent& joystickEvent,
                                                       InputEventArray& inputEventArray)
{
    SetThrottle(inputEventArray, joystickEvent.blockTime, joystickEvent.keyValue);
    SetSynReport(inputEventArray);
}
