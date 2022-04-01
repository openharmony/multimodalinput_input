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
} // namespace

int32_t ProcessingJoystickDevice::TransformJsonDataToInputData(const DeviceItem& originalEvent,
                                                               InputEventArray& inputEventArray)
{
    CALL_LOG_ENTER;
    if (originalEvent.events.empty()) {
        MMI_HILOGE("manage joystick array faild, inputData is empty");
        return RET_ERR;
    }
    std::vector<DeviceEvent> inputData = originalEvent.events;
    if (inputData.empty()) {
        MMI_HILOGE("manage finger array faild, inputData is empty");
        return RET_ERR;
    }
    std::vector<JoystickEvent> JoystickEventArray;
    if (AnalysisJoystickEvent(inputData, JoystickEventArray) == RET_ERR) {
        return RET_ERR;
    }
    TransformPadEventToInputEvent(JoystickEventArray, inputEventArray);
    return RET_OK;
}

int32_t ProcessingJoystickDevice::AnalysisJoystickEvent(const std::vector<DeviceEvent>& inputData,
                                                        std::vector<JoystickEvent>& JoystickEventArray)
{
    JoystickEvent joystickEvent = {};
    for (const auto &item : inputData) {
        joystickEvent = {};
        joystickEvent.blockTime = item.blockTime;
        joystickEvent.eventType = item.eventType;
        if ((joystickEvent.eventType == "KEY_EVENT_CLICK") || (joystickEvent.eventType == "KEY_EVENT_PRESS") ||
            (joystickEvent.eventType == "KEY_EVENT_RELEASE")) {
            if (item.keyValue > 0) {
                MMI_HILOGE("not find keyValue On Event:%{public}s", joystickEvent.eventType.c_str());
                return RET_ERR;
            }
            joystickEvent.keyValue = item.keyValue;
        } else if (joystickEvent.eventType == "THROTTLE") {
            if (item.keyValue > 0) {
                MMI_HILOGE("not find keyValue On Event:%{public}s", joystickEvent.eventType.c_str());
                return RET_ERR;
            }
            joystickEvent.keyValue = item.keyValue;
        } else if ((joystickEvent.eventType == "ROCKER_1")) {
            if (item.event.empty()) {
                MMI_HILOGE("not find event On Event:%{public}s", joystickEvent.eventType.c_str());
                return RET_ERR;
            }
            if (item.direction.empty()) {
                MMI_HILOGE("not find direction On Event:%{public}s", joystickEvent.eventType.c_str());
                return RET_ERR;
            }
            joystickEvent.gameEvents = item.event;
            joystickEvent.direction = item.direction;
        } else if (joystickEvent.eventType == "DERECTION_KEY") {
            if (item.direction.empty()) {
                MMI_HILOGE("not find direction On Event:%{public}s", joystickEvent.eventType.c_str());
                return RET_ERR;
            }
            joystickEvent.direction = item.direction;
        } else {
            continue;
        }
        JoystickEventArray.push_back(joystickEvent);
    }

    return RET_OK;
}

void ProcessingJoystickDevice::TransformPadEventToInputEvent(const std::vector<JoystickEvent>& JoystickEventArray,
                                                             InputEventArray& inputEventArray)
{
    for (const auto &item : JoystickEventArray) {
        if (item.eventType == "KEY_EVENT_PRESS") {
            TransformKeyPressEvent(item, inputEventArray);
        } else if (item.eventType == "KEY_EVENT_RELEASE") {
            TransformKeyReleaseEvent(item, inputEventArray);
        } else if (item.eventType == "KEY_EVENT_CLICK") {
            TransformKeyClickEvent(item, inputEventArray);
        } else if (item.eventType == "DERECTION_KEY") {
            TransformDerectionKeyEvent(item, inputEventArray);
        } else if (item.eventType == "ROCKER_1") {
            TransformRocker1Event(item, inputEventArray);
        } else if (item.eventType == "THROTTLE") {
            TransformThrottle1Event(item, inputEventArray);
        }
    }
}

void ProcessingJoystickDevice::TransformKeyPressEvent(const JoystickEvent& joystickEvent,
                                                      InputEventArray& inputEventArray)
{
    uint16_t keyValue = static_cast<uint16_t>(joystickEvent.keyValue);
    SetKeyPressEvent(inputEventArray, joystickEvent.blockTime, keyValue);
    SetSynReport(inputEventArray);
}

void ProcessingJoystickDevice::TransformKeyReleaseEvent(const JoystickEvent& joystickEvent,
                                                        InputEventArray& inputEventArray)
{
    uint16_t keyValue = static_cast<uint16_t>(joystickEvent.keyValue);
    SetKeyReleaseEvent(inputEventArray, joystickEvent.blockTime, keyValue);
    SetSynReport(inputEventArray);
}

void ProcessingJoystickDevice::TransformKeyClickEvent(const JoystickEvent& joystickEvent,
                                                      InputEventArray& inputEventArray)
{
    uint16_t keyValue = static_cast<uint16_t>(joystickEvent.keyValue);
    SetKeyPressEvent(inputEventArray, joystickEvent.blockTime, keyValue);
    SetSynReport(inputEventArray);
    SetKeyReleaseEvent(inputEventArray, joystickEvent.blockTime, keyValue);
    SetSynReport(inputEventArray);
}

void ProcessingJoystickDevice::TransformRocker1Event(const JoystickEvent& joystickEvent,
                                                     InputEventArray& inputEventArray)
{
    std::string direction = joystickEvent.direction;
    for (const auto &item : joystickEvent.gameEvents) {
        if ((direction == "left")||(direction == "right")) {
            SetEvAbsX(inputEventArray, 0, item);
        } else if ((direction == "up") || (direction == "down")) {
            SetEvAbsY(inputEventArray, 0, item);
        } else if (direction == "lt") {
            SetEvAbsRz(inputEventArray, 0, item);
        }
        SetSynReport(inputEventArray);
    }

    if ((direction == "left") || (direction == "right")) {
        SetEvAbsX(inputEventArray, 0, default_absx_value);
    } else if ((direction == "up") || (direction == "down")) {
        SetEvAbsY(inputEventArray, 0, default_absy_value);
    } else if (direction == "lt") {
        SetEvAbsRz(inputEventArray, 0, default_absz_value);
    } else {
        // nothint to do.
    }
    SetSynReport(inputEventArray);
}


void ProcessingJoystickDevice::TransformDerectionKeyEvent(const JoystickEvent& joystickEvent,
                                                          InputEventArray& inputEventArray)
{
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
        // nothint to do.
    }
}

void ProcessingJoystickDevice::TransformThrottle1Event(const JoystickEvent& joystickEvent,
                                                       InputEventArray& inputEventArray)
{
    SetThrottle(inputEventArray, joystickEvent.blockTime, joystickEvent.keyValue);
    SetSynReport(inputEventArray);
}
