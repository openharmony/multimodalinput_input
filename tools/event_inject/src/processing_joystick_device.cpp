/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

using namespace std;
using namespace OHOS::MMI;

namespace {
    static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "ProcessingJoystickDevice" };
}

int32_t ProcessingJoystickDevice::TransformJsonDataToInputData(const Json& originalEvent,
                                                               InputEventArray& inputEventArray)
{
    MMI_LOGI("Enter TransformJsonDataForJoystick function.");
    if (originalEvent.empty()) {
        return RET_ERR;
    }
    if (originalEvent.find("events") == originalEvent.end()) {
        MMI_LOGE("manage joystick array faild, inputData is empty.");
        return RET_ERR;
    }
    Json inputData = originalEvent.at("events");
    if (inputData.empty()) {
        MMI_LOGE("manage finger array faild, inputData is empty.");
        return RET_ERR;
    }
    vector<JoystickEvent> JoystickEventArray;
    if (AnalysisJoystickEvent(inputData, JoystickEventArray) == RET_ERR) {
        return RET_ERR;
    }
    TransformPadEventToInputEvent(JoystickEventArray, inputEventArray);
    MMI_LOGI("Leave TransformJsonDataForJoystick function.");

    return RET_OK;
}

int32_t ProcessingJoystickDevice::AnalysisJoystickEvent(const Json& inputData,
                                                        std::vector<JoystickEvent>& JoystickEventArray)
{
    JoystickEvent joystickEvent = {};
    string eventType;
    for (auto item : inputData) {
        joystickEvent = {};
        eventType = item.at("eventType").get<std::string>();
        if ((item.find("blockTime")) != item.end()) {
            joystickEvent.blockTime = item.at("blockTime").get<int32_t>();
        }
        joystickEvent.eventType = eventType;
        if ((eventType == "KEY_EVENT_CLICK") || (eventType == "KEY_EVENT_PRESS") ||
            (eventType == "KEY_EVENT_RELEASE")) {
            if ((item.find("keyValue")) == item.end()) {
                MMI_LOGE("function AnalysisJoystickEvent not find keyValue On Event: %{public}s.", eventType.c_str());
                return RET_ERR;
            }
            joystickEvent.keyValue = item.at("keyValue").get<int32_t>();
        } else if (eventType == "THROTTLE") {
            if ((item.find("keyValue")) == item.end()) {
                MMI_LOGE("function AnalysisJoystickEvent not find keyValue On Event: %{public}s.", eventType.c_str());
                return RET_ERR;
            }
            joystickEvent.keyValue = item.at("keyValue").get<int32_t>();
        } else if ((eventType == "ROCKER_1")) {
            if ((item.find("event")) == item.end()) {
                MMI_LOGE("function AnalysisJoystickEvent not find event On Event: %{public}s.", eventType.c_str());
                return RET_ERR;
            }
            if ((item.find("direction")) == item.end()) {
                MMI_LOGE("function AnalysisJoystickEvent not find direction On Event: %{public}s.", eventType.c_str());
                return RET_ERR;
            }
            joystickEvent.gameEvents = item.at("event").get<std::vector<int32_t>>();
            joystickEvent.direction = item.at("direction").get<std::string>();
        } else if (eventType == "DERECTION_KEY") {
            if ((item.find("direction")) == item.end()) {
                MMI_LOGE("function AnalysisJoystickEvent not find direction On Event: %{public}s.", eventType.c_str());
                return RET_ERR;
            }
            joystickEvent.direction = item.at("direction").get<std::string>();
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
    for (JoystickEvent joystickEvent : JoystickEventArray) {
        if (joystickEvent.eventType == "KEY_EVENT_PRESS") {
            TransformKeyPressEvent(joystickEvent, inputEventArray);
        } else if (joystickEvent.eventType == "KEY_EVENT_RELEASE") {
            TransformKeyReleaseEvent(joystickEvent, inputEventArray);
        } else if (joystickEvent.eventType == "KEY_EVENT_CLICK") {
            TransformKeyClickEvent(joystickEvent, inputEventArray);
        } else if (joystickEvent.eventType == "DERECTION_KEY") {
            TransformDerectionKeyEvent(joystickEvent, inputEventArray);
        } else if (joystickEvent.eventType == "ROCKER_1") {
            TransformRocker1Event(joystickEvent, inputEventArray);
        } else if (joystickEvent.eventType == "THROTTLE") {
            TransformThrottle1Event(joystickEvent, inputEventArray);
        } else {
            // nothing to do.
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
    string direction = joystickEvent.direction;
    for (int32_t item : joystickEvent.gameEvents) {
        if ((direction == "left")||(direction == "right")) {
            SetEvAbsX(inputEventArray, 0, item);
        } else if ((direction == "up") || (direction == "down")) {
            SetEvAbsY(inputEventArray, 0, item);
        } else if (direction == "lt") {
            SetEvAbsRz(inputEventArray, 0, item);
        } else {
            // nothint to do.
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
    string direction = joystickEvent.direction;
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
