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

#include "processing_game_pad_device.h"

using namespace OHOS::MMI;

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "ProcessingGamePadDevice" };
} // namespace

int32_t ProcessingGamePadDevice::TransformJsonDataToInputData(const Json& originalEvent,
    InputEventArray& inputEventArray)
{
    CALL_LOG_ENTER;
    if (originalEvent.empty()) {
        return RET_ERR;
    }
    if (originalEvent.find("events") == originalEvent.end()) {
        MMI_LOGE("manage game pad array faild, inputData is empty");
        return RET_ERR;
    }
    Json inputData = originalEvent.at("events");
    if (inputData.empty()) {
        MMI_LOGE("manage finger array faild, inputData is empty");
        return RET_ERR;
    }
    std::vector<GamePadEvent> padEventArray;
    if (AnalysisGamePadEvent(inputData, padEventArray) == RET_ERR) {
        return RET_ERR;
    }
    TransformPadEventToInputEvent(padEventArray, inputEventArray);
    return RET_OK;
}

int32_t ProcessingGamePadDevice::AnalysisGamePadEvent(const Json& inputData, std::vector<GamePadEvent>& padEventArray)
{
    for (const auto &item : inputData) {
        GamePadEvent padEvent = {};
        std::string eventType = item.at("eventType").get<std::string>();
        padEvent.eventType = eventType;
        if ((item.find("blockTime")) != item.end()) {
            padEvent.blockTime = item.at("blockTime").get<int64_t>();
        }
        if ((eventType == "KEY_EVENT_CLICK") || (eventType == "KEY_EVENT_PRESS") ||
            (eventType == "KEY_EVENT_RELEASE")) {
            if ((item.find("keyValue")) == item.end()) {
                MMI_LOGE("not find keyValue On Event:%{public}s", eventType.c_str());
                return RET_ERR;
            }
            padEvent.keyValue = item.at("keyValue").get<int32_t>();
        } else if ((eventType == "ROCKER_1") || (eventType == "ROCKER_2")) {
            if ((item.find("event")) == item.end()) {
                MMI_LOGE("not find event On Event:%{public}s", eventType.c_str());
                return RET_ERR;
            }
            if ((item.find("direction")) == item.end()) {
                MMI_LOGE("not find direction On Event:%{public}s", eventType.c_str());
                return RET_ERR;
            }
            padEvent.gameEvents = item.at("event").get<std::vector<uint32_t>>();
            padEvent.direction = item.at("direction").get<std::string>();
        } else if (eventType == "DERECTION_KEY") {
            if ((item.find("direction")) == item.end()) {
                MMI_LOGE("not find direction On Event:%{public}s", eventType.c_str());
                return RET_ERR;
            }
            padEvent.direction = item.at("direction").get<std::string>();
        } else {
            continue;
        }
        padEventArray.push_back(padEvent);
    }

    return RET_OK;
}

void ProcessingGamePadDevice::TransformPadEventToInputEvent(const std::vector<GamePadEvent>& padEventArray,
                                                            InputEventArray& inputEventArray)
{
    for (const auto &item : padEventArray) {
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
        } else if (item.eventType == "ROCKER_2") {
            TransformRocker2Event(item, inputEventArray);
        } else {
            MMI_LOGW("json file format error");
        }
    }
}

void ProcessingGamePadDevice::TransformKeyPressEvent(const GamePadEvent& padEvent, InputEventArray& inputEventArray)
{
    uint16_t keyValue = static_cast<uint16_t>(padEvent.keyValue);
    SetKeyPressEvent(inputEventArray, padEvent.blockTime, keyValue);
    SetSynReport(inputEventArray);
}

void ProcessingGamePadDevice::TransformKeyReleaseEvent(const GamePadEvent& padEvent, InputEventArray& inputEventArray)
{
    uint16_t keyValue = static_cast<uint16_t>(padEvent.keyValue);
    SetKeyReleaseEvent(inputEventArray, padEvent.blockTime, keyValue);
    SetSynReport(inputEventArray);
}

void ProcessingGamePadDevice::TransformKeyClickEvent(const GamePadEvent& padEvent, InputEventArray& inputEventArray)
{
    uint16_t keyValue = static_cast<uint16_t>(padEvent.keyValue);
    SetKeyPressEvent(inputEventArray, padEvent.blockTime, keyValue);
    SetSynReport(inputEventArray);
    SetKeyReleaseEvent(inputEventArray, padEvent.blockTime, keyValue);
    SetSynReport(inputEventArray);
}

void ProcessingGamePadDevice::TransformRocker1Event(const GamePadEvent& padEvent, InputEventArray& inputEventArray)
{
    std::string direction = padEvent.direction;
    for (const auto &item : padEvent.gameEvents) {
        uint32_t value;
        if (direction == "left") {
            value = ~item + 1;
            SetEvAbsX(inputEventArray, 0, value);
        } else if (direction == "right") {
            value = item;
            SetEvAbsX(inputEventArray, 0, value);
        } else if (direction == "up") {
            value = ~item + 1;
            SetEvAbsY(inputEventArray, 0, value);
        } else if (direction == "down") {
            value = item;
            SetEvAbsY(inputEventArray, 0, value);
        } else if (direction == "lt") {
            value = item;
            SetEvAbsZ(inputEventArray, 0, value);
        }
        SetSynReport(inputEventArray);
    }

    if (direction == "left") {
        SetEvAbsX(inputEventArray, 0, 0);
    } else if (direction == "right") {
        SetEvAbsX(inputEventArray, 0, 0);
    } else if (direction == "up") {
        SetEvAbsY(inputEventArray, 0, -1);
    } else if (direction == "down") {
        SetEvAbsY(inputEventArray, 0, -1);
    } else if (direction == "lt") {
        SetEvAbsZ(inputEventArray, 0, 0);
    } else {
        // nothint to do.
    }
    SetSynReport(inputEventArray);
}

void ProcessingGamePadDevice::TransformRocker2Event(const GamePadEvent& padEvent, InputEventArray& inputEventArray)
{
    std::string direction = padEvent.direction;
    for (uint32_t item : padEvent.gameEvents) {
        uint32_t value;
        if (direction == "left") {
            value = ~item + 1;
            SetEvAbsRx(inputEventArray, 0, value);
        } else if (direction == "right") {
            value = item;
            SetEvAbsRx(inputEventArray, 0, value);
        } else if (direction == "up") {
            value = ~item + 1;
            SetEvAbsRy(inputEventArray, 0, value);
        } else if (direction == "down") {
            value = item;
            SetEvAbsRy(inputEventArray, 0, value);
        } else if (direction == "rt") {
            value = item;
            SetEvAbsRz(inputEventArray, 0, value);
        }
        SetSynReport(inputEventArray);
    }

    if (direction == "left") {
        SetEvAbsRx(inputEventArray, 0, 0);
    } else if (direction == "right") {
        SetEvAbsRx(inputEventArray, 0, 0);
    } else if (direction == "up") {
        SetEvAbsRy(inputEventArray, 0, -1);
    } else if (direction == "down") {
        SetEvAbsRy(inputEventArray, 0, -1);
    } else if (direction == "rt") {
        SetEvAbsRz(inputEventArray, 0, 0);
    } else {
        // nothint to do.
    }
    SetSynReport(inputEventArray);
}

void ProcessingGamePadDevice::TransformDerectionKeyEvent(const GamePadEvent& padEvent, InputEventArray& inputEventArray)
{
    std::string direction = padEvent.direction;
    if (direction == "left") {
        SetEvAbsHat0X(inputEventArray, padEvent.blockTime, -1);
        SetSynReport(inputEventArray);
        SetEvAbsHat0X(inputEventArray, padEvent.blockTime, 0);
        SetSynReport(inputEventArray);
    } else if (direction == "right") {
        SetEvAbsHat0X(inputEventArray, padEvent.blockTime, 1);
        SetSynReport(inputEventArray);
        SetEvAbsHat0X(inputEventArray, padEvent.blockTime, 0);
        SetSynReport(inputEventArray);
    } else if (direction == "up") {
        SetEvAbsHat0Y(inputEventArray, padEvent.blockTime, -1);
        SetSynReport(inputEventArray);
        SetEvAbsHat0Y(inputEventArray, padEvent.blockTime, 0);
        SetSynReport(inputEventArray);
    } else if (direction == "down") {
        SetEvAbsHat0Y(inputEventArray, padEvent.blockTime, 1);
        SetSynReport(inputEventArray);
        SetEvAbsHat0Y(inputEventArray, padEvent.blockTime, 0);
        SetSynReport(inputEventArray);
    }  else {
        // nothint to do.
    }
}
