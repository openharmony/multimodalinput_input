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

#include "processing_game_pad_device.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "ProcessingGamePadDevice"

namespace OHOS {
namespace MMI {
int32_t ProcessingGamePadDevice::TransformJsonDataToInputData(const DeviceItem &originalEvent,
    InputEventArray &inputEventArray)
{
    CALL_DEBUG_ENTER;
    if (originalEvent.events.empty()) {
        MMI_HILOGE("Manage game pad array failed, inputData is empty");
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

void ProcessingGamePadDevice::TransformPadEventToInputEvent(const std::vector<DeviceEvent>& inputData,
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
        } else if (item.eventType == "ROCKER_2") {
            TransformRocker2Event(item, inputEventArray);
        } else {
            MMI_HILOGW("Format json file error");
        }
    }
}

void ProcessingGamePadDevice::TransformKeyPressEvent(const DeviceEvent& padEvent, InputEventArray& inputEventArray)
{
    uint16_t keyValue = static_cast<uint16_t>(padEvent.keyValue);
    SetKeyPressEvent(inputEventArray, padEvent.blockTime, keyValue);
    SetSynReport(inputEventArray);
}

void ProcessingGamePadDevice::TransformKeyReleaseEvent(const DeviceEvent& padEvent, InputEventArray& inputEventArray)
{
    uint16_t keyValue = static_cast<uint16_t>(padEvent.keyValue);
    SetKeyReleaseEvent(inputEventArray, padEvent.blockTime, keyValue);
    SetSynReport(inputEventArray);
}

void ProcessingGamePadDevice::TransformKeyClickEvent(const DeviceEvent& padEvent, InputEventArray& inputEventArray)
{
    uint16_t keyValue = static_cast<uint16_t>(padEvent.keyValue);
    SetKeyPressEvent(inputEventArray, padEvent.blockTime, keyValue);
    SetSynReport(inputEventArray);
    SetKeyReleaseEvent(inputEventArray, padEvent.blockTime, keyValue);
    SetSynReport(inputEventArray);
}

void ProcessingGamePadDevice::TransformRocker1Event(const DeviceEvent& padEvent, InputEventArray& inputEventArray)
{
    if (padEvent.direction.empty()) {
        MMI_HILOGW("Direction is empty");
        return;
    }
    if (padEvent.event.empty()) {
        MMI_HILOGW("Event is empty");
        return;
    }
    std::string direction = padEvent.direction;
    for (const auto &item : padEvent.event) {
        uint32_t value;
        if (direction == "left") {
            value = ~item + 1;
            SetEvAbsX(inputEventArray, 0, value);
        } else if (direction == "up") {
            value = ~item + 1;
            SetEvAbsY(inputEventArray, 0, value);
        } else if (direction == "right") {
            value = item;
            SetEvAbsX(inputEventArray, 0, value);
        } else if (direction == "down") {
            value = item;
            SetEvAbsY(inputEventArray, 0, value);
        } else if (direction == "lt") {
            value = item;
            SetEvAbsZ(inputEventArray, 0, value);
        } else {
            MMI_HILOGW("Unknown direction move type");
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
        MMI_HILOGW("Unknown direction type");
    }
    SetSynReport(inputEventArray);
}

void ProcessingGamePadDevice::TransformRocker2Event(const DeviceEvent& padEvent, InputEventArray& inputEventArray)
{
    if (padEvent.direction.empty()) {
        MMI_HILOGW("Not find direction");
        return;
    }
    if (padEvent.event.empty()) {
        MMI_HILOGW("Not find event");
        return;
    }
    std::string direction = padEvent.direction;
    for (uint32_t item : padEvent.event) {
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
        } else {
            MMI_HILOGW("Unknown direction move type");
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
        MMI_HILOGW("Unknown direction type");
    }
    SetSynReport(inputEventArray);
}

void ProcessingGamePadDevice::TransformDirectionKeyEvent(const DeviceEvent& padEvent, InputEventArray& inputEventArray)
{
    if (padEvent.direction.empty()) {
        MMI_HILOGW("Not find direction");
        return;
    }
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
        MMI_HILOGW("Unknown direction type");
    }
}
} // namespace MMI
} // namespace OHOS
