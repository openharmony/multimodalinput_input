/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "processing_pen_device.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "ProcessingPenDevice"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t EV_ABS_Z_DEFAULT_VALUE { 450 };
constexpr int32_t EV_ABS_MISC_DEFAULT_VALUE { 2114 };
} // namespace

int32_t ProcessingPenDevice::TransformJsonDataToInputData(const DeviceItem& penEventArrays,
    InputEventArray& inputEventArray)
{
    CALL_DEBUG_ENTER;
    if (penEventArrays.events.empty()) {
        MMI_HILOGE("Manage pen array failed, inputData is empty.");
        return RET_ERR;
    }
    std::vector<DeviceEvent> inputData = penEventArrays.events;
    if (inputData.empty()) {
        MMI_HILOGE("Manage pen array failed, inputData is empty.");
        return RET_ERR;
    }
    std::vector<PenEvent> penEventArray;
    if (AnalysisPenPadEvent(inputData, penEventArray) == RET_ERR) {
        MMI_HILOGE("AnalysisPenPadEvent error.");
        return RET_ERR;
    }
    TransformPenEventToInputEvent(penEventArray, inputEventArray);
    return RET_OK;
}

void ProcessingPenDevice::TransformPenEventToInputEvent(const std::vector<PenEvent>& penEventArray,
                                                        InputEventArray& inputEventArray)
{
    SetPenApproachPadEvent(penEventArray[0], inputEventArray);
    for (const auto &item : penEventArray) {
        SetPenSlidePadEvent(item, inputEventArray);
    }
    uint64_t lastEventIndex = penEventArray.size() - 1;
    SetPenLeavePadEvent(penEventArray[lastEventIndex], inputEventArray);
}

void ProcessingPenDevice::SetPenApproachPadEvent(const PenEvent& penEvent, InputEventArray& inputEventArray)
{
    SetEvAbsX(inputEventArray, 0, penEvent.xPos);
    SetEvAbsY(inputEventArray, 0, penEvent.yPos);
    SetAbsTiltX(inputEventArray, 0, penEvent.tiltX);
    SetAbsTiltY(inputEventArray, 0, penEvent.tiltY);
    SetEvAbsZ(inputEventArray, 0, EV_ABS_Z_DEFAULT_VALUE);
    SetAbsDistance(inputEventArray, 0, penEvent.distance);
    if (penEvent.eventType == "PEN_TOUCH") {
        SetBtnPen(inputEventArray, 0, 1);
    } else if (penEvent.eventType == "RUBBER_TOUCH") {
        SetBtnRubber(inputEventArray, 0, 1);
    } else {
        MMI_HILOGW("Unknown eventType type");
    }

    SetMscSerial(inputEventArray, 0);
    SetAbsMisc(inputEventArray, 0, EV_ABS_MISC_DEFAULT_VALUE);
    SetSynReport(inputEventArray);
}

void ProcessingPenDevice::SetPenSlidePadEvent(const PenEvent& penEvent, InputEventArray& inputEventArray)
{
    if (penEvent.eventType == "PEN_KEY") {
        SetBtnStylus(inputEventArray, 0, static_cast<uint16_t>(penEvent.keyValue), penEvent.keyStatus);
        return;
    }
    if (penEvent.distance == 0) {
        SetMscSerial(inputEventArray, 0);
        SetSynReport(inputEventArray, 0);
        return;
    }
    SetEvAbsX(inputEventArray, 0, penEvent.xPos);
    SetEvAbsY(inputEventArray, 0, penEvent.yPos);
    static int32_t previousPressure = 0;
    if (penEvent.pressure > 0) {
        if (previousPressure == 0) {
            SetAbsPressure(inputEventArray, 0, penEvent.pressure);
            SetBtnTouch(inputEventArray, 0, 1);
        } else if (previousPressure > 0) {
            SetAbsPressure(inputEventArray, 0, penEvent.pressure);
        } else {
            MMI_HILOGW("Unknown previousPressure type");
        }
    } else if ((penEvent.pressure == 0) && (previousPressure > 0)) {
        SetAbsPressure(inputEventArray, 0, penEvent.pressure);
        SetBtnTouch(inputEventArray, 0, 0);
    } else {
        MMI_HILOGW("Unknown pressure type");
    }
    previousPressure = penEvent.pressure;
    SetAbsDistance(inputEventArray, 0, penEvent.distance);
    SetAbsTiltX(inputEventArray, 0, penEvent.tiltX);
    SetAbsTiltY(inputEventArray, 0, penEvent.tiltY);
    SetMscSerial(inputEventArray, 0);
    SetSynReport(inputEventArray);
}

void ProcessingPenDevice::SetPenLeavePadEvent(const PenEvent& penEvent, InputEventArray& inputEventArray)
{
    SetEvAbsX(inputEventArray, 0);
    SetEvAbsY(inputEventArray, 0);
    SetAbsTiltX(inputEventArray, 0);
    SetAbsTiltY(inputEventArray, 0);
    SetEvAbsZ(inputEventArray, 0);
    SetAbsDistance(inputEventArray, 0, 0);
    if (penEvent.eventType == "PEN_TOUCH") {
        SetBtnPen(inputEventArray, 0, 0);
    } else if (penEvent.eventType == "RUBBER_TOUCH") {
        SetBtnRubber(inputEventArray, 0, 0);
    } else {
        MMI_HILOGW("Unknown eventType type");
    }

    SetMscSerial(inputEventArray, 0);
    SetAbsMisc(inputEventArray, 0, 0);
    SetSynReport(inputEventArray);
}

int32_t ProcessingPenDevice::AnalysisPenPadEvent(const std::vector<DeviceEvent>& inputData,
    std::vector<PenEvent>& penEventArray)
{
    if (inputData.empty()) {
        return RET_ERR;
    }
    uint64_t endEventIndex = inputData.size() - 1;
    if (AnalysisPenApproachPadEvent(inputData[0], penEventArray) == RET_ERR) {
        return RET_ERR;
    }
    for (uint64_t i = 1; i < endEventIndex; i++) {
        if (AnalysisPenSlidePadEvent(inputData[i], penEventArray) == RET_ERR) {
            return RET_ERR;
        }
    }
    if (AnalysisPenLeavePadEvent(inputData[endEventIndex], penEventArray) == RET_ERR) {
        return RET_ERR;
    }

    return RET_OK;
}

int32_t ProcessingPenDevice::AnalysisPenApproachPadEvent(const DeviceEvent& event, std::vector<PenEvent>& penEventArray)
{
    PenEvent penEvent = {};
    penEvent.eventType = event.eventType;
    if ((penEvent.eventType != "RUBBER_TOUCH") && (penEvent.eventType != "PEN_TOUCH")) {
        MMI_HILOGE("Enter the correct event type in the configuration file.");
        return RET_ERR;
    }
    penEvent.distance = event.distance;
    penEvent.yPos = event.yPos;
    penEvent.tiltX = event.tiltX;
    penEvent.tiltY = event.tiltY;
    penEvent.pressure = event.pressure;
    penEvent.xPos = event.xPos;
    penEventArray.push_back(penEvent);

    return RET_OK;
}

int32_t ProcessingPenDevice::AnalysisPenSlidePadEvent(const DeviceEvent& event, std::vector<PenEvent>& penEventArray)
{
    PenEvent penEvent = {};
    penEvent.eventType = event.eventType;
    if (penEvent.eventType == "PEN_KEY") {
        penEvent.keyValue = event.keyValue;
        penEvent.keyStatus = event.keyStatus;
    } else if ((penEvent.eventType == "PEN_TOUCH") || (penEvent.eventType == "RUBBER_TOUCH")) {
        penEvent.yPos = event.yPos;
        penEvent.xPos = event.xPos;
        penEvent.tiltY = event.tiltY;
        penEvent.tiltX = event.tiltX;
        penEvent.distance = event.distance;
        penEvent.pressure = event.pressure;
    } else {
        MMI_HILOGW("Unknown eventType type");
    }
    penEventArray.push_back(penEvent);

    return RET_OK;
}

int32_t ProcessingPenDevice::AnalysisPenLeavePadEvent(const DeviceEvent& event, std::vector<PenEvent>& penEventArray)
{
    PenEvent penEvent = {};
    penEvent.eventType = event.eventType;
    if ((penEvent.eventType != "RUBBER_TOUCH") && (penEvent.eventType != "PEN_TOUCH")) {
        MMI_HILOGE("Enter the correct event type in the configuration file.");
        return RET_ERR;
    }
    penEvent.yPos = event.yPos;
    penEvent.tiltY = event.tiltY;
    penEvent.xPos = event.xPos;
    penEvent.tiltX = event.tiltX;
    penEvent.distance = event.distance;
    penEvent.pressure = event.pressure;
    penEventArray.push_back(penEvent);

    return RET_OK;
}
} // namespace MMI
} // namespace OHOS