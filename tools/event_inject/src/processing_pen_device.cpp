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

#include "processing_pen_device.h"

using namespace std;
using namespace OHOS::MMI;

namespace {
    static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "ProcessingPenDevice" };
}

int32_t ProcessingPenDevice::TransformJsonDataToInputData(const Json& penEventArrays,
    InputEventArray& inputEventArray)
{
    MMI_LOGD("Enter");
    if (penEventArrays.empty()) {
        return RET_ERR;
    }
    if (penEventArrays.find("events") == penEventArrays.end()) {
        MMI_LOGE("manage pen array faild, inputData is empty.");
        return RET_ERR;
    }
    Json inputData = penEventArrays.at("events");
    if (inputData.empty()) {
        MMI_LOGE("manage pen array faild, inputData is empty.");
        return RET_ERR;
    }
    vector<PenEvent> penEventArray;
    if (AnalysisPenPadEvent(inputData, penEventArray) == RET_ERR) {
        MMI_LOGE("AnalysisPenPadEvent error.");
        return RET_ERR;
    }
    TransformPenEventToInputEvent(penEventArray, inputEventArray);
    MMI_LOGD("Leave");
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
        // nothing to do.
    }

    SetMscSerial(inputEventArray, 0);
    SetAbsMisc(inputEventArray, 0, EV_ABS_MISC_DEFAULT_VALUE);
    SetSynReport(inputEventArray);
}

void ProcessingPenDevice::SetPenSlidePadEvent(const PenEvent& penEvent, InputEventArray& inputEventArray)
{
    static int32_t previousPressure = 0;
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
    if (penEvent.pressure > 0) {
        if (previousPressure == 0) {
            SetAbsPressure(inputEventArray, 0, penEvent.pressure);
            SetBtnTouch(inputEventArray, 0, 1);
        } else if (previousPressure > 0) {
            SetAbsPressure(inputEventArray, 0, penEvent.pressure);
        } else {
            // nothing to do.
        }
    } else if ((penEvent.pressure == 0) && (previousPressure > 0)) {
        SetAbsPressure(inputEventArray, 0, penEvent.pressure);
        SetBtnTouch(inputEventArray, 0, 0);
    } else {
        // nothing to do.
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
        // nothing to do.
    }

    SetMscSerial(inputEventArray, 0);
    SetAbsMisc(inputEventArray, 0, 0);
    SetSynReport(inputEventArray);
}

int32_t ProcessingPenDevice::AnalysisPenPadEvent(const Json& inputData, std::vector<PenEvent>& penEventArray)
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

int32_t ProcessingPenDevice::AnalysisPenApproachPadEvent(const Json& event, std::vector<PenEvent>& penEventArray)
{
    if (event.empty()) {
        MMI_LOGE("AnalysisPenApproachPadEvent is empty.");
        return RET_ERR;
    }
    PenEvent penEvent = {};
    penEvent.eventType = event.at("eventType").get<std::string>();
    if ((penEvent.eventType != "RUBBER_TOUCH") && (penEvent.eventType != "PEN_TOUCH")) {
        MMI_LOGE("Enter the correct event type in the configuration file.");
        return RET_ERR;
    }
    penEvent.xPos = event.at("xPos").get<int32_t>();
    penEvent.yPos = event.at("yPos").get<int32_t>();
    penEvent.tiltX = event.at("tiltX").get<int32_t>();
    penEvent.tiltY = event.at("tiltY").get<int32_t>();
    penEvent.pressure = event.at("pressure").get<int32_t>();
    penEvent.distance = event.at("distance").get<int32_t>();
    penEventArray.push_back(penEvent);

    return RET_OK;
}

int32_t ProcessingPenDevice::AnalysisPenSlidePadEvent(const Json& event, std::vector<PenEvent>& penEventArray)
{
    if (event.empty()) {
        MMI_LOGE("AnalysisPenSlidePadEvent is empty.");
        return RET_ERR;
    }
    PenEvent penEvent = {};
    penEvent.eventType = event.at("eventType").get<std::string>();
    if (penEvent.eventType == "PEN_KEY") {
        penEvent.keyValue = event.at("keyValue").get<int32_t>();
        penEvent.keyStatus = event.at("keyStatus").get<int32_t>();
    } else if ((penEvent.eventType == "PEN_TOUCH") || (penEvent.eventType == "RUBBER_TOUCH")) {
        penEvent.xPos = event.at("xPos").get<int32_t>();
        penEvent.yPos = event.at("yPos").get<int32_t>();
        penEvent.tiltX = event.at("tiltX").get<int32_t>();
        penEvent.tiltY = event.at("tiltY").get<int32_t>();
        penEvent.pressure = event.at("pressure").get<int32_t>();
        penEvent.distance = event.at("distance").get<int32_t>();
    } else {
        // nothing to do.
    }
    penEventArray.push_back(penEvent);

    return RET_OK;
}

int32_t ProcessingPenDevice::AnalysisPenLeavePadEvent(const Json& event, std::vector<PenEvent>& penEventArray)
{
    if (event.empty()) {
        MMI_LOGE("AnalysisPenLeavePadEvent is empty.");
        return RET_ERR;
    }
    PenEvent penEvent = {};
    penEvent.eventType = event.at("eventType").get<std::string>();
    if ((penEvent.eventType != "RUBBER_TOUCH") && (penEvent.eventType != "PEN_TOUCH")) {
        MMI_LOGE("Enter the correct event type in the configuration file.");
        return RET_ERR;
    }
    penEvent.xPos = event.at("xPos").get<int32_t>();
    penEvent.yPos = event.at("yPos").get<int32_t>();
    penEvent.tiltX = event.at("tiltX").get<int32_t>();
    penEvent.tiltY = event.at("tiltY").get<int32_t>();
    penEvent.pressure = event.at("pressure").get<int32_t>();
    penEvent.distance = event.at("distance").get<int32_t>();
    penEventArray.push_back(penEvent);

    return RET_OK;
}