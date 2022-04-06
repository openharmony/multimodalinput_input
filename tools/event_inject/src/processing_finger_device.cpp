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

#include "processing_finger_device.h"

using namespace OHOS::MMI;

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "ProcessingFingerDevice" };
} // namespace

int32_t ProcessingFingerDevice::TransformJsonDataToInputData(const DeviceItem& fingerEventArrays,
    InputEventArray& inputEventArray)
{
    CALL_LOG_ENTER;
    std::vector<DeviceEvent> inputData = fingerEventArrays.events;
    if (inputData.empty()) {
        MMI_HILOGE("manage finger array faild, inputData is empty.");
        return RET_ERR;
    }
    TouchPadInputEvents touchPadInputEvents = {};
    AnalysisTouchPadFingerDate(inputData, touchPadInputEvents);
    TouchPadInputEvent pressEvents = touchPadInputEvents.eventArray[0];
    AnalysisTouchPadFingerPressData(inputEventArray, pressEvents);
    for (uint64_t i = 1; i < touchPadInputEvents.eventNumber; i++) {
        AnalysisTouchPadFingerMoveData(inputEventArray, touchPadInputEvents.eventArray[i]);
    }
    uint64_t releaseEventIndex = touchPadInputEvents.eventNumber - 1;
    TouchPadInputEvent releaseEvents = touchPadInputEvents.eventArray[releaseEventIndex];
    AnalysisTouchPadFingerReleaseData(inputEventArray, releaseEvents);
    return RET_OK;
}

void ProcessingFingerDevice::AnalysisTouchPadFingerDate(const std::vector<DeviceEvent>& inputData,
    TouchPadInputEvents& touchPadInputEvents)
{
    TouchPadCoordinates touchPadCoordinates = {};
    TouchPadInputEvent touchPadInputEvent = {};
    for (size_t i = 0; i < inputData.size(); i++) {
        for (size_t j = 0; j < inputData[i].posXY.size(); j++) {
            touchPadCoordinates.xPos = inputData[i].posXY[j].xPos;
            touchPadCoordinates.yPos = inputData[i].posXY[j].yPos;
            touchPadInputEvent.events.push_back(touchPadCoordinates);
            touchPadInputEvent.groupNumber = j + 1;
        }
        touchPadInputEvents.eventNumber = inputData.size();
        touchPadInputEvents.eventArray.push_back(touchPadInputEvent);
        touchPadInputEvent.events.clear();
    }
}

void ProcessingFingerDevice::AnalysisTouchPadFingerPressData(InputEventArray& inputEventArray,
                                                             const TouchPadInputEvent& touchPadInputEvent)
{
    int32_t xPos = 0;
    int32_t yPos = 0;
    for (uint64_t i = 0; i < static_cast<uint64_t>(touchPadInputEvent.groupNumber); i++) {
        xPos = touchPadInputEvent.events[i].xPos;
        yPos = touchPadInputEvent.events[i].yPos;
        if (touchPadInputEvent.groupNumber > 1) {
            SetMtSlot(inputEventArray, FINGER_BLOCK_TIME, static_cast<int32_t>(i));
        }
        SetTrackingId(inputEventArray, FINGER_BLOCK_TIME);
        SetPositionX(inputEventArray, FINGER_BLOCK_TIME, xPos);
        SetPositionY(inputEventArray, FINGER_BLOCK_TIME, yPos);
        SetMtTouchMajor(inputEventArray, FINGER_BLOCK_TIME, 1);
        SetMtTouchMinor(inputEventArray, FINGER_BLOCK_TIME, 1);
        SetBtnTouch(inputEventArray, FINGER_BLOCK_TIME, 1);
        SetMtTouchFingerType(inputEventArray, FINGER_BLOCK_TIME,
                             static_cast<int32_t>(touchPadInputEvent.groupNumber), 1);
        SetEvAbsX(inputEventArray, FINGER_BLOCK_TIME, xPos);
        SetEvAbsY(inputEventArray, FINGER_BLOCK_TIME, yPos);
    }
    SetSynReport(inputEventArray);
}

void ProcessingFingerDevice::AnalysisTouchPadFingerMoveData(InputEventArray& inputEventArray,
                                                            const TouchPadInputEvent& touchPadInputEvent)
{
    int32_t xPos = 0;
    int32_t yPos = 0;
    for (uint64_t i = 0; i < static_cast<uint64_t>(touchPadInputEvent.groupNumber); i++) {
        xPos = touchPadInputEvent.events[i].xPos;
        yPos = touchPadInputEvent.events[i].yPos;
        if (touchPadInputEvent.groupNumber > 1) {
            SetMtSlot(inputEventArray, FINGER_BLOCK_TIME, static_cast<int32_t>(i));
        }
        SetPositionX(inputEventArray, FINGER_BLOCK_TIME, xPos);
        SetPositionY(inputEventArray, FINGER_BLOCK_TIME, yPos);
        SetMtTouchMajor(inputEventArray, FINGER_BLOCK_TIME, 1);
        SetMtTouchMinor(inputEventArray, FINGER_BLOCK_TIME, 1);
        SetEvAbsX(inputEventArray, FINGER_BLOCK_TIME, xPos);
        SetEvAbsY(inputEventArray, FINGER_BLOCK_TIME, yPos);
    }
    SetSynReport(inputEventArray);
}

void ProcessingFingerDevice::AnalysisTouchPadFingerReleaseData(InputEventArray& inputEventArray,
                                                               const TouchPadInputEvent& touchPadInputEvent)
{
    for (uint64_t i = 0; i < static_cast<uint64_t>(touchPadInputEvent.groupNumber); i++) {
        if (touchPadInputEvent.groupNumber > 1) {
            SetMtSlot(inputEventArray, FINGER_BLOCK_TIME, static_cast<int32_t>(i));
        }
        SetTrackingId(inputEventArray, FINGER_BLOCK_TIME, -1);
        SetBtnTouch(inputEventArray, FINGER_BLOCK_TIME, 0);
        SetMtTouchFingerType(inputEventArray, FINGER_BLOCK_TIME,
                             static_cast<int32_t>(touchPadInputEvent.groupNumber), 0);
    }
    SetSynReport(inputEventArray);
}
