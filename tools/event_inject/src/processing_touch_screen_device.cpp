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

#include "processing_touch_screen_device.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "ProcessingTouchScreenDevice"

namespace OHOS {
namespace MMI {
int32_t ProcessingTouchScreenDevice::TransformJsonDataToInputData(const DeviceItem &touchScreenEventArrays,
                                                                  InputEventArray &inputEventArray)
{
    CALL_DEBUG_ENTER;
    if (!touchScreenEventArrays.events.empty()) {
        return TransformJsonDataSingleTouchScreen(touchScreenEventArrays, inputEventArray);
    }
    std::vector<DeviceEvent> inputData = touchScreenEventArrays.events;
    if (inputData.empty()) {
        MMI_HILOGE("Manage touchScreen array failed, inputData is empty.");
        return RET_ERR;
    }
    TouchScreenInputEvents touchScreenInputEvents = {};
    AnalysisTouchScreenDate(inputData, touchScreenInputEvents);
    TouchScreenInputEvent pressEvents = touchScreenInputEvents.eventArray[0];
    AnalysisTouchScreenPressData(inputEventArray, pressEvents);
    for (uint64_t i = 1; i < static_cast<uint64_t>(touchScreenInputEvents.eventNumber); i++) {
        AnalysisTouchScreenMoveData(inputEventArray, touchScreenInputEvents.eventArray[i]);
    }
    uint64_t releaseEventIndex = static_cast<uint64_t>(touchScreenInputEvents.eventNumber) - 1;
    TouchScreenInputEvent releaseEvents = touchScreenInputEvents.eventArray[releaseEventIndex];
    AnalysisTouchScreenReleaseData(inputEventArray, releaseEvents);
    return RET_OK;
}

int32_t ProcessingTouchScreenDevice::TransformJsonDataSingleTouchScreen(const DeviceItem &touchScreenEventArrays,
    InputEventArray &inputEventArray)
{
    CALL_DEBUG_ENTER;
    std::vector<DeviceEvent> inputData = touchScreenEventArrays.events;
    if (inputData.empty()) {
        MMI_HILOGE("Manage touchScreen array failed, inputData is empty.");
        return RET_ERR;
    }

    std::vector<TouchSingleEventData> touchSingleEventDatas;
    AnalysisSingleTouchScreenDate(inputData, touchSingleEventDatas);
    for (const auto &item : touchSingleEventDatas) {
        AnalysisTouchScreenToInputData(inputEventArray, item);
    }
    return RET_OK;
}

void ProcessingTouchScreenDevice::AnalysisTouchScreenDate(const std::vector<DeviceEvent> &inputData,
                                                          TouchScreenInputEvents &touchScreenInputEvents)
{
    TouchScreenCoordinates touchScreenCoordinates = {};
    TouchScreenInputEvent touchScreenInputEvent = {};
    for (const auto &item : inputData) {
        touchScreenInputEvent.groupNumber = 0;
        for (auto &posXYItem : item.posXY) {
            touchScreenCoordinates.xPos = posXYItem.xPos;
            touchScreenCoordinates.yPos = posXYItem.yPos;
            touchScreenInputEvent.events.push_back(touchScreenCoordinates);
            ++touchScreenInputEvent.groupNumber;
        }
        touchScreenInputEvents.eventNumber = static_cast<uint32_t>(inputData.size());
        touchScreenInputEvents.eventArray.push_back(touchScreenInputEvent);
        touchScreenInputEvent.events.clear();
    }
}

void ProcessingTouchScreenDevice::AnalysisSingleTouchScreenDate(const std::vector<DeviceEvent> &inputData,
    std::vector<TouchSingleEventData> &touchSingleEventDatas)
{
    TouchSingleEventData touchSingleEventData = {};
    for (auto &item : inputData) {
        touchSingleEventData = {};
        touchSingleEventData.eventType = item.eventType;
        touchSingleEventData.trackingId = item.trackingId;
        if (touchSingleEventData.eventType != "release") {
            touchSingleEventData.xPos = item.xPos;
            touchSingleEventData.yPos = item.yPos;
        }
        touchSingleEventData.blockTime = item.blockTime;
        touchSingleEventData.reportType = item.reportType;
        touchSingleEventDatas.push_back(touchSingleEventData);
    }
}

void ProcessingTouchScreenDevice::AnalysisTouchScreenPressData(InputEventArray &inputEventArray,
                                                               const TouchScreenInputEvent &touchScreenInputEvent)
{
    int32_t yPos = 0;
    int32_t xPos = 0;
    for (uint32_t i = 0; i < touchScreenInputEvent.groupNumber; i++) {
        yPos = touchScreenInputEvent.events[i].yPos;
        xPos = touchScreenInputEvent.events[i].xPos;
        SetTrackingId(inputEventArray, 0, static_cast<int32_t>(i + 1));
        SetSynMtReport(inputEventArray, 0);
        SetPositionY(inputEventArray, 0, yPos);
        SetPositionX(inputEventArray, 0, xPos);
        SetBtnTouch(inputEventArray, 0, 1);
    }
    SetSynReport(inputEventArray);
}

void ProcessingTouchScreenDevice::AnalysisTouchScreenMoveData(InputEventArray &inputEventArray,
                                                              const TouchScreenInputEvent &touchScreenInputEvent)
{
    int32_t xPos = 0;
    int32_t yPos = 0;
    for (uint32_t i = 0; i < touchScreenInputEvent.groupNumber; i++) {
        xPos = touchScreenInputEvent.events[i].xPos;
        yPos = touchScreenInputEvent.events[i].yPos;
        SetPositionX(inputEventArray, 0, xPos);
        SetPositionY(inputEventArray, 0, yPos);
        SetTrackingId(inputEventArray, 0, static_cast<int32_t>(i + 1));
        SetSynMtReport(inputEventArray, 0);
    }
    SetSynReport(inputEventArray);
}

void ProcessingTouchScreenDevice::AnalysisTouchScreenReleaseData(InputEventArray &inputEventArray,
                                                                 const TouchScreenInputEvent &touchScreenInputEvent)
{
    for (uint32_t i = 0; i < touchScreenInputEvent.groupNumber; i++) {
        SetTrackingId(inputEventArray, 0, static_cast<int32_t>(i + 1));
        SetBtnTouch(inputEventArray, 0, 0);
        SetSynMtReport(inputEventArray, 0);
    }
    SetSynReport(inputEventArray);
    SetSynMtReport(inputEventArray, 0);
    SetSynReport(inputEventArray);
}

void ProcessingTouchScreenDevice::AnalysisTouchScreenToInputData(InputEventArray &inputEventArray,
                                                                 const TouchSingleEventData &touchSingleEventData)
{
    if (touchSingleEventData.eventType == "press") {
        AnalysisTouchScreenPressData(inputEventArray, touchSingleEventData);
    } else if (touchSingleEventData.eventType == "move") {
        AnalysisTouchScreenMoveData(inputEventArray, touchSingleEventData);
    } else if (touchSingleEventData.eventType == "release") {
        AnalysisTouchScreenReleaseData(inputEventArray, touchSingleEventData);
    }
}

void ProcessingTouchScreenDevice::AnalysisTouchScreenPressData(InputEventArray &inputEventArray,
                                                               const TouchSingleEventData &touchSingleEventData)
{
    SetPositionX(inputEventArray, 0, touchSingleEventData.xPos);
    SetPositionY(inputEventArray, 0, touchSingleEventData.yPos);
    SetTrackingId(inputEventArray, 0, touchSingleEventData.trackingId);
    SetBtnTouch(inputEventArray, 0, 1);
    if (touchSingleEventData.reportType == "mtReport") {
        SetSynMtReport(inputEventArray, 0);
    } else if (touchSingleEventData.reportType == "synReport") {
        SetSynMtReport(inputEventArray, 0);
        SetSynReport(inputEventArray, touchSingleEventData.blockTime);
    }
}

void ProcessingTouchScreenDevice::AnalysisTouchScreenMoveData(InputEventArray &inputEventArray,
                                                              const TouchSingleEventData &touchSingleEventData)
{
    SetPositionX(inputEventArray, 0, touchSingleEventData.xPos);
    SetPositionY(inputEventArray, 0, touchSingleEventData.yPos);
    SetTrackingId(inputEventArray, 0, touchSingleEventData.trackingId);
    if (touchSingleEventData.reportType == "mtReport") {
        SetSynMtReport(inputEventArray, 0);
    } else if (touchSingleEventData.reportType == "synReport") {
        SetSynMtReport(inputEventArray, 0);
        SetSynReport(inputEventArray, touchSingleEventData.blockTime);
    }
}

void ProcessingTouchScreenDevice::AnalysisTouchScreenReleaseData(InputEventArray &inputEventArray,
                                                                 const TouchSingleEventData &touchSingleEventData)
{
    SetTrackingId(inputEventArray, 0, touchSingleEventData.trackingId);
    SetBtnTouch(inputEventArray, 0, 0);
    if (touchSingleEventData.reportType == "mtReport") {
        SetSynMtReport(inputEventArray, 0);
    } else if (touchSingleEventData.reportType == "synReport") {
        SetSynMtReport(inputEventArray, 0);
        SetSynReport(inputEventArray);
        SetSynMtReport(inputEventArray, 0);
        SetSynReport(inputEventArray, touchSingleEventData.blockTime);
    }
}
} // namespace MMI
} // namespace OHOS