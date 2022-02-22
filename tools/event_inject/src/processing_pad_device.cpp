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

#include "processing_pad_device.h"

using namespace std;
using namespace OHOS::MMI;

namespace {
    static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "ProcessingPadDevice" };
}

int32_t ProcessingPadDevice::TransformJsonDataToInputData(const Json& fingerEventArrays,
    InputEventArray& inputEventArray)
{
    MMI_LOGD("Enter");
    if (fingerEventArrays.empty()) {
        return RET_ERR;
    }
    Json inputData = fingerEventArrays.at("events");
    if (inputData.empty()) {
        MMI_LOGE("manage finger array faild, inputData is empty.");
        return RET_ERR;
    }
    vector<PadEvent> padEventArray;
    if (AnalysisPadEvent(inputData, padEventArray) == RET_ERR) {
        return RET_ERR;
    }
    TransformPadEventToInputEvent(padEventArray, inputEventArray);
    MMI_LOGD("Leave");

    return RET_OK;
}

void ProcessingPadDevice::TransformPadEventToInputEvent(const std::vector<PadEvent>& padEventArray,
                                                        InputEventArray& inputEventArray)
{
    for (const auto &item : padEventArray) {
        if (item.eventType == "KEY_EVENT_PRESS") {
            TransformKeyPressEvent(item, inputEventArray);
        } else if (item.eventType == "KEY_EVENT_RELEASE") {
            TransformKeyReleaseEvent(item, inputEventArray);
        } else if (item.eventType == "KEY_EVENT_CLICK") {
            TransformKeyClickEvent(item, inputEventArray);
        } else if (item.eventType == "RING_EVENT") {
            TransformRingEvent(item, inputEventArray);
        }
    }
}

int32_t ProcessingPadDevice::AnalysisPadEvent(const Json& inputData, std::vector<PadEvent>& padEventArray)
{
    PadEvent padEvent = {};
    for (const auto &item : inputData) {
        padEvent.eventType = item.at("eventType").get<std::string>();
        if ((item.find("keyValue")) != item.end()) {
            padEvent.keyValue = item.at("keyValue").get<int32_t>();
        }
        if ((item.find("ringEvents")) != item.end()) {
            padEvent.ringEvents = item.at("ringEvents").get<std::vector<int32_t>>();
        }
        padEventArray.push_back(padEvent);
    }
    return RET_OK;
}

void ProcessingPadDevice::TransformKeyPressEvent(const PadEvent& padEvent, InputEventArray& inputEventArray)
{
    SetKeyPressEvent(inputEventArray, 0, static_cast<uint16_t>(padEvent.keyValue));
    SetAbsMisc(inputEventArray, 0, 1);
    SetSynReport(inputEventArray);
}

void ProcessingPadDevice::TransformKeyReleaseEvent(const PadEvent& padEvent, InputEventArray& inputEventArray)
{
    SetKeyReleaseEvent(inputEventArray, 0, static_cast<uint16_t>(padEvent.keyValue));
    SetAbsMisc(inputEventArray, 0, 0);
    SetSynReport(inputEventArray);
}

void ProcessingPadDevice::TransformKeyClickEvent(const PadEvent& padEvent, InputEventArray& inputEventArray)
{
    SetKeyPressEvent(inputEventArray, 0, static_cast<uint16_t>(padEvent.keyValue));
    SetAbsMisc(inputEventArray, 0, 1);
    SetSynReport(inputEventArray);
    SetKeyReleaseEvent(inputEventArray, 0, static_cast<uint16_t>(padEvent.keyValue));
    SetAbsMisc(inputEventArray, 0, 0);
    SetSynReport(inputEventArray);
}

void ProcessingPadDevice::TransformRingEvent(const PadEvent& padEvent, InputEventArray& inputEventArray)
{
    uint64_t eventCount = static_cast<uint64_t>(padEvent.ringEvents.size());
    for (uint64_t i = 0; i < eventCount; i++) {
        SetEvAbsWheel(inputEventArray, 0, padEvent.ringEvents[i]);
        if (i == 0) {
            SetAbsMisc(inputEventArray, 0, 1);
        } else if (i == (eventCount - 1)) {
            SetAbsMisc(inputEventArray, 0, 0);
        } else {
            // nothing to do.
        }
        SetSynReport(inputEventArray);
    }
}
