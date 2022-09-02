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

#ifndef PROCESSING_PEN_DEVICE_H
#define PROCESSING_PEN_DEVICE_H

#include "device_base.h"
#include "msg_head.h"

namespace OHOS {
namespace MMI {
class ProcessingPenDevice : public DeviceBase {
    struct PenEvent {
        std::string eventType;
        int32_t xPos { 0 };
        int32_t yPos { 0 };
        int32_t tiltX { 0 };
        int32_t tiltY { 0 };
        int32_t pressure { 0 };
        int32_t distance { 0 };
        int32_t keyValue { 0 };
        int32_t keyStatus { 0 };
    };
public:
    ProcessingPenDevice() = default;
    DISALLOW_COPY_AND_MOVE(ProcessingPenDevice);
    ~ProcessingPenDevice() = default;
    int32_t TransformJsonDataToInputData(const DeviceItem& inputEventArrays, InputEventArray& inputEventArray);
private:
    void TransformPenEventToInputEvent(const std::vector<PenEvent>& penEventArray, InputEventArray& inputEventArray);
    void SetPenApproachPadEvent(const PenEvent &penEvent, InputEventArray& inputEventArray);
    void SetPenSlidePadEvent(const PenEvent& penEvent, InputEventArray& inputEventArray);
    void SetPenLeavePadEvent(const PenEvent& penEvent, InputEventArray& inputEventArray);
    int32_t AnalysisPenPadEvent(const std::vector<DeviceEvent>& inputData, std::vector<PenEvent>& penEventArray);
    int32_t AnalysisPenApproachPadEvent(const DeviceEvent& event, std::vector<PenEvent>& penEventArray);
    int32_t AnalysisPenSlidePadEvent(const DeviceEvent& event, std::vector<PenEvent>& penEventArray);
    int32_t AnalysisPenLeavePadEvent(const DeviceEvent& event, std::vector<PenEvent>& penEventArray);
};
} // namespace MMI
} // namespace OHOS
#endif // PROCESSING_PEN_DEVICE_H