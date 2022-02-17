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
#ifndef PROCESSING_PEN_DEVICE_H
#define PROCESSING_PEN_DEVICE_H

#include "msg_head.h"
#include "device_base.h"

namespace OHOS {
namespace MMI {
class ProcessingPenDevice : public DeviceBase {
    struct PenEvent {
        std::string eventType;
        int32_t xPos;
        int32_t yPos;
        int32_t tiltX;
        int32_t tiltY;
        int32_t pressure;
        int32_t distance;
        int32_t keyValue;
        int32_t keyStatus;
    };
public:
    ProcessingPenDevice() = default;
    ~ProcessingPenDevice() = default;
    int32_t TransformJsonDataToInputData(const Json& inputEventArrays, InputEventArray& inputEventArray);
private:
    void TransformPenEventToInputEvent(const std::vector<PenEvent>& penEventArray, InputEventArray& inputEventArray);
    void SetPenApproachPadEvent(const PenEvent &penEvent, InputEventArray& inputEventArray);
    void SetPenSlidePadEvent(const PenEvent& penEvent, InputEventArray& inputEventArray);
    void SetPenLeavePadEvent(const PenEvent& penEvent, InputEventArray& inputEventArray);
    int32_t AnalysisPenPadEvent(const Json& inputData, std::vector<PenEvent>& penEventArray);
    int32_t AnalysisPenApproachPadEvent(const Json& event, std::vector<PenEvent>& penEventArray);
    int32_t AnalysisPenSlidePadEvent(const Json& event, std::vector<PenEvent>& penEventArray);
    int32_t AnalysisPenLeavePadEvent(const Json& event, std::vector<PenEvent>& penEventArray);
private:
    static constexpr int32_t EV_ABS_Z_DEFAULT_VALUE = 450;
    static constexpr int32_t EV_ABS_MISC_DEFAULT_VALUE = 2114;
};
} // namespace MMI
} // namespace OHOS
#endif // PROCESSING_PEN_DEVICE_H