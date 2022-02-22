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
#ifndef PROCESSING_FINGER_DEVICE_H
#define PROCESSING_FINGER_DEVICE_H

#include "msg_head.h"
#include "device_base.h"

namespace OHOS {
namespace MMI {
class ProcessingFingerDevice : public DeviceBase {
    struct TouchPadCoordinates {
        int32_t xPos;
        int32_t yPos;
    };

    struct TouchPadInputEvent {
        uint32_t groupNumber;
        std::vector<TouchPadCoordinates> events;
    };

    struct TouchPadInputEvents {
        uint64_t eventNumber;
        std::vector<TouchPadInputEvent> eventArray;
    };
public:
    ProcessingFingerDevice() = default;
    ~ProcessingFingerDevice() = default;
    int32_t TransformJsonDataToInputData(const Json& inputEventArrays, InputEventArray& inputEventArray);
private:
    void AnalysisTouchPadFingerDate(const Json& inputData, TouchPadInputEvents& touchPadInputEvents);
    void AnalysisTouchPadFingerPressData(InputEventArray& inputEventArray,
                                         const TouchPadInputEvent& touchPadInputEvent);
    void AnalysisTouchPadFingerMoveData(InputEventArray& inputEventArray, const TouchPadInputEvent& touchPadInputEvent);
    void AnalysisTouchPadFingerReleaseData(InputEventArray& inputEventArray,
                                           const TouchPadInputEvent& touchPadInputEvent);
private:
    static constexpr int32_t FINGER_BLOCK_TIME = 6;
};
} // namespace MMI
} // namespace OHOS
#endif // PROCESSING_FINGER_DEVICE_H