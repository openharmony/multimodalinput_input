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

#include "device_base.h"
#include "msg_head.h"

namespace OHOS {
namespace MMI {
class ProcessingFingerDevice : public DeviceBase {
    struct TouchPadCoordinates {
        int32_t xPos { 0 };
        int32_t yPos { 0 };
    };

    struct TouchPadInputEvent {
        uint32_t groupNumber { 0 };
        std::vector<TouchPadCoordinates> events;
    };

    struct TouchPadInputEvents {
        uint64_t eventNumber { 0 };
        std::vector<TouchPadInputEvent> eventArray;
    };
public:
    ProcessingFingerDevice() = default;
    DISALLOW_COPY_AND_MOVE(ProcessingFingerDevice);
    ~ProcessingFingerDevice() = default;
    int32_t TransformJsonDataToInputData(const DeviceItem &inputEventArrays, InputEventArray &inputEventArray);
private:
    void AnalysisTouchPadFingerDate(const std::vector<DeviceEvent> &inputData,
                                    TouchPadInputEvents &touchPadInputEvents);
    void AnalysisTouchPadFingerPressData(InputEventArray &inputEventArray,
                                         const TouchPadInputEvent &touchPadInputEvent);
    void AnalysisTouchPadFingerMoveData(InputEventArray &inputEventArray, const TouchPadInputEvent &touchPadInputEvent);
    void AnalysisTouchPadFingerReleaseData(InputEventArray &inputEventArray,
                                           const TouchPadInputEvent &touchPadInputEvent);
};
} // namespace MMI
} // namespace OHOS
#endif // PROCESSING_FINGER_DEVICE_H