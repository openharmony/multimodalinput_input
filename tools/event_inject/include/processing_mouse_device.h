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

#ifndef PROCESSING_MOUSE_DEVICE_H
#define PROCESSING_MOUSE_DEVICE_H

#include "device_base.h"
#include "msg_head.h"

namespace OHOS {
namespace MMI {
class ProcessingMouseDevice : public DeviceBase {
    struct MouseEvent {
        int32_t xPos { 0 };
        int32_t yPos { 0 };
        int32_t keyValue { 0 };
        int32_t distance { 0 };
        int64_t blockTime { 0 };
        std::string eventType;
        std::string direction;
    };
public:
    ProcessingMouseDevice() = default;
    ~ProcessingMouseDevice() = default;
    DISALLOW_COPY_AND_MOVE(ProcessingMouseDevice);
    int32_t TransformJsonDataToInputData(const DeviceItem& inputEventArrays, InputEventArray& inputEventArray);
private:
    int32_t AnalysisMouseEvent(const std::vector<DeviceEvent>& inputData, std::vector<MouseEvent>& mouseEventArray);
    void TransformMouseEventToInputEvent(const std::vector<MouseEvent>& mouseEventArray,
                                         InputEventArray& inputEventArray);
    void TransformKeyPressEvent(const MouseEvent& mouseEvent, InputEventArray& inputEventArray);
    void TransformKeyReleaseEvent(const MouseEvent& mouseEvent, InputEventArray& inputEventArray);
    void TransformKeyClickEvent(const MouseEvent& mouseEvent, InputEventArray& inputEventArray);
    void TransformMouseMoveEvent(const MouseEvent& mouseEvent, InputEventArray& inputEventArray);
    void TransformMouseWheelEvent(const MouseEvent& mouseEvent, InputEventArray& inputEventArray);
    void TransformMouseHwheelEvent(const MouseEvent& mouseEvent, InputEventArray& inputEventArray);
};
} // namespace MMI
} // namespace OHOS
#endif // PROCESSING_MOUSE_DEVICE_H