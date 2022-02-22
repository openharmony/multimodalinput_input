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

#include "msg_head.h"
#include "device_base.h"

namespace OHOS {
namespace MMI {
class ProcessingMouseDevice : public DeviceBase {
    struct MouseEvent {
        int32_t xPos;
        int32_t yPos;
        int32_t keyValue;
        int32_t distance;
        int32_t blockTime;
        std::string eventType;
        std::string direction;
    };
public:
    ProcessingMouseDevice() = default;
    ~ProcessingMouseDevice() = default;
    int32_t TransformJsonDataToInputData(const Json& inputEventArrays, InputEventArray& inputEventArray);
private:
    int32_t AnalysisMouseEvent(const Json& inputData, std::vector<MouseEvent>& mouseEventArray);
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