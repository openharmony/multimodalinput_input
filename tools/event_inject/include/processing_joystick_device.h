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
#ifndef PROCESSING_JOYSTICK_DEVICE_H
#define PROCESSING_JOYSTICK_DEVICE_H

#include "msg_head.h"
#include "device_base.h"

namespace OHOS {
namespace MMI {
class ProcessingJoystickDevice : public DeviceBase {
    struct JoystickEvent {
        std::string eventType;
        std::string direction;
        int32_t keyValue;
        int32_t blockTime;
        std::vector<int32_t> gameEvents;
    };
public:
    ProcessingJoystickDevice() = default;
    ~ProcessingJoystickDevice() = default;
    int32_t TransformJsonDataToInputData(const Json& originalEvent, InputEventArray& inputEventArray);
private:
    int32_t AnalysisJoystickEvent(const Json& inputData, std::vector<JoystickEvent>& JoystickEventArray);
    void TransformPadEventToInputEvent(const std::vector<JoystickEvent>& JoystickEventArray,
                                       InputEventArray& inputEventArray);
    void TransformKeyPressEvent(const JoystickEvent& joystickEvent, InputEventArray& inputEventArray);
    void TransformKeyReleaseEvent(const JoystickEvent& joystickEvent, InputEventArray& inputEventArray);
    void TransformKeyClickEvent(const JoystickEvent& joystickEvent, InputEventArray& inputEventArray);
    void TransformRocker1Event(const JoystickEvent& joystickEvent, InputEventArray& inputEventArray);
    void TransformDerectionKeyEvent(const JoystickEvent& joystickEvent, InputEventArray& inputEventArray);
    void TransformThrottle1Event(const JoystickEvent& joystickEvent, InputEventArray& inputEventArray);
private:
    static constexpr int32_t default_absx_value = 8188;
    static constexpr int32_t default_absy_value = 8192;
    static constexpr int32_t default_absz_value = 125;
};
} // namespace MMI
} // namespace OHOS
#endif // PROCESSING_JOYSTICK_DEVICE_H