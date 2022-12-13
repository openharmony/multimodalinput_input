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

#include "device_base.h"
#include "msg_head.h"

namespace OHOS {
namespace MMI {
class ProcessingJoystickDevice : public DeviceBase {
public:
    ProcessingJoystickDevice() = default;
    DISALLOW_COPY_AND_MOVE(ProcessingJoystickDevice);
    ~ProcessingJoystickDevice() = default;
    int32_t TransformJsonDataToInputData(const DeviceItem& originalEvent, InputEventArray& inputEventArray);
private:
    void TransformPadEventToInputEvent(const std::vector<DeviceEvent>& inputData,
                                       InputEventArray& inputEventArray);
    void TransformKeyPressEvent(const DeviceEvent& joystickEvent, InputEventArray& inputEventArray);
    void TransformKeyReleaseEvent(const DeviceEvent& joystickEvent, InputEventArray& inputEventArray);
    void TransformKeyClickEvent(const DeviceEvent& joystickEvent, InputEventArray& inputEventArray);
    void TransformRocker1Event(const DeviceEvent& joystickEvent, InputEventArray& inputEventArray);
    void TransformDirectionKeyEvent(const DeviceEvent& joystickEvent, InputEventArray& inputEventArray);
    void TransformThrottle1Event(const DeviceEvent& joystickEvent, InputEventArray& inputEventArray);
};
} // namespace MMI
} // namespace OHOS
#endif // PROCESSING_JOYSTICK_DEVICE_H