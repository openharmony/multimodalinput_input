/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef I_INPUT_DEVICE_MANAGER_H
#define I_INPUT_DEVICE_MANAGER_H

#include <cstdint>
#include <functional>
#include <string>

#include "input_device.h"

struct libinput_device;

namespace OHOS {
namespace MMI {
class IInputDeviceManager {
public:
    class IInputDevice {
    public:
        virtual struct libinput_device* GetRawDevice() const = 0;
        virtual std::string GetName() const = 0;
        virtual bool IsJoystick() const = 0;
        virtual bool IsMouse() const = 0;
    };

    virtual bool CheckDevice(int32_t deviceId, std::function<bool(const IInputDevice&)> pred) const = 0;
    virtual void ForEachDevice(std::function<void(int32_t, const IInputDevice&)> callback) const = 0;
    virtual void ForDevice(int32_t deviceId, std::function<void(const IInputDevice&)> callback) const = 0;
    virtual void ForOneDevice(std::function<bool(int32_t, const IInputDevice&)> pred,
        std::function<void(int32_t, const IInputDevice&)> callback) const = 0;
    virtual int32_t FindInputDeviceId(struct libinput_device *device) = 0;
    virtual bool HasPointerDevice() = 0;
    virtual std::shared_ptr<InputDevice> GetInputDevice(int32_t deviceId, bool checked = true) const = 0;
};
} // namespace MMI
} // namespace OHOS
#endif // I_INPUT_DEVICE_MANAGER_H
