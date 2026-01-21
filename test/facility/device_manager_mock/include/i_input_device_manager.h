/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef MMI_I_INPUT_DEVICE_MANAGER_MOCK_H
#define MMI_I_INPUT_DEVICE_MANAGER_MOCK_H

#include <cstdint>
#include <memory>
#include <vector>

#include "device_observer.h"
#include "input_device.h"
#include "libinput.h"

namespace OHOS {
namespace MMI {
class IInputDeviceManager {
public:
    class IInputDevice {
    public:
        virtual struct libinput_device* GetRawDevice() const = 0;
        virtual std::string GetName() const = 0;
        virtual bool IsJoystick() const = 0;
    };

    virtual bool CheckDevice(int32_t deviceId, std::function<bool(const IInputDevice&)> pred) const = 0;
    virtual void ForEachDevice(std::function<void(int32_t, const IInputDevice&)> callback) const = 0;
    virtual void ForDevice(int32_t deviceId, std::function<void(const IInputDevice&)> callback) const = 0;
    virtual void ForOneDevice(std::function<bool(int32_t, const IInputDevice&)> pred,
        std::function<void(int32_t, const IInputDevice&)> callback) const = 0;
    virtual std::vector<int32_t> GetInputDeviceIds() const = 0;
    virtual std::shared_ptr<InputDevice> GetInputDevice(int32_t deviceId) const = 0;
    virtual std::shared_ptr<InputDevice> GetInputDevice(int32_t deviceId, bool checked) const = 0;
    virtual struct libinput_device* GetLibinputDevice(int32_t deviceId) const = 0;
    virtual bool IsRemoteInputDevice(int32_t deviceId) const = 0;
    virtual int32_t FindInputDeviceId(struct libinput_device* inputDevice) = 0;
    virtual void Attach(std::shared_ptr<IDeviceObserver> observer) = 0;
    virtual void Detach(std::shared_ptr<IDeviceObserver> observer) = 0;
    virtual void GetMultiKeyboardDevice(std::vector<struct libinput_device*> &inputDevice) = 0;
    virtual bool HasLocalMouseDevice() = 0;
    virtual bool HasPointerDevice() = 0;
    virtual std::vector<libinput_device*> GetTouchPadDeviceOrigins() = 0;
    virtual bool GetIsDeviceReportEvent(int32_t deviceId) = 0;
    virtual std::vector<int32_t> GetTouchPadIds() = 0;
    virtual bool IsInputDeviceEnable(int32_t deviceId) = 0;
    virtual bool IsTouchPadDevice(struct libinput_device *device) const = 0;
    virtual void OnInputDeviceAdded(struct libinput_device *inputDevice) = 0;
    virtual void OnInputDeviceRemoved(struct libinput_device *inputDevice) = 0;
    virtual void SetIsDeviceReportEvent(int32_t deviceId, bool isReportEvent) = 0;
};
} // namespace MMI
} // namespace OHOS
#endif // MMI_I_INPUT_DEVICE_MANAGER_MOCK_H
