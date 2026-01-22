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

#ifndef MMI_INPUT_DEVICE_MANAGER_MOCK_H
#define MMI_INPUT_DEVICE_MANAGER_MOCK_H

#include <unordered_map>
#include <gmock/gmock.h>

#include "i_input_device_manager.h"
#include "nocopyable.h"
#include "uds_session.h"

namespace OHOS {
namespace MMI {
class InputDeviceManagerMock final : public IInputDeviceManager {
public:
    class HiddenInputDevice : public IInputDevice {
    public:
        HiddenInputDevice() = default;
        virtual ~HiddenInputDevice() = default;
        DISALLOW_COPY_AND_MOVE(HiddenInputDevice);

        MOCK_METHOD(struct libinput_device*, GetRawDevice, (), (const));
        MOCK_METHOD(std::string, GetName, (), (const));
        MOCK_METHOD(bool, IsJoystick, (), (const));
    };

    void AddInputDevice(int32_t deviceId, std::shared_ptr<IInputDevice> dev);
    void RemoveInputDevice(int32_t deviceId);
    bool CheckDevice(int32_t deviceId, std::function<bool(const IInputDevice&)> pred) const;
    void ForEachDevice(std::function<void(int32_t, const IInputDevice&)> callback) const;
    void ForDevice(int32_t deviceId, std::function<void(const IInputDevice&)> callback) const;
    void ForOneDevice(std::function<bool(int32_t, const IInputDevice&)> pred,
        std::function<void(int32_t, const IInputDevice&)> callback) const;
    MOCK_METHOD(std::vector<int32_t>, GetInputDeviceIds, (), (const));
    MOCK_METHOD(std::shared_ptr<InputDevice>, GetInputDevice, (int32_t), (const));
    MOCK_METHOD(std::shared_ptr<InputDevice>, GetInputDevice, (int32_t, bool), (const));
    MOCK_METHOD(struct libinput_device*, GetLibinputDevice, (int32_t), (const));
    MOCK_METHOD(bool, IsRemoteInputDevice, (int32_t), (const));
    MOCK_METHOD(int32_t, FindInputDeviceId, (struct libinput_device*));
    MOCK_METHOD(void, Attach, (std::shared_ptr<IDeviceObserver>));
    MOCK_METHOD(void, Detach, (std::shared_ptr<IDeviceObserver>));
    MOCK_METHOD(void, GetMultiKeyboardDevice, (std::vector<struct libinput_device*>&));
    MOCK_METHOD(bool, HasLocalMouseDevice, ());
    MOCK_METHOD(bool, HasPointerDevice, ());
    MOCK_METHOD(std::vector<libinput_device*>, GetTouchPadDeviceOrigins, ());
    MOCK_METHOD(bool, GetIsDeviceReportEvent, (int32_t));
    MOCK_METHOD(std::vector<int32_t>, GetTouchPadIds, ());
    MOCK_METHOD(bool, IsInputDeviceEnable, (int32_t));
    MOCK_METHOD(bool, IsTouchPadDevice, (struct libinput_device*), (const));
    MOCK_METHOD(void, OnInputDeviceAdded, (struct libinput_device*));
    MOCK_METHOD(void, OnInputDeviceRemoved, (struct libinput_device*));
    MOCK_METHOD(void, SetIsDeviceReportEvent, (int32_t, bool));

    static std::shared_ptr<InputDeviceManagerMock> GetInstance();
    static void ReleaseInstance();

private:
    std::unordered_map<int32_t, std::shared_ptr<IInputDevice>> devices_;
    static std::shared_ptr<InputDeviceManagerMock> instance_;
};

#define INPUT_DEV_MGR InputDeviceManagerMock::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // MMI_INPUT_DEVICE_MANAGER_MOCK_H