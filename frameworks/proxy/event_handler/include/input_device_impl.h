/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_INPUT_DEVICE_EVENT_H
#define OHOS_INPUT_DEVICE_EVENT_H

#include <list>
#include <map>
#include <mutex>

#include "i_input_device_listener.h"
#include "input_device.h"
#include "napi_constants.h"

namespace OHOS {
namespace MMI {
class InputDeviceImpl final {
public:
    static InputDeviceImpl& GetInstance();
    DISALLOW_COPY_AND_MOVE(InputDeviceImpl);
    ~InputDeviceImpl() = default;

    using FunInputDevInfo = std::function<void(std::shared_ptr<InputDevice>)>;
    using FunInputDevIds = std::function<void(std::vector<int32_t>&)>;
    using FunInputDevKeys = std::function<void(std::vector<bool>&)>;
    using FunKeyboardTypes = std::function<void(int32_t)>;
    using InputDevListenerPtr = std::shared_ptr<IInputDeviceListener>;
    using FunSetInputDeviceAck = std::function<void(int32_t)>;

    int32_t RegisterDevListener(const std::string &type, InputDevListenerPtr listener);
    int32_t UnregisterDevListener(const std::string &type, InputDevListenerPtr listener = nullptr);
    int32_t GetInputDeviceIds(FunInputDevIds callback);
    int32_t GetInputDevice(int32_t deviceId, FunInputDevInfo callback);
    int32_t SupportKeys(int32_t deviceId, std::vector<int32_t> keyCodes, FunInputDevKeys callback);
    int32_t GetKeyboardType(int32_t deviceId, FunKeyboardTypes callback);
    int32_t SetKeyboardRepeatDelay(int32_t delay);
    int32_t SetKeyboardRepeatRate(int32_t rate);
    int32_t GetKeyboardRepeatDelay(std::function<void(int32_t)> callback);
    int32_t GetKeyboardRepeatRate(std::function<void(int32_t)> callback);
    void OnInputDevice(int32_t userData, std::shared_ptr<InputDevice> devData);
    void OnInputDeviceIds(int32_t userData, std::vector<int32_t> &ids);
    void OnSupportKeys(int32_t userData, std::vector<bool> &keystrokeAbility);
    void OnDevListener(int32_t deviceId, const std::string &type);
    void OnKeyboardType(int32_t userData, int32_t keyboardType);
    int32_t GetUserData();
    int32_t RegisterInputdevice(int32_t deviceId, bool enable, FunSetInputDeviceAck callback);
    void OnSetInputDeviceAck(int32_t index, int32_t result);

    void OnConnected();
    void OnDisconnected();

private:
    InputDeviceImpl() = default;
    int32_t StartListeningToServer();
    void StopListeningToServer();

    std::map<std::string, std::list<InputDevListenerPtr>> devListener_ {
        { CHANGED_TYPE, {} }
    };
    int32_t userData_ { 0 };
    std::atomic_bool isListeningProcess_ { false };
    std::mutex inputDeviceMutex_;
    std::mutex devListenerMutex_;
    std::map<int32_t, FunSetInputDeviceAck> inputdeviceList_;
    int32_t operationIndex_ { 0 };
};
} // namespace MMI
} // namespace OHOS
#define INPUT_DEVICE_IMPL OHOS::MMI::InputDeviceImpl::GetInstance()
#endif // OHOS_INPUT_DEVICE_EVENT_H