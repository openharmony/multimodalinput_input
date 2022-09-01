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
#ifndef OHOS_INPUT_DEVICE_EVENT_H
#define OHOS_INPUT_DEVICE_EVENT_H

#include <functional>
#include <map>
#include <mutex>
#include <vector>

#include "singleton.h"

#include "i_input_device_listener.h"
#include "input_device.h"
#include "mmi_event_handler.h"

namespace OHOS {
namespace MMI {
class InputDeviceImpl final {
    DECLARE_SINGLETON(InputDeviceImpl);

public:
    DISALLOW_MOVE(InputDeviceImpl);

    using FunInputDevInfo = std::function<void(std::shared_ptr<InputDevice>)>;
    using FunInputDevIds = std::function<void(std::vector<int32_t>&)>;
    using FunInputDevKeys = std::function<void(std::vector<bool>&)>;
    using FunKeyboardTypes = std::function<void(int32_t)>;
    using DevInfo = std::pair<EventHandlerPtr, FunInputDevInfo>;
    using DevIds = std::pair<EventHandlerPtr, FunInputDevIds>;
    using DevKeys = std::pair<EventHandlerPtr, FunInputDevKeys>;
    using DevKeyboardTypes = std::pair<EventHandlerPtr, FunKeyboardTypes>;
    struct InputDeviceData {
        DevInfo inputDevice;
        DevIds ids;
        DevKeys keys;
        DevKeyboardTypes kbTypes;
    };
    using InputDevListenerPtr = std::shared_ptr<IInputDeviceListener>;
    using DevListener = std::pair<EventHandlerPtr, InputDevListenerPtr>;

    int32_t RegisterDevListener(const std::string &type, InputDevListenerPtr listener);
    int32_t UnregisterDevListener(const std::string &type, InputDevListenerPtr listener = nullptr);
    int32_t GetInputDeviceIdsAsync(FunInputDevIds callback);
    int32_t GetInputDeviceAsync(int32_t deviceId, FunInputDevInfo callback);
    int32_t SupportKeys(int32_t deviceId, std::vector<int32_t> keyCodes, FunInputDevKeys callback);
    int32_t GetKeyboardType(int32_t deviceId, FunKeyboardTypes callback);
    void OnInputDevice(int32_t userData, std::shared_ptr<InputDevice> devData);
    void OnInputDeviceIds(int32_t userData, std::vector<int32_t> &ids);
    void OnSupportKeys(int32_t userData, const std::vector<bool> &keystrokeAbility);
    void OnDevListener(int32_t deviceId, const std::string &type);
    void OnKeyboardType(int32_t userData, int32_t keyboardType);
    int32_t GetUserData();
    std::shared_ptr<InputDevice> DevDataUnmarshalling(NetPacket &pkt);

private:
    const DevInfo* GetDeviceInfo(int32_t) const;
    const DevIds* GetDeviceIds(int32_t) const;
    const DevKeys* GetDeviceKeys(int32_t) const;
    const DevKeyboardTypes* GetKeyboardTypes(int32_t) const;
    void OnInputDeviceTask(const DevInfo &devInfo, int32_t userData, std::shared_ptr<InputDevice> devData);
    void OnInputDeviceIdsTask(const DevIds &devIds, int32_t userData, std::vector<int32_t> &ids);
    void OnSupportKeysTask(const DevKeys &devKeys, int32_t userData, std::vector<bool> &supportRet);
    void OnDevListenerTask(const DevListener &devMonitor, const std::string &type, int32_t deviceId);
    void OnKeyboardTypeTask(const DevKeyboardTypes &kbTypes, int32_t userData, int32_t keyboardType);
private:
    std::map<int32_t, InputDeviceData> inputDevices_;
    std::map<std::string, std::list<DevListener>> devListener_ = { { "change", {} } };
    std::mutex mtx_;
    int32_t userData_ {0};
    bool isListeningProcess_ {false};
};

#define InputDevImpl ::OHOS::Singleton<InputDeviceImpl>::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // OHOS_INPUT_DEVICE_EVENT_H