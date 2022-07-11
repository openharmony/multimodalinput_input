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

#include "nocopyable.h"

#include "mmi_event_handler.h"

namespace OHOS {
namespace MMI {
class InputDeviceImpl {
public:
    static InputDeviceImpl& GetInstance();
    DISALLOW_COPY_AND_MOVE(InputDeviceImpl);
    ~InputDeviceImpl() = default;

    struct AxisInfo {
        int32_t axisType { 0 };
        int32_t min { 0 };
        int32_t max { 0 };
        int32_t fuzz { 0 };
        int32_t flat { 0 };
        int32_t resolution { 0 };
    };
    struct InputDeviceInfo {
        int32_t id { -1 };
        std::string name { "null" };
        uint32_t deviceType { 0 };
        int32_t busType { 0 };
        int32_t product { 0 };
        int32_t vendor { 0 };
        int32_t version { 0 };
        std::string phys { "null" };
        std::string uniq { "null" };
        std::vector<AxisInfo> axis;
    };

    using CppFunInputDevInfo = std::function<void(const std::shared_ptr<InputDeviceInfo>)>;
    using CppFunInputDevIds = std::function<void(std::vector<int32_t>&)>;

    using FunInputDevInfo = std::function<void(int32_t, std::shared_ptr<InputDeviceInfo>)>;
    using FunInputDevIds = std::function<void(int32_t, std::vector<int32_t>&)>;
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
        CppFunInputDevInfo cppDev { nullptr };
        CppFunInputDevIds cppIds { nullptr };
    };
    using FunInputDevMonitor = std::function<void(std::string, int32_t)>;
    using DevMonitor = std::pair<EventHandlerPtr, FunInputDevMonitor>;

    void RegisterInputDeviceMonitor(std::function<void(std::string, int32_t)> listening);
    void UnRegisterInputDeviceMonitor();

    void GetInputDeviceIdsAsync(std::function<void(int32_t, std::vector<int32_t>&)> callback);
    void GetInputDeviceAsync(int32_t deviceId,
        std::function<void(int32_t, std::shared_ptr<InputDeviceInfo>)> callback);
    void SupportKeys(int32_t deviceId, std::vector<int32_t> keyCodes,
        std::function<void(std::vector<bool>&)> callback);
    void GetKeyboardType(int32_t deviceId, std::function<void(int32_t)> callback);
    void OnInputDevice(int32_t userData, std::shared_ptr<InputDeviceInfo> devData);
    void OnInputDeviceIds(int32_t userData, std::vector<int32_t> &ids);
    void OnSupportKeys(int32_t userData, const std::vector<bool> &keystrokeAbility);
    void OnDevMonitor(std::string type, int32_t deviceId);
    void OnKeyboardType(int32_t userData, int32_t keyboardType);
    int32_t GetUserData();

private:
    const DevInfo* GetDeviceInfo(int32_t) const;
    const DevIds* GetDeviceIds(int32_t) const;
    const DevKeys* GetDeviceKeys(int32_t) const;
    const DevKeyboardTypes* GetKeyboardTypes(int32_t) const;
    void OnInputDeviceTask(InputDeviceImpl::DevInfo devInfo, int32_t userData,
        std::shared_ptr<InputDeviceInfo> devData);
    void OnInputDeviceIdsTask(InputDeviceImpl::DevIds devIds, int32_t userData, std::vector<int32_t> ids);
    void OnSupportKeysTask(InputDeviceImpl::DevKeys devKeys, int32_t userData,
        std::vector<bool> keystrokeAbility);
    void OnDevMonitorTask(DevMonitor devMonitor, std::string type, int32_t deviceId);
    void OnKeyboardTypeTask(InputDeviceImpl::DevKeyboardTypes kbTypes, int32_t userData,
        int32_t keyboardType);
private:
    InputDeviceImpl() = default;
    std::map<int32_t, InputDeviceData> inputDevices_;
    DevMonitor devMonitor_;
    std::mutex mtx_;
    int32_t userData_ {0};
};
} // namespace MMI
} // namespace OHOS
#define InputDevImpl OHOS::MMI::InputDeviceImpl::GetInstance()
#endif // OHOS_INPUT_DEVICE_EVENT_H