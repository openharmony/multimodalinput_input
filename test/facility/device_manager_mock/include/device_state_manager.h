/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef MMI_DEVICE_STATE_MANAGER_MOCK_H
#define MMI_DEVICE_STATE_MANAGER_MOCK_H

#include <functional>
#include <map>
#include <memory>
#include <set>
#include <string>

#include "gmock/gmock.h"
#include "libinput.h"
#include "nocopyable.h"

namespace OHOS {
namespace MMI {
using EnableCallback = std::function<int32_t(int32_t)>;

class IDeviceStateManager {
public:
    virtual void AddTouches(int32_t deviceId, const std::set<int32_t> &touches) = 0;
    virtual void AddPressedButtons(int32_t deviceId, const std::set<int32_t> &pressedButtons) = 0;
    virtual void AddPressedKeys(int32_t deviceId, const std::set<int32_t> &pressedKeys) = 0;
    virtual void SetProximity(int32_t deviceId, bool proximity) = 0;
    virtual void SetAxisBegin(int32_t deviceId, bool axisBegin) = 0;

    virtual void EnableDevice(int32_t deviceId, EnableCallback callback) = 0;
    virtual void DisableDevice(int32_t deviceId) = 0;
    virtual void HandleEvent(struct libinput_event *event) = 0;
    virtual void OnDeviceRemoved(int32_t deviceId) = 0;
};

class DeviceStateManager final : public IDeviceStateManager {
public:
    DeviceStateManager() = default;
    ~DeviceStateManager() = default;
    DISALLOW_COPY_AND_MOVE(DeviceStateManager);

    MOCK_METHOD(void, AddTouches, (int32_t, const std::set<int32_t>&), (override));
    MOCK_METHOD(void, AddPressedButtons, (int32_t, const std::set<int32_t>&), (override));
    MOCK_METHOD(void, AddPressedKeys, (int32_t, const std::set<int32_t>&), (override));
    MOCK_METHOD(void, SetProximity, (int32_t, bool), (override));
    MOCK_METHOD(void, SetAxisBegin, (int32_t, bool), (override));

    MOCK_METHOD(void, EnableDevice, (int32_t, EnableCallback), (override));
    MOCK_METHOD(void, DisableDevice, (int32_t), (override));
    MOCK_METHOD(void, HandleEvent, (struct libinput_event *event), (override));
    MOCK_METHOD(void, OnDeviceRemoved, (int32_t), (override));

    static std::shared_ptr<DeviceStateManager> GetInstance();
    static void ReleaseInstance();

private:
    static std::shared_ptr<DeviceStateManager> instance_;
};

#define DEVICE_STATE_MGR ::OHOS::MMI::DeviceStateManager::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // MMI_DEVICE_STATE_MANAGER_MOCK_H
