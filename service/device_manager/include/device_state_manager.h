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

#ifndef DEVICE_STATE_MANAGER_H
#define DEVICE_STATE_MANAGER_H

#include <functional>
#include <map>
#include <memory>
#include <set>
#include <string>

#include "libinput.h"
#include "nocopyable.h"

namespace OHOS {
namespace MMI {
using EnableCallback = std::function<int32_t(int32_t)>;

class DeviceStateManager final {
private:
    class DeviceState final {
    public:
        DeviceState(int32_t deviceId);
        ~DeviceState() = default;
        DISALLOW_COPY(DeviceState);
        DeviceState(DeviceState &&other);
        DeviceState& operator=(DeviceState &&other);

        void HandleEvent(struct libinput_event *event);
        void AddTouches(const std::set<int32_t> &touches);
        void AddPressedButtons(const std::set<int32_t> &pressedButtons);
        void AddPressedKeys(const std::set<int32_t> &pressedKeys);
        void SetProximity(bool proximity);
        void SetAxisBegin(bool axisBegin);
        bool HaveActiveOperations() const;

        void Enable(EnableCallback callback);
        void Disable();
        bool IsEnabled() const;
        void NotifyEnabled();

    private:
        void HandleTouchEvent(struct libinput_event *event);
        void HandlePointerAxisEvent(struct libinput_event *event);
        void HandlePointerButtonEvent(struct libinput_event *event);
        void HandleTouchpadEvent(struct libinput_event *event);
        void HandleKeyboardEvent(struct libinput_event *event);
        void HandleTabletToolEvent(struct libinput_event *event);
        void HandleJoystickButtonEvent(struct libinput_event *event);

        int32_t deviceId_ { -1 };
        bool enabled_ { false };
        bool isProximity_ { false };
        bool isPressed_ { false };
        bool isAxisBegin_ { false };
        std::set<int32_t> touches_;
        std::set<int32_t> pressedButtons_;
        std::set<int32_t> pressedKeys_;
        std::function<int32_t(int32_t)> pendingEnableCallback_;
    };

public:
    static std::shared_ptr<DeviceStateManager> GetInstance();

    DeviceStateManager() = default;
    ~DeviceStateManager() = default;
    DISALLOW_COPY_AND_MOVE(DeviceStateManager);

    void AddTouches(int32_t deviceId, const std::set<int32_t> &touches);
    void AddPressedButtons(int32_t deviceId, const std::set<int32_t> &pressedButtons);
    void AddPressedKeys(int32_t deviceId, const std::set<int32_t> &pressedKeys);
    void SetProximity(int32_t deviceId, bool proximity);
    void SetAxisBegin(int32_t deviceId, bool axisBegin);

    void EnableDevice(int32_t deviceId, EnableCallback callback);
    void DisableDevice(int32_t deviceId);
    void HandleEvent(struct libinput_event *event);
    void OnDeviceRemoved(int32_t deviceId);

private:
    std::map<int32_t, DeviceState> deviceStates_;
};

#define DEVICE_STATE_MGR ::OHOS::MMI::DeviceStateManager::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // DEVICE_STATE_MANAGER_H
