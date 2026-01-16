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

#ifndef JOYSTICK_EVENT_INTERFACE_H
#define JOYSTICK_EVENT_INTERFACE_H

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>

#include "component_manager.h"
#include "device_observer.h"
#include "i_joystick_event_normalize.h"
#include "key_event.h"
#include "libinput.h"
#include "pointer_event.h"

namespace OHOS {
namespace MMI {
class JoystickEventInterface final {
private:
    class InputDeviceObserver final : public IDeviceObserver {
    public:
        InputDeviceObserver(std::shared_ptr<JoystickEventInterface> parent);
        ~InputDeviceObserver() override = default;
        DISALLOW_COPY_AND_MOVE(InputDeviceObserver);

        void OnDeviceAdded(int32_t deviceId) override;
        void OnDeviceRemoved(int32_t deviceId) override;
        void UpdatePointerDevice(bool hasPointerDevice, bool isVisible, bool isHotPlug) override {}

    private:
        std::weak_ptr<JoystickEventInterface> parent_;
    };

public:
    static std::shared_ptr<JoystickEventInterface> GetInstance();

    JoystickEventInterface() = default;
    ~JoystickEventInterface();
    DISALLOW_COPY_AND_MOVE(JoystickEventInterface);

    void AttachInputServiceContext(std::shared_ptr<IInputServiceContext> env);
    std::shared_ptr<KeyEvent> OnButtonEvent(struct libinput_event *event);
    std::shared_ptr<PointerEvent> OnAxisEvent(struct libinput_event *event);
    void CheckIntention(std::shared_ptr<PointerEvent> pointerEvent,
        std::function<void(std::shared_ptr<KeyEvent>)> handler);

private:
    void SetUpDeviceObserver(std::shared_ptr<JoystickEventInterface> self);
    void TearDownDeviceObserver();
    void OnDeviceAdded(std::shared_ptr<JoystickEventInterface> self, int32_t deviceId);
    void OnDeviceRemoved(std::shared_ptr<JoystickEventInterface> self, int32_t deviceId);
    void LoadJoystick();
    void OnJoystickLoaded();
    void UnloadJoystick();

    std::mutex mutex_;
    std::atomic_bool loading_ { false };
    std::weak_ptr<IInputServiceContext> env_;
    std::shared_ptr<IDeviceObserver> inputDevObserver_;
    int32_t unloadTimerId_ { -1 };
    ComponentManager::Handle<IJoystickEventNormalize> joystick_ {
        nullptr, ComponentManager::Component<IJoystickEventNormalize>() };
};

#define JOYSTICK_NORMALIZER OHOS::MMI::JoystickEventInterface::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // JOYSTICK_EVENT_INTERFACE_H
