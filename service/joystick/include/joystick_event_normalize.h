/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef JOYSTICK_EVENT_NORMALIZE_H
#define JOYSTICK_EVENT_NORMALIZE_H

#include "device_observer.h"
#include "i_joystick_event_normalize.h"
#include "joystick_event_processor.h"

namespace OHOS {
namespace MMI {
class JoystickEventNormalize final : public IJoystickEventNormalize {
private:
    class InputDeviceObserver final : public IDeviceObserver {
    public:
        InputDeviceObserver(std::shared_ptr<JoystickEventNormalize> parent);
        ~InputDeviceObserver() override = default;
        DISALLOW_COPY_AND_MOVE(InputDeviceObserver);

        void OnDeviceAdded(int32_t deviceId) override;
        void OnDeviceRemoved(int32_t deviceId) override;
        void UpdatePointerDevice(bool hasPointerDevice, bool isVisible, bool isHotPlug) override {}

    private:
        std::weak_ptr<JoystickEventNormalize> parent_;
    };

public:
    static std::shared_ptr<JoystickEventNormalize> GetInstance();

    JoystickEventNormalize() = default;
    ~JoystickEventNormalize();
    DISALLOW_COPY_AND_MOVE(JoystickEventNormalize);

    std::shared_ptr<KeyEvent> OnButtonEvent(struct libinput_event *event) override;
    std::shared_ptr<PointerEvent> OnAxisEvent(struct libinput_event *event) override;
    void CheckIntention(std::shared_ptr<PointerEvent> pointerEvent,
        std::function<void(std::shared_ptr<KeyEvent>)> handler) override;

private:
    void SetUpDeviceObserver(std::shared_ptr<JoystickEventNormalize> self);
    void TearDownDeviceObserver();
    void OnDeviceAdded(int32_t deviceId);
    void OnDeviceRemoved(int32_t deviceId);
    std::shared_ptr<JoystickEventProcessor> GetProcessor(struct libinput_device *inputDev);
    std::shared_ptr<JoystickEventProcessor> FindProcessor(int32_t deviceId) const;

private:
    std::shared_ptr<IDeviceObserver> inputDevObserver_;
    std::map<struct libinput_device*, std::shared_ptr<JoystickEventProcessor>> processors_;
};
} // namespace MMI
} // namespace OHOS
#endif // JOYSTICK_EVENT_NORMALIZE_H
