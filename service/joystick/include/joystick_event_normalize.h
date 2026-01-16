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

#include "i_joystick_event_normalize.h"
#include "joystick_event_processor.h"

namespace OHOS {
namespace MMI {
class JoystickEventNormalize final : public IJoystickEventNormalize {
public:
    explicit JoystickEventNormalize(IInputServiceContext *env);
    ~JoystickEventNormalize() = default;
    DISALLOW_COPY_AND_MOVE(JoystickEventNormalize);

    void OnDeviceAdded(int32_t deviceId) override;
    void OnDeviceRemoved(int32_t deviceId) override;
    bool HasJoystick() const override;
    std::shared_ptr<KeyEvent> OnButtonEvent(struct libinput_event *event) override;
    std::shared_ptr<PointerEvent> OnAxisEvent(struct libinput_event *event) override;
    void CheckIntention(std::shared_ptr<PointerEvent> pointerEvent,
        std::function<void(std::shared_ptr<KeyEvent>)> handler) override;

    static std::shared_ptr<ITimerManager> GetTimerManager(IInputServiceContext *env);
    static std::shared_ptr<IInputWindowsManager> GetInputWindowsManager(IInputServiceContext *env);
    static std::shared_ptr<IInputDeviceManager> GetDeviceManager(IInputServiceContext *env);
    static std::shared_ptr<IKeyMapManager> GetKeyMapManager(IInputServiceContext *env);

private:
    std::shared_ptr<JoystickEventProcessor> GetProcessor(struct libinput_device *inputDev);
    std::shared_ptr<JoystickEventProcessor> FindProcessor(int32_t deviceId) const;

private:
    IInputServiceContext *env_ { nullptr };
    std::map<struct libinput_device*, std::shared_ptr<JoystickEventProcessor>> processors_;
};
} // namespace MMI
} // namespace OHOS
#endif // JOYSTICK_EVENT_NORMALIZE_H
