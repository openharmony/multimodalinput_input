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

#ifndef MMI_JOYSTICK_EVENT_INTERFACE_MOCK_H
#define MMI_JOYSTICK_EVENT_INTERFACE_MOCK_H

#include <functional>
#include <memory>

#include "gmock/gmock.h"
#include "key_event.h"
#include "libinput.h"
#include "nocopyable.h"
#include "pointer_event.h"

namespace OHOS {
namespace MMI {
class IJoystickEventInterface {
public:
    IJoystickEventInterface() = default;
    virtual ~IJoystickEventInterface() = default;

    virtual std::shared_ptr<KeyEvent> OnButtonEvent(struct libinput_event *event) = 0;
    virtual std::shared_ptr<PointerEvent> OnAxisEvent(struct libinput_event *event) = 0;
    virtual void CheckIntention(std::shared_ptr<PointerEvent> pointerEvent,
        std::function<void(std::shared_ptr<KeyEvent>)> handler) = 0;
};

class JoystickEventInterface final : public IJoystickEventInterface {
public:
    static std::shared_ptr<JoystickEventInterface> GetInstance();
    static void ReleaseInstance();

    JoystickEventInterface() = default;
    ~JoystickEventInterface() override = default;
    DISALLOW_COPY_AND_MOVE(JoystickEventInterface);

    MOCK_METHOD(std::shared_ptr<KeyEvent>, OnButtonEvent, (struct libinput_event*));
    MOCK_METHOD(std::shared_ptr<PointerEvent>, OnAxisEvent, (struct libinput_event*));
    MOCK_METHOD(void, CheckIntention,
        (std::shared_ptr<PointerEvent>, std::function<void(std::shared_ptr<KeyEvent>)>));

private:
    static std::shared_ptr<JoystickEventInterface> instance_;
};

#define JOYSTICK_NORMALIZER OHOS::MMI::JoystickEventInterface::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // MMI_JOYSTICK_EVENT_INTERFACE_MOCK_H
