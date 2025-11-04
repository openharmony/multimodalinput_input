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

#ifndef MMI_I_JOYSTICK_EVENT_NORMALIZE_MOCK_H
#define MMI_I_JOYSTICK_EVENT_NORMALIZE_MOCK_H

#include <functional>
#include <memory>

#include "libinput.h"

#include "key_event.h"
#include "pointer_event.h"

namespace OHOS {
namespace MMI {
class IJoystickEventNormalize {
public:
    static std::shared_ptr<IJoystickEventNormalize> GetInstance();

    IJoystickEventNormalize() = default;
    virtual ~IJoystickEventNormalize() = default;

    virtual std::shared_ptr<KeyEvent> OnButtonEvent(struct libinput_event *event) = 0;
    virtual std::shared_ptr<PointerEvent> OnAxisEvent(struct libinput_event *event) = 0;
    virtual void CheckIntention(std::shared_ptr<PointerEvent> pointerEvent,
        std::function<void(std::shared_ptr<KeyEvent>)> handler) = 0;
};

#define JOYSTICK_NORMALIZER OHOS::MMI::IJoystickEventNormalize::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // MMI_I_JOYSTICK_EVENT_NORMALIZE_MOCK_H
