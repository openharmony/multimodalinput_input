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

#include "joystick_event_processor.h"

namespace OHOS {
namespace MMI {
class JoystickEventNormalize final {
public:
    JoystickEventNormalize() = default;
    ~JoystickEventNormalize() = default;
    DISALLOW_COPY_AND_MOVE(JoystickEventNormalize);

    std::shared_ptr<KeyEvent> OnButtonEvent(struct libinput_event *event);
    std::shared_ptr<PointerEvent> OnAxisEvent(struct libinput_event *event);
    void CheckIntention(std::shared_ptr<PointerEvent> pointerEvent,
        std::function<void(std::shared_ptr<KeyEvent>)> handler);

private:
    std::shared_ptr<JoystickEventProcessor> GetProcessor(struct libinput_device *inputDev);
    std::shared_ptr<JoystickEventProcessor> FindProcessor(int32_t deviceId) const;

private:
    std::map<struct libinput_device*, std::shared_ptr<JoystickEventProcessor>> processors_;
};
} // namespace MMI
} // namespace OHOS
#endif // JOYSTICK_EVENT_NORMALIZE_H
