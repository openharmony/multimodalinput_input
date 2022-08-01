/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef INPUT_EVENT_NORMALIZE_H
#define INPUT_EVENT_NORMALIZE_H

#include <memory>

#include "i_input_event_handler.h"
#include "key_event_handler.h"

namespace OHOS {
namespace MMI {
class InputEventNormalizeHandler : public IInputEventHandler {
public:
    InputEventNormalizeHandler() = default;
    ~InputEventNormalizeHandler() = default;
    void HandleEvent(libinput_event* event) override;
    void HandleKeyEvent(std::shared_ptr<KeyEvent> keyEvent) override;
    void HandlePointerEvent(std::shared_ptr<PointerEvent> pointerEvent) override;
    void HandleTouchEvent(std::shared_ptr<PointerEvent> pointerEvent) override;
    int32_t AddHandleTimer(int32_t timeout = 300);

private:
    int32_t OnEventDeviceAdded(libinput_event *event);
    int32_t OnEventDeviceRemoved(libinput_event *event);
    int32_t HandleKeyboardEvent(libinput_event* event);
    void Repeat(const std::shared_ptr<KeyEvent> keyEvent);
    int32_t HandleTouchPadEvent(libinput_event* event);
    int32_t HandleGestureEvent(libinput_event* event);
    int32_t HandleMouseEvent(libinput_event* event);
    int32_t HandleTouchEvent(libinput_event* event);
    int32_t HandleTableToolEvent(libinput_event* event);

private:
    int32_t timerId_ = -1;
    std::shared_ptr<KeyEvent> keyEvent_ = nullptr;
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    KeyEventHandler keyEventHandler_;
#endif // OHOS_BUILD_ENABLE_KEYBOARD
};
} // namespace MMI
} // namespace OHOS
#endif // INPUT_EVENT_NORMALIZE_H