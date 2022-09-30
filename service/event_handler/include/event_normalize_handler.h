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

#ifndef EVENT_NORMALIZE_HANDLER_H
#define EVENT_NORMALIZE_HANDLER_H

#include <memory>

#include "i_input_event_handler.h"

namespace OHOS {
namespace MMI {
class EventNormalizeHandler : public IInputEventHandler {
public:
    EventNormalizeHandler() = default;
    ~EventNormalizeHandler() = default;
    void HandleEvent(libinput_event* event);
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    void HandleKeyEvent(const std::shared_ptr<KeyEvent> keyEvent) override;
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#ifdef OHOS_BUILD_ENABLE_POINTER
    void HandlePointerEvent(const std::shared_ptr<PointerEvent> pointerEvent) override;
#endif // OHOS_BUILD_ENABLE_POINTER
#ifdef OHOS_BUILD_ENABLE_TOUCH
    void HandleTouchEvent(const std::shared_ptr<PointerEvent> pointerEvent) override;
#endif // OHOS_BUILD_ENABLE_TOUCH
    int32_t AddHandleTimer(int32_t timeout = 300);
#ifdef OHOS_BUILD_ENABLE_COOPERATE
    bool CheckKeyboardWhiteList(std::shared_ptr<KeyEvent> keyEvent);
#endif // OHOS_BUILD_ENABLE_COOPERATE
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
#ifdef OHOS_BUILD_ENABLE_COOPERATE
    bool IsNeedFilterOut(const std::string& deviceId, const std::shared_ptr<KeyEvent> keyEvent);
#endif // OHOS_BUILD_ENABLE_COOPERATE

private:
    int32_t timerId_ { -1 };
    void ResetTouchUpEvent(std::shared_ptr<PointerEvent> pointerEvent, struct libinput_event *event);
};
} // namespace MMI
} // namespace OHOS
#endif // EVENT_NORMALIZE_HANDLER_H