/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef EVENT_NORMALIZE_HANDLER_H
#define EVENT_NORMALIZE_HANDLER_H

#include <chrono>
#include <condition_variable>
#include <ctime>
#include <fstream>
#include <iostream>
#include <list>
#include <memory>
#include <mutex>
#include <queue>
#include <sstream>
#include <stdio.h>
#include <string>
#include <sys/stat.h>
#include <thread>

#include "i_input_event_handler.h"
#include "key_event_normalize.h"

namespace OHOS {
namespace MMI {
class EventNormalizeHandler : public IInputEventHandler {
public:
    EventNormalizeHandler() = default;
    ~EventNormalizeHandler() = default;
    void HandleEvent(libinput_event* event, int64_t frameTime);
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
    static void PushEventStr();
    static std::string PopEventStr();
    static void WriteEventFile();
    void Dump(int32_t fd, const std::vector<std::string> &args);
    std::string::size_type InitEventString(int32_t eventType);
    std::string ConvertKeyEventToStr(const std::shared_ptr<KeyEvent> keyEvent);
    std::string ConvertPointerEventToStr(const std::shared_ptr<PointerEvent> pointerEvent);
    std::string ConvertSwitchEventToStr(const std::shared_ptr<SwitchEvent> switchEvent);
    std::string ConvertTimeToStr(int64_t timestamp);
private:
    int32_t OnEventDeviceAdded(libinput_event *event);
    int32_t OnEventDeviceRemoved(libinput_event *event);
    int32_t HandleKeyboardEvent(libinput_event* event);
    void Repeat(const std::shared_ptr<KeyEvent> keyEvent);
    int32_t HandleTouchPadEvent(libinput_event* event);
    int32_t HandleGestureEvent(libinput_event* event);
    int32_t HandleMouseEvent(libinput_event* event);
    int32_t HandleTouchEvent(libinput_event* event, int64_t frameTime);
    int32_t HandleSwitchInputEvent(libinput_event* event);
    int32_t HandleTableToolEvent(libinput_event* event);
    int32_t HandleJoystickEvent(libinput_event* event);
    void HandlePalmEvent(libinput_event* event, std::shared_ptr<PointerEvent> pointerEvent);
    int32_t GestureIdentify(libinput_event* event);
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    void UpdateKeyEventHandlerChain(const std::shared_ptr<KeyEvent> keyEvent);
#endif // OHOS_BUILD_ENABLE_KEYBOARD
    int32_t SetOriginPointerId(std::shared_ptr<PointerEvent> pointerEvent);

private:
    static std::queue<std::string> eventQueue_;
    static std::list<std::string> dumperEventList_;
    static std::mutex queueMutex_;
    static std::condition_variable queueCondition_;
    static bool runningSignal_;
    static std::string eventString_;
    int32_t timerId_ { -1 };
    bool isShield_ { false };
    std::set<int32_t> buttonIds_ {};
    void ResetTouchUpEvent(std::shared_ptr<PointerEvent> pointerEvent, struct libinput_event *event);
    bool ProcessNullEvent(libinput_event *event, int64_t frameTime);
    void RestoreTouchPadStatus();
    void TerminateRotate(libinput_event* event);
    void TerminateAxis(libinput_event* event);
};
} // namespace MMI
} // namespace OHOS
#endif // EVENT_NORMALIZE_HANDLER_H