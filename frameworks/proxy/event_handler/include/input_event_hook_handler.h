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

#ifndef INPUT_EVENT_HOOK_HANDLER_H
#define INPUT_EVENT_HOOK_HANDLER_H

#include <chrono>
#include <memory>
#include <queue>
#include <shared_mutex>

#include "i_input_event_consumer.h"
#include "key_event.h"
#include "pointer_event.h"

namespace OHOS {
namespace MMI {
class InputEventHookHandler {
public:
    InputEventHookHandler(const InputEventHookHandler&) = delete;
    InputEventHookHandler& operator=(const InputEventHookHandler&) = delete;
    static InputEventHookHandler& GetInstance();
private:
    InputEventHookHandler() = default;
    ~InputEventHookHandler() = default;

public:
    int32_t AddInputEventHook(std::shared_ptr<IInputEventConsumer> consumer, HookEventType hookEventType);
    int32_t RemoveInputEventHook(HookEventType hookEventType);
    int32_t DispatchToNextHandler(int32_t eventId, HookEventType hookEventType);
    void OnKeyEvent(std::shared_ptr<KeyEvent> keyEvent);
    void OnPointerEvent(std::shared_ptr<PointerEvent> pointerEvent);
    void OnConnected();

private:
    void AddKeyHook(std::function<void(std::shared_ptr<KeyEvent>)> keyHook);
    void AddMouseHook(std::function<void(std::shared_ptr<PointerEvent>)> mouseHook);
    void AddTouchHook(std::function<void(std::shared_ptr<PointerEvent>)> touchHook);
    int32_t AddInputEventHookLocal(std::shared_ptr<IInputEventConsumer> consumer, HookEventType hookEventType);
    int32_t AddInputEventHookToServer(HookEventType hookEventType);
    int32_t RemoveInputEventHookLocal(HookEventType hookEventType);
    int32_t RemoveInputEventHookOfServer(HookEventType hookEventType);
    bool CheckHookStatsBit(HookEventType hookEventType);
    void SetHookStatsBit(HookEventType hookEventType);
    void ClearHookStatsBit(HookEventType hookEventType);
    bool IsHookExisted(HookEventType hookEventType);
    int32_t DispatchToNextHandler(std::shared_ptr<KeyEvent> keyEvent);
    int32_t DispatchToNextHandler(std::shared_ptr<PointerEvent> pointerEvent);

private:
    struct StashKeyEvent {
        std::shared_ptr<KeyEvent> event;
        long long timeStampRcvd { 0 };
    };

    struct StashPointerEvent {
        std::shared_ptr<PointerEvent> event;
        long long timeStampRcvd { 0 };
    };

    using StashTouchEvent = StashPointerEvent;
    using StashMouseEvent = StashPointerEvent;

    struct HookConsumer {
        std::function<void(std::shared_ptr<KeyEvent>)> keyHookCallback_;
        std::function<void(std::shared_ptr<PointerEvent>)> touchHookCallback_;
        std::function<void(std::shared_ptr<PointerEvent>)> mouseHookCallback_;
    };

private:
    std::deque<StashKeyEvent> stashKeyEvents_;
    std::deque<StashTouchEvent> stashTouchEvents_;
    std::deque<StashMouseEvent> stashMouseEvents_;
    HookConsumer hookConsumer_;
    std::atomic_uint32_t currentHookStats_ { 0 };
    std::shared_mutex rwMutex_;
};
} // namespace MMI
} // namespace OHOS
#define INPUT_EVENT_HOOK_HANDLER OHOS::MMI::InputEventHookHandler::GetInstance()
#endif // INPUT_EVENT_HOOK_HANDLER_H