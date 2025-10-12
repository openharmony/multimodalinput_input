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

#ifndef INPUT_EVENT_STAGER_H
#define INPUT_EVENT_STAGER_H

#include <chrono>
#include <memory>
#include <queue>
#include <shared_mutex>

#include "i_input_event_consumer.h"
#include "key_event.h"
#include "pointer_event.h"

namespace OHOS {
namespace MMI {
class InputEventStager {
public:
    InputEventStager(const InputEventStager&) = delete;
    InputEventStager& operator=(const InputEventStager&) = delete;
    static InputEventStager& GetInstance();
private:
    InputEventStager() = default;
    ~InputEventStager() = default;
public:
    int32_t UpdateKeyEvent(std::shared_ptr<KeyEvent> event);
    int32_t UpdateTouchEvent(std::shared_ptr<PointerEvent> event);
    int32_t UpdateMouseEvent(std::shared_ptr<PointerEvent> event);
    std::shared_ptr<KeyEvent> GetKeyEvent(int32_t eventId);
    std::shared_ptr<PointerEvent> GetTouchEvent(int32_t eventId);
    std::shared_ptr<PointerEvent> GetMouseEvent(int32_t eventId);
    void ClearStashEvents(HookEventType hookEventType);
    
private:
    int32_t RemoveExpiredKeyEvent();
    int32_t RemoveExpiredTouchEvent();
    int32_t RemoveExpiredMouseEvent();
    static long long GetNowMs();

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

private:
    std::deque<StashKeyEvent> stashKeyEvents_;
    std::deque<StashTouchEvent> stashTouchEvents_;
    std::deque<StashMouseEvent> stashMouseEvents_;
    std::shared_mutex rwMutex_;
};
} // namespace MMI
} // namespace OHOS
#define INPUT_EVENT_STAGER OHOS::MMI::InputEventStager::GetInstance()
#endif // INPUT_EVENT_HOOK_HANDLER_H