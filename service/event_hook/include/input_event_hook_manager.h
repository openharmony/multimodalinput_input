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

#ifndef INPUT_EVENT_HOOK_MANAGER_H
#define INPUT_EVENT_HOOK_MANAGER_H

#include <queue>
#include <shared_mutex>

#include "i_input_event_handler.h"
#include "input_event_hook.h"
#include "input_handler_type.h"
#include "key_event.h"
#include "pointer_event.h"
#include "axis_event.h"
#include "uds_session.h"

namespace OHOS {
namespace MMI {
class InputEventHookManager : public IInputEventHandler {
public:
    InputEventHookManager() = default;
    DISALLOW_COPY_AND_MOVE(InputEventHookManager);
    ~InputEventHookManager() override;

public:
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    void HandleKeyEvent(const std::shared_ptr<KeyEvent> keyEvent) override;
    int32_t DispatchToNextHandler(int32_t pid, const std::shared_ptr<KeyEvent> keyEvent);
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#ifdef OHOS_BUILD_ENABLE_POINTER
    void HandlePointerEvent(const std::shared_ptr<PointerEvent> pointerEvent) override;
    int32_t DispatchMouseToNextHandler(int32_t pid, const std::shared_ptr<PointerEvent> pointerEvent);
#endif // OHOS_BUILD_ENABLE_POINTER
#ifdef OHOS_BUILD_ENABLE_TOUCH
    void HandleTouchEvent(const std::shared_ptr<PointerEvent> pointerEvent) override;
    int32_t DispatchTouchToNextHandler(int32_t pid, const std::shared_ptr<PointerEvent> pointerEvent);
#endif // OHOS_BUILD_ENABLE_TOUCH
    int32_t AddInputEventHook(int32_t pid, HookEventType hookEventType);
    int32_t RemoveInputEventHook(int32_t pid, HookEventType hookEventType);
    bool IsHooksExisted(HookEventType hookEventType);
    void Dump(int32_t fd, const std::vector<std::string> &args);

private:
    void Init();
    void InitSessionLostCallback();
    void OnSessionLost(SessionPtr session);
    void PrependHook(HookEventType hookEventType, std::shared_ptr<InputEventHook> hook);
    bool IsHookExisted(int32_t pid, HookEventType hookEventType);
    std::shared_ptr<InputEventHook> GetHookByPid(int32_t pid, HookEventType hookEventType);
    int32_t RemoveHookByPid(int32_t pid, HookEventType hookEventType);
    size_t GetHookNum(HookEventType hookEventType);
    std::shared_ptr<InputEventHook> GetFirstValidHook(HookEventType hookEventType);
    std::shared_ptr<InputEventHook> GetNextHook(std::shared_ptr<InputEventHook> hook);
    bool HandleHooks(const std::shared_ptr<KeyEvent> keyEvent);
    bool HandleHooks(const std::shared_ptr<PointerEvent> pointerEvent);

private:
    std::shared_mutex rwMutex_;
    std::atomic_bool isInitialized_ { false };
    std::unordered_map<HookEventType, std::deque<std::shared_ptr<InputEventHook>>> hooks_;
};
} // namespace MMI
} // namespace OHOS
#endif // INPUT_EVENT_HOOK_MANAGER_H