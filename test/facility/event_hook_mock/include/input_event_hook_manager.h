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

#ifndef MMI_INPUT_EVENT_HOOK_MANAGER_MOCK_H
#define MMI_INPUT_EVENT_HOOK_MANAGER_MOCK_H

#include "gmock/gmock.h"
#include "i_input_event_handler.h"
#include "input_handler_type.h"
#include "nocopyable.h"

namespace OHOS {
namespace MMI {
class IInputEventHookManager : public IInputEventHandler {
public:
    IInputEventHookManager() = default;
    virtual ~IInputEventHookManager() = default;

    virtual int32_t AddInputEventHook(int32_t pid, HookEventType hookEventType) = 0;
    virtual int32_t RemoveInputEventHook(int32_t pid, HookEventType hookEventType) = 0;
};

class InputEventHookManager final : public IInputEventHookManager {
public:
    static std::shared_ptr<InputEventHookManager> GetInstance();
    static void ReleaseInstance();

    InputEventHookManager() = default;
    ~InputEventHookManager() override = default;
    DISALLOW_COPY_AND_MOVE(InputEventHookManager);

    MOCK_METHOD(void, HandleKeyEvent, (const std::shared_ptr<KeyEvent>));
    MOCK_METHOD(void, HandlePointerEvent, (const std::shared_ptr<PointerEvent>));
    MOCK_METHOD(void, HandleTouchEvent, (const std::shared_ptr<PointerEvent>));
    MOCK_METHOD(int32_t, AddInputEventHook, (int32_t, HookEventType));
    MOCK_METHOD(int32_t, RemoveInputEventHook, (int32_t, HookEventType));

private:
    static std::shared_ptr<InputEventHookManager> instance_;
};
} // namespace MMI
} // namespace OHOS
#endif // MMI_INPUT_EVENT_HOOK_MANAGER_MOCK_H
