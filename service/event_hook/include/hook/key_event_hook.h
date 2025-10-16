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

#ifndef KEY_EVENT_HOOK_H
#define KEY_EVENT_HOOK_H

#include "input_event_hook.h"
#include <shared_mutex>
#include "dispatch_order_checker.h"
#include "expiration_checker.h"
#include "key_loop_closure_checker.h"
#include "key_event.h"
#include "uds_session.h"

namespace OHOS {
namespace MMI {

class KeyEventHook final: public InputEventHook {
public:
    KeyEventHook(SessionPtr session, NextHookGetter nextHookGetter) :InputEventHook(session, HOOK_EVENT_TYPE_KEY,
        nextHookGetter) {}
    bool OnKeyEvent(std::shared_ptr<KeyEvent> keyEvent) override;
    int32_t DispatchToNextHandler(std::shared_ptr<KeyEvent> keyEvent) override;

private:
    bool DispatchDirectly(std::shared_ptr<KeyEvent> keyEvent);

private:
    DispatchOrderChecker orderChecker_;
    ExpirationChecker expirationChecker_;
    KeyLoopClosureChecker closureChecker_;
};
} // namespace MMI
} // namespace OHOS
#endif // KEY_EVENT_HOOK_H