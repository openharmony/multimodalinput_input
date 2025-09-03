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

#ifndef KEY_EVENT_HOOK_HANDLER_H
#define KEY_EVENT_HOOK_HANDLER_H

#include <chrono>
#include <memory>
#include <queue>
#include <shared_mutex>

#include "key_event.h"

namespace OHOS {
namespace MMI {
class KeyEventHookHandler {
public:
    KeyEventHookHandler(const KeyEventHookHandler&) = delete;
    KeyEventHookHandler& operator=(const KeyEventHookHandler&) = delete;
    static KeyEventHookHandler& GetInstance();
private:
    KeyEventHookHandler() = default;
    ~KeyEventHookHandler() = default;

public:
    int32_t AddKeyEventHook(std::function<void(std::shared_ptr<KeyEvent>)> callback, int32_t &hookId);
    int32_t RemoveKeyEventHook(int32_t hookId);
    int32_t DispatchToNextHandler(int32_t eventId);
    void OnKeyEvent(std::shared_ptr<KeyEvent> keyEvent);
    void SetHookIdUpdater(std::function<void(int32_t)> callback);
    std::function<void(int32_t)> GetHookIdUpdater();
    void OnConnected();

private:
    void SetHookCallback(std::function<void(std::shared_ptr<KeyEvent>)> callback);
    void ResetHookCallback();
    std::function<void(std::shared_ptr<KeyEvent>)> GetHookCallback();
    void UpdatePendingKeys();
    void RemoveAllPendingKeys();
    void AppendPendingKeys(int32_t eventId, long long timeStamp);
    void RemoveExpiredPendingKeys(int32_t eventId);
    bool IsValidEvent(int32_t eventId);
    void UpdateGlobalHookId(int32_t hookId);

private:
    struct PendingKey {
        int32_t eventId { -1 };
        long long timeStampRcvd { 0 };
    };

private:
    std::deque<PendingKey> pendingKeys_;
    std::function<void(std::shared_ptr<KeyEvent>)> hookCallback_;
    std::function<void(int32_t)> hookIdUpdater_;
    std::shared_mutex rwMutex_;
};
} // namespace MMI
} // namespace OHOS
#define KEY_EVENT_HOOK_HANDLER OHOS::MMI::KeyEventHookHandler::GetInstance()
#endif // KEY_EVENT_HOOK_HANDLER_H
