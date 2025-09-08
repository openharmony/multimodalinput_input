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

#ifndef KEY_EVENT_HOOK_MANAGER_H
#define KEY_EVENT_HOOK_MANAGER_H

#include <chrono>
#include <map>
#include <queue>
#include <shared_mutex>

#include "key_event.h"
#include "uds_session.h"

namespace OHOS {
namespace MMI {
class KeyEventHookManager  {
public:
    KeyEventHookManager(const KeyEventHookManager&) = delete;
    KeyEventHookManager& operator=(const KeyEventHookManager&) = delete;
    static KeyEventHookManager& GetInstance();
private:
    KeyEventHookManager() = default;
    ~KeyEventHookManager() = default;

    struct Hook {
    public:
        Hook(int32_t hookId, SessionPtr sess, std::function<bool(std::shared_ptr<Hook>,
            std::shared_ptr<KeyEvent>)> callback) : id(hookId), session(sess), handler(callback) {}
        int32_t id { -1 };
        SessionPtr session { nullptr };
        std::function<bool(std::shared_ptr<Hook>, std::shared_ptr<KeyEvent>)> handler;
    };

public:
    bool OnKeyEvent(const std::shared_ptr<KeyEvent> keyEvent);
    int32_t AddKeyEventHook(int32_t pid, SessionPtr sess, int32_t &hookId);
    int32_t RemoveKeyEventHook(int32_t pid, int32_t hookId);
    int32_t DispatchToNextHandler(int32_t pid, int32_t eventId);
    bool IsHooksExisted();
    void Dump(int32_t fd, const std::vector<std::string> &args);

private:
    void Init();
    void InitSessionLostCallback();
    void OnSessionLost(SessionPtr session);
    int32_t GenerateHookId();
    void PrependHook(std::shared_ptr<Hook> hook);
    int32_t RemoveHookById(int32_t hookId);
    bool IsHookExisted(int32_t pid);
    bool IsValidKeyEvent(std::shared_ptr<KeyEvent> keyEvent);
    bool HandleHooks(std::shared_ptr<KeyEvent> keyEvent);
    size_t GetHookNum();
    std::shared_ptr<KeyEventHookManager::Hook> GetHookByPid(int32_t pid);
    std::shared_ptr<KeyEventHookManager::Hook> GetFirstValidHook();
    std::shared_ptr<KeyEventHookManager::Hook> GetNextHook(std::shared_ptr<Hook> hook);
    bool HookHandler(SessionPtr session, std::shared_ptr<Hook> hook, std::shared_ptr<KeyEvent> keyEvent);
    bool DispatchDirectly(std::shared_ptr<KeyEvent> keyEvent);
    int32_t CheckAndUpdateEventLoopClosure(int32_t hookId, std::shared_ptr<KeyEvent> keyEvent);
    int32_t HandleEventLoopClosureKeyDown(int32_t hookId, int32_t keyCode);
    int32_t HandleEventLoopClosureKeyUpOrCancel(int32_t hookId, int32_t keyCode);

private:
    std::atomic_bool isInitialized_ { false };
    std::shared_mutex rwMutex_;
    std::deque<std::shared_ptr<Hook>> hooks_;
};
} // namespace MMI
} // namespace OHOS
#define KEY_EVENT_HOOK_MGR OHOS::MMI::KeyEventHookManager::GetInstance()
#endif // KEY_EVENT_HOOK_MANAGER_H