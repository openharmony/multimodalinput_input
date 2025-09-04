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

#include "key_event_hook_manager.h"

#include "error_multimodal.h"
#include "event_dispatch_order_checker.h"
#include "event_loop_closure_checker.h"
#include "input_event_data_transformation.h"
#include "input_event_handler.h"
#include "timer_manager.h"
#include "util_ex.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyEventHookManager"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t STASH_EVENT_TIMEOUT_MS { 3000 };
} // namespace

KeyEventHookManager &KeyEventHookManager::GetInstance()
{
    static KeyEventHookManager instance;
    return instance;
}

bool KeyEventHookManager::OnKeyEvent(const std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    if (!IsValidKeyEvent(keyEvent)) {
        return false;
    }
    return HandleHooks(keyEvent);
}

bool KeyEventHookManager::IsValidKeyEvent(std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPF(keyEvent);
    return keyEvent->GetKeyCode() > KeyEvent::KEYCODE_UNKNOWN;
}

int32_t KeyEventHookManager::AddKeyEventHook(int32_t pid, SessionPtr sess, int32_t &hookId)
{
    CALL_INFO_TRACE;
    CHKPR(sess, RET_ERR);
    Init();
    if (IsHookExisted(pid)) {
        MMI_HILOGE("Hook from pid:%{public}d existed already", pid);
        return ERROR_REPEAT_INTERCEPTOR;
    }
    auto hook = std::make_shared<Hook>(GenerateHookId(), sess, [sess, this] (std::shared_ptr<Hook> hook,
        std::shared_ptr<KeyEvent> keyEvent) -> bool {
        return this->HookHandler(sess, hook, keyEvent);
    });
    CHKPR(hook, RET_ERR);
    PrependHook(hook);
    hookId = hook->id;
    return RET_OK;
}

int32_t KeyEventHookManager::RemoveKeyEventHook(int32_t pid, int32_t hookId)
{
    CALL_INFO_TRACE;
    if (!IsHookExisted(pid)) {
        MMI_HILOGW("No hook from pid:%{public}d", pid);
        return RET_OK;
    }
    if (RemoveHookById(hookId) != RET_OK) {
        MMI_HILOGW("RemoveHookById failed, hookId:%{public}d", hookId);
        return RET_ERR;
    }
    if (EVENT_LOOP_CLOSURE_CHECKER.RemoveChecker(hookId) != RET_OK) {
        MMI_HILOGW("RemoveChecker of hook:%{public}d failed", hookId);
    }
    if (EVENT_DISPATCH_ORDER_CHECKER.RemoveChecker(hookId) != RET_OK) {
        MMI_HILOGW("RemoveChecker of hook:%{public}d failed", hookId);
    }
    return RET_OK;
}

int32_t KeyEventHookManager::DispatchToNextHandler(int32_t pid, int32_t eventId)
{
    CALL_DEBUG_ENTER;
    if (!IsHookExisted(pid)) {
        MMI_HILOGW("No hook from pid:%{public}d", pid);
        return ERROR_INVALID_PARAMETER;
    }
    static StashEvent stashEvent;
    if (GetStashEvent(eventId, stashEvent) != RET_OK) {
        MMI_HILOGW("GetStashEvent failed, eventId:%{public}d, caused by timeout or invalid eventId", eventId);
        return ERROR_INVALID_PARAMETER;
    }
    CHKPR(stashEvent.hook, RET_ERR);
    if (EVENT_DISPATCH_ORDER_CHECKER.CheckDispatchOrder(stashEvent.hook->id, eventId) != RET_OK) {
        MMI_HILOGW("CheckDispatchOrder failed, eventId:%{public}d", eventId);
        return ERROR_INVALID_PARAMETER;
    }
    if (CheckAndUpdateEventLoopClosure(stashEvent) != RET_OK) {
        MMI_HILOGW("CheckAndUpdateEventLoopClosure failed, eventId:%{public}d", eventId);
        return RET_OK;
    }
    RemoveStashEvent(eventId);
    auto nextHook = GetNextHook(stashEvent.hook);
    bool ret { false };
    if (nextHook != nullptr && nextHook->handler != nullptr) {
        ret = nextHook->handler(nextHook, stashEvent.keyEvent);
    } else { // No hooks left, dispatch directly
        ret = DispatchDirectly(stashEvent.keyEvent);
    }
    EVENT_DISPATCH_ORDER_CHECKER.UpdateLastDispatchedId(stashEvent.hook->id, eventId);
    return ret ? RET_OK : RET_ERR;
}

void KeyEventHookManager::InitSessionLostCallback()
{
    CALL_INFO_TRACE;
    auto udsServerPtr = InputHandler->GetUDSServer();
    CHKPV(udsServerPtr);
    udsServerPtr->AddSessionDeletedCallback(
        [this] (SessionPtr session) {
            return this->OnSessionLost(session);
        }
    );
}

void KeyEventHookManager::Init()
{
    CALL_INFO_TRACE;
    std::unique_lock<std::shared_mutex> lock(rwMutex_);
    if (isInitialized_.load())  {
        return;
    }
    InitSessionLostCallback();
    isInitialized_.store(true);
}

void KeyEventHookManager::OnSessionLost(SessionPtr session)
{
    CALL_INFO_TRACE;
    CHKPV(session);
    auto pid = session->GetPid();
    auto hook = GetHookByPid(pid);
    CHKPV(hook);
    if (EVENT_LOOP_CLOSURE_CHECKER.RemoveChecker(hook->id) != RET_OK) {
        MMI_HILOGW("RemoveChecker of hook:%{public}d, pid:%{public}d failed", hook->id, pid);
    }
    if (EVENT_DISPATCH_ORDER_CHECKER.RemoveChecker(hook->id) != RET_OK) {
        MMI_HILOGW("RemoveChecker of hook:%{public}d failed", hook->id);
    }
    if (RemoveHookById(hook->id) != RET_OK) {
        MMI_HILOGE("Remove hook:%{public}d of pid:%{public}d failed", hook->id, pid);
    }
}

int32_t KeyEventHookManager::GenerateHookId()
{
    static std::atomic_int32_t globalHookId { 0 };
    return globalHookId++;
}

void KeyEventHookManager::PrependHook(std::shared_ptr<Hook> hook)
{
    CALL_DEBUG_ENTER;
    std::unique_lock<std::shared_mutex> lock(rwMutex_);
    hooks_.push_front(hook);
}

int32_t KeyEventHookManager::RemoveHookById(int32_t hookId)
{
    CALL_DEBUG_ENTER;
    std::unique_lock<std::shared_mutex> lock(rwMutex_);
    auto iter = std::find_if(hooks_.begin(), hooks_.end(), [hookId](const auto &hook) -> bool {
        CHKPF(hook);
        return hook->id == hookId;
    });
    if (iter == hooks_.end()) {
        MMI_HILOGW("No hook with id:%{public}d existed", hookId);
        return RET_ERR;
    }
    hooks_.erase(iter);
    return RET_OK;
}

bool KeyEventHookManager::IsHookExisted(int32_t pid)
{
    std::shared_lock<std::shared_mutex> lock(rwMutex_);
    auto iter = std::find_if(hooks_.begin(), hooks_.end(), [pid] (const auto &hook) -> bool {
        CHKPF(hook);
        CHKPF(hook->session);
        return hook->session->GetPid() == pid;
    });
    return iter != hooks_.end();
}

bool KeyEventHookManager::IsHooksExisted()
{
    CALL_DEBUG_ENTER;
    std::shared_lock<std::shared_mutex> lock(rwMutex_);
    return !hooks_.empty();
}

void KeyEventHookManager::Dump(int32_t fd, const std::vector<std::string> &args)
{
    CALL_INFO_TRACE;
    mprintf(fd, "Hook information:\t");
    mprintf(fd, "Hook count: %zu", GetHookNum());
    std::shared_lock<std::shared_mutex> lock(rwMutex_);
    for (const auto &hook : hooks_) {
        CHKPC(hook);
        mprintf(fd, "HookId:%10d \t", hook->id);
        CHKPC(hook->session);
        mprintf(fd, "Pid   :%10d \t", hook->session->GetPid());
    }
}

bool KeyEventHookManager::HandleHooks(std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    if (!IsHooksExisted()) {
        MMI_HILOGW("No hook existed");
        return false;
    }
    auto validHeadHook = GetFirstValidHook();
    CHKPF(validHeadHook);
    CHKPF(validHeadHook->handler);
    if (!(validHeadHook->handler(validHeadHook, keyEvent))) {
        MMI_HILOGE("Handle hook:%{public}d failed", validHeadHook->id);
        return false;
    }
    MMI_HILOGD("Handle hook:%{public}d success", validHeadHook->id);
    return true;
}

size_t KeyEventHookManager::GetHookNum()
{
    std::shared_lock<std::shared_mutex> lock(rwMutex_);
    return hooks_.size();
}

std::shared_ptr<KeyEventHookManager::Hook> KeyEventHookManager::GetHookByPid(int32_t pid)
{
    CALL_DEBUG_ENTER;
    std::shared_lock<std::shared_mutex> lock(rwMutex_);
    auto iter = std::find_if(hooks_.begin(), hooks_.end(), [pid](const auto &hook) -> bool {
        CHKPF(hook);
        CHKPF(hook->session);
        return hook->session->GetPid() == pid;
    });
    if (iter == hooks_.end()) {
        MMI_HILOGW("No hook from pid:%{public}d existed", pid);
        return nullptr;
    }
    return *iter;
}

std::shared_ptr<KeyEventHookManager::Hook> KeyEventHookManager::GetFirstValidHook()
{
    CALL_DEBUG_ENTER;
    std::shared_lock<std::shared_mutex> lock(rwMutex_);
    auto iter = std::find_if(hooks_.begin(), hooks_.end(), [](const auto &hook) -> bool {
        return hook != nullptr && hook->handler != nullptr;
    });
    if (iter == hooks_.end()) {
        MMI_HILOGW("No valid hook existed");
        return nullptr;
    }
    return *iter;
}

std::shared_ptr<KeyEventHookManager::Hook> KeyEventHookManager::GetNextHook(std::shared_ptr<Hook> hook)
{
    CALL_DEBUG_ENTER;
    std::shared_lock<std::shared_mutex> lock(rwMutex_);
    CHKPP(hook);
    auto iter = std::find(hooks_.begin(), hooks_.end(), hook);
    if (iter == hooks_.end()) {
        MMI_HILOGE("No hook existed");
        return nullptr;
    }
    auto nextIter = std::next(iter);
    if (nextIter == hooks_.end()) {
        MMI_HILOGW("No next hook existed");
        return nullptr;
    }
    return *nextIter;
}

bool KeyEventHookManager::HookHandler(SessionPtr session, std::shared_ptr<Hook> hook,
    std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPF(keyEvent);
    NetPacket pkt(MmiMessageId::ON_HOOK_KEY_EVENT);
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet write key event failed");
        return false;
    }
    if (InputEventDataTransformation::KeyEventToNetPacket(keyEvent, pkt) != RET_OK) {
        MMI_HILOGE("Packet key event failed, errCode:%{public}d", STREAM_BUF_WRITE_FAIL);
        return false;
    }
    CHKPF(session);
    if (!session->SendMsg(pkt)) {
        MMI_HILOGE("Send to hook:%{public}d failed", session->GetPid());
        return false;
    }
    MMI_HILOGD("Send to hook:%{public}d success", session->GetPid());
    StashEvent stashEvent;
    if (MakeStashEvent(session, hook, keyEvent, stashEvent) != RET_OK) {
        MMI_HILOGE("MakeStashEvent failed");
        return false;
    }
    AddStashEvent(keyEvent->GetId(), stashEvent);
    return true;
}

int32_t KeyEventHookManager::MakeStashEvent(SessionPtr session, std::shared_ptr<Hook> hook,
    std::shared_ptr<KeyEvent> keyEvent, StashEvent &stashEvent)
{
    CALL_DEBUG_ENTER;
    CHKPR(session, RET_ERR);
    CHKPR(hook, RET_ERR);
    CHKPR(keyEvent, RET_ERR);
    stashEvent.pid = session->GetPid();
    auto eventId = keyEvent->GetId();
    stashEvent.timerId = TimerMgr->AddTimer(STASH_EVENT_TIMEOUT_MS, 1, [this, eventId]() {
        this->OnStashEventTimeout(eventId); }, "KeyEventHookManager::StashEvent");
    stashEvent.keyEvent = KeyEvent::Clone(keyEvent);
    stashEvent.hook = hook;
    return RET_OK;
}

bool KeyEventHookManager::DispatchDirectly(std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPF(keyEvent);
    auto udsServerPtr = InputHandler->GetUDSServer();
    CHKPF(udsServerPtr);
    auto dispatchHandler = InputHandler->GetEventDispatchHandler();
    CHKPF(dispatchHandler);
    if (dispatchHandler->DispatchKeyEventPid(*udsServerPtr, keyEvent) != RET_OK) {
        MMI_HILOGE("DispatchKeyEventPid failed");
        return false;
    }
    return true;
}

void KeyEventHookManager::AddStashEvent(int32_t eventId, StashEvent stashEvent)
{
    CALL_DEBUG_ENTER;
    std::unique_lock<std::shared_mutex> lock(rwMutex_);
    stashEvents_.insert({eventId, stashEvent});
}

void KeyEventHookManager::RemoveStashEvent(int32_t eventId)
{
    CALL_DEBUG_ENTER;
    std::unique_lock<std::shared_mutex> lock(rwMutex_);
    auto iter = stashEvents_.find(eventId);
    if (iter == stashEvents_.end()) {
        MMI_HILOGW("No event:%{public}d existed", eventId);
        return;
    }
    TimerMgr->RemoveTimer(iter->second.timerId);
    stashEvents_.erase(iter);
}

int32_t KeyEventHookManager::GetStashEvent(int32_t eventId, StashEvent &stashEvent)
{
    CALL_DEBUG_ENTER;
    std::shared_lock<std::shared_mutex> lock(rwMutex_);
    if (stashEvents_.find(eventId) == stashEvents_.end()) {
        MMI_HILOGW("No event:%{public}d existed", eventId);
        return RET_ERR;
    }
    stashEvent = stashEvents_[eventId];
    return RET_OK;
}

void KeyEventHookManager::OnStashEventTimeout(int32_t eventId)
{
    CALL_DEBUG_ENTER;
    RemoveStashEvent(eventId);
}

int32_t KeyEventHookManager::CheckAndUpdateEventLoopClosure(const StashEvent &stashEvent)
{
    CHKPR(stashEvent.keyEvent, RET_ERR);
    CHKPR(stashEvent.hook, RET_ERR);
    auto keyAction = stashEvent.keyEvent->GetKeyAction();
    auto keyCode = stashEvent.keyEvent->GetKeyCode();
    auto hookId = stashEvent.hook->id;
    if (keyAction == KeyEvent::KEY_ACTION_DOWN) {
        return HandleEventLoopClosureKeyDown(hookId, keyCode);
    } else if (keyAction == KeyEvent::KEY_ACTION_UP || keyAction == KeyEvent::KEY_ACTION_CANCEL) {
        return HandleEventLoopClosureKeyUpOrCancel(hookId, keyCode);
    } else {
        MMI_HILOGW("Unsupported action:%{public}d", keyAction);
    }
    return RET_ERR;
}

int32_t KeyEventHookManager::HandleEventLoopClosureKeyDown(int32_t hookId, int32_t keyCode)
{
    return EVENT_LOOP_CLOSURE_CHECKER.UpdatePendingDownKeys(hookId, keyCode);
}

int32_t KeyEventHookManager::HandleEventLoopClosureKeyUpOrCancel(int32_t hookId, int32_t keyCode)
{
    if (EVENT_LOOP_CLOSURE_CHECKER.CheckLoopClosure(hookId, keyCode) != RET_OK) {
        MMI_HILOGW("CheckLoopClosure of key:%{private}d failed", keyCode);
        return RET_ERR;
    }
    if (EVENT_LOOP_CLOSURE_CHECKER.RemovePendingDownKeys(hookId, keyCode) != RET_OK) {
        MMI_HILOGW("RemovePendingDownKeys of key:%{private}d failed", keyCode);
        return RET_ERR;
    }
    MMI_HILOGD("HandleKeyUpOrCancel of key:%{private}d success, hookId:%{public}d", keyCode, hookId);
    return RET_OK;
}
} // namespace MMI
} // namespace OHOS
