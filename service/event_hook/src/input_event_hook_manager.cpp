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

#include "input_event_hook_manager.h"

#include "error_multimodal.h"
#include "event_dispatch_order_checker.h"
#include "event_expiration_checker.h"
#include "event_loop_closure_checker.h"
#include "input_event_data_transformation.h"
#include "input_event_handler.h"
#include "timer_manager.h"
#include "util_ex.h"
#include "pointer_event_hook.h"
#include "key_event_hook.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputEventHookManager"

namespace OHOS {
namespace MMI {

InputEventHookManager::~InputEventHookManager() {}

int32_t InputEventHookManager::AddInputEventHook(int32_t pid, HookEventType hookEventType)
{
    CALL_INFO_TRACE;
    Init();
    auto udsServerPtr = InputHandler->GetUDSServer();
    CHKPR(udsServerPtr, RET_ERR);
    auto session = udsServerPtr->GetSessionByPid(pid);
    auto nextHookGetter = [this] (std::shared_ptr<InputEventHook> hook) -> std::shared_ptr<InputEventHook> {
        return this->GetNextHook(hook);
    };
    if (hookEventType & HOOK_EVENT_TYPE_KEY) {
        PrependHook(HOOK_EVENT_TYPE_KEY, std::make_shared<KeyEventHook>(session, nextHookGetter));
    }
    if (hookEventType & HOOK_EVENT_TYPE_MOUSE) {
        auto mouseHook = std::make_shared<PointerEventHook>(session, HOOK_EVENT_TYPE_MOUSE, nextHookGetter);
        PrependHook(HOOK_EVENT_TYPE_MOUSE, std::make_shared<PointerEventHook>(session, HOOK_EVENT_TYPE_MOUSE,
            nextHookGetter));
    }
    if (hookEventType & HOOK_EVENT_TYPE_TOUCH) {
        PrependHook(HOOK_EVENT_TYPE_TOUCH, std::make_shared<PointerEventHook>(session, HOOK_EVENT_TYPE_TOUCH,
            nextHookGetter));
    }
    MMI_HILOGI("AddInputEventHook success %{public}u", hookEventType);
    return RET_OK;
}

int32_t InputEventHookManager::RemoveInputEventHook(int32_t pid, HookEventType hookEventType)
{
    CALL_INFO_TRACE;
    if (hookEventType & HOOK_EVENT_TYPE_KEY) {
        RemoveHookByPid(pid, HOOK_EVENT_TYPE_KEY);
    }
    if (hookEventType & HOOK_EVENT_TYPE_MOUSE) {
        RemoveHookByPid(pid, HOOK_EVENT_TYPE_MOUSE);
    }
    if (hookEventType & HOOK_EVENT_TYPE_TOUCH) {
        RemoveHookByPid(pid, HOOK_EVENT_TYPE_TOUCH);
    }
    MMI_HILOGI("RemoveInputEventHook success %{public}u", hookEventType);
    return RET_OK;
}

void InputEventHookManager::HandleKeyEvent(const std::shared_ptr<KeyEvent> keyEvent)
{
    if (IsHooksExisted(HOOK_EVENT_TYPE_KEY) && HandleHooks(keyEvent)) {
        return;
    }
    CHKPV(nextHandler_);
    nextHandler_->HandleKeyEvent(keyEvent);
}

void InputEventHookManager::HandlePointerEvent(const std::shared_ptr<PointerEvent> pointerEvent)
{
    if (IsHooksExisted(HOOK_EVENT_TYPE_MOUSE) && HandleHooks(pointerEvent)) {
        return;
    }
    CHKPV(nextHandler_);
    nextHandler_->HandlePointerEvent(pointerEvent);
}

void InputEventHookManager::HandleTouchEvent(const std::shared_ptr<PointerEvent> pointerEvent)
{
    if (IsHooksExisted(HOOK_EVENT_TYPE_TOUCH) && HandleHooks(pointerEvent)) {
        return;
    }
    CHKPV(nextHandler_);
    nextHandler_->HandleTouchEvent(pointerEvent);
}

int32_t InputEventHookManager::DispatchToNextHandler(int32_t pid, std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    auto hook = GetHookByPid(pid, HOOK_EVENT_TYPE_KEY);
    CHKPR(hook, RET_ERR);
    return hook->DispatchToNextHandler(keyEvent);
}

int32_t InputEventHookManager::DispatchMouseToNextHandler(int32_t pid, const std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    auto hook = GetHookByPid(pid, HOOK_EVENT_TYPE_MOUSE);
    CHKPR(hook, RET_ERR);
    return hook->DispatchToNextHandler(pointerEvent);
}

int32_t InputEventHookManager::DispatchTouchToNextHandler(int32_t pid, const std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    auto hook = GetHookByPid(pid, HOOK_EVENT_TYPE_TOUCH);
    CHKPR(hook, RET_ERR);
    return hook->DispatchToNextHandler(pointerEvent);
}

bool InputEventHookManager::IsHooksExisted(HookEventType hookEventType)
{
    std::shared_lock<std::shared_mutex> lock(rwMutex_);
    auto it = hooks_.find(hookEventType);
    if (it == hooks_.end()) {
        return false;
    }
    return !(it->second.empty());
}

void InputEventHookManager::Dump(int32_t fd, const std::vector<std::string> &args)
{
    CALL_INFO_TRACE;
    mprintf(fd, "Hook information:\t");
    std::shared_lock<std::shared_mutex> lock(rwMutex_);
    for (const auto &[hookType, hooks] : hooks_) {
        mprintf(fd, "HookType:%10u Hook count:%zu\n", hookType, hooks.size());
        for (const auto &hook : hooks) {
            CHKPC(hook);
            mprintf(fd, "HookPid:%10d programName:%s", hook->GetHookPid(), hook->GetProgramName().c_str());
        }
    }
}

void InputEventHookManager::Init()
{
    std::unique_lock<std::shared_mutex> lock(rwMutex_);
    if (isInitialized_.load())  {
        return;
    }
    InitSessionLostCallback();
    isInitialized_.store(true);
}

void InputEventHookManager::InitSessionLostCallback()
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

void InputEventHookManager::OnSessionLost(SessionPtr session)
{
    CALL_INFO_TRACE;
    CHKPV(session);
    auto pid = session->GetPid();
    RemoveHookByPid(pid, HOOK_EVENT_TYPE_KEY);
    RemoveHookByPid(pid, HOOK_EVENT_TYPE_MOUSE);
    RemoveHookByPid(pid, HOOK_EVENT_TYPE_TOUCH);
}

void InputEventHookManager::PrependHook(HookEventType hookEventType, std::shared_ptr<InputEventHook> hook)
{
    CALL_DEBUG_ENTER;
    std::unique_lock<std::shared_mutex> lock(rwMutex_);
    hooks_[hookEventType].push_front(hook);
}

bool InputEventHookManager::IsHookExisted(int32_t pid, HookEventType hookEventType)
{
    std::shared_lock<std::shared_mutex> lock(rwMutex_);
    auto it = hooks_.find(hookEventType);
    if (it == hooks_.end()) {
        return false;
    }
    auto& hookList = it->second;
    auto iter = std::find_if(hookList.begin(), hookList.end(), [pid](const std::shared_ptr<InputEventHook>& hook) {
            return (hook != nullptr) && hook->GetHookPid() == pid;
        }
    );
    return iter != hookList.end();
}

std::shared_ptr<InputEventHook> InputEventHookManager::GetHookByPid(int32_t pid, HookEventType hookEventType)
{
    std::shared_lock<std::shared_mutex> lock(rwMutex_);
    auto it = hooks_.find(hookEventType);
    if (it == hooks_.end()) {
        MMI_HILOGW("No hook existed for event type %{public}d", static_cast<int32_t>(hookEventType));
        return nullptr;
    }
    auto& hookList = it->second;
    auto iter = std::find_if(hookList.begin(), hookList.end(), [pid](const std::shared_ptr<InputEventHook>& hook) {
            return (hook != nullptr) && hook->GetHookPid() == pid;
        }
    );
    if (iter == hookList.end()) {
        return nullptr;
    }
    return *iter;
}

int32_t InputEventHookManager::RemoveHookByPid(int32_t pid, HookEventType hookEventType)
{
    std::unique_lock<std::shared_mutex> lock(rwMutex_);
    auto it = hooks_.find(hookEventType);
    if (it == hooks_.end()) {
        MMI_HILOGW("No hook existed for event type %{public}d", static_cast<int32_t>(hookEventType));
        return RET_OK;
    }
    auto& hookList = it->second;
    hookList.erase(std::remove_if(hookList.begin(), hookList.end(), [pid](const std::shared_ptr<InputEventHook>& hook) {
        return !hook || (hook->GetHookPid() == RET_ERR) || (hook->GetHookPid() == pid);}),
    hookList.end());
    MMI_HILOGI("RemoveHookByPid success pid:%{public}d %{public}u", pid, hookEventType);
    return RET_OK;
}

size_t InputEventHookManager::GetHookNum(HookEventType hookEventType)
{
    std::shared_lock<std::shared_mutex> lock(rwMutex_);
    auto it = hooks_.find(hookEventType);
    if (it == hooks_.end()) {
        return 0;
    }
    return it->second.size();
}

std::shared_ptr<InputEventHook> InputEventHookManager::GetFirstValidHook(HookEventType hookEventType)
{
    std::shared_lock<std::shared_mutex> lock(rwMutex_);
    auto it = hooks_.find(hookEventType);
    if (it == hooks_.end() || it->second.empty()) {
        MMI_HILOGD("No hook for event type %{public}u", hookEventType);
        return nullptr;
    }
    return it->second.front();
}

std::shared_ptr<InputEventHook> InputEventHookManager::GetNextHook(std::shared_ptr<InputEventHook> hook)
{
    CALL_DEBUG_ENTER;
    std::shared_lock<std::shared_mutex> lock(rwMutex_);
    CHKPP(hook);
    auto hookEventType = hook->GetHookEventType();
    auto it = hooks_.find(hookEventType);
    if (it == hooks_.end()) {
        return nullptr;
    }
    auto& hookList = it->second;
    auto iter = std::find(hookList.begin(), hookList.end(), hook);
    if (iter == hookList.end()) {
        MMI_HILOGE("No hook existed");
        return nullptr;
    }
    auto nextIter = std::next(iter);
    if (nextIter == hookList.end()) {
        MMI_HILOGW("No next hook existed");
        return nullptr;
    }
    return *nextIter;
}

bool InputEventHookManager::HandleHooks(const std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPF(keyEvent);
    auto headHook = GetFirstValidHook(HOOK_EVENT_TYPE_KEY);
    CHKPF(headHook);
    return headHook->OnKeyEvent(keyEvent);
}

bool InputEventHookManager::HandleHooks(const std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPF(pointerEvent);
    std::shared_ptr<InputEventHook> headHook { nullptr };
    if (auto sourceType = pointerEvent->GetSourceType(); sourceType == PointerEvent::SOURCE_TYPE_MOUSE) {
        headHook = GetFirstValidHook(HOOK_EVENT_TYPE_MOUSE);
    } else if (sourceType == PointerEvent::SOURCE_TYPE_TOUCHSCREEN) {
        headHook = GetFirstValidHook(HOOK_EVENT_TYPE_TOUCH);
    } else {
        MMI_HILOGW("Unsupported sourceType");
        return false;
    }
    CHKPF(headHook);
    return headHook->OnPointerEvent(pointerEvent);
}
} // namespace MMI
} // namespace OHOS
