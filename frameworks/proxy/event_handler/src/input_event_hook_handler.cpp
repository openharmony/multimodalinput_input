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

#include "input_event_hook_handler.h"

#include "error_multimodal.h"
#include "mmi_log.h"
#include "multimodal_event_handler.h"
#include "multimodal_input_connect_manager.h"
#include "input_handler_type.h"
#include "input_event_stager.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputEventHookHandler"

namespace OHOS {
namespace MMI {

InputEventHookHandler &InputEventHookHandler::GetInstance()
{
    static InputEventHookHandler instance;
    return instance;
}

int32_t InputEventHookHandler::AddInputEventHookLocal(std::shared_ptr<IInputEventConsumer> consumer,
    HookEventType hookEventType)
{
    CALL_INFO_TRACE;
    CHKPR(consumer, ERROR_INVALID_PARAMETER);
    if (hookEventType & HOOK_EVENT_TYPE_KEY) {
        AddKeyHook([consumer](std::shared_ptr<KeyEvent> event) {
            consumer->OnInputEvent(event);
        });
    }
    if (hookEventType & HOOK_EVENT_TYPE_MOUSE) {
        AddMouseHook([consumer](std::shared_ptr<PointerEvent> event) {
            consumer->OnInputEvent(event);
        });
}
    if (hookEventType & HOOK_EVENT_TYPE_TOUCH) {
        AddTouchHook([consumer](std::shared_ptr<PointerEvent> event) {
            consumer->OnInputEvent(event);
        });
    }
    MMI_HILOGI("AddInputEventHookLocal success hookEventType:%{public}u", hookEventType);
    return RET_OK;
}

int32_t InputEventHookHandler::AddInputEventHook(std::shared_ptr<IInputEventConsumer> consumer,
    HookEventType hookEventType)
{
    CALL_INFO_TRACE;
    CHKPR(consumer, RET_ERR);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Client init failed");
        return RET_ERR;
    }
    if (IsHookExisted(hookEventType)) {
        MMI_HILOGE("Hook:%{public}u existed already hookEventType:%{public}u",
            currentHookStats_.load(std::memory_order_relaxed), hookEventType);
        return ERROR_REPEAT_INTERCEPTOR;
    }
    if (int32_t ret = AddInputEventHookToServer(hookEventType); ret != RET_OK) {
        MMI_HILOGE("AddInputEventHook failed hookEventType:%{public}u", hookEventType);
        RemoveInputEventHookLocal(hookEventType);
        return ret;
    }
    if (int32_t ret = AddInputEventHookLocal(consumer, hookEventType); ret != RET_OK) {
        MMI_HILOGE("AddInputEventHook failed hookEventType:%{public}u", hookEventType);
        return ret;
    }
    MMI_HILOGI("AddInputEventHook success hookEventType:%{public}u", hookEventType);
    return RET_OK;
}

int32_t InputEventHookHandler::RemoveInputEventHookLocal(HookEventType hookEventType)
{
    CALL_INFO_TRACE;
    std::unique_lock<std::shared_mutex> lock(rwMutex_);
    if ((hookEventType & HOOK_EVENT_TYPE_KEY) & CheckHookStatsBit(HOOK_EVENT_TYPE_KEY)) {
        hookConsumer_.keyHookCallback_ = nullptr;
        ClearHookStatsBit(HOOK_EVENT_TYPE_KEY);
    }
    if ((hookEventType & HOOK_EVENT_TYPE_MOUSE) & CheckHookStatsBit(HOOK_EVENT_TYPE_MOUSE)) {
        hookConsumer_.mouseHookCallback_ = nullptr;
        ClearHookStatsBit(HOOK_EVENT_TYPE_MOUSE);
    }
    if ((hookEventType & HOOK_EVENT_TYPE_TOUCH) & CheckHookStatsBit(HOOK_EVENT_TYPE_TOUCH)) {
        hookConsumer_.touchHookCallback_ = nullptr;
        ClearHookStatsBit(HOOK_EVENT_TYPE_TOUCH);
    }
    return RET_OK;
}

int32_t InputEventHookHandler::RemoveInputEventHook(HookEventType hookEventType)
{
    if (int32_t ret = RemoveInputEventHookLocal(hookEventType); ret != RET_OK) {
        MMI_HILOGE("RemoveInputEventHookLocal failed ret:%{public}d, hookEventType:%{public}u", ret, hookEventType);
        return ret;
    }
    if (int32_t ret = RemoveInputEventHookOfServer(hookEventType); ret != RET_OK) {
        MMI_HILOGE("Remove hook failed ret:%{public}d, hookEventType:%{public}u", ret, hookEventType);
        return ret;
    }
    INPUT_EVENT_STAGER.ClearStashEvents(hookEventType);
    MMI_HILOGI("Remove hook success hookEventType:%{public}u", hookEventType);
    return RET_OK;
}

int32_t InputEventHookHandler::DispatchToNextHandler(int32_t eventId, HookEventType hookEventType)
{
    if (CheckHookStatsBit(HOOK_EVENT_TYPE_KEY)) {
        auto event = INPUT_EVENT_STAGER.GetKeyEvent(eventId);
        CHKPR(event, ERROR_INVALID_PARAMETER);
        return DispatchToNextHandler(event);
    } else if (CheckHookStatsBit(HOOK_EVENT_TYPE_MOUSE)) {
        auto event = INPUT_EVENT_STAGER.GetMouseEvent(eventId);
        CHKPR(event, ERROR_INVALID_PARAMETER);
        return DispatchToNextHandler(event);
    } else if (CheckHookStatsBit(HOOK_EVENT_TYPE_TOUCH)) {
        auto event = INPUT_EVENT_STAGER.GetTouchEvent(eventId);
        CHKPR(event, ERROR_INVALID_PARAMETER);
        return DispatchToNextHandler(event);
    } else {
        return RET_ERR;
    }
}

void InputEventHookHandler::OnKeyEvent(std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPV(keyEvent);
    std::shared_lock<std::shared_mutex> lock(rwMutex_);
    INPUT_EVENT_STAGER.UpdateKeyEvent(keyEvent);
    CHKPV(hookConsumer_.keyHookCallback_);
    hookConsumer_.keyHookCallback_(keyEvent);
}

void InputEventHookHandler::OnPointerEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPV(pointerEvent);
    std::shared_lock<std::shared_mutex> lock(rwMutex_);
    auto sourceType = pointerEvent->GetSourceType();
    if (sourceType == PointerEvent::SOURCE_TYPE_TOUCHSCREEN) {
        INPUT_EVENT_STAGER.UpdateTouchEvent(pointerEvent);
        CHKPV(hookConsumer_.touchHookCallback_);
        hookConsumer_.touchHookCallback_(pointerEvent);
    } else if (sourceType == PointerEvent::SOURCE_TYPE_MOUSE) {
        INPUT_EVENT_STAGER.UpdateMouseEvent(pointerEvent);
        CHKPV(hookConsumer_.mouseHookCallback_);
        hookConsumer_.mouseHookCallback_(pointerEvent);
    } else {
        MMI_HILOGD("Unsupported sourceType:%{public}d", sourceType);
    }
}

void InputEventHookHandler::OnConnected()
{
    CALL_DEBUG_ENTER;
    if (currentHookStats_.load() == 0) {
        MMI_HILOGI("No hook existed");
        return;
    }
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Client init failed");
        return;
    }
    uint32_t hookEventType { 0 };
    std::shared_lock<std::shared_mutex> lock(rwMutex_);
    if (CheckHookStatsBit(HOOK_EVENT_TYPE_KEY) && hookConsumer_.keyHookCallback_) {
        hookEventType |= HOOK_EVENT_TYPE_KEY;
    }
    if (CheckHookStatsBit(HOOK_EVENT_TYPE_TOUCH) && hookConsumer_.touchHookCallback_) {
        hookEventType |= HOOK_EVENT_TYPE_TOUCH;
    }
    if (CheckHookStatsBit(HOOK_EVENT_TYPE_MOUSE) && hookConsumer_.mouseHookCallback_) {
        hookEventType |= HOOK_EVENT_TYPE_MOUSE;
    }
    AddInputEventHookToServer(hookEventType);
}

void InputEventHookHandler::AddKeyHook(std::function<void(std::shared_ptr<KeyEvent>)> keyHook)
{
    CHKPV(keyHook);
    std::unique_lock<std::shared_mutex> lock(rwMutex_);
    hookConsumer_.keyHookCallback_ = keyHook;
    SetHookStatsBit(HOOK_EVENT_TYPE_KEY);
}

void InputEventHookHandler::AddMouseHook(std::function<void(std::shared_ptr<PointerEvent>)> mouseHook)
{
    CHKPV(mouseHook);
    std::unique_lock<std::shared_mutex> lock(rwMutex_);
    hookConsumer_.mouseHookCallback_ = mouseHook;
    SetHookStatsBit(HOOK_EVENT_TYPE_MOUSE);
}

void InputEventHookHandler::AddTouchHook(std::function<void(std::shared_ptr<PointerEvent>)> touchHook)
{
    CHKPV(touchHook);
    std::unique_lock<std::shared_mutex> lock(rwMutex_);
    hookConsumer_.touchHookCallback_ = touchHook;
    SetHookStatsBit(HOOK_EVENT_TYPE_TOUCH);
}

int32_t InputEventHookHandler::AddInputEventHookToServer(HookEventType hookEventType)
{
    CALL_INFO_TRACE;
    if (int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->AddInputEventHook(hookEventType); ret != RET_OK) {
        MMI_HILOGE("AddInputEventHook to server, ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t InputEventHookHandler::RemoveInputEventHookOfServer(HookEventType hookEventType)
{
    CALL_INFO_TRACE;
    if (int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->RemoveInputEventHook(hookEventType); ret != RET_OK) {
        MMI_HILOGE("RemoveInputEventHook of server, ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

bool InputEventHookHandler::CheckHookStatsBit(HookEventType hookEventType)
{
    return (currentHookStats_.load(std::memory_order_relaxed) & static_cast<uint32_t>(hookEventType)) != 0;
}

void InputEventHookHandler::SetHookStatsBit(HookEventType hookEventType)
{
    currentHookStats_.fetch_or(static_cast<uint32_t>(hookEventType), std::memory_order_relaxed);
}

void InputEventHookHandler::ClearHookStatsBit(HookEventType hookEventType)
{
    currentHookStats_.fetch_and(~static_cast<uint32_t>(hookEventType), std::memory_order_relaxed);
}

bool InputEventHookHandler::IsHookExisted(HookEventType hookEventType)
{
    if (bool flag = ((hookEventType & HOOK_EVENT_TYPE_KEY) != 0) &&
        CheckHookStatsBit(HOOK_EVENT_TYPE_KEY) && hookConsumer_.keyHookCallback_; flag) {
        return true;
    }
    if (bool flag = ((hookEventType & HOOK_EVENT_TYPE_TOUCH) != 0) &&
        CheckHookStatsBit(HOOK_EVENT_TYPE_TOUCH) && hookConsumer_.touchHookCallback_; flag) {
        return true;
    }
    if (bool flag = ((hookEventType & HOOK_EVENT_TYPE_MOUSE) != 0) &&
        CheckHookStatsBit(HOOK_EVENT_TYPE_MOUSE) && hookConsumer_.mouseHookCallback_; flag) {
        return true;
    }
    return false;
}

int32_t InputEventHookHandler::DispatchToNextHandler(std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_INFO_TRACE;
    if (int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->DispatchToNextHandler(keyEvent); ret != RET_OK) {
        MMI_HILOGE("DispatchToNextHandler keyEvent of server, ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t InputEventHookHandler::DispatchToNextHandler(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_INFO_TRACE;
    if (int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->DispatchToNextHandler(pointerEvent); ret != RET_OK) {
        MMI_HILOGE("DispatchToNextHandler pointerEvent of server, ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}
} // namespace MMI
} // namespace OHOS
