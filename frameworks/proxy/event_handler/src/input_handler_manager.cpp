/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "input_handler_manager.h"
#include <cinttypes>

#include "mmi_log.h"
#include "net_packet.h"
#include "proto.h"

#include "bytrace_adapter.h"
#include "input_handler_type.h"
#include "input_manager_impl.h"
#include "multimodal_event_handler.h"
#include "multimodal_input_connect_manager.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "InputHandlerManager" };
} // namespace

int32_t InputHandlerManager::AddHandler(InputHandlerType handlerType,
    std::shared_ptr<IInputEventConsumer> consumer, HandleEventType eventType)
{
    CALL_INFO_TRACE;
    CHKPR(consumer, INVALID_HANDLER_ID);
    std::lock_guard<std::mutex> guard(mtxHandlers_);
    if (inputHandlers_.size() >= MAX_N_INPUT_HANDLERS) {
        MMI_HILOGE("The number of handlers exceeds the maximum");
        return INVALID_HANDLER_ID;
    }
    int32_t handlerId = GetNextId();
    if (handlerId == INVALID_HANDLER_ID) {
        MMI_HILOGE("Exceeded limit of 32-bit maximum number of integers");
        return INVALID_HANDLER_ID;
    }
    MMI_HILOGD("Register new handler:%{public}d", handlerId);
    if (RET_OK == AddLocal(handlerId, handlerType, eventType, consumer)) {
        MMI_HILOGD("New handler successfully registered, report to server");
        AddToServer(handlerId, handlerType, eventType);
    } else {
        handlerId = INVALID_HANDLER_ID;
    }
    return handlerId;
}

void InputHandlerManager::RemoveHandler(int32_t handlerId, InputHandlerType handlerType)
{
    CALL_INFO_TRACE;
    MMI_HILOGD("Unregister handler:%{public}d,type:%{public}d", handlerId, handlerType);
    std::lock_guard<std::mutex> guard(mtxHandlers_);
    if (RET_OK == RemoveLocal(handlerId, handlerType)) {
        MMI_HILOGD("Handler:%{public}d unregistered, report to server", handlerId);
        RemoveFromServer(handlerId, handlerType);
    }
}

void InputHandlerManager::MarkConsumed(int32_t monitorId, int32_t eventId)
{
    CALL_INFO_TRACE;
    MMI_HILOGD("Mark consumed state, monitor:%{public}d,event:%{public}d", monitorId, eventId);
    int32_t ret = MultimodalInputConnMgr->MarkEventConsumed(monitorId, eventId);
    if (ret != 0) {
        MMI_HILOGE("Send to server failed, ret:%{public}d", ret);
    }
}

int32_t InputHandlerManager::AddLocal(int32_t handlerId, InputHandlerType handlerType,
    HandleEventType eventType, std::shared_ptr<IInputEventConsumer> monitor)
{
    auto eventHandler = InputMgrImpl->GetCurrentEventHandler();
    CHKPR(eventHandler, RET_ERR);
    InputHandlerManager::Handler handler {
        .handlerId_ = handlerId,
        .handlerType_ = handlerType,
        .eventType_ = eventType,
        .consumer_ = monitor,
        .eventHandler_ = eventHandler,
    };
    auto ret = inputHandlers_.emplace(handler.handlerId_, handler);
    if (!ret.second) {
        MMI_HILOGE("Duplicate handler:%{public}d", handler.handlerId_);
        return RET_ERR;
    }
    return RET_OK;
}

void InputHandlerManager::AddToServer(int32_t handlerId, InputHandlerType handlerType,
    HandleEventType eventType)
{
    int32_t ret = MultimodalInputConnMgr->AddInputHandler(handlerId, handlerType, eventType);
    if (ret != 0) {
        MMI_HILOGE("Send to server failed, ret:%{public}d", ret);
    }
}

int32_t InputHandlerManager::RemoveLocal(int32_t handlerId, InputHandlerType handlerType)
{
    auto tItr = inputHandlers_.find(handlerId);
    if (tItr == inputHandlers_.end()) {
        MMI_HILOGE("No handler with specified");
        return RET_ERR;
    }
    if (handlerType != tItr->second.handlerType_) {
        MMI_HILOGE("Unmatched handler type, InputHandlerType:%{public}d,FindHandlerType:%{public}d",
                   handlerType, tItr->second.handlerType_);
        return RET_ERR;
    }
    inputHandlers_.erase(tItr);
    return RET_OK;
}

void InputHandlerManager::RemoveFromServer(int32_t handlerId, InputHandlerType handlerType)
{
    MMI_HILOGD("Remove handler:%{public}d from server", handlerId);
    int32_t ret = MultimodalInputConnMgr->RemoveInputHandler(handlerId, handlerType);
    if (ret != 0) {
        MMI_HILOGE("Send to server failed, ret:%{public}d", ret);
    }
}

int32_t InputHandlerManager::GetNextId()
{
    if (nextId_ == std::numeric_limits<int32_t>::max()) {
        MMI_HILOGE("Exceeded limit of 32-bit maximum number of integers");
        return INVALID_HANDLER_ID;
    }
    return nextId_++;
}

std::shared_ptr<IInputEventConsumer> InputHandlerManager::FindHandler(int32_t handlerId)
{
    auto tItr = inputHandlers_.find(handlerId);
    if (tItr != inputHandlers_.end()) {
        return tItr->second.consumer_;
    }
    return nullptr;
}

EventHandlerPtr InputHandlerManager::GetEventHandler(int32_t handlerId)
{
    auto tItr = inputHandlers_.find(handlerId);
    if (tItr != inputHandlers_.end()) {
        return tItr->second.eventHandler_;
    }
    return nullptr;
}

bool InputHandlerManager::PostTask(int32_t handlerId, const AppExecFwk::EventHandler::Callback &callback)
{
    auto eventHandler = GetEventHandler(handlerId);
    CHKPF(eventHandler);
    return MMIEventHandler::PostTask(eventHandler, callback);
}

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
void InputHandlerManager::OnKeyEventTask(std::shared_ptr<IInputEventConsumer> consumer, int32_t handlerId,
    std::shared_ptr<KeyEvent> keyEvent)
{
    CHK_PID_AND_TID();
    CHKPV(consumer);
    CHKPV(keyEvent);
    consumer->OnInputEvent(keyEvent);
    MMI_HILOGD("Key event callback id:%{public}d keyCode:%{public}d", handlerId, keyEvent->GetKeyCode());
}

void InputHandlerManager::OnInputEvent(int32_t handlerId, std::shared_ptr<KeyEvent> keyEvent)
{
    CHK_PID_AND_TID();
    CHKPV(keyEvent);
    std::lock_guard<std::mutex> guard(mtxHandlers_);
    BytraceAdapter::StartBytrace(keyEvent, BytraceAdapter::TRACE_STOP, BytraceAdapter::KEY_INTERCEPT_EVENT);
    auto consumer = FindHandler(handlerId);
    CHKPV(consumer);
    if (!PostTask(handlerId,
        std::bind(&InputHandlerManager::OnKeyEventTask, this, consumer, handlerId, keyEvent))) {
        MMI_HILOGE("Post task failed");
    }
    MMI_HILOGD("Key event id:%{public}d keyCode:%{public}d", handlerId, keyEvent->GetKeyCode());
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
void InputHandlerManager::OnPointerEventTask(std::shared_ptr<IInputEventConsumer> consumer, int32_t handlerId,
    std::shared_ptr<PointerEvent> pointerEvent)
{
    CHK_PID_AND_TID();
    CHKPV(consumer);
    CHKPV(pointerEvent);
    consumer->OnInputEvent(pointerEvent);
    MMI_HILOGD("Pointer event callback id:%{public}d pointerId:%{public}d", handlerId, pointerEvent->GetPointerId());
}

void InputHandlerManager::OnInputEvent(int32_t handlerId, std::shared_ptr<PointerEvent> pointerEvent)
{
    CHK_PID_AND_TID();
    CHKPV(pointerEvent);
    std::lock_guard<std::mutex> guard(mtxHandlers_);
    BytraceAdapter::StartBytrace(pointerEvent, BytraceAdapter::TRACE_STOP, BytraceAdapter::POINT_INTERCEPT_EVENT);
    auto consumer = FindHandler(handlerId);
    CHKPV(consumer);
    if (!PostTask(handlerId,
        std::bind(&InputHandlerManager::OnPointerEventTask, this, consumer, handlerId, pointerEvent))) {
        MMI_HILOGE("Post task failed");
    }
    MMI_HILOGD("Pointer event id:%{public}d pointerId:%{public}d", handlerId, pointerEvent->GetPointerId());
}
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
#if defined(OHOS_BUILD_ENABLE_INTERCEPTOR) || defined(OHOS_BUILD_ENABLE_MONITOR)
void InputHandlerManager::OnConnected()
{
    CALL_DEBUG_ENTER;
    for (auto &inputHandler : inputHandlers_) {
        AddToServer(inputHandler.second.handlerId_, inputHandler.second.handlerType_, inputHandler.second.eventType_);
    }
}
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR || OHOS_BUILD_ENABLE_MONITOR
} // namespace MMI
} // namespace OHOS
