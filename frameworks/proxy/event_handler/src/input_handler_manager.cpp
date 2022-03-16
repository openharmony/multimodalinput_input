/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "input_handler_manager.h"

#include "bytrace_adapter.h"
#include "input_handler_type.h"
#include "mmi_log.h"
#include "multimodal_event_handler.h"
#include "net_packet.h"
#include "proto.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "InputHandlerManager" };
} // namespace

int32_t InputHandlerManager::AddHandler(InputHandlerType handlerType,
    std::shared_ptr<IInputEventConsumer> consumer)
{
    CHKPR(consumer, INVALID_HANDLER_ID);
    if (inputHandlers_.size() >= MAX_N_INPUT_HANDLERS) {
        MMI_LOGE("The number of handlers exceeds the maximum");
        return INVALID_HANDLER_ID;
    }
    int32_t handlerId = GetNextId();
    if (handlerId == INVALID_HANDLER_ID) {
        MMI_LOGE("Exceeded limit of 32-bit maximum number of integers");
        return INVALID_HANDLER_ID;
    }
    MMI_LOGD("Register new handler:%{public}d", handlerId);
    if (RET_OK == AddLocal(handlerId, handlerType, consumer)) {
        MMI_LOGD("New handler successfully registered, report to server");
        AddToServer(handlerId, handlerType);
    } else {
        handlerId = INVALID_HANDLER_ID;
    }
    return handlerId;
}

void InputHandlerManager::RemoveHandler(int32_t handlerId, InputHandlerType handlerType)
{
    MMI_LOGD("Unregister handler:%{public}d,type:%{public}d", handlerId, handlerType);
    if (RET_OK == RemoveLocal(handlerId, handlerType)) {
        MMI_LOGD("Handler:%{public}d unregistered, report to server", handlerId);
        RemoveFromServer(handlerId, handlerType);
    }
}

void InputHandlerManager::MarkConsumed(int32_t monitorId, int32_t eventId)
{
    MMI_LOGD("Mark consumed state, monitor:%{public}d,event:%{public}d", monitorId, eventId);
    MMIClientPtr client = MMIEventHdl.GetMMIClient();
    CHKPV(client);
    NetPacket pkt(MmiMessageId::MARK_CONSUMED);
    if (!pkt.Write(monitorId) || !pkt.Write(eventId)) {
        MMI_LOGE("Packet write is error, errCode:%{public}d", STREAM_BUF_WRITE_FAIL);
        return;
    }
    if (!client->SendMessage(pkt)) {
        MMI_LOGE("Send message failed, errCode:%{public}d", MSG_SEND_FAIL);
        return;
    }
}

int32_t InputHandlerManager::AddLocal(int32_t handlerId, InputHandlerType handlerType,
    std::shared_ptr<IInputEventConsumer> monitor)
{
    std::lock_guard<std::mutex> guard(lockHandlers_);
    InputHandlerManager::Handler handler {
        .handlerId_ = handlerId,
        .handlerType_ = handlerType,
        .consumer_ = monitor
    };
    auto ret = inputHandlers_.emplace(handler.handlerId_, handler);
    if (!ret.second) {
        MMI_LOGE("Duplicate handler:%{public}d", handler.handlerId_);
        return RET_ERR;
    }
    return RET_OK;
}

void InputHandlerManager::AddToServer(int32_t handlerId, InputHandlerType handlerType)
{
    MMIClientPtr client { MMIEventHdl.GetMMIClient() };
    CHKPV(client);
    NetPacket pkt(MmiMessageId::ADD_INPUT_HANDLER);
    if (!pkt.Write(handlerId) || !pkt.Write(handlerType)) {
        MMI_LOGE("Packet write is error, errCode:%{public}d", STREAM_BUF_WRITE_FAIL);
        return;
    }
    if (!client->SendMessage(pkt)) {
        MMI_LOGE("Send message failed, errCode:%{public}d", MSG_SEND_FAIL);
        return;
    }
}

int32_t InputHandlerManager::RemoveLocal(int32_t handlerId, InputHandlerType handlerType)
{
    std::lock_guard<std::mutex> guard(lockHandlers_);
    auto tItr = inputHandlers_.find(handlerId);
    if (tItr == inputHandlers_.end()) {
        MMI_LOGE("No handler with specified");
        return RET_ERR;
    }
    if (handlerType != tItr->second.handlerType_) {
        MMI_LOGE("Unmatched handler type, InputHandlerType:%{public}d,FindHandlerType:%{public}d",
                 handlerType, tItr->second.handlerType_);
        return RET_ERR;
    }
    inputHandlers_.erase(tItr);
    return RET_OK;
}

void InputHandlerManager::RemoveFromServer(int32_t handlerId, InputHandlerType handlerType)
{
    MMI_LOGD("Remove handler:%{public}d from server", handlerId);
    MMIClientPtr client { MMIEventHdl.GetMMIClient() };
    CHKPV(client);
    NetPacket pkt(MmiMessageId::REMOVE_INPUT_HANDLER);
    if (!pkt.Write(handlerId) || !pkt.Write(handlerType)) {
        MMI_LOGE("Packet write is error, errCode:%{public}d", STREAM_BUF_WRITE_FAIL);
        return;
    }
    if (!client->SendMessage(pkt)) {
        MMI_LOGE("Send message failed, errCode:%{public}d", MSG_SEND_FAIL);
        return;
    }
}

int32_t InputHandlerManager::GetNextId()
{
    if (nextId_ == std::numeric_limits<int32_t>::max()) {
        MMI_LOGE("Exceeded limit of 32-bit maximum number of integers");
        return INVALID_HANDLER_ID;
    }
    return nextId_++;
}

std::shared_ptr<IInputEventConsumer> InputHandlerManager::FindHandler(int32_t handlerId)
{
    std::lock_guard<std::mutex> guard(lockHandlers_);
    auto tItr = inputHandlers_.find(handlerId);
    if (tItr != inputHandlers_.end()) {
        return tItr->second.consumer_;
    }
    return nullptr;
}

void InputHandlerManager::OnInputEvent(int32_t handlerId, std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPV(keyEvent);
    std::shared_ptr<IInputEventConsumer> consumer = FindHandler(handlerId);
    if (consumer != nullptr) {
        consumer->OnInputEvent(keyEvent);
    }
}

void InputHandlerManager::OnInputEvent(int32_t handlerId, std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_LOG_ENTER;
    MMI_LOGD("handler:%{public}d", handlerId);
    CHKPV(pointerEvent);
    BytraceAdapter::StartBytrace(pointerEvent, BytraceAdapter::TRACE_STOP, BytraceAdapter::POINT_INTERCEPT_EVENT);
    std::shared_ptr<IInputEventConsumer> consumer = FindHandler(handlerId);
    if (consumer != nullptr) {
        consumer->OnInputEvent(pointerEvent);
    }
}

void InputHandlerManager::OnConnected()
{
    CALL_LOG_ENTER;
    for (auto &inputHandler : inputHandlers_) {
        AddToServer(inputHandler.second.handlerId_, inputHandler.second.handlerType_);
    }
}
} // namespace MMI
} // namespace OHOS
