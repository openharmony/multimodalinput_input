/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "bytrace.h"
#include "input_handler_type.h"
#include "log.h"
#include "multimodal_event_handler.h"
#include "net_packet.h"
#include "proto.h"

namespace OHOS {
namespace MMI {
namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "InputHandlerManager" };
}

int32_t InputHandlerManager::AddHandler(InputHandlerType handlerType,
    std::shared_ptr<IInputEventConsumer> consumer)
{
    CHKPR(consumer, ERROR_NULL_POINTER, RET_ERR);
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
    MMI_LOGD("Unregister handler:%{public}d with type:%{public}d", handlerId, handlerType);
    if (RET_OK == RemoveLocal(handlerId, handlerType)) {
        MMI_LOGD("Handler:%{public}d unregistered, report to server", handlerId);
        RemoveFromServer(handlerId, handlerType);
    }
}

void InputHandlerManager::MarkConsumed(int32_t monitorId, int32_t eventId)
{
    MMI_LOGD("Mark consumed state, monitor:%{public}d, event:%{public}d", monitorId, eventId);
    MMIClientPtr client = MMIEventHdl.GetMMIClient();
    if (client == nullptr) {
        MMI_LOGE("Get MMIClint false");
        return;
    }
    NetPacket pkt(MmiMessageId::MARK_CONSUMED);
    CHK(pkt.Write(monitorId), STREAM_BUF_WRITE_FAIL);
    CHK(pkt.Write(eventId), STREAM_BUF_WRITE_FAIL);
    CHK(client->SendMessage(pkt), MSG_SEND_FAIL);
}

int32_t InputHandlerManager::AddLocal(int32_t handlerId, InputHandlerType handlerType,
    std::shared_ptr<IInputEventConsumer> monitor)
{
    std::lock_guard<std::mutex> guard(lockHandlers_);
    InputHandlerManager::InputHandler handler {
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
    if (client == nullptr) {
        MMI_LOGE("AddToServer Get MMIClint false");
        return;
    }
    NetPacket pkt(MmiMessageId::ADD_INPUT_HANDLER);
    CHK(pkt.Write(handlerId), STREAM_BUF_WRITE_FAIL);
    CHK(pkt.Write(handlerType), STREAM_BUF_WRITE_FAIL);
    CHK(client->SendMessage(pkt), MSG_SEND_FAIL);
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
        MMI_LOGE("Unmatched handler type, InputHandlerType:%{public}d, FindHandlerType:%{public}d",
                 handlerType, tItr->second.handlerType_);
        return RET_ERR;
    }
    inputHandlers_.erase(tItr);
    return RET_OK;
}

void InputHandlerManager::RemoveFromServer(int32_t handlerId, InputHandlerType handlerType)
{
    MMI_LOGD("Remove handler:%{public}d from server", handlerId);
    MMIClientPtr client = MMIEventHdl.GetMMIClient();
    if (client == nullptr) {
        MMI_LOGE("RemoveFromServer Get MMIClint false");
        return;
    }
    NetPacket pkt(MmiMessageId::REMOVE_INPUT_HANDLER);
    CHK(pkt.Write(handlerId), STREAM_BUF_WRITE_FAIL);
    CHK(pkt.Write(handlerType), STREAM_BUF_WRITE_FAIL);
    CHK(client->SendMessage(pkt), MSG_SEND_FAIL);
}

int32_t InputHandlerManager::GetNextId()
{
    if (nextId_ == std::numeric_limits<int32_t>::max()) {
        MMI_LOGE("Exceeded limit of 32-bit maximum number of integers");
        return INVALID_HANDLER_ID;
    }
    return nextId_++;
}

void InputHandlerManager::OnInputEvent(int32_t handlerId, std::shared_ptr<KeyEvent> keyEvent)
{
    std::lock_guard<std::mutex> guard(lockHandlers_);
    auto tItr = inputHandlers_.find(handlerId);
    if (tItr != inputHandlers_.end()) {
        if (tItr->second.consumer_ != nullptr) {
            tItr->second.consumer_->OnInputEvent(keyEvent);
        }
    }
}

void InputHandlerManager::OnInputEvent(int32_t handlerId, std::shared_ptr<PointerEvent> pointerEvent)
{
    MMI_LOGD("Enter handler:%{public}d", handlerId);
    int32_t eventTouch = 9;
    std::string touchEvent = "TouchEventFilterAsync";
    FinishAsyncTrace(BYTRACE_TAG_MULTIMODALINPUT, touchEvent, eventTouch);
    std::map<int32_t, InputHandler>::iterator tItr;
    std::map<int32_t, InputHandler>::iterator tItrEnd;
    {
        std::lock_guard<std::mutex> guard(lockHandlers_);
        tItr = inputHandlers_.find(handlerId);
        tItrEnd = inputHandlers_.end();
    }
    if (tItr != tItrEnd) {
        if (tItr->second.consumer_ != nullptr) {
            tItr->second.consumer_->OnInputEvent(pointerEvent);
        }
    }
    MMI_LOGD("Leave");
}
} // namespace MMI
} // namespace OHOS

