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
#include <limits>
#include "input_handler_type.h"
#include "log.h"
#include "multimodal_event_handler.h"
#include "net_packet.h"
#include "proto.h"

namespace OHOS {
namespace MMI {
namespace {
    static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "InputHandlerManager" };
}

const int32_t InputHandlerManager::MIN_HANDLER_ID = 1;
const int32_t InputHandlerManager::INVALID_HANDLER_ID = -1;

int32_t InputHandlerManager::AddHandler(InputHandlerType handlerType,
    std::shared_ptr<IInputEventConsumer> consumer)
{
    if (inputHandlers_.size() >= MAX_N_INPUT_HANDLERS) {
        MMI_LOGE("The number of handlers exceeds the maximum");
        return INVALID_HANDLER_ID;
    }
    int32_t handlerId = GetNextId();
    if (RET_ERR == handlerId) {
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
    MMI_LOGD("Mark consumed state:monitorId=%{public}d, eventId=%{public}d", monitorId, eventId);
    MMIClientPtr client = MMIEventHdl.GetMMIClient();
    if (client == nullptr) {
        MMI_LOGE("Get MMIClint false");
        return;
    }
    NetPacket pkt(MmiMessageId::MARK_CONSUMED);
    pkt << monitorId << eventId;
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
        MMI_LOGE("Duplicate handler:%{public}d", handlerId);
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
    pkt << handlerId << handlerType;
    CHK(client->SendMessage(pkt), MSG_SEND_FAIL);
}

int32_t InputHandlerManager::RemoveLocal(int32_t handlerId, InputHandlerType handlerType)
{
    std::lock_guard<std::mutex> guard(lockHandlers_);
    auto tItr = inputHandlers_.find(handlerId);
    if (inputHandlers_.end() == tItr) {
        MMI_LOGW("No handler with specified ID");
        return RET_ERR;
    }
    if (tItr->second.handlerType_ != handlerType) {
        MMI_LOGW("Unmatched handler type");
        return RET_ERR;
    }
    inputHandlers_.erase(tItr);
    return RET_OK;
}

void InputHandlerManager::RemoveFromServer(int32_t handlerId, InputHandlerType handlerType)
{
    MMI_LOGD("Remove handler:%{public}d from server", handlerId);
    MMIClientPtr client { MMIEventHdl.GetMMIClient() };
    if (client == nullptr) {
        MMI_LOGE("RemoveFromServer Get MMIClint false");
        return;
    }
    NetPacket pkt(MmiMessageId::REMOVE_INPUT_HANDLER);
    pkt << handlerId << handlerType;
    CHK(client->SendMessage(pkt), MSG_SEND_FAIL);
}

int32_t InputHandlerManager::GetNextId()
{
    if (nextId_ == std::numeric_limits<int32_t>::max()) {
        MMI_LOGE("Exceeded limit of 32-bit maximum number of integers");
        return RET_ERR;
    }
    return nextId_++;
}

void InputHandlerManager::OnInputEvent(int32_t handlerId, std::shared_ptr<KeyEvent> keyEvent)
{
    std::lock_guard<std::mutex> guard(lockHandlers_);
    auto tItr = inputHandlers_.find(handlerId);
    if (tItr != inputHandlers_.end()) {
        if (tItr->second.consumer_ == nullptr) {
            tItr->second.consumer_->OnInputEvent(keyEvent);
        }
    }
}

void InputHandlerManager::OnInputEvent(int32_t handlerId, std::shared_ptr<PointerEvent> pointerEvent)
{
    MMI_LOGD("OnInputEvent handlerId:%{public}d", handlerId);
    std::lock_guard<std::mutex> guard(lockHandlers_);
    auto tItr = inputHandlers_.find(handlerId);
    if (tItr != inputHandlers_.end()) {
        if (tItr->second.consumer_ != nullptr) {
            tItr->second.consumer_->OnInputEvent(pointerEvent);
        }
    }
}
}
} // namespace OHOS::MMI

