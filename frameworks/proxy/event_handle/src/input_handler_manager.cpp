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
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "InputHandlerManager"};
}

const size_t InputHandlerManager::MAX_N_HANDLERS { 16 };
const int32_t InputHandlerManager::MIN_HANDLER_ID { 1 };

int32_t InputHandlerManager::AddHandler(InputHandlerType handlerType, std::shared_ptr<IInputEventConsumer> consumer)
{
    if (inputHandlers_.size() >= MAX_N_HANDLERS) {
        MMI_LOGE("The number of handlers exceeds the maximum...");
        return -1;
    }
    int32_t handlerId { TakeNextId() };
    AddLocal(handlerId, handlerType, consumer);
    AddToServer(handlerId, handlerType);
    return handlerId;
}

void InputHandlerManager::RemoveHandler(int32_t handlerId, InputHandlerType handlerType)
{
    RemoveLocal(handlerId, handlerType);
    RemoveFromServer(handlerId, handlerType);
}

void InputHandlerManager::MarkConsumed(int32_t monitorId, int32_t eventId)
{
    MMIClientPtr client = MMIEventHdl.GetMMIClient();
    if (!client) {
        MMI_LOGE("Get MMIClint false...");
        return;
    }
    NetPacket pkt(MmiMessageId::MARK_CONSUMED);
    pkt << monitorId << eventId;
    client->SendMessage(pkt);
}

void InputHandlerManager::AddLocal(int32_t handlerId, InputHandlerType handlerType,
    std::shared_ptr<IInputEventConsumer> monitor)
{
    std::lock_guard<std::mutex> guard(lockHandlers_);
    InputHandlerManager::InputHandler handler {
        .id_ = handlerId,
        .handlerType_ = handlerType,
        .consumer_ = monitor
    };
    inputHandlers_.emplace(handler.id_, handler);
}

void InputHandlerManager::AddToServer(int32_t handlerId, InputHandlerType handlerType)
{
    MMIClientPtr client { MMIEventHdl.GetMMIClient() };
    if (!client) {
        MMI_LOGE("AddToServer Get MMIClint false...");
        return;
    }
    NetPacket pkt(MmiMessageId::ADD_INPUT_HANDLER);
    pkt << handlerId << handlerType;
    client->SendMessage(pkt);
}

void InputHandlerManager::RemoveLocal(int32_t id, InputHandlerType handlerType)
{
    MMI_LOGD("RemoveLocal in");
    std::lock_guard<std::mutex> guard(lockHandlers_);
    auto tItr = inputHandlers_.find(id);
    if (inputHandlers_.end() == tItr) {
        MMI_LOGE("not find id...");
        return;
    }
    if (tItr->second.handlerType_ != handlerType) {
        MMI_LOGE("not find handlerType...");
        return;
    }
    inputHandlers_.erase(tItr);
}

void InputHandlerManager::RemoveFromServer(int32_t id, InputHandlerType handlerType)
{
    MMI_LOGD("RemoveFromServer in");
    MMIClientPtr client { MMIEventHdl.GetMMIClient() };
    if (!client) {
        MMI_LOGE("RemoveFromServer Get MMIClint false...");
        return;
    }
    NetPacket pkt(MmiMessageId::REMOVE_INPUT_HANDLER);
    pkt << id << handlerType;
    client->SendMessage(pkt);
}

int32_t InputHandlerManager::TakeNextId()
{
    if (nextId_ >= std::numeric_limits<int32_t>::max()) {
        nextId_ = MIN_HANDLER_ID;
    }
    int32_t retId { nextId_++ };
    while (inputHandlers_.find(retId) != inputHandlers_.end()) {
        retId = nextId_++;
    }
    return retId;
}

void InputHandlerManager::OnInputEvent(int32_t handlerId, std::shared_ptr<KeyEvent> keyEvent)
{
    std::lock_guard<std::mutex> guard(lockHandlers_);
    auto tItr = inputHandlers_.find(handlerId);
    if (tItr != inputHandlers_.end()) {
        if (tItr->second.consumer_) {
            tItr->second.consumer_->OnInputEvent(keyEvent);
        }
    }
}

void InputHandlerManager::OnInputEvent(int32_t handlerId, std::shared_ptr<PointerEvent> pointerEvent)
{
    MMI_LOGD("OnInputEvent handlerId : %{public}d", handlerId);
    std::lock_guard<std::mutex> guard(lockHandlers_);
    auto tItr = inputHandlers_.find(handlerId);
    if (tItr != inputHandlers_.end()) {
        if (tItr->second.consumer_) {
            tItr->second.consumer_->OnInputEvent(pointerEvent);
        }
    }
}
}
} // namespace OHOS::MMI

