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

#include "bytrace_adapter.h"
#include "input_handler_type.h"
#include "multimodal_event_handler.h"
#include "multimodal_input_connect_manager.h"
#include "mmi_log.h"
#include "napi_constants.h"
#include "net_packet.h"
#include "proto.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "InputHandlerManager" };
} // namespace

InputHandlerManager::InputHandlerManager()
{
    monitorCallback_ = std::bind(&InputHandlerManager::OnDispatchEventProcessed, this, std::placeholders::_1);
}

int32_t InputHandlerManager::AddHandler(InputHandlerType handlerType, std::shared_ptr<IInputEventConsumer> consumer,
    HandleEventType eventType, int32_t priority, uint32_t deviceTags)
{
    CALL_INFO_TRACE;
    CHKPR(consumer, INVALID_HANDLER_ID);
    std::lock_guard<std::mutex> guard(mtxHandlers_);
    if (inputHandlers_.size() >= MAX_N_INPUT_HANDLERS) {
        MMI_HILOGE("The number of handlers exceeds the maximum");
        return ERROR_EXCEED_MAX_COUNT;
    }
    int32_t handlerId = GetNextId();
    if (handlerId == INVALID_HANDLER_ID) {
        MMI_HILOGE("Exceeded limit of 32-bit maximum number of integers");
        return INVALID_HANDLER_ID;
    }

    if (eventType == HANDLE_EVENT_TYPE_NONE) {
        MMI_HILOGE("Invalid event type");
        return INVALID_HANDLER_ID;
    }
    const HandleEventType currentType = GetEventType();
    MMI_HILOGD("Register new handler:%{public}d", handlerId);
    if (RET_OK == AddLocal(handlerId, handlerType, eventType, priority, deviceTags, consumer)) {
        MMI_HILOGD("New handler successfully registered, report to server");
        const HandleEventType newType = GetEventType();
        if (currentType != newType) {
            int32_t ret = AddToServer(handlerType, newType, priority, deviceTags);
            if (ret != RET_OK) {
                MMI_HILOGD("Handler:%{public}d permissions failed, remove the monitor", handlerId);
                RemoveLocal(handlerId, handlerType);
                return ret;
            }
        }
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
    const HandleEventType currentType = GetEventType();
    if (RET_OK == RemoveLocal(handlerId, handlerType)) {
        MMI_HILOGD("Handler:%{public}d unregistered, report to server", handlerId);
        const HandleEventType newType = GetEventType();
        const int32_t newLevel = GetPriority();
        const uint64_t newTags = GetDeviceTags();
        if (currentType != newType) {
            RemoveFromServer(handlerType, newType, newLevel, newTags);
        }
    }
}

int32_t InputHandlerManager::AddLocal(int32_t handlerId, InputHandlerType handlerType, HandleEventType eventType,
    int32_t priority, uint32_t deviceTags, std::shared_ptr<IInputEventConsumer> monitor)
{
    InputHandlerManager::Handler handler {
        .handlerId_ = handlerId,
        .handlerType_ = handlerType,
        .eventType_ = eventType,
        .priority_ = priority,
        .deviceTags_ = deviceTags,
        .consumer_ = monitor,
    };
    auto ret = inputHandlers_.emplace(handler.handlerId_, handler);
    if (!ret.second) {
        MMI_HILOGE("Duplicate handler:%{public}d", handler.handlerId_);
        return RET_ERR;
    }
    if (handlerType == InputHandlerType::INTERCEPTOR) {
        auto iterIndex = interHandlers_.begin();
        for (; iterIndex != interHandlers_.end(); ++iterIndex) {
            if (handler.priority_ < iterIndex->priority_) {
                break;
            }
        }
        auto iter = interHandlers_.emplace(iterIndex, handler);
        if (iter == interHandlers_.end()) {
            MMI_HILOGE("Add new handler failed");
            return RET_ERR;
        }
    }
    return RET_OK;
}

int32_t InputHandlerManager::AddToServer(InputHandlerType handlerType, HandleEventType eventType,
    int32_t priority, uint32_t deviceTags)
{
    int32_t ret = MultimodalInputConnMgr->AddInputHandler(handlerType, eventType, priority, deviceTags);
    if (ret != RET_OK) {
        MMI_HILOGE("Send to server failed, ret:%{public}d", ret);
    }
    return ret;
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

    if (handlerType == InputHandlerType::INTERCEPTOR) {
        for (auto it = interHandlers_.begin(); it != interHandlers_.end(); ++it) {
            if (handlerId == it->handlerId_) {
                interHandlers_.erase(it);
                break;
            }
        }
    }
    return RET_OK;
}

void InputHandlerManager::RemoveFromServer(InputHandlerType handlerType, HandleEventType eventType,
    int32_t priority, uint32_t deviceTags)
{
    int32_t ret = MultimodalInputConnMgr->RemoveInputHandler(handlerType, eventType, priority, deviceTags);
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

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
void InputHandlerManager::OnInputEvent(std::shared_ptr<KeyEvent> keyEvent, uint32_t deviceTags)
{
    CHK_PID_AND_TID();
    CHKPV(keyEvent);
    std::lock_guard<std::mutex> guard(mtxHandlers_);
    BytraceAdapter::StartBytrace(keyEvent, BytraceAdapter::TRACE_STOP, BytraceAdapter::KEY_INTERCEPT_EVENT);
    if (!interHandlers_.empty()) {
        for (const auto &item : interHandlers_) {
            if ((item.deviceTags_ !=  deviceTags) &&
                ((item.eventType_ & HANDLE_EVENT_TYPE_KEY) != HANDLE_EVENT_TYPE_KEY)) {
                continue;
            }
            int32_t handlerId = item.handlerId_;
            auto consumer = item.consumer_;
            CHKPV(consumer);
            consumer->OnInputEvent(keyEvent);
            MMI_HILOGD("Key event id:%{public}d keyCode:%{public}d", handlerId, keyEvent->GetKeyCode());
            break;
        }
    } else {
        for (const auto &item : inputHandlers_) {
            if ((item.second.eventType_ & HANDLE_EVENT_TYPE_KEY) != HANDLE_EVENT_TYPE_KEY) {
                continue;
            }
            int32_t handlerId = item.first;
            auto consumer = item.second.consumer_;
            CHKPV(consumer);
            consumer->OnInputEvent(keyEvent);
            MMI_HILOGD("Key event id:%{public}d keyCode:%{public}d", handlerId, keyEvent->GetKeyCode());
        }
    }
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
void InputHandlerManager::GetConsumerInfos(std::shared_ptr<PointerEvent> pointerEvent, uint32_t deviceTags,
    std::map<int32_t, std::shared_ptr<IInputEventConsumer>> &consumerInfos)
{
    std::lock_guard<std::mutex> guard(mtxHandlers_);
    int32_t consumerCount = 0;
    if (!interHandlers_.empty()) {
        for (const auto &item : interHandlers_) {
            if ((item.deviceTags_ !=  deviceTags) &&
                ((item.eventType_ & HANDLE_EVENT_TYPE_POINTER) != HANDLE_EVENT_TYPE_POINTER)) {
                continue;
            }
            int32_t handlerId = item.handlerId_;
            auto consumer = item.consumer_;
            CHKPV(consumer);
            auto ret = consumerInfos.emplace(handlerId, consumer);
            if (!ret.second) {
                MMI_HILOGI("Duplicate handler:%{public}d", handlerId);
                continue;
            }
            consumerCount++;
            break;
        }
    } else {
        for (const auto &item : inputHandlers_) {
            if ((item.second.eventType_ & HANDLE_EVENT_TYPE_POINTER) != HANDLE_EVENT_TYPE_POINTER) {
                continue;
            }
            int32_t handlerId = item.first;
            auto consumer = item.second.consumer_;
            CHKPV(consumer);
            auto ret = consumerInfos.emplace(handlerId, consumer);
            if (!ret.second) {
                MMI_HILOGI("Duplicate handler:%{public}d", handlerId);
                continue;
            }
            consumerCount++;
        }
    }

    if (consumerCount == 0) {
        MMI_HILOGE("All task post failed");
        return;
    }
    int32_t tokenType = MultimodalInputConnMgr->GetTokenType();
    if (tokenType != TokenType::TOKEN_HAP) {
        return;
    }
    if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_MOUSE) {
        mouseEventIds_.emplace(pointerEvent->GetId());
    }
    if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_TOUCHSCREEN) {
        processedEvents_.emplace(pointerEvent->GetId(), consumerCount);
    }
}

void InputHandlerManager::OnInputEvent(std::shared_ptr<PointerEvent> pointerEvent, uint32_t deviceTags)
{
    CHK_PID_AND_TID();
    CHKPV(pointerEvent);
    BytraceAdapter::StartBytrace(pointerEvent, BytraceAdapter::TRACE_STOP, BytraceAdapter::POINT_INTERCEPT_EVENT);
    std::map<int32_t, std::shared_ptr<IInputEventConsumer>> consumerInfos;
    GetConsumerInfos(pointerEvent, deviceTags, consumerInfos);
    for (const auto &iter : consumerInfos) {
        auto tempEvent = std::make_shared<PointerEvent>(*pointerEvent);
        tempEvent->SetProcessedCallback(monitorCallback_);
        CHKPV(iter.second);
        auto consumer = iter.second;
        consumer->OnInputEvent(tempEvent);
        MMI_HILOGD("Pointer event id:%{public}d pointerId:%{public}d", iter.first, pointerEvent->GetPointerId());
    }
}
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

#if defined(OHOS_BUILD_ENABLE_INTERCEPTOR) || defined(OHOS_BUILD_ENABLE_MONITOR)
void InputHandlerManager::OnConnected()
{
    CALL_DEBUG_ENTER;
    HandleEventType eventType = GetEventType();
    int32_t priority = GetPriority();
    uint32_t deviceTags = GetDeviceTags();
    if (eventType != HANDLE_EVENT_TYPE_NONE) {
        AddToServer(GetHandlerType(), eventType, priority, deviceTags);
    }
}
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR || OHOS_BUILD_ENABLE_MONITOR

bool InputHandlerManager::HasHandler(int32_t handlerId)
{
    std::lock_guard<std::mutex> guard(mtxHandlers_);
    auto iter = inputHandlers_.find(handlerId);
    return (iter != inputHandlers_.end());
}

HandleEventType InputHandlerManager::GetEventType() const
{
    if (inputHandlers_.empty()) {
        MMI_HILOGD("InputHandlers is empty");
        return HANDLE_EVENT_TYPE_NONE;
    }
    HandleEventType eventType { HANDLE_EVENT_TYPE_NONE };
    if (!interHandlers_.empty()) {
        eventType |= interHandlers_.front().eventType_;
    } else {
        for (const auto &inputHandler : inputHandlers_) {
            eventType |= inputHandler.second.eventType_;
        }
    }
    return eventType;
}

int32_t InputHandlerManager::GetPriority() const
{
    if (inputHandlers_.empty()) {
        MMI_HILOGD("InputHandlers is empty");
        return DEFUALT_INTERCEPTOR_PRIORITY;
    }
    int32_t priority { DEFUALT_INTERCEPTOR_PRIORITY };
    if (!interHandlers_.empty()) {
        priority = interHandlers_.front().priority_;
    }
    return priority;
}

uint32_t InputHandlerManager::GetDeviceTags() const
{
    if (inputHandlers_.empty()) {
        MMI_HILOGD("InputHandlers is empty");
        return DEFUALT_INTERCEPTOR_PRIORITY;
    }
    uint32_t deviceTags { CapabilityToTags(InputDeviceCapability::INPUT_DEV_CAP_MAX) };
    if (!interHandlers_.empty()) {
        deviceTags = interHandlers_.front().deviceTags_;
    }
    return deviceTags;
}

void InputHandlerManager::OnDispatchEventProcessed(int32_t eventId)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mtxHandlers_);
    MMIClientPtr client = MMIEventHdl.GetMMIClient();
    CHKPV(client);
    if (mouseEventIds_.find(eventId) != mouseEventIds_.end()) {
        mouseEventIds_.erase(eventId);
        return;
    }
    auto iter = processedEvents_.find(eventId);
    if (iter == processedEvents_.end()) {
        MMI_HILOGE("EventId not in processedEvents_");
        return;
    }
    int32_t count = iter->second;
    processedEvents_.erase(iter);
    count--;
    if (count > 0) {
        processedEvents_.emplace(eventId, count);
        return;
    }
    NetPacket pkt(MmiMessageId::MARK_PROCESS);
    pkt << eventId << ANR_MONITOR;
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet write event failed");
        return;
    }
    if (!client->SendMessage(pkt)) {
        MMI_HILOGE("Send message failed, errCode:%{public}d", MSG_SEND_FAIL);
        return;
    }
}
} // namespace MMI
} // namespace OHOS
