/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "anr_handler.h"
#include "bytrace_adapter.h"
#include "multimodal_event_handler.h"
#include "multimodal_input_connect_manager.h"
#include "mmi_log.h"
#include "error_multimodal.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputHandlerManager"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t DEVICE_TAGS { 1 };
constexpr int32_t THREE_FINGERS { 3 };
constexpr int32_t FOUR_FINGERS { 4 };
} // namespace
InputHandlerManager::InputHandlerManager()
{
    monitorCallback_ =
        [this] (int32_t eventId, int64_t actionTime) { return this->OnDispatchEventProcessed(eventId, actionTime); };
    monitorCallbackConsume_ =
        [this] (int32_t eventId, int64_t actionTime) {
            return this->OnDispatchEventProcessed(eventId, actionTime, true);
        };
}

int32_t InputHandlerManager::AddHandler(InputHandlerType handlerType, std::shared_ptr<IInputEventConsumer> consumer,
    HandleEventType eventType, int32_t priority, uint32_t deviceTags)
{
    CALL_DEBUG_ENTER;
    CHKPR(consumer, INVALID_HANDLER_ID);
    if (handlerType == InputHandlerType::INTERCEPTOR) {
        eventType = HANDLE_EVENT_TYPE_NONE;
        if ((deviceTags & CapabilityToTags(InputDeviceCapability::INPUT_DEV_CAP_KEYBOARD)) != 0) {
            eventType |= HANDLE_EVENT_TYPE_KEY;
        }
        if ((deviceTags & (CapabilityToTags(InputDeviceCapability::INPUT_DEV_CAP_MAX) -
            CapabilityToTags(InputDeviceCapability::INPUT_DEV_CAP_KEYBOARD))) != 0) {
            eventType |= HANDLE_EVENT_TYPE_POINTER;
        }
    }
    std::lock_guard guard(mtxHandlers_);
    CHKFR(((monitorHandlers_.size() + interHandlers_.size()) < MAX_N_INPUT_HANDLERS), ERROR_EXCEED_MAX_COUNT,
          "The number of handlers exceeds the maximum");
    int32_t handlerId = GetNextId();
    CHKFR((handlerId != INVALID_HANDLER_ID), INVALID_HANDLER_ID, "Exceeded limit of 32-bit maximum number of integers");
    CHKFR((eventType != HANDLE_EVENT_TYPE_NONE), INVALID_HANDLER_ID, "Invalid event type");
    const HandleEventType currentType = GetEventType();
    MMI_HILOGD("Register new handler:%{public}d, currentType:%{public}d, deviceTags:%{public}d", handlerId, currentType,
        deviceTags);
    uint32_t currentTags = GetDeviceTags();
    if (RET_OK == AddLocal(handlerId, handlerType, eventType, priority, deviceTags, consumer)) {
        MMI_HILOGD("New handler successfully registered, report to server");
        const HandleEventType newType = GetEventType();
        if (currentType != newType || ((currentTags & deviceTags) != deviceTags)) {
            uint32_t allDeviceTags = GetDeviceTags();
            MMI_HILOGD("The handlerType:%{public}d, newType:%{public}d, deviceTags:%{public}d, priority:%{public}d",
                handlerType, newType, allDeviceTags, priority);
            int32_t ret = AddToServer(handlerType, newType, priority, allDeviceTags);
            if (ret != RET_OK) {
                MMI_HILOGE("Add Handler:%{public}d:%{public}d to server failed, (eventType,deviceTag) current: "
                           "(%{public}d, %{public}d), new: (%{public}d, %{public}d), priority:%{public}d",
                           handlerType, handlerId, currentType, currentTags, newType, deviceTags, priority);
                RemoveLocal(handlerId, handlerType, allDeviceTags);
                return ret;
            }
        }
        MMI_HILOGI("Finish add Handler:%{public}d:%{public}d, (eventType,deviceTag) current:"
                   " (%{public}d, %{public}d), new: (%{public}d, %{public}d), priority:%{public}d",
                   handlerType, handlerId, currentType, currentTags, newType, deviceTags, priority);
    } else {
        MMI_HILOGE("Add Handler:%{public}d:%{public}d local failed, (eventType,deviceTag,priority): "
                   "(%{public}d, %{public}d, %{public}d)", handlerType, handlerId, eventType, deviceTags, priority);
        handlerId = INVALID_HANDLER_ID;
    }
    return handlerId;
}

int32_t InputHandlerManager::AddGestureMonitor(
    InputHandlerType handlerType, std::shared_ptr<IInputEventConsumer> consumer,
    HandleEventType eventType, TouchGestureType gestureType, int32_t fingers)
{
    CHKPR(consumer, INVALID_HANDLER_ID);
    std::lock_guard guard(mtxHandlers_);
    CHKFR(((monitorHandlers_.size() + interHandlers_.size()) < MAX_N_INPUT_HANDLERS), ERROR_EXCEED_MAX_COUNT,
          "The number of handlers exceeds the maximum");
    int32_t handlerId = GetNextId();
    CHKFR((handlerId != INVALID_HANDLER_ID), INVALID_HANDLER_ID,
        "Exceeded limit of 32-bit maximum number of integers");
    CHKFR((eventType != HANDLE_EVENT_TYPE_NONE), INVALID_HANDLER_ID, "Invalid event type");
    int32_t ret = AddGestureToLocal(handlerId, eventType, gestureType, fingers, consumer);
    if (ret == RET_OK) {
        const HandleEventType newType = GetEventType();
        ret = MULTIMODAL_INPUT_CONNECT_MGR->AddGestureMonitor(handlerType, newType, gestureType, fingers);
        if (ret != RET_OK) {
            MMI_HILOGE("Add gesture handler:%{public}d to server failed, ret:%{public}d", gestureType, ret);
            uint32_t deviceTags = 0;
            RemoveLocal(handlerId, handlerType, deviceTags);
            return INVALID_HANDLER_ID;
        }
        MMI_HILOGI("Finish add gesture handler(%{public}d:%{public}d:%{public}d:%{public}d) to server",
            handlerId, eventType, gestureType, fingers);
    } else {
        handlerId = INVALID_HANDLER_ID;
    }
    return handlerId;
}

int32_t InputHandlerManager::AddHandler(InputHandlerType handlerType, std::shared_ptr<IInputEventConsumer> consumer,
    std::vector<int32_t> actionsType)
{
    CALL_DEBUG_ENTER;
    CHKPR(consumer, INVALID_HANDLER_ID);
    std::lock_guard guard(mtxHandlers_);
    CHKFR(((actionsMonitorHandlers_.size() + monitorHandlers_.size() + interHandlers_.size()) <
        MAX_N_INPUT_HANDLERS), ERROR_EXCEED_MAX_COUNT, "The number of handlers exceeds the maximum");
    int32_t handlerId = GetNextId();
    CHKFR((handlerId != INVALID_HANDLER_ID), INVALID_HANDLER_ID, "Exceeded limit of 32-bit maximum number of integers");
    MMI_HILOGD("Register new handler:%{public}d", handlerId);
    if (RET_OK == AddLocal(handlerId, handlerType, actionsType, consumer)) {
        MMI_HILOGD("New handler successfully registered, report to server");
        if (IsNeedAddToServer(actionsType)) {
            MMI_HILOGD("The handlerType:%{public}d", handlerType);
            int32_t ret = AddToServer(handlerType, HANDLE_EVENT_TYPE_NONE, 0, 0, actionsType);
            if (ret != RET_OK) {
                MMI_HILOGE("Add Handler:%{public}d:%{public}d to server failed", handlerType, handlerId);
                RemoveLocalActions(handlerId, handlerType);
                return ret;
            }
        }
        MMI_HILOGI("Finish add Handler:%{public}d:%{public}d to server", handlerType, handlerId);
    } else {
        MMI_HILOGE("Add Handler:%{public}d:%{public}d local failed", handlerType, handlerId);
        handlerId = INVALID_HANDLER_ID;
    }
    return handlerId;
}

int32_t InputHandlerManager::RemoveGestureMonitor(int32_t handlerId, InputHandlerType handlerType)
{
    std::lock_guard guard(mtxHandlers_);
    auto iter = monitorHandlers_.find(handlerId);
    if (iter == monitorHandlers_.end()) {
        MMI_HILOGE("No handler(%{public}d) with specified", handlerId);
        return RET_ERR;
    }
    const auto gestureHandler = iter->second.gestureHandler_;
    monitorHandlers_.erase(iter);
    const HandleEventType newType = GetEventType();

    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->RemoveGestureMonitor(handlerType, newType,
        gestureHandler.gestureType, gestureHandler.fingers);
    if (ret != RET_OK) {
        MMI_HILOGE("Remove gesture handler:%{public}d to server failed, ret:%{public}d",
            gestureHandler.gestureType, ret);
    } else {
        MMI_HILOGI("Finish remove gesture handler:%{public}d:%{public}d:%{public}d,(%{public}d,%{public}d)",
            handlerType, newType, handlerId, gestureHandler.gestureType, gestureHandler.fingers);
    }
    return ret;
}

bool InputHandlerManager::IsNeedAddToServer(std::vector<int32_t> actionsType)
{
    bool isNeedAddToServer = false;
    for (auto action : actionsType) {
        if (std::find(addToServerActions_.begin(), addToServerActions_.end(), action) == addToServerActions_.end()) {
            addToServerActions_.push_back(action);
            isNeedAddToServer = true;
        }
    }
    return isNeedAddToServer;
}

int32_t InputHandlerManager::RemoveHandler(int32_t handlerId, InputHandlerType handlerType)
{
    CALL_DEBUG_ENTER;
    MMI_HILOGD("Unregister handler:%{public}d,type:%{public}d", handlerId, handlerType);
    std::lock_guard guard(mtxHandlers_);
    uint32_t deviceTags = 0;
    auto iter = monitorHandlers_.find(handlerId);
    bool isInterHandlers = false;
    for (auto inter = interHandlers_.begin(); inter != interHandlers_.end(); ++inter) {
        if (handlerId == inter->handlerId_) {
            isInterHandlers = true;
            break;
        }
    }
    if (iter != monitorHandlers_.end() || isInterHandlers) {
        const HandleEventType currentType = GetEventType();
        uint32_t currentTags = GetDeviceTags();
        int32_t ret = RemoveLocal(handlerId, handlerType, deviceTags);
        const HandleEventType newType = GetEventType();
        const int32_t newLevel = GetPriority();
        const uint64_t newTags = GetDeviceTags();
        if (ret == RET_OK && (currentType != newType || ((currentTags & deviceTags) != 0))) {
            ret = RemoveFromServer(handlerType, newType, newLevel, newTags);
            if (ret != RET_OK) {
                return ret;
            }
            MMI_HILOGI("Remove Handler:%{public}d:%{public}d, (eventType,deviceTag): (%{public}d:%{public}d) ",
                handlerType, handlerId, currentType, currentTags);
        }
        return ret;
    }

    auto it = actionsMonitorHandlers_.find(handlerId);
    if (it != actionsMonitorHandlers_.end()) {
        std::vector<int32_t> actionsType = it->second.actionsType_;
        size_t currentSize = addToServerActions_.size();
        int32_t ret = RemoveLocalActions(handlerId, handlerType);
        size_t newSize = addToServerActions_.size();
        if (ret == RET_OK && currentSize != newSize) {
            ret = RemoveFromServer(handlerType, HANDLE_EVENT_TYPE_NONE, 0, 0, actionsType);
            if (ret != RET_OK) {
                return ret;
            }
            MMI_HILOGI("Remove Handler:%{public}d:%{public}d", handlerType, handlerId);
        }
        return ret;
    }
    return RET_ERR;
}

int32_t InputHandlerManager::AddGestureToLocal(int32_t handlerId, HandleEventType eventType,
    TouchGestureType gestureType, int32_t fingers, std::shared_ptr<IInputEventConsumer> consumer)
{
    if ((eventType & HANDLE_EVENT_TYPE_TOUCH_GESTURE) != HANDLE_EVENT_TYPE_TOUCH_GESTURE) {
        MMI_HILOGE("Illegal type:%{public}d", eventType);
        return RET_ERR;
    }
    if (!CheckMonitorValid(gestureType, fingers)) {
        MMI_HILOGE("Wrong number of fingers:%{public}d", fingers);
        return RET_ERR;
    }
    for (const auto &handler : monitorHandlers_) {
        if (handler.second.eventType_ == eventType &&
            handler.second.gestureHandler_.gestureType == gestureType &&
            handler.second.gestureHandler_.fingers == fingers) {
            MMI_HILOGE("Gesture(%{public}d) listener already exists", gestureType);
            return RET_ERR;
        }
    }
    InputHandlerManager::Handler handler {
        .handlerId_ = handlerId,
        .handlerType_ = InputHandlerType::MONITOR,
        .eventType_ = eventType,
        .consumer_ = consumer,
        .gestureHandler_ {
            .gestureType = gestureType,
            .fingers = fingers
        }
    };
    auto ret = monitorHandlers_.emplace(handlerId, handler);
    if (!ret.second) {
        MMI_HILOGE("Duplicate handler:%{public}d", handlerId);
        return RET_ERR;
    }
    return RET_OK;
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
    if (handlerType == InputHandlerType::MONITOR) {
        auto ret = monitorHandlers_.emplace(handler.handlerId_, handler);
        if (!ret.second) {
            MMI_HILOGE("Duplicate handler:%{public}d", handler.handlerId_);
            return RET_ERR;
        }
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

int32_t InputHandlerManager::AddLocal(int32_t handlerId, InputHandlerType handlerType, std::vector<int32_t> actionsType,
    std::shared_ptr<IInputEventConsumer> monitor)
{
    InputHandlerManager::Handler handler{
        .handlerId_ = handlerId,
        .handlerType_ = handlerType,
        .eventType_ = HANDLE_EVENT_TYPE_NONE,
        .consumer_ = monitor,
        .actionsType_ = actionsType,
    };
    if (handlerType == InputHandlerType::MONITOR) {
        auto ret = actionsMonitorHandlers_.emplace(handler.handlerId_, handler);
        if (!ret.second) {
            MMI_HILOGE("Actions duplicate handler:%{public}d", handler.handlerId_);
            return RET_ERR;
        }
    }
    return RET_OK;
}

int32_t InputHandlerManager::AddToServer(InputHandlerType handlerType, HandleEventType eventType, int32_t priority,
    uint32_t deviceTags, std::vector<int32_t> actionsType)
{
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->AddInputHandler(handlerType,
        eventType, priority, deviceTags, actionsType);
    if (ret != RET_OK) {
        MMI_HILOGE("Send to server failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t InputHandlerManager::RemoveLocal(int32_t handlerId, InputHandlerType handlerType, uint32_t &deviceTags)
{
    if (handlerType == InputHandlerType::MONITOR) {
        auto iter = monitorHandlers_.find(handlerId);
        if (iter == monitorHandlers_.end()) {
            MMI_HILOGE("No handler with specified");
            return RET_ERR;
        }
        if (handlerType != iter->second.handlerType_) {
            MMI_HILOGE("Unmatched handler type, InputHandlerType:%{public}d,FindHandlerType:%{public}d", handlerType,
                iter->second.handlerType_);
            return RET_ERR;
        }
        monitorHandlers_.erase(iter);
    }

    if (handlerType == InputHandlerType::INTERCEPTOR) {
        for (auto it = interHandlers_.begin(); it != interHandlers_.end(); ++it) {
            if (handlerId == it->handlerId_) {
                deviceTags = it->deviceTags_;
                interHandlers_.erase(it);
                break;
            }
        }
    }
    return RET_OK;
}

void InputHandlerManager::UpdateAddToServerActions()
{
    std::vector<int32_t> addToServerActions;
    for (const auto &[key, value] : actionsMonitorHandlers_) {
        for (auto action : value.actionsType_) {
            if (std::find(addToServerActions.begin(), addToServerActions.end(), action) ==
                addToServerActions.end()) {
                addToServerActions.push_back(action);
            }
        }
    }
    addToServerActions_.clear();
    addToServerActions_ = addToServerActions;
}

int32_t InputHandlerManager::RemoveLocalActions(int32_t handlerId, InputHandlerType handlerType)
{
    if (handlerType == InputHandlerType::MONITOR) {
        auto iter = actionsMonitorHandlers_.find(handlerId);
        if (iter == actionsMonitorHandlers_.end()) {
            MMI_HILOGE("No handler with specified");
            return RET_ERR;
        }
        if (handlerType != iter->second.handlerType_) {
            MMI_HILOGE("Unmatched handler type, FindHandlerType:%{public}d", iter->second.handlerType_);
            return RET_ERR;
        }
        actionsMonitorHandlers_.erase(iter);
        UpdateAddToServerActions();
    }
    return RET_OK;
}

int32_t InputHandlerManager::RemoveFromServer(InputHandlerType handlerType, HandleEventType eventType, int32_t priority,
    uint32_t deviceTags, std::vector<int32_t> actionsType)
{
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->RemoveInputHandler(handlerType, eventType,
        priority, deviceTags, actionsType);
    if (ret != 0) {
        MMI_HILOGE("Send to server failed, ret:%{public}d", ret);
    }
    return ret;
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
    if (GetHandlerType() == InputHandlerType::MONITOR) {
        auto iter = monitorHandlers_.find(handlerId);
        if (iter != monitorHandlers_.end()) {
            return iter->second.consumer_;
        }
    }
    if (GetHandlerType() == InputHandlerType::INTERCEPTOR) {
        for (const auto &item : interHandlers_) {
            if (item.handlerId_ == handlerId) {
                return item.consumer_;
            }
        }
    }
    return nullptr;
}

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
void InputHandlerManager::OnInputEvent(std::shared_ptr<KeyEvent> keyEvent, uint32_t deviceTags)
{
    CHK_PID_AND_TID();
    CHKPV(keyEvent);
    BytraceAdapter::StartBytrace(keyEvent, BytraceAdapter::TRACE_STOP, BytraceAdapter::KEY_INTERCEPT_EVENT);
    if (GetHandlerType() == InputHandlerType::MONITOR) {
        std::map<int32_t, Handler> tempMonitorHandlers;
        {
            std::lock_guard guard(mtxHandlers_);
            tempMonitorHandlers = monitorHandlers_;
        }
        for (const auto &item : tempMonitorHandlers) {
            if ((item.second.eventType_ & HANDLE_EVENT_TYPE_KEY) != HANDLE_EVENT_TYPE_KEY) {
                continue;
            }
            int32_t handlerId = item.first;
            std::shared_ptr<IInputEventConsumer> consumer = item.second.consumer_;
            CHKPV(consumer);
            {
                std::lock_guard guard(mtxHandlers_);
                auto iter = monitorHandlers_.find(handlerId);
                if (iter == monitorHandlers_.end()) {
                    MMI_HILOGE("No handler with specified");
                    continue;
                }
            }
            consumer->OnInputEvent(keyEvent);
            MMI_HILOG_DISPATCHD("Key event id:%{public}d keyCode:%{private}d",
                handlerId, keyEvent->GetKeyCode());
        }
    }
    if (GetHandlerType() == InputHandlerType::INTERCEPTOR) {
        std::lock_guard guard(mtxHandlers_);
        for (const auto &item : interHandlers_) {
            if ((item.eventType_ & HANDLE_EVENT_TYPE_KEY) != HANDLE_EVENT_TYPE_KEY) {
                continue;
            }
            int32_t handlerId = item.handlerId_;
            std::shared_ptr<IInputEventConsumer> consumer = item.consumer_;
            CHKPV(consumer);
            consumer->OnInputEvent(keyEvent);
            MMI_HILOG_DISPATCHD("Key event id:%{public}d keyCode:%{private}d",
                handlerId, keyEvent->GetKeyCode());
            break;
        }
    }
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
bool InputHandlerManager::CheckInputDeviceSource(
    const std::shared_ptr<PointerEvent> pointerEvent, uint32_t deviceTags) const
{
    if ((pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_TOUCHSCREEN) &&
        ((deviceTags & CapabilityToTags(InputDeviceCapability::INPUT_DEV_CAP_TOUCH)) ||
        (deviceTags & CapabilityToTags(InputDeviceCapability::INPUT_DEV_CAP_TABLET_TOOL)))) {
        return true;
    } else if ((pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_MOUSE) &&
        (deviceTags & CapabilityToTags(InputDeviceCapability::INPUT_DEV_CAP_POINTER))) {
        return true;
    } else if ((pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_TOUCHPAD) &&
        (deviceTags & CapabilityToTags(InputDeviceCapability::INPUT_DEV_CAP_POINTER))) {
        return true;
    }
    return false;
}

void InputHandlerManager::GetConsumerInfos(std::shared_ptr<PointerEvent> pointerEvent, uint32_t deviceTags,
    std::map<int32_t, std::shared_ptr<IInputEventConsumer>> &consumerInfos)
{
    std::lock_guard guard(mtxHandlers_);
    int32_t consumerCount = 0;
    if (GetHandlerType() == InputHandlerType::MONITOR) {
        lastPointerEvent_ = std::make_shared<PointerEvent>(*pointerEvent);
        consumerCount = GetMonitorConsumerInfos(pointerEvent, consumerInfos);
    }
    if (GetHandlerType() == InputHandlerType::INTERCEPTOR) {
        for (const auto &item : interHandlers_) {
            if ((item.eventType_ & HANDLE_EVENT_TYPE_POINTER) != HANDLE_EVENT_TYPE_POINTER) {
                continue;
            }
            if (((deviceTags & item.deviceTags_) == item.deviceTags_) &&
                !CheckInputDeviceSource(pointerEvent, item.deviceTags_)) {
                continue;
            }
            int32_t handlerId = item.handlerId_;
            std::shared_ptr<IInputEventConsumer> consumer = item.consumer_;
            CHKPV(consumer);
            auto ret = consumerInfos.emplace(handlerId, consumer);
            if (!ret.second) {
                MMI_HILOGI("Duplicate handler:%{public}d", handlerId);
                continue;
            }
            consumerCount++;
            break;
        }
    }

    if (consumerCount == 0) {
        MMI_HILOGD("All task post failed");
        return;
    }
    int32_t tokenType = MULTIMODAL_INPUT_CONNECT_MGR->GetTokenType();
    if (tokenType != TokenType::TOKEN_HAP && tokenType != TokenType::TOKEN_SYSTEM_HAP) {
        return;
    }
    AddMouseEventId(pointerEvent);
}

void InputHandlerManager::AddMouseEventId(std::shared_ptr<PointerEvent> pointerEvent)
{
    if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_MOUSE) {
        mouseEventIds_.emplace(pointerEvent->GetId());
    }
}

bool InputHandlerManager::IsPinchType(std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPF(pointerEvent);
    if (pointerEvent->GetSourceType() != PointerEvent::SOURCE_TYPE_MOUSE &&
        pointerEvent->GetSourceType() != PointerEvent::SOURCE_TYPE_TOUCHPAD) {
        return false;
    }
    if ((pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_AXIS_BEGIN &&
        pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_AXIS_UPDATE &&
        pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_AXIS_END)) {
        return false;
    }
    return true;
}

bool InputHandlerManager::IsRotateType(std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPF(pointerEvent);
    if (pointerEvent->GetSourceType() != PointerEvent::SOURCE_TYPE_MOUSE ||
        (pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_ROTATE_BEGIN &&
        pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_ROTATE_UPDATE &&
        pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_ROTATE_END)) {
        return false;
    }
    return true;
}


bool InputHandlerManager::IsThreeFingersSwipeType(std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPF(pointerEvent);
    if (pointerEvent->GetSourceType() != PointerEvent::SOURCE_TYPE_TOUCHPAD ||
        pointerEvent->GetFingerCount() != THREE_FINGERS ||
        (pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_SWIPE_BEGIN &&
        pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_SWIPE_UPDATE &&
        pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_SWIPE_END)) {
        return false;
    }
    return true;
}

bool InputHandlerManager::IsFourFingersSwipeType(std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPF(pointerEvent);
    if (pointerEvent->GetSourceType() != PointerEvent::SOURCE_TYPE_TOUCHPAD ||
        pointerEvent->GetFingerCount() != FOUR_FINGERS ||
        (pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_SWIPE_BEGIN &&
        pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_SWIPE_UPDATE &&
        pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_SWIPE_END)) {
        return false;
    }
    return true;
}

bool InputHandlerManager::IsThreeFingersTapType(std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    if (pointerEvent->GetSourceType() != PointerEvent::SOURCE_TYPE_TOUCHPAD ||
        pointerEvent->GetFingerCount() != THREE_FINGERS ||
        (pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_TRIPTAP)) {
        return false;
    }
    return true;
}

#ifdef OHOS_BUILD_ENABLE_FINGERPRINT
bool InputHandlerManager::IsFingerprintType(std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_FINGERPRINT &&
        ((PointerEvent::POINTER_ACTION_FINGERPRINT_DOWN <= pointerEvent->GetPointerAction() &&
        pointerEvent->GetPointerAction() <= PointerEvent::POINTER_ACTION_FINGERPRINT_CLICK) ||
        pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_FINGERPRINT_CANCEL ||
        pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_FINGERPRINT_HOLD ||
        pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_FINGERPRINT_TOUCH)) {
            return true;
    }
    MMI_HILOGD("not fingerprint event");
    return false;
}
#endif // OHOS_BUILD_ENABLE_FINGERPRINT

#ifdef OHOS_BUILD_ENABLE_X_KEY
bool InputHandlerManager::IsXKeyType(std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_X_KEY) {
        return true;
    }
    MMI_HILOGD("Not X-key event");
    return false;
}
#endif // OHOS_BUILD_ENABLE_X_KEY

bool InputHandlerManager::CheckIfNeedAddToConsumerInfos(const Handler &monitor,
    std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPF(pointerEvent);
#ifdef OHOS_BUILD_ENABLE_FINGERPRINT
    if ((monitor.eventType_ & HANDLE_EVENT_TYPE_FINGERPRINT) == HANDLE_EVENT_TYPE_FINGERPRINT &&
        IsFingerprintType(pointerEvent)) {
        return true;
    }
#endif // OHOS_BUILD_ENABLE_FINGERPRINT
#ifdef OHOS_BUILD_ENABLE_X_KEY
    if ((monitor.eventType_ & HANDLE_EVENT_TYPE_X_KEY) == HANDLE_EVENT_TYPE_X_KEY &&
        IsXKeyType(pointerEvent)) {
        return true;
    }
#endif // OHOS_BUILD_ENABLE_X_KEY
    if ((monitor.eventType_ & HANDLE_EVENT_TYPE_POINTER) == HANDLE_EVENT_TYPE_POINTER) {
        return true;
    } else if ((monitor.eventType_ & HANDLE_EVENT_TYPE_TOUCH_GESTURE) == HANDLE_EVENT_TYPE_TOUCH_GESTURE) {
        return true;
    } else if ((monitor.eventType_ & HANDLE_EVENT_TYPE_SWIPEINWARD) == HANDLE_EVENT_TYPE_SWIPEINWARD) {
        return true;
    } else if ((monitor.eventType_ & HANDLE_EVENT_TYPE_TOUCH) == HANDLE_EVENT_TYPE_TOUCH &&
        pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_TOUCHSCREEN) {
        return true;
    } else if ((monitor.eventType_ & HANDLE_EVENT_TYPE_MOUSE) == HANDLE_EVENT_TYPE_MOUSE &&
        pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_MOUSE) {
        return true;
    } else if ((monitor.eventType_ & HANDLE_EVENT_TYPE_PINCH) == HANDLE_EVENT_TYPE_PINCH &&
        IsPinchType(pointerEvent)) {
        return true;
    } else if ((monitor.eventType_ & HANDLE_EVENT_TYPE_THREEFINGERSSWIP) == HANDLE_EVENT_TYPE_THREEFINGERSSWIP &&
        IsThreeFingersSwipeType(pointerEvent)) {
        return true;
    } else if ((monitor.eventType_ & HANDLE_EVENT_TYPE_FOURFINGERSSWIP) == HANDLE_EVENT_TYPE_FOURFINGERSSWIP &&
        IsFourFingersSwipeType(pointerEvent)) {
        return true;
    } else if ((monitor.eventType_ & HANDLE_EVENT_TYPE_ROTATE) == HANDLE_EVENT_TYPE_ROTATE &&
        IsRotateType(pointerEvent)) {
        return true;
    } else if ((monitor.eventType_ & HANDLE_EVENT_TYPE_THREEFINGERSTAP) == HANDLE_EVENT_TYPE_THREEFINGERSTAP &&
        IsThreeFingersTapType(pointerEvent)) {
        return true;
    }
    return false;
}

int32_t InputHandlerManager::GetMonitorConsumerInfos(std::shared_ptr<PointerEvent> pointerEvent,
    std::map<int32_t, std::shared_ptr<IInputEventConsumer>> &consumerInfos)
{
    int32_t consumerCount = 0;
    CHKPR(pointerEvent, consumerCount);
    MMI_HILOG_DISPATCHD("id:%{public}d ac:%{public}d recv", pointerEvent->GetId(), pointerEvent->GetPointerAction());
    for (const auto &item : monitorHandlers_) {
        if (!CheckIfNeedAddToConsumerInfos(item.second, pointerEvent)) {
            continue;
        }
        if (!IsMatchGesture(item.second, pointerEvent->GetPointerAction(), pointerEvent->GetPointerCount())) {
            continue;
        }
        int32_t handlerId = item.first;
        std::shared_ptr<IInputEventConsumer> consumer = item.second.consumer_;
        CHKPR(consumer, INVALID_HANDLER_ID);
        auto ret = consumerInfos.emplace(handlerId, consumer);
        if (!ret.second) {
            MMI_HILOGI("Duplicate handler:%{public}d", handlerId);
            continue;
        }
        consumerCount++;
    }
    for (const auto &item : actionsMonitorHandlers_) {
        for (auto action : item.second.actionsType_) {
            if (action != pointerEvent->GetPointerAction()) {
                continue;
            }
            int32_t handlerId = item.first;
            std::shared_ptr<IInputEventConsumer> consumer = item.second.consumer_;
            CHKPR(consumer, INVALID_HANDLER_ID);
            auto ret = consumerInfos.emplace(handlerId, consumer);
            if (!ret.second) {
                MMI_HILOGI("Duplicate handler:%{public}d", handlerId);
                continue;
            }
            consumerCount++;
        }
    }
    return consumerCount;
}

void InputHandlerManager::OnInputEvent(std::shared_ptr<PointerEvent> pointerEvent, uint32_t deviceTags)
{
    CHK_PID_AND_TID();
    CHKPV(pointerEvent);
    BytraceAdapter::StartBytrace(pointerEvent, BytraceAdapter::TRACE_STOP, BytraceAdapter::POINT_INTERCEPT_EVENT);
    std::map<int32_t, std::shared_ptr<IInputEventConsumer>> consumerInfos;
    GetConsumerInfos(pointerEvent, deviceTags, consumerInfos);
    for (auto iter = consumerInfos.begin(); iter != consumerInfos.end(); ++iter) {
        auto tempEvent = std::make_shared<PointerEvent>(*pointerEvent);
        if (std::next(iter) == consumerInfos.end()) {
            tempEvent->SetProcessedCallback(monitorCallbackConsume_);
        } else {
            tempEvent->SetProcessedCallback(monitorCallback_);
        }
        if (tempEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_SWIPE_BEGIN ||
            tempEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_SWIPE_END) {
            MMI_HILOGI("Swipe event sended to handler! action type:%{public}d finger count:%{public}d",
                tempEvent->GetPointerAction(),
                tempEvent->GetFingerCount());
        }
        CHKPV(iter->second);
        auto consumer = iter->second;
        consumer->OnInputEvent(tempEvent);
        MMI_HILOG_DISPATCHD("Pointer event id:%{public}d pointerId:%{public}d",
            iter->first, pointerEvent->GetPointerId());
    }
}
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

#if defined(OHOS_BUILD_ENABLE_INTERCEPTOR) || defined(OHOS_BUILD_ENABLE_MONITOR)
template<typename T>
bool InputHandlerManager::RecoverPointerEvent(std::initializer_list<T> pointerActionEvents, T pointerActionEvent)
{
    CALL_INFO_TRACE;
    std::unique_lock lock(mtxHandlers_);
    CHKPF(lastPointerEvent_);
    int32_t pointerAction = lastPointerEvent_->GetPointerAction();
    for (const auto &it : pointerActionEvents) {
        if (pointerAction == it) {
            PointerEvent::PointerItem item;
            int32_t pointerId = lastPointerEvent_->GetPointerId();
            if (!lastPointerEvent_->GetPointerItem(pointerId, item)) {
                MMI_HILOG_DISPATCHD("Get pointer item failed. pointer:%{public}d",
                    pointerId);
                return false;
            }
            item.SetPressed(false);
            lastPointerEvent_->UpdatePointerItem(pointerId, item);
            lastPointerEvent_->SetPointerAction(pointerActionEvent);
            auto copiedPointerEvent = std::make_shared<PointerEvent>(*lastPointerEvent_);
            lock.unlock();
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
            OnInputEvent(copiedPointerEvent, DEVICE_TAGS);
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
            return true;
        }
    }
    return false;
}

void InputHandlerManager::OnDisconnected()
{
    CALL_INFO_TRACE;
    std::initializer_list<int32_t> pointerActionSwipeEvents { PointerEvent::POINTER_ACTION_SWIPE_UPDATE,
        PointerEvent::POINTER_ACTION_SWIPE_BEGIN };
    if (RecoverPointerEvent(pointerActionSwipeEvents, PointerEvent::POINTER_ACTION_SWIPE_END)) {
        MMI_HILOGE("Swipe end event for service exception re-sending");
        return;
    }
}

void InputHandlerManager::OnConnected()
{
    std::lock_guard guard(mtxHandlers_);
    MMI_HILOGI("Reregister gesture monitors on reconnection");
    RegisterGestureMonitors();
    MMI_HILOGI("Enable event monitors(interceptors) on reconnection");
    HandleEventType eventType = GetEventType();
    int32_t priority = GetPriority();
    uint32_t deviceTags = GetDeviceTags();
    std::vector<int32_t> actionsType = GetActionsType();
    if (eventType != HANDLE_EVENT_TYPE_NONE || !actionsType.empty()) {
        AddToServer(GetHandlerType(), eventType, priority, deviceTags, actionsType);
    }
}
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR || OHOS_BUILD_ENABLE_MONITOR

bool InputHandlerManager::HasHandler(int32_t handlerId)
{
    std::lock_guard guard(mtxHandlers_);
    bool hasHandler = false;
    if (GetHandlerType() == InputHandlerType::MONITOR) {
        auto iter = monitorHandlers_.find(handlerId);
        hasHandler = (iter != monitorHandlers_.end()) ? true : false;
        if (!hasHandler) {
            auto iter = actionsMonitorHandlers_.find(handlerId);
            return (iter != actionsMonitorHandlers_.end());
        }
        return hasHandler;
    }
    if (GetHandlerType() == InputHandlerType::INTERCEPTOR) {
        for (const auto &item : interHandlers_) {
            if (item.handlerId_ == handlerId) {
                return true;
            }
        }
    }
    return false;
}

HandleEventType InputHandlerManager::GetEventType() const
{
    uint32_t eventType{ HANDLE_EVENT_TYPE_NONE };
    if (GetHandlerType() == InputHandlerType::MONITOR) {
        if (monitorHandlers_.empty()) {
            MMI_HILOGD("The monitorHandlers_ is empty");
            return HANDLE_EVENT_TYPE_NONE;
        }
        for (const auto &inputHandler : monitorHandlers_) {
            eventType |= inputHandler.second.eventType_;
        }
    }

    if (GetHandlerType() == InputHandlerType::INTERCEPTOR) {
        if (interHandlers_.empty()) {
            MMI_HILOGD("The interHandlers_ is empty");
            return HANDLE_EVENT_TYPE_NONE;
        }
        for (const auto &interHandler : interHandlers_) {
            eventType |= interHandler.eventType_;
        }
    }
    return eventType;
}

int32_t InputHandlerManager::GetPriority() const
{
    int32_t priority{ DEFUALT_INTERCEPTOR_PRIORITY };
    if (GetHandlerType() == InputHandlerType::INTERCEPTOR) {
        if (!interHandlers_.empty()) {
            priority = interHandlers_.front().priority_;
        }
    }
    return priority;
}

uint32_t InputHandlerManager::GetDeviceTags() const
{
    uint32_t deviceTags = 0;
    if (GetHandlerType() == InputHandlerType::INTERCEPTOR) {
        for (const auto &item : interHandlers_) {
            deviceTags |= item.deviceTags_;
        }
    }
    if (GetHandlerType() == InputHandlerType::MONITOR) {
        for (const auto &item : monitorHandlers_) {
            deviceTags |= item.second.deviceTags_;
        }
    }
    return deviceTags;
}

std::vector<int32_t> InputHandlerManager::GetActionsType() const
{
    return addToServerActions_;
}

void InputHandlerManager::OnDispatchEventProcessed(int32_t eventId, int64_t actionTime)
{
    std::lock_guard guard(mtxHandlers_);
    CALL_DEBUG_ENTER;
    MMIClientPtr client = MMIEventHdl.GetMMIClient();
    CHKPV(client);
    if (mouseEventIds_.find(eventId) != mouseEventIds_.end()) {
        mouseEventIds_.erase(eventId);
        return;
    }
}

void InputHandlerManager::OnDispatchEventProcessed(int32_t eventId, int64_t actionTime, bool isNeedConsume)
{
    OnDispatchEventProcessed(eventId, actionTime);
    ANRHDL->SetLastProcessedEventId(ANR_MONITOR, eventId, actionTime);
}

bool InputHandlerManager::IsMatchGesture(const Handler &handler, int32_t action, int32_t count)
{
    if ((handler.eventType_ & HANDLE_EVENT_TYPE_TOUCH_GESTURE) != HANDLE_EVENT_TYPE_TOUCH_GESTURE) {
        return true;
    }
    auto iter = monitorHandlers_.find(handler.handlerId_);
    if (iter == monitorHandlers_.end()) {
        return false;
    }
    GestureHandler &gestureHandler = iter->second.gestureHandler_;
    TouchGestureType type = TOUCH_GESTURE_TYPE_NONE;
    switch (action) {
        case PointerEvent::TOUCH_ACTION_SWIPE_DOWN:
        case PointerEvent::TOUCH_ACTION_SWIPE_UP:
        case PointerEvent::TOUCH_ACTION_SWIPE_RIGHT:
        case PointerEvent::TOUCH_ACTION_SWIPE_LEFT:
            type = TOUCH_GESTURE_TYPE_SWIPE;
            break;
        case PointerEvent::TOUCH_ACTION_PINCH_OPENED:
        case PointerEvent::TOUCH_ACTION_PINCH_CLOSEED:
            type = TOUCH_GESTURE_TYPE_PINCH;
            break;
        case PointerEvent::TOUCH_ACTION_GESTURE_END: {
            if (!gestureHandler.gestureState) {
                return false;
            }
            gestureHandler.gestureState = false;
            return true;
        }
        default: {
            MMI_HILOGD("Unknown action:%{public}d", action);
            return false;
        }
    }
    if (((gestureHandler.gestureType & type) == type) &&
        (gestureHandler.fingers == count || gestureHandler.fingers == ALL_FINGER_COUNT)) {
        gestureHandler.gestureState = true;
        return true;
    }
    return false;
}

void InputHandlerManager::RegisterGestureMonitors() const
{
    for (const auto &[_, handler] : monitorHandlers_) {
        if ((handler.eventType_ & HANDLE_EVENT_TYPE_TOUCH_GESTURE) != HANDLE_EVENT_TYPE_TOUCH_GESTURE) {
            continue;
        }
        MMI_HILOGI("AddGestureMonitor(%{public}u, %{public}d) to server",
            handler.gestureHandler_.gestureType, handler.gestureHandler_.fingers);
        auto ret = MULTIMODAL_INPUT_CONNECT_MGR->AddGestureMonitor(
            InputHandlerType::MONITOR, HANDLE_EVENT_TYPE_TOUCH_GESTURE,
            handler.gestureHandler_.gestureType, handler.gestureHandler_.fingers);
        if (ret != RET_OK) {
            MMI_HILOGE("AddGestureMonitor to server fail, ret:%{public}d", ret);
        }
    }
}
} // namespace MMI
} // namespace OHOS
