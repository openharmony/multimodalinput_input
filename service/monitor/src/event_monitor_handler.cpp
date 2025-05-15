/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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
 
#include "bytrace_adapter.h"
#include "input_event_data_transformation.h"
#include "input_event_handler.h"
#include "util_ex.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "EventMonitorHandler"

namespace OHOS {
namespace MMI {
namespace {
#ifdef OHOS_BUILD_ENABLE_TOUCH
constexpr size_t MAX_EVENTIDS_SIZE { 1000 };
#endif // OHOS_BUILD_ENABLE_TOUCH
constexpr int32_t ACTIVE_EVENT { 2 };
constexpr int32_t REMOVE_OBSERVER { -2 };
constexpr int32_t UNOBSERVED { -1 };
constexpr int32_t POWER_UID { 5528 };
constexpr int32_t THREE_FINGERS { 3 };
constexpr int32_t FOUR_FINGERS { 4 };
} // namespace

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
void EventMonitorHandler::HandleKeyEvent(const std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPV(keyEvent);
    OnHandleEvent(keyEvent);
    CHKPV(nextHandler_);
    nextHandler_->HandleKeyEvent(keyEvent);
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

#ifdef OHOS_BUILD_ENABLE_POINTER
void EventMonitorHandler::HandlePointerEvent(const std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPV(pointerEvent);
    if (OnHandleEvent(pointerEvent)) {
        BytraceAdapter::StartBytrace(pointerEvent, BytraceAdapter::TRACE_STOP);
        MMI_HILOGD("Monitor is succeeded");
        return;
    }
    CHKPV(nextHandler_);
    nextHandler_->HandlePointerEvent(pointerEvent);
}
#endif // OHOS_BUILD_ENABLE_POINTER

#ifdef OHOS_BUILD_ENABLE_TOUCH
void EventMonitorHandler::HandleTouchEvent(const std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPV(pointerEvent);
    if (OnHandleEvent(pointerEvent)) {
        BytraceAdapter::StartBytrace(pointerEvent, BytraceAdapter::TRACE_STOP);
        MMI_HILOGD("Monitor is succeeded");
        return;
    }
    int32_t pointerId = pointerEvent->GetPointerId();
    PointerEvent::PointerItem item;
    if (pointerEvent->GetPointerItem(pointerId, item)) {
        if (item.GetToolType() == PointerEvent::TOOL_TYPE_KNUCKLE) {
            MMI_HILOGD("Knuckle event, skip");
            return;
        }
    }
    CHKPV(nextHandler_);
    nextHandler_->HandleTouchEvent(pointerEvent);
}
#endif // OHOS_BUILD_ENABLE_TOUCH

bool EventMonitorHandler::CheckHasInputHandler(HandleEventType eventType)
{
    return monitors_.CheckHasInputHandler(eventType);
}

int32_t EventMonitorHandler::AddInputHandler(InputHandlerType handlerType, HandleEventType eventType,
    std::shared_ptr<IInputEventConsumer> callback, TouchGestureType gestureType, int32_t fingers)
{
    CALL_INFO_TRACE;
    CHKPR(callback, RET_ERR);
    if ((eventType & HANDLE_EVENT_TYPE_ALL) == HANDLE_EVENT_TYPE_NONE) {
        MMI_HILOGE("Invalid event type");
        return RET_ERR;
    }
    InitSessionLostCallback();
    SessionHandler mon { handlerType, eventType, callback, gestureType, fingers };
    return monitors_.AddMonitor(mon);
}

int32_t EventMonitorHandler::AddInputHandler(InputHandlerType handlerType,
    HandleEventType eventType, SessionPtr session, TouchGestureType gestureType, int32_t fingers)
{
    CALL_INFO_TRACE;
    CHKPR(session, RET_ERR);
    if ((eventType & HANDLE_EVENT_TYPE_ALL) == HANDLE_EVENT_TYPE_NONE) {
        MMI_HILOGE("Invalid event type");
        return RET_ERR;
    }
    InitSessionLostCallback();
    SessionHandler mon { handlerType, eventType, session, gestureType, fingers };
    return monitors_.AddMonitor(mon);
}

int32_t EventMonitorHandler::AddInputHandler(InputHandlerType handlerType,
    std::vector<int32_t> actionsType, SessionPtr session)
{
    CALL_INFO_TRACE;
    CHKPR(session, RET_ERR);
    InitSessionLostCallback();
    SessionHandler mon { handlerType, HANDLE_EVENT_TYPE_NONE, session, actionsType };
    return monitors_.AddMonitor(mon);
}

void EventMonitorHandler::RemoveInputHandler(InputHandlerType handlerType, HandleEventType eventType,
    std::shared_ptr<IInputEventConsumer> callback, TouchGestureType gestureType, int32_t fingers)
{
    CALL_INFO_TRACE;
    CHKPV(callback);
    if (handlerType == InputHandlerType::MONITOR) {
        SessionHandler monitor { handlerType, eventType, callback, gestureType, fingers };
        monitors_.RemoveMonitor(monitor);
    }
}

void EventMonitorHandler::RemoveInputHandler(InputHandlerType handlerType, std::vector<int32_t> actionsType,
    SessionPtr session)
{
    CALL_INFO_TRACE;
    if (handlerType == InputHandlerType::MONITOR) {
        SessionHandler monitor { handlerType, HANDLE_EVENT_TYPE_NONE, session, actionsType };
        monitors_.RemoveMonitor(monitor);
    }
}

void EventMonitorHandler::RemoveInputHandler(InputHandlerType handlerType, HandleEventType eventType,
    SessionPtr session, TouchGestureType gestureType, int32_t fingers)
{
    CALL_INFO_TRACE;
    if (handlerType == InputHandlerType::MONITOR) {
        SessionHandler monitor { handlerType, eventType, session, gestureType, fingers };
        monitors_.RemoveMonitor(monitor);
    }
}

void EventMonitorHandler::MarkConsumed(int32_t eventId, SessionPtr session)
{
    LogTracer lt(eventId, 0, 0);
    monitors_.MarkConsumed(eventId, session);
}

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
bool EventMonitorHandler::OnHandleEvent(std::shared_ptr<KeyEvent> keyEvent)
{
    MMI_HILOGD("Handle KeyEvent");
    CHKPF(keyEvent);
    auto keyHandler = InputHandler->GetEventNormalizeHandler();
    CHKPF(keyHandler);
    if (keyEvent->GetKeyCode() != keyHandler->GetCurrentHandleKeyCode()) {
        MMI_HILOGW("Keycode has been changed");
    }
    if (keyEvent->HasFlag(InputEvent::EVENT_FLAG_NO_MONITOR)) {
        MMI_HILOGD("This event has been tagged as not to be monitored");
    } else {
        if (monitors_.HandleEvent(keyEvent)) {
            MMI_HILOGD("Key event was consumed");
            return true;
        }
    }
    return false;
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
bool EventMonitorHandler::OnHandleEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPF(pointerEvent);
    if (pointerEvent->HasFlag(InputEvent::EVENT_FLAG_NO_MONITOR)) {
        MMI_HILOGD("This event has been tagged as not to be monitored");
    } else {
        if (monitors_.HandleEvent(pointerEvent)) {
            MMI_HILOGD("Pointer event was monitor");
            return true;
        }
    }
    MMI_HILOGD("Interception and monitor failed");
    return false;
}
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

void EventMonitorHandler::InitSessionLostCallback()
{
    if (sessionLostCallbackInitialized_) {
        return;
    }
    auto udsServerPtr = InputHandler->GetUDSServer();
    CHKPV(udsServerPtr);
    udsServerPtr->AddSessionDeletedCallback([this] (SessionPtr session) {
        return this->OnSessionLost(session);
    });
    sessionLostCallbackInitialized_ = true;
    MMI_HILOGD("The callback on session deleted is registered successfully");
}

void EventMonitorHandler::OnSessionLost(SessionPtr session)
{
    monitors_.OnSessionLost(session);
}

bool EventMonitorHandler::SessionHandler::Expect(std::shared_ptr<PointerEvent> pointerEvent) const
{
    if (GestureMonitorHandler::IsTouchGestureEvent(pointerEvent->GetPointerAction())) {
        return (((eventType_ & HANDLE_EVENT_TYPE_TOUCH_GESTURE) == HANDLE_EVENT_TYPE_TOUCH_GESTURE) &&
            gesture_.IsMatchGesture(pointerEvent->GetPointerAction(), pointerEvent->GetPointerCount()));
    } else {
        return ((eventType_ & HANDLE_EVENT_TYPE_ALL) == eventType_);
    }
}

void EventMonitorHandler::SessionHandler::SendToClient(std::shared_ptr<KeyEvent> keyEvent, NetPacket &pkt) const
{
    CHKPV(keyEvent);
    CHKPV(session_);
    if (InputEventDataTransformation::KeyEventToNetPacket(keyEvent, pkt) != RET_OK) {
        MMI_HILOGE("Packet key event failed, errCode:%{public}d", STREAM_BUF_WRITE_FAIL);
        return;
    }
    if (!session_->SendMsg(pkt)) {
        MMI_HILOGE("Send message failed, errCode:%{public}d", MSG_SEND_FAIL);
    }
}

void EventMonitorHandler::SessionHandler::SendToClient(std::shared_ptr<PointerEvent> pointerEvent,
                                                       NetPacket &pkt) const
{
    CHKPV(pointerEvent);
    CHKPV(session_);
    MMI_HILOGD("Service SendToClient InputHandlerType:%{public}d, TokenType:%{public}d, pid:%{public}d",
        handlerType_, session_->GetTokenType(), session_->GetPid());
    if (!session_->SendMsg(pkt)) {
        MMI_HILOGE("Send message failed, errCode:%{public}d", MSG_SEND_FAIL);
    }
}

int32_t EventMonitorHandler::MonitorCollection::AddMonitor(const SessionHandler& monitor)
{
    if (monitors_.size() >= MAX_N_INPUT_MONITORS) {
        MMI_HILOGE("The number of monitors exceeds the maximum:%{public}zu, monitors errCode:%{public}d",
                   monitors_.size(), INVALID_MONITOR_MON);
        return RET_ERR;
    }
    bool isFound = false;
    SessionHandler handler = monitor;
    auto iter = monitors_.find(monitor);
    if (iter != monitors_.end()) {
        isFound = true;
    }
    if (isFound && iter->actionsType_.empty()) {
        return UpdateEventTypeMonitor(iter, monitor, handler, isFound);
    } else if (isFound && !iter->actionsType_.empty()) {
        return UpdateActionsTypeMonitor(iter, monitor, isFound);
    }
 
    if (!monitor.actionsType_.empty()) {
        for (auto action : monitor.actionsType_) {
            if (std::find(insertToMonitorsActions_.begin(), insertToMonitorsActions_.end(), action) ==
                insertToMonitorsActions_.end()) {
                insertToMonitorsActions_.push_back(action);
            }
        }
    }
    auto [sIter, isOk] = monitors_.insert(monitor);
    if (!isOk) {
        MMI_HILOGE("Failed to add monitor");
        return RET_ERR;
    }
    MMI_HILOGD("Service Add Monitor Success");
    return RET_OK;
}

int32_t EventMonitorHandler::MonitorCollection::UpdateEventTypeMonitor(const std::set<SessionHandler>::iterator &iter,
    const SessionHandler &monitor, SessionHandler &handler, bool isFound)
{
    if (iter->eventType_ == monitor.eventType_ &&
        ((monitor.eventType_ & HANDLE_EVENT_TYPE_TOUCH_GESTURE) != HANDLE_EVENT_TYPE_TOUCH_GESTURE)) {
        MMI_HILOGD("Monitor with event type (%{public}u) already exists", monitor.eventType_);
        return RET_OK;
    }
    if ((monitor.eventType_ & HANDLE_EVENT_TYPE_TOUCH_GESTURE) == HANDLE_EVENT_TYPE_TOUCH_GESTURE) {
        auto gestureHandler = iter->gesture_;
        gestureHandler.AddGestureMonitor(monitor.gesture_.gestureType_, monitor.gesture_.fingers_);
        handler(gestureHandler);
    }

    monitors_.erase(iter);
    auto [sIter, isOk] = monitors_.insert(handler);
    if (!isOk) {
        if (isFound) {
            MMI_HILOGE("Internal error: monitor has been removed");
        } else {
            MMI_HILOGE("Failed to add monitor");
        }
        return RET_ERR;
    }
    MMI_HILOGD("Event type is updated:%{public}u", monitor.eventType_);
    return RET_OK;
}

int32_t EventMonitorHandler::MonitorCollection::UpdateActionsTypeMonitor(const std::set<SessionHandler>::iterator &iter,
    const SessionHandler &monitor, bool isFound)
{
    if (!IsNeedInsertToMonitors(iter->actionsType_)) {
            return RET_OK;
        }
        monitors_.erase(iter);
        auto [sIter, isOk] = monitors_.insert(monitor);
        if (!isOk && isFound) {
            MMI_HILOGE("Internal error: monitor has been removed");
            return RET_ERR;
        } else if (!isOk && !isFound) {
            MMI_HILOGE("Failed to add monitor");
            return RET_ERR;
        }
        MMI_HILOGD("Actions type is updated");
        return RET_OK;
}

bool EventMonitorHandler::MonitorCollection::IsNeedInsertToMonitors(std::vector<int32_t> actionsType)
{
    bool isNeedInsertToMonitors = false;
    for (auto action : actionsType) {
        if (std::find(insertToMonitorsActions_.begin(), insertToMonitorsActions_.end(), action) ==
            insertToMonitorsActions_.end()) {
            insertToMonitorsActions_.push_back(action);
            isNeedInsertToMonitors = true;
        }
    }
    return isNeedInsertToMonitors;
}

void EventMonitorHandler::MonitorCollection::RemoveMonitor(const SessionHandler& monitor)
{
    SessionHandler handler = monitor;
    auto iter = monitors_.find(monitor);
    if (iter == monitors_.cend()) {
        MMI_HILOGE("Monitor does not exist");
        return;
    }

    if ((monitor.eventType_ & HANDLE_EVENT_TYPE_TOUCH_GESTURE) == HANDLE_EVENT_TYPE_TOUCH_GESTURE) {
        auto gestureHandler = iter->gesture_;
        gestureHandler.RemoveGestureMonitor(monitor.gesture_.gestureType_, monitor.gesture_.fingers_);
        handler(gestureHandler);
    }
    monitors_.erase(iter);
    if (monitor.session_) {
        int32_t pid = monitor.session_->GetPid();
        auto it = endScreenCaptureMonitors_.find(pid);
        if (it != endScreenCaptureMonitors_.end()) {
            auto setIter = endScreenCaptureMonitors_[pid].find(monitor);
            if (setIter != endScreenCaptureMonitors_[pid].end()) {
                endScreenCaptureMonitors_[pid].erase(setIter);
            }
            if (endScreenCaptureMonitors_[pid].empty()) {
                endScreenCaptureMonitors_.erase(it);
            }
        }
    }
    if (monitor.eventType_ == HANDLE_EVENT_TYPE_NONE) {
        MMI_HILOGD("Unregister monitor successfully");
        return;
    }

    auto [sIter, isOk] = monitors_.insert(handler);
    if (!isOk) {
        MMI_HILOGE("Internal error, monitor has been removed");
        return;
    }
    MMI_HILOGD("Event type is updated:%{public}u", monitor.eventType_);
}

void EventMonitorHandler::MonitorCollection::MarkConsumed(int32_t eventId, SessionPtr session)
{
    if (!HasMonitor(session)) {
        MMI_HILOGW("Specified monitor does not exist");
        return;
    }
    auto tIter = states_.begin();
    for (; tIter != states_.end(); ++tIter) {
        const auto &eventIds = tIter->second.eventIds_;
        if (eventIds.find(eventId) != eventIds.cend()) {
            break;
        }
    }
    if (tIter == states_.end()) {
        MMI_HILOGE("No operation corresponding to this event");
        return;
    }
    ConsumptionState &state = tIter->second;

    if (state.isMonitorConsumed_) {
        MMI_HILOGE("Corresponding operation has been marked as consumed");
        return;
    }
    state.isMonitorConsumed_ = true;
    CHKPV(state.lastPointerEvent_);
#ifdef OHOS_BUILD_ENABLE_TOUCH
    MMI_HILOGD("Cancel operation");
    auto pointerEvent = std::make_shared<PointerEvent>(*state.lastPointerEvent_);
    WIN_MGR->CancelAllTouches(pointerEvent);
#endif // OHOS_BUILD_ENABLE_TOUCH
}

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
bool EventMonitorHandler::MonitorCollection::HandleEvent(std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPF(keyEvent);
    MMI_HILOGD("There are currently %{public}zu monitors", monitors_.size());
    NetPacket pkt(MmiMessageId::REPORT_KEY_EVENT);
    pkt << InputHandlerType::MONITOR << static_cast<uint32_t>(evdev_device_udev_tags::EVDEV_UDEV_TAG_INPUT);
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet write key event failed");
        return false;
    }
    for (const auto &mon : monitors_) {
        if ((mon.eventType_ & HANDLE_EVENT_TYPE_KEY) != HANDLE_EVENT_TYPE_KEY) {
            continue;
        }
        if (!keyEvent->GetFourceMonitorFlag()) {
            mon.SendToClient(keyEvent, pkt);
        } else if (mon.session_ != nullptr && mon.session_->GetUid() == POWER_UID) {
            mon.SendToClient(keyEvent, pkt);
        }
    }
    if (NapProcess::GetInstance()->GetNapClientPid() != REMOVE_OBSERVER &&
        NapProcess::GetInstance()->GetNapClientPid() != UNOBSERVED) {
        for (const auto &mon : monitors_) {
            OHOS::MMI::NapProcess::NapStatusData napData;
            auto sess = mon.session_;
            if (!sess) {
                continue;
            }
            napData.pid = sess->GetPid();
            napData.uid = sess->GetUid();
            napData.bundleName = sess->GetProgramName();
            if (NapProcess::GetInstance()->IsNeedNotify(napData)) {
                int32_t syncState = ACTIVE_EVENT;
                NapProcess::GetInstance()->AddMmiSubscribedEventData(napData, syncState);
                NapProcess::GetInstance()->NotifyBundleName(napData, syncState);
            }
        }
    }
    return false;
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
bool EventMonitorHandler::MonitorCollection::HandleEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPF(pointerEvent);
#ifdef OHOS_BUILD_ENABLE_TOUCH
    UpdateConsumptionState(pointerEvent);
#endif // OHOS_BUILD_ENABLE_TOUCH
    Monitor(pointerEvent);
    if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_TOUCHSCREEN ||
        pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_TOUCHPAD) {
        auto iter = states_.find(pointerEvent->GetDeviceId());
        return (iter != states_.end() ? iter->second.isMonitorConsumed_ : false);
    }
    MMI_HILOGD("This is not a touch-screen event");
    return false;
}
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

bool EventMonitorHandler::MonitorCollection::HasMonitor(SessionPtr session)
{
    SessionHandler monitor { InputHandlerType::MONITOR, HANDLE_EVENT_TYPE_ALL, session };
    return (monitors_.find(monitor) != monitors_.end());
}

bool EventMonitorHandler::MonitorCollection::HasScreenCaptureMonitor(SessionPtr session)
{
    int32_t pid = session->GetPid();
    return (endScreenCaptureMonitors_.find(pid) != endScreenCaptureMonitors_.end());
}

void EventMonitorHandler::MonitorCollection::RemoveScreenCaptureMonitor(SessionPtr session)
{
    if (session->GetTokenType() != TokenType::TOKEN_HAP) {
        return;
    }
    int32_t pid = session->GetPid();
    std::set<SessionHandler> monitorSet;
    for (const auto &monitor : monitors_) {
        if (monitor.session_ == session) {
            SessionHandler screenCaptureMointor(monitor);
            monitorSet.insert(screenCaptureMointor);
        }
    }
    for (const auto &monitor : monitorSet) {
        auto it = monitors_.find(monitor);
        if (it != monitors_.end()) {
            monitors_.erase(it);
        }
    }
    endScreenCaptureMonitors_.emplace(pid, monitorSet);
}

void EventMonitorHandler::MonitorCollection::RecoveryScreenCaptureMonitor(SessionPtr session)
{
    if (session->GetTokenType() != TokenType::TOKEN_HAP) {
        return;
    }
    int32_t pid = session->GetPid();
    auto it = endScreenCaptureMonitors_.find(pid);
    if (it != endScreenCaptureMonitors_.end()) {
        for (auto &monitor : endScreenCaptureMonitors_[pid]) {
            SessionHandler screenCaptureMointor(monitor);
            monitors_.insert(screenCaptureMointor);
        }
        endScreenCaptureMonitors_.erase(it);
    }
}

#ifdef OHOS_BUILD_ENABLE_TOUCH
void EventMonitorHandler::MonitorCollection::UpdateConsumptionState(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(pointerEvent);
    if (pointerEvent->GetSourceType() != PointerEvent::SOURCE_TYPE_TOUCHSCREEN &&
        pointerEvent->GetSourceType() != PointerEvent::SOURCE_TYPE_TOUCHPAD) {
        return;
    }
    auto sIter = states_.find(pointerEvent->GetDeviceId());
    if (sIter == states_.end()) {
        auto [tIter, isOk] = states_.emplace(pointerEvent->GetDeviceId(), ConsumptionState());
        if (!isOk) {
            MMI_HILOGE("Failed to emplace consumption state");
            return;
        }
        sIter = tIter;
    }
    ConsumptionState &state = sIter->second;
    if (state.eventIds_.size() >= MAX_EVENTIDS_SIZE) {
        auto iter = state.eventIds_.begin();
        state.eventIds_.erase(iter);
    }
    auto [tIter, isOk] = state.eventIds_.emplace(pointerEvent->GetId());
    if (!isOk) {
        MMI_HILOGW("Failed to stash event");
    }
    state.lastPointerEvent_ = pointerEvent;

    if (pointerEvent->GetPointerIds().size() != 1) {
        MMI_HILOGD("In intermediate process");
        return;
    }
    if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_DOWN ||
        pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_AXIS_BEGIN ||
        pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_SWIPE_BEGIN) {
        MMI_HILOGD("First press down");
        state.eventIds_.clear();
        auto [tIter, isOk] = state.eventIds_.emplace(pointerEvent->GetId());
        if (!isOk) {
            MMI_HILOGW("Event number is duplicated");
        }
        state.isMonitorConsumed_ = false;
    } else if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_UP ||
        pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_AXIS_END ||
        pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_SWIPE_END) {
        MMI_HILOGD("Last lift up");
        state.eventIds_.clear();
    }
}
#endif // OHOS_BUILD_ENABLE_TOUCH

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
void EventMonitorHandler::MonitorCollection::IsSendToClient(const SessionHandler &monitor,
    std::shared_ptr<PointerEvent> pointerEvent, NetPacket &pkt)
{
    if (monitor.Expect(pointerEvent)) {
        if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_SWIPE_BEGIN ||
            pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_SWIPE_END) {
            MMI_HILOGI("Swipe event sended in monitor! action type:%{public}d finger count:%{public}d",
                pointerEvent->GetPointerAction(),
                pointerEvent->GetFingerCount());
        }
        if (monitor.session_ && CheckIfNeedSendToClient(monitor, pointerEvent, fingerFocusPidSet)) {
            monitor.SendToClient(pointerEvent, pkt);
            return;
        }
        if (monitor.callback_) {
            monitor.callback_->OnInputEvent(monitor.handlerType_, pointerEvent);
        }
    }
    if (monitor.actionsType_.empty()) {
        return;
    }
    auto iter = std::find(monitor.actionsType_.begin(), monitor.actionsType_.end(),
    pointerEvent->GetPointerAction());
    if (iter != monitor.actionsType_.end() && monitor.session_) {
        monitor.SendToClient(pointerEvent, pkt);
    }
}

void EventMonitorHandler::MonitorCollection::Monitor(std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPV(pointerEvent);
    MMI_HILOGD("There are currently %{public}zu monitors", monitors_.size());
    NetPacket pkt(MmiMessageId::REPORT_POINTER_EVENT);
    pkt << InputHandlerType::MONITOR << static_cast<uint32_t>(evdev_device_udev_tags::EVDEV_UDEV_TAG_INPUT);
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet write pointer event failed");
        return;
    }
    if (InputEventDataTransformation::Marshalling(pointerEvent, pkt) != RET_OK) {
        MMI_HILOGE("Marshalling pointer event failed, errCode:%{public}d", STREAM_BUF_WRITE_FAIL);
        return;
    }
    int32_t pointerId = pointerEvent->GetPointerId();
    PointerEvent::PointerItem pointerItem;
    pointerEvent->GetPointerItem(pointerId, pointerItem);
    int32_t displayX = pointerItem.GetDisplayX();
    int32_t displayY = pointerItem.GetDisplayY();
    std::unordered_set<int32_t> fingerFocusPidSet;
    for (const auto &monitor : monitors_) {
        if ((monitor.eventType_ & HANDLE_EVENT_TYPE_FINGERPRINT) == HANDLE_EVENT_TYPE_FINGERPRINT &&
            monitor.session_->GetPid() == WIN_MGR->GetPidByWindowId(WIN_MGR->GetFocusWindowId())) {
            fingerFocusPidSet.insert(monitor.session_->GetPid());
        }
    }
    for (const auto &monitor : monitors_) {
        IsSendToClient(monitor, pointerEvent, pkt);
        PointerEvent::PointerItem pointerItem1;
        pointerEvent->GetPointerItem(pointerId, pointerItem1);
        int32_t displayX1 = pointerItem1.GetDisplayX();
        int32_t displayY1 = pointerItem1.GetDisplayY();
        if (displayX != displayX1 || displayY != displayY1) {
            MMI_HILOGW("Display coord changed %{public}d, %{public}d, %{public}d, %{public}d, %{public}d",
                pointerId, displayX, displayY, displayX1, displayY1);
        }
    }
    if (NapProcess::GetInstance()->GetNapClientPid() != REMOVE_OBSERVER &&
        NapProcess::GetInstance()->GetNapClientPid() != UNOBSERVED) {
        for (const auto &mon : monitors_) {
            OHOS::MMI::NapProcess::NapStatusData napData;
            auto sess = mon.session_;
            if (!sess) {
                continue;
            }
            napData.pid = sess->GetPid();
            napData.uid = sess->GetUid();
            napData.bundleName = sess->GetProgramName();
            if (NapProcess::GetInstance()->IsNeedNotify(napData)) {
                int32_t syncState = ACTIVE_EVENT;
                NapProcess::GetInstance()->AddMmiSubscribedEventData(napData, syncState);
                NapProcess::GetInstance()->NotifyBundleName(napData, syncState);
            }
        }
    }
}
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

bool EventMonitorHandler::MonitorCollection::IsPinch(std::shared_ptr<PointerEvent> pointerEvent)
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

bool EventMonitorHandler::MonitorCollection::IsRotate(std::shared_ptr<PointerEvent> pointerEvent)
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


bool EventMonitorHandler::MonitorCollection::IsThreeFingersSwipe(std::shared_ptr<PointerEvent> pointerEvent)
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

bool EventMonitorHandler::MonitorCollection::IsFourFingersSwipe(std::shared_ptr<PointerEvent> pointerEvent)
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

bool EventMonitorHandler::MonitorCollection::IsThreeFingersTap(std::shared_ptr<PointerEvent> pointerEvent)
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
bool EventMonitorHandler::MonitorCollection::IsFingerprint(std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_FINGERPRINT &&
        (PointerEvent::POINTER_ACTION_FINGERPRINT_DOWN <= pointerEvent->GetPointerAction() &&
        pointerEvent->GetPointerAction() <= PointerEvent::POINTER_ACTION_FINGERPRINT_TOUCH)) {
            return true;
    }
    MMI_HILOGD("not fingerprint event");
    return false;
}

bool EventMonitorHandler::MonitorCollection::FingerprintEventMonitorHandle(
    SessionHandler monitor, std::shared_ptr<PointerEvent> pointerEvent, std::unordered_set<int32_t> fingerFocusPidSet)
{
    if ((monitor.eventType_ & HANDLE_EVENT_TYPE_FINGERPRINT) == HANDLE_EVENT_TYPE_FINGERPRINT) {
        if (pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_FINGERPRINT_SLIDE) {
            MMI_HILOGD("fingerprint event pointer action is:%{public}d", pointerEvent->GetPointerAction());
            return true;
        }
        if (fingerFocusPidSet.empty()) {
            MMI_HILOGD("fingerprint slide event send all monitor pid:%{public}d", monitor.session_->GetPid());
            return true;
        }
        if (fingerFocusPidSet.count(monitor.session_->GetPid())) {
            MMI_HILOGD("fingerprint slide event send focus monitor pid:%{public}d", monitor.session_->GetPid());
            return true;
        }
        MMI_HILOGD("fingerprint slide event not send monitor pid:%{public}d, focus pid:%{public}d",
            monitor.session_->GetPid(),
            WIN_MGR->GetPidByWindowId(WIN_MGR->GetFocusWindowId()));
        return false;
    }
    MMI_HILOGD("monitor eventType is not fingerprint pid:%{public}d", monitor.session_->GetPid());
    return false;
}
#endif // OHOS_BUILD_ENABLE_FINGERPRINT

#ifdef OHOS_BUILD_ENABLE_X_KEY
bool EventMonitorHandler::MonitorCollection::IsXKey(std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_X_KEY) {
        return true;
    }
    MMI_HILOGD("not X-key event");
    return false;
}
#endif // OHOS_BUILD_ENABLE_X_KEY

bool EventMonitorHandler::MonitorCollection::CheckIfNeedSendToClient(
    SessionHandler monitor, std::shared_ptr<PointerEvent> pointerEvent, std::unordered_set<int32_t> fingerFocusPidSet)
{
    CHKPF(pointerEvent);
#ifdef OHOS_BUILD_ENABLE_FINGERPRINT
    if (IsFingerprint(pointerEvent)) {
        return FingerprintEventMonitorHandle(monitor, pointerEvent, fingerFocusPidSet);
    }
#endif // OHOS_BUILD_ENABLE_FINGERPRINT
#ifdef OHOS_BUILD_ENABLE_X_KEY
    if ((monitor.eventType_ & HANDLE_EVENT_TYPE_X_KEY) == HANDLE_EVENT_TYPE_X_KEY && IsXKey(pointerEvent)) {
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
        IsPinch(pointerEvent)) {
        return true;
    } else if ((monitor.eventType_ & HANDLE_EVENT_TYPE_THREEFINGERSSWIP) == HANDLE_EVENT_TYPE_THREEFINGERSSWIP &&
        IsThreeFingersSwipe(pointerEvent)) {
        return true;
    } else if ((monitor.eventType_ & HANDLE_EVENT_TYPE_FOURFINGERSSWIP) == HANDLE_EVENT_TYPE_FOURFINGERSSWIP &&
        IsFourFingersSwipe(pointerEvent)) {
        return true;
    } else if ((monitor.eventType_ & HANDLE_EVENT_TYPE_ROTATE) == HANDLE_EVENT_TYPE_ROTATE &&
        IsRotate(pointerEvent)) {
        return true;
    } else if ((monitor.eventType_ & HANDLE_EVENT_TYPE_THREEFINGERSTAP) == HANDLE_EVENT_TYPE_THREEFINGERSTAP &&
        IsThreeFingersTap(pointerEvent)) {
        return true;
    }
    return false;
}

void EventMonitorHandler::MonitorCollection::OnSessionLost(SessionPtr session)
{
    CALL_INFO_TRACE;
    std::set<SessionHandler>::const_iterator cItr = monitors_.cbegin();
    while (cItr != monitors_.cend()) {
        if (cItr->session_ != session) {
            ++cItr;
        } else {
            cItr = monitors_.erase(cItr);
        }
    }
    CHKPV(session);
    int32_t pid = session->GetPid();
    auto it = endScreenCaptureMonitors_.find(pid);
    if (it != endScreenCaptureMonitors_.end()) {
        endScreenCaptureMonitors_.erase(it);
    }
}

bool EventMonitorHandler::MonitorCollection::CheckHasInputHandler(HandleEventType eventType)
{
    for (const auto &item : monitors_) {
        if ((item.eventType_ & eventType) == eventType) {
            return true;
        }
    }
    return false;
}

void EventMonitorHandler::Dump(int32_t fd, const std::vector<std::string> &args)
{
    return monitors_.Dump(fd, args);
}

void EventMonitorHandler::MonitorCollection::Dump(int32_t fd, const std::vector<std::string> &args)
{
    CALL_DEBUG_ENTER;
    mprintf(fd, "Monitor information:\t");
    mprintf(fd, "monitors: count=%zu", monitors_.size());
    for (const auto &item : monitors_) {
        SessionPtr session = item.session_;
        if (!session) {
            continue;
        }
        mprintf(fd,
                "handlerType:%d | Pid:%d | Uid:%d | Fd:%d "
                "| EarliestEventTime:%" PRId64 " | Descript:%s "
                "| EventType:%u | ProgramName:%s \t",
                item.handlerType_, session->GetPid(),
                session->GetUid(), session->GetFd(),
                session->GetEarliestEventTime(), session->GetDescript().c_str(),
                item.eventType_, session->GetProgramName().c_str());
    }
}

#ifdef PLAYER_FRAMEWORK_EXISTS
void EventMonitorHandler::ProcessScreenCapture(int32_t pid, bool isStart)
{
    auto udsServerPtr = InputHandler->GetUDSServer();
    CHKPV(udsServerPtr);
    SessionPtr session = udsServerPtr->GetSessionByPid(pid);
    CHKPV(session);
    if (isStart) {
        if (!monitors_.HasMonitor(session) && !monitors_.HasScreenCaptureMonitor(session)) {
            MMI_HILOGI("This process has no screen capture monitor");
            return;
        }
        monitors_.RecoveryScreenCaptureMonitor(session);
    } else {
        if (!monitors_.HasMonitor(session)) {
            MMI_HILOGI("This process has no screen capture monitor");
            return;
        }
        monitors_.RemoveScreenCaptureMonitor(session);
    }
}
#endif // PLAYER_FRAMEWORK_EXISTS
} // namespace MMI
} // namespace OHOS
