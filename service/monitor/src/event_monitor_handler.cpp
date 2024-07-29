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

#include "event_monitor_handler.h"

#include "anr_manager.h"
#include "app_debug_listener.h"
#include "bytrace_adapter.h"
#include "define_multimodal.h"
#include "input_event_data_transformation.h"
#include "input_event_handler.h"
#include "mmi_log.h"
#include "napi_constants.h"
#include "net_packet.h"
#include "proto.h"
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

int32_t EventMonitorHandler::AddInputHandler(InputHandlerType handlerType,
    HandleEventType eventType, std::shared_ptr<IInputEventConsumer> callback)
{
    CALL_INFO_TRACE;
    CHKPR(callback, RET_ERR);
    if ((eventType & HANDLE_EVENT_TYPE_ALL) == HANDLE_EVENT_TYPE_NONE) {
        MMI_HILOGE("Invalid event type");
        return RET_ERR;
    }
    InitSessionLostCallback();
    SessionHandler mon {handlerType, eventType, nullptr, callback};
    return monitors_.AddMonitor(mon);
}

int32_t EventMonitorHandler::AddInputHandler(InputHandlerType handlerType,
    HandleEventType eventType, SessionPtr session)
{
    CALL_INFO_TRACE;
    CHKPR(session, RET_ERR);
    if ((eventType & HANDLE_EVENT_TYPE_ALL) == HANDLE_EVENT_TYPE_NONE) {
        MMI_HILOGE("Invalid event type");
        return RET_ERR;
    }
    InitSessionLostCallback();
    SessionHandler mon { handlerType, eventType, session };
    return monitors_.AddMonitor(mon);
}

void EventMonitorHandler::RemoveInputHandler(InputHandlerType handlerType,
    HandleEventType eventType, std::shared_ptr<IInputEventConsumer> callback)
{
    CALL_INFO_TRACE;
    CHKPV(callback);
    if (handlerType == InputHandlerType::MONITOR) {
        SessionHandler monitor {handlerType, eventType, nullptr, callback};
        monitors_.RemoveMonitor(monitor);
    }
}

void EventMonitorHandler::RemoveInputHandler(InputHandlerType handlerType, HandleEventType eventType,
    SessionPtr session)
{
    CALL_INFO_TRACE;
    if (handlerType == InputHandlerType::MONITOR) {
        SessionHandler monitor { handlerType, eventType, session };
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
    if (sessionLostCallbackInitialized_)  {
        return;
    }
    auto udsServerPtr = InputHandler->GetUDSServer();
    CHKPV(udsServerPtr);
    udsServerPtr->AddSessionDeletedCallback([this] (SessionPtr session) {
        return this->OnSessionLost(session);
    }
    );
    sessionLostCallbackInitialized_ = true;
    MMI_HILOGD("The callback on session deleted is registered successfully");
}

void EventMonitorHandler::OnSessionLost(SessionPtr session)
{
    monitors_.OnSessionLost(session);
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
        return;
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
    auto iter = monitors_.find(monitor);
    if (iter != monitors_.end()) {
        if (iter->eventType_ == monitor.eventType_) {
            MMI_HILOGD("Monitor with event type (%{public}u) already exists", monitor.eventType_);
            return RET_OK;
        }
        isFound = true;
        monitors_.erase(iter);
    }

    auto [sIter, isOk] = monitors_.insert(monitor);
    if (!isOk) {
        if (isFound) {
            MMI_HILOGE("Internal error: monitor has been removed");
        } else {
            MMI_HILOGE("Failed to add monitor");
        }
        return RET_ERR;
    }

    if (isFound) {
        MMI_HILOGD("Event type is updated:%{public}u", monitor.eventType_);
    } else {
        MMI_HILOGD("Service Add Monitor Success");
    }
    return RET_OK;
}

void EventMonitorHandler::MonitorCollection::RemoveMonitor(const SessionHandler& monitor)
{
    auto iter = monitors_.find(monitor);
    if (iter == monitors_.cend()) {
        MMI_HILOGE("Monitor does not exist");
        return;
    }

    monitors_.erase(iter);
    if (monitor.eventType_ == HANDLE_EVENT_TYPE_NONE) {
        MMI_HILOGD("Unregister monitor successfully");
        return;
    }

    auto [sIter, isOk] = monitors_.insert(monitor);
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
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
    pointerEvent->SetActionTime(GetSysClockTime());
    pointerEvent->UpdateId();
    pointerEvent->AddFlag(InputEvent::EVENT_FLAG_NO_INTERCEPT | InputEvent::EVENT_FLAG_NO_MONITOR);
    auto inputEventNormalizeHandler = InputHandler->GetEventNormalizeHandler();
    CHKPV(inputEventNormalizeHandler);
    inputEventNormalizeHandler->HandleTouchEvent(pointerEvent);
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
        if ((mon.eventType_ & HANDLE_EVENT_TYPE_KEY) == HANDLE_EVENT_TYPE_KEY) {
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
    for (const auto &monitor : monitors_) {
        if ((monitor.eventType_ & pointerEvent->GetHandlerEventType()) == pointerEvent->GetHandlerEventType()) {
            if (monitor.session_) {
                monitor.SendToClient(pointerEvent, pkt);
                continue;
            }
            if (monitor.callback) {
                monitor.callback->OnInputEvent(monitor.handlerType_, pointerEvent);
            }
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
} // namespace MMI
} // namespace OHOS
