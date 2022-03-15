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

#include "input_handler_manager_global.h"

#include "define_multimodal.h"
#include "event_dispatch.h"
#include "input_event_data_transformation.h"
#include "input_event_handler.h"
#include "mmi_log.h"
#include "net_packet.h"
#include "proto.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "InputHandlerManagerGlobal" };
} // namespace

int32_t InputHandlerManagerGlobal::AddInputHandler(int32_t handlerId,
    InputHandlerType handlerType, SessionPtr session)
{
    InitSessionLostCallback();
    if (!IsValidHandlerId(handlerId)) {
        MMI_LOGE("Invalid handler");
        return RET_ERR;
    }
    CHKPR(session, RET_ERR);
    if (handlerType == InputHandlerType::MONITOR) {
        if (!session->HasPermission()) {
            MMI_LOGE("no permission, can not add monitor");
            return RET_ERR;
        }
        MMI_LOGD("Register monitor:%{public}d", handlerId);
        SessionHandler mon { handlerId, handlerType, session };
        return monitors_.AddMonitor(mon);
    }
    if (handlerType == InputHandlerType::INTERCEPTOR) {
        MMI_LOGD("Register interceptor:%{public}d", handlerId);
        SessionHandler interceptor { handlerId, handlerType, session };
        return interceptors_.AddInterceptor(interceptor);
    }
    MMI_LOGW("Invalid handler type:%{public}d", handlerType);
    return RET_ERR;
}

void InputHandlerManagerGlobal::RemoveInputHandler(int32_t handlerId,
    InputHandlerType handlerType, SessionPtr session)
{
    if (handlerType == InputHandlerType::MONITOR) {
        if (!session->HasPermission()) {
            MMI_LOGE("no permission, can not remove monitor");
            return;
        }
        MMI_LOGD("Unregister monitor:%{public}d", handlerId);
        SessionHandler monitor { handlerId, handlerType, session };
        monitors_.RemoveMonitor(monitor);
    } else if (handlerType == InputHandlerType::INTERCEPTOR) {
        MMI_LOGD("Unregister interceptor:%{public}d", handlerId);
        SessionHandler interceptor { handlerId, handlerType, session };
        interceptors_.RemoveInterceptor(interceptor);
    }
}

void InputHandlerManagerGlobal::MarkConsumed(int32_t handlerId, int32_t eventId, SessionPtr session)
{
    MMI_LOGD("Mark consumed state, monitor:%{public}d", handlerId);
    monitors_.MarkConsumed(handlerId, eventId, session);
}

bool InputHandlerManagerGlobal::HandleEvent(std::shared_ptr<KeyEvent> keyEvent)
{
    MMI_LOGD("Handle KeyEvent");
    CHKPF(keyEvent);
    if (keyEvent->HasFlag(InputEvent::EVENT_FLAG_NO_INTERCEPT)) {
        MMI_LOGD("This event has been tagged as not to be intercepted");
    } else {
        if (interceptors_.HandleEvent(keyEvent)) {
            MMI_LOGD("Key event was intercepted");
            return true;
        }
    }
    if (keyEvent->HasFlag(InputEvent::EVENT_FLAG_NO_MONITOR)) {
        MMI_LOGD("This event has been tagged as not to be monitored");
    } else {
        if (monitors_.HandleEvent(keyEvent)) {
            MMI_LOGD("Key event was consumed");
            return true;
        }
    }
    return false;
}

bool InputHandlerManagerGlobal::HandleEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPF(pointerEvent);
    if (pointerEvent->HasFlag(InputEvent::EVENT_FLAG_NO_INTERCEPT)) {
        MMI_LOGD("This event has been tagged as not to be intercepted");
    } else {
        if (interceptors_.HandleEvent(pointerEvent)) {
            MMI_LOGD("Pointer event was intercepted");
            return true;
        }
    }
    if (pointerEvent->HasFlag(InputEvent::EVENT_FLAG_NO_MONITOR)) {
        MMI_LOGD("This event has been tagged as not to be monitored");
    } else {
        if (monitors_.HandleEvent(pointerEvent)) {
            MMI_LOGD("Pointer event was monitor");
            return true;
        }
    }
    MMI_LOGD("Interception and monitor failed");
    return false;
}

void InputHandlerManagerGlobal::InitSessionLostCallback()
{
    if (sessionLostCallbackInitialized_)  {
        return;
    }
    auto udsServerPtr = InputHandler->GetUDSServer();
    CHKPV(udsServerPtr);
    udsServerPtr->AddSessionDeletedCallback(std::bind(
        &InputHandlerManagerGlobal::OnSessionLost, this, std::placeholders::_1));
    sessionLostCallbackInitialized_ = true;
    MMI_LOGD("The callback on session deleted is registered successfully");
}

void InputHandlerManagerGlobal::OnSessionLost(SessionPtr session)
{
    monitors_.OnSessionLost(session);
    interceptors_.OnSessionLost(session);
}

void InputHandlerManagerGlobal::SessionHandler::SendToClient(std::shared_ptr<KeyEvent> keyEvent) const
{
    CHKPV(keyEvent);
    NetPacket pkt(MmiMessageId::REPORT_KEY_EVENT);
    if (!pkt.Write(id_)) {
        MMI_LOGE("Write to stream failed, errCode:%{public}d", STREAM_BUF_WRITE_FAIL);
        return;
    }
    if (InputEventDataTransformation::KeyEventToNetPacket(keyEvent, pkt) != RET_OK) {
        MMI_LOGE("Packet key event failed, errCode:%{public}d", STREAM_BUF_WRITE_FAIL);
        return;
    }
    if (!session_->SendMsg(pkt)) {
        MMI_LOGE("Send message failed, errCode:%{public}d", MSG_SEND_FAIL);
        return;
    }
}

void InputHandlerManagerGlobal::SessionHandler::SendToClient(std::shared_ptr<PointerEvent> pointerEvent) const
{
    CHKPV(pointerEvent);
    NetPacket pkt(MmiMessageId::REPORT_POINTER_EVENT);
    MMI_LOGD("Service SendToClient id:%{public}d,InputHandlerType:%{public}d", id_, handlerType_);
    if (!pkt.Write(id_) || !pkt.Write(handlerType_)) {
        MMI_LOGE("Write id_ to stream failed, errCode:%{public}d", STREAM_BUF_WRITE_FAIL);
        return;
    }
    if (InputEventDataTransformation::Marshalling(pointerEvent, pkt) != RET_OK) {
        MMI_LOGE("Marshalling pointer event failed, errCode:%{public}d", STREAM_BUF_WRITE_FAIL);
        return;
    }
    if (!session_->SendMsg(pkt)) {
        MMI_LOGE("Send message failed, errCode:%{public}d", MSG_SEND_FAIL);
        return;
    }
}

int32_t InputHandlerManagerGlobal::MonitorCollection::AddMonitor(const SessionHandler& monitor)
{
    if (monitors_.size() >= MAX_N_INPUT_MONITORS) {
        MMI_LOGE("The number of monitors exceeds the maximum:%{public}zu,monitors,errCode:%{public}d",
                 monitors_.size(), INVALID_MONITOR_MON);
        return RET_ERR;
    }
    auto ret = monitors_.insert(monitor);
    if (ret.second) {
        MMI_LOGD("Service AddMonitor Success");
    } else {
        MMI_LOGW("Duplicate monitors");
    }
    return RET_OK;
}

void InputHandlerManagerGlobal::MonitorCollection::RemoveMonitor(const SessionHandler& monitor)
{
    std::set<SessionHandler>::const_iterator tItr = monitors_.find(monitor);
    if (tItr != monitors_.end()) {
        monitors_.erase(tItr);
        MMI_LOGD("Service RemoveMonitor Success");
    }
}

void InputHandlerManagerGlobal::MonitorCollection::MarkConsumed(int32_t monitorId, int32_t eventId, SessionPtr session)
{
    if (!HasMonitor(monitorId, session)) {
        MMI_LOGW("Specified monitor does not exist, monitor:%{public}d", monitorId);
        return;
    }
    if (isMonitorConsumed_) {
        MMI_LOGW("Event consumed");
        return;
    }
    if ((downEventId_ < 0) || (lastPointerEvent_ == nullptr)) {
        MMI_LOGI("No touch event or press event without a previous finger is not handled");
        return;
    }
    if (downEventId_ > eventId) {
        MMI_LOGW("A new process has began %{public}d,%{public}d", downEventId_, eventId);
        return;
    }
    isMonitorConsumed_ = true;
    MMI_LOGD("Cancel operation");
    auto pointerEvent = std::make_shared<PointerEvent>(*lastPointerEvent_);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
    pointerEvent->SetActionTime(GetSysClockTime());
    pointerEvent->AddFlag(InputEvent::EVENT_FLAG_NO_INTERCEPT | InputEvent::EVENT_FLAG_NO_MONITOR);
    EventDispatch eDispatch;
    eDispatch.HandlePointerEvent(pointerEvent);
}

int32_t InputHandlerManagerGlobal::MonitorCollection::GetPriority() const
{
    return IInputEventHandler::DEFAULT_MONITOR;
}

bool InputHandlerManagerGlobal::MonitorCollection::HandleEvent(std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPF(keyEvent);
    MMI_LOGD("There are currently %{public}zu monitors", monitors_.size());
    for (const auto &mon : monitors_) {
        mon.SendToClient(keyEvent);
    }
    return false;
}

bool InputHandlerManagerGlobal::MonitorCollection::HandleEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPF(pointerEvent);
    UpdateConsumptionState(pointerEvent);
    Monitor(pointerEvent);
    return isMonitorConsumed_;
}

bool InputHandlerManagerGlobal::MonitorCollection::HasMonitor(int32_t monitorId, SessionPtr session)
{
    SessionHandler monitor { monitorId, InputHandlerType::MONITOR, session };
    return (monitors_.find(monitor) != monitors_.end());
}

void InputHandlerManagerGlobal::MonitorCollection::UpdateConsumptionState(std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPV(pointerEvent);
    if (pointerEvent->GetSourceType() != PointerEvent::SOURCE_TYPE_TOUCHSCREEN) {
        MMI_LOGE("This is not a touch-screen event");
        return;
    }
    lastPointerEvent_ = pointerEvent;

    if (pointerEvent->GetPointersIdList().size() != 1) {
        MMI_LOGD("First press down and last press up intermediate process");
        return;
    }
    if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_DOWN) {
        MMI_LOGD("First press down");
        downEventId_ = pointerEvent->GetId();
        isMonitorConsumed_ = false;
    } else if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_UP) {
        MMI_LOGD("Last press up");
        downEventId_ = -1;
        lastPointerEvent_.reset();
    }
}

void InputHandlerManagerGlobal::MonitorCollection::Monitor(std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPV(pointerEvent);
    MMI_LOGD("There are currently %{public}zu monitors", monitors_.size());
    for (const auto &monitor : monitors_) {
        monitor.SendToClient(pointerEvent);
    }
}

void InputHandlerManagerGlobal::MonitorCollection::OnSessionLost(SessionPtr session)
{
    std::set<SessionHandler>::const_iterator cItr = monitors_.cbegin();
    while (cItr != monitors_.cend()) {
        if (cItr->session_ != session) {
            ++cItr;
        } else {
            cItr = monitors_.erase(cItr);
        }
    }
}

int32_t InputHandlerManagerGlobal::InterceptorCollection::GetPriority() const
{
    return IInputEventHandler::DEFAULT_INTERCEPTOR;
}

bool InputHandlerManagerGlobal::InterceptorCollection::HandleEvent(std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPF(keyEvent);
    std::lock_guard<std::mutex> guard(lockInterceptors_);
    if (interceptors_.empty()) {
        return false;
    }
    MMI_LOGD("There are currently:%{public}zu interceptors", interceptors_.size());
    for (const auto &interceptor : interceptors_) {
        interceptor.SendToClient(keyEvent);
    }
    return true;
}

bool InputHandlerManagerGlobal::InterceptorCollection::HandleEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPF(pointerEvent);
    std::lock_guard<std::mutex> guard(lockInterceptors_);
    if (interceptors_.empty()) {
        return false;
    }
    MMI_LOGD("There are currently:%{public}zu interceptors", interceptors_.size());
    for (const auto &interceptor : interceptors_) {
        interceptor.SendToClient(pointerEvent);
    }
    return true;
}

int32_t InputHandlerManagerGlobal::InterceptorCollection::AddInterceptor(const SessionHandler& interceptor)
{
    std::lock_guard<std::mutex> guard(lockInterceptors_);
    if (interceptors_.size() >= MAX_N_INPUT_INTERCEPTORS) {
        MMI_LOGE("The number of interceptors exceeds limit");
        return RET_ERR;
    }
    auto ret = interceptors_.insert(interceptor);
    if (ret.second) {
        MMI_LOGD("Register interceptor successfully");
    } else {
        MMI_LOGW("Duplicate interceptors");
    }
    return RET_OK;
}

void InputHandlerManagerGlobal::InterceptorCollection::RemoveInterceptor(const SessionHandler& interceptor)
{
    std::lock_guard<std::mutex> guard(lockInterceptors_);
    std::set<SessionHandler>::const_iterator tItr = interceptors_.find(interceptor);
    if (tItr != interceptors_.cend()) {
        interceptors_.erase(tItr);
        MMI_LOGD("Unregister interceptor successfully");
    }
}

void InputHandlerManagerGlobal::InterceptorCollection::OnSessionLost(SessionPtr session)
{
    std::lock_guard<std::mutex> guard(lockInterceptors_);
    std::set<SessionHandler>::const_iterator cItr = interceptors_.cbegin();
    while (cItr != interceptors_.cend()) {
        if (cItr->session_ != session) {
            ++cItr;
        } else {
            cItr = interceptors_.erase(cItr);
        }
    }
}
} // namespace MMI
} // namespace OHOS
