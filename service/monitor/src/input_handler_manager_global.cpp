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
#include "input_handler_manager_global.h"
#include "input_event_handler.h"
#include "define_multimodal.h"
#include "input_event_data_transformation.h"
#include "log.h"
#include "net_packet.h"
#include "proto.h"

namespace OHOS::MMI {
namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "InputHandlerManagerGlobal" };
}

int32_t InputHandlerManagerGlobal::AddInputHandler(int32_t handlerId,
    InputHandlerType handlerType, SessionPtr session)
{
    InitSessionLostCallback();
    CHKR(IsValidHandlerId(handlerId), PARAM_INPUT_INVALID, RET_ERR);
    CHKPR(session, ERROR_NULL_POINTER);
    if (InputHandlerType::MONITOR != handlerType) {
        MMI_LOGE("AddInputHandler InputHandlerType Not MONITOR:%{public}d", handlerType);
        return RET_ERR;
    }
    MMI_LOGD("Register monitor:%{public}d", handlerId);
    SessionHandler mon { handlerId, handlerType, session };
    return monitors_.AddMonitor(mon);
    if (InputHandlerType::INTERCEPTOR != handlerType) {
        MMI_LOGW("Invalid handler type");
        return RET_ERR;
    }
    MMI_LOGD("Register interceptor(%{public}d).", handlerId);
    SessionHandler interceptor { handlerId, handlerType, session };
    return interceptors_.AddInterceptor(interceptor);
}

void InputHandlerManagerGlobal::RemoveInputHandler(int32_t handlerId,
    InputHandlerType handlerType, SessionPtr session)
{
    if (InputHandlerType::MONITOR != handlerType) {
        MMI_LOGE("RemoveInputHandler InputHandlerType Not MONITOR:%{public}d", handlerType);
        return;
    }
    MMI_LOGD("Unregister monitor(%{public}d).", handlerId);
    SessionHandler monitor { handlerId, handlerType, session };
    monitors_.RemoveMonitor(monitor);
    if (InputHandlerType::INTERCEPTOR != handlerType) {
        MMI_LOGW("Invalid handler type");
    }
    MMI_LOGD("Unregister interceptor:%{public}d", handlerId);
    SessionHandler interceptor { handlerId, handlerType, session };
    interceptors_.RemoveInterceptor(interceptor);
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
    if (interceptors_.HandleEvent(keyEvent)) {
        MMI_LOGD("Key event was intercepted");
        return true;
    }
    if (monitors_.HandleEvent(keyEvent)) {
        MMI_LOGD("Key event was consumed");
        return true;
    }
    return false;
}

bool InputHandlerManagerGlobal::HandleEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    MMI_LOGD("Handle PointerEvent");
    CHKPF(pointerEvent);
    if (interceptors_.HandleEvent(pointerEvent)) {
        MMI_LOGD("Pointer event was intercepted");
        return true;
    }
    if (monitors_.HandleEvent(pointerEvent)) {
        MMI_LOGD("Pointer event was consumed");
        return true;
    }
    return false;
}

void InputHandlerManagerGlobal::InitSessionLostCallback()
{
    if (sessionLostCallbackInitialized_)  {
        return;
    }
    auto udsServerPtr = InputHandler->GetUDSServer();
    CHKP(udsServerPtr);
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
    NetPacket pkt(MmiMessageId::REPORT_KEY_EVENT);
    CHK(pkt.Write(id_), STREAM_BUF_WRITE_FAIL);
    CHK((InputEventDataTransformation::KeyEventToNetPacket(keyEvent, pkt) == RET_OK),
        STREAM_BUF_WRITE_FAIL);
    CHK(session_->SendMsg(pkt), MSG_SEND_FAIL);
}

void InputHandlerManagerGlobal::SessionHandler::SendToClient(std::shared_ptr<PointerEvent> pointerEvent) const
{
    NetPacket pkt(MmiMessageId::REPORT_POINTER_EVENT);
    MMI_LOGD("Service SendToClient id:%{public}d,InputHandlerType:%{public}d", id_, handlerType_);
    CHK(pkt.Write(id_), STREAM_BUF_WRITE_FAIL);
    CHK(pkt.Write(handlerType_), STREAM_BUF_WRITE_FAIL);
    CHK((OHOS::MMI::InputEventDataTransformation::Marshalling(pointerEvent, pkt) == RET_OK),
        STREAM_BUF_WRITE_FAIL);
    CHK(session_->SendMsg(pkt), MSG_SEND_FAIL);
}

int32_t InputHandlerManagerGlobal::MonitorCollection::AddMonitor(const SessionHandler& monitor)
{
    std::lock_guard<std::mutex> guard(lockMonitors_);
    if (monitors_.size() >= MAX_N_INPUT_MONITORS) {
        MMI_LOGE("The number of monitors exceeds the maximum:%{public}d monitors, errCode:%{public}d",
                 static_cast<int32_t>(monitors_.size()), INVALID_MONITOR_MON);
        return RET_ERR;
    }
    auto iter = monitors_.find(monitor);
    if (iter != monitors_.end()) {
        MMI_LOGW("Repeate register, errCode:%{public}d", INVALID_MONITOR_MON);
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
    std::lock_guard<std::mutex> guard(lockMonitors_);
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
    if (monitorConsumed_) {
        MMI_LOGW("Event consumed");
        return;
    }
    if ((downEventId_ < 0) || (lastPointerEvent_ == nullptr)) {
        MMI_LOGI("No touch event or press event without a previous finger is not handled");
        return;
    }
    if (downEventId_ > eventId) {
        MMI_LOGW("A new process has began.");
        return;
    }
    monitorConsumed_ = true;
    lastPointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
    lastPointerEvent_->SetActionTime(time(nullptr));

    NetPacket rPkt(MmiMessageId::ON_POINTER_EVENT);
    CHK((InputEventDataTransformation::Marshalling(lastPointerEvent_, rPkt) == RET_OK),
        STREAM_BUF_WRITE_FAIL);
    CHK(session->SendMsg(rPkt), MSG_SEND_FAIL);
}

int32_t InputHandlerManagerGlobal::MonitorCollection::GetPriority() const
{
    return IInputEventHandler::DEFAULT_MONITOR;
}

bool InputHandlerManagerGlobal::MonitorCollection::HandleEvent(std::shared_ptr<KeyEvent> keyEvent)
{
    std::lock_guard<std::mutex> guard(lockMonitors_);
    for (const auto &mon : monitors_) {
        mon.SendToClient(keyEvent);
    }
    return false;
}

bool InputHandlerManagerGlobal::MonitorCollection::HandleEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    UpdateConsumptionState(pointerEvent);
    Monitor(pointerEvent);
    return monitorConsumed_;
}

bool InputHandlerManagerGlobal::MonitorCollection::HasMonitor(int32_t monitorId, SessionPtr session)
{
    std::lock_guard<std::mutex> guard(lockMonitors_);
    SessionHandler monitor { monitorId, InputHandlerType::MONITOR, session };
    return (monitors_.find(monitor) != monitors_.end());
}

void InputHandlerManagerGlobal::MonitorCollection::UpdateConsumptionState(std::shared_ptr<PointerEvent> pointerEvent)
{
    MMI_LOGD("Update consumption state");
    CHKP(pointerEvent);
    if (pointerEvent->GetSourceType() != PointerEvent::SOURCE_TYPE_TOUCHSCREEN) {
        MMI_LOGE("This is not a touch-screen event");
        return;
    }
    lastPointerEvent_ = pointerEvent;
    const size_t nPtrsIndNewProc = 1;

    if (pointerEvent->GetPointersIdList().size() != nPtrsIndNewProc) {
        MMI_LOGD("First press and last lift intermediate process");
        return;
    }
    if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_DOWN) {
        MMI_LOGD("Press for the first time");
        downEventId_ = pointerEvent->GetId();
        monitorConsumed_ = false;
    } else if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_UP) {
        MMI_LOGD("The last time lift");
        downEventId_ = -1;
        lastPointerEvent_.reset();
    }
}

void InputHandlerManagerGlobal::MonitorCollection::Monitor(std::shared_ptr<PointerEvent> pointerEvent)
{
    std::lock_guard<std::mutex> guard(lockMonitors_);
    MMI_LOGD("There are currently %{public}d monitors.", static_cast<int32_t>(monitors_.size()));
    for (const auto &monitor : monitors_) {
        monitor.SendToClient(pointerEvent);
    }
}

void InputHandlerManagerGlobal::MonitorCollection::OnSessionLost(SessionPtr session)
{
    std::lock_guard<std::mutex> guard(lockMonitors_);
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
    std::lock_guard<std::mutex> guard(lockInterceptors_);
    if (interceptors_.empty()) {
        return false;
    }
    MMI_LOGD("There are currently:%{public}d interceptors",
        static_cast<int32_t>(interceptors_.size()));
    for (const auto &interceptor : interceptors_) {
        interceptor.SendToClient(keyEvent);
    }
    return true;
}

bool InputHandlerManagerGlobal::InterceptorCollection::HandleEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    std::lock_guard<std::mutex> guard(lockInterceptors_);
    if (interceptors_.empty()) {
        return false;
    }
    MMI_LOGD("There are currently:%{public}d interceptors",
        static_cast<int32_t>(interceptors_.size()));
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
} // namespace OHOS::MMI

