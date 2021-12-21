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
#include "define_multimodal.h"
#include "input_event_data_transformation.h"
#include "log.h"
#include "net_packet.h"
#include "proto.h"

namespace OHOS::MMI {
namespace {
    static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "InputHandlerManagerGlobal"};
}

int32_t InputHandlerManagerGlobal::AddInputHandler(int32_t handlerId, InputHandlerType handlerType, SessionPtr session)
{
    if (InputHandlerType::MONITOR == handlerType) {
        SessionMonitor mon { handlerId, session };
        return monitors_.AddMonitor(mon);
    }
    MMI_LOGE("AddInputHandler InputHandlerType Not MONITOR...");
    return -1;
}

void InputHandlerManagerGlobal::RemoveInputHandler(int32_t handlerId, InputHandlerType handlerType, SessionPtr session)
{
    if (InputHandlerType::MONITOR == handlerType) {
        SessionMonitor mon { handlerId, session };
        return monitors_.RemoveMonitor(mon);
    }
}

void InputHandlerManagerGlobal::MarkConsumed(int32_t handlerId, int32_t eventId, SessionPtr session)
{
    monitors_.MarkConsumed(handlerId, eventId, session);
}

bool InputHandlerManagerGlobal::HandleEvent(std::shared_ptr<KeyEvent> keyEvent)
{
    return monitors_.HandleEvent(keyEvent);
}

bool InputHandlerManagerGlobal::HandleEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    MMI_LOGD("HandleEvent in");
    return monitors_.HandleEvent(pointerEvent);
}

void InputHandlerManagerGlobal::SessionMonitor::SendToClient(std::shared_ptr<KeyEvent> keyEvent) const
{
    NetPacket pkt(MmiMessageId::REPORT_KEY_EVENT);
    pkt << id_ << InputHandlerType::MONITOR;
    auto retCode = InputEventDataTransformation::KeyEventToNetPacket(keyEvent, pkt);
    if (retCode != RET_OK) {
        return;
    }
    session_->SendMsg(pkt);
}

void InputHandlerManagerGlobal::SessionMonitor::SendToClient(std::shared_ptr<PointerEvent> pointerEvent) const
{
    NetPacket pkt(MmiMessageId::REPORT_POINTER_EVENT);
    MMI_LOGD("Service SendToClient id : %{public}d InputHandlerType : %{public}d", id_, InputHandlerType::MONITOR); 
    pkt << id_ << InputHandlerType::MONITOR;
    auto retCode = InputEventDataTransformation::SerializePointerEvent(pointerEvent, pkt);
    if (retCode != RET_OK) {
        MMI_LOGE("SerializePointerEvent false..."); 
        return;
    }
    session_->SendMsg(pkt);
}

int32_t InputHandlerManagerGlobal::MonitorCollection::AddMonitor(const SessionMonitor& mon)
{
    if (monitors_.size() >= MAX_N_MONITORS) {
        MMI_LOGE("The number of monitors exceeds the maximum...");
        return RET_ERR;
    }
    monitors_.insert(mon);
    MMI_LOGD("Service AddMonitor Success");
    return RET_OK;
}

void InputHandlerManagerGlobal::MonitorCollection::RemoveMonitor(const SessionMonitor& mon)
{
    std::set<SessionMonitor>::const_iterator tItr = monitors_.find(mon);
    if (tItr != monitors_.end()) {
        monitors_.erase(tItr);
        MMI_LOGD("Service RemoveMonitor Success");
    }
}

void InputHandlerManagerGlobal::MonitorCollection::MarkConsumed(int32_t monitorId, int32_t eventId, SessionPtr session)
{
    SessionMonitor mon { monitorId, session };
    if (monitors_.find(mon) == monitors_.end()) {
        return;
    }
    if (monitorConsumed_) {
        return;
    }
    if (!downEvent_) {
        return;
    }
    if (eventId < downEvent_->GetId()) {
        return;
    }
    pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
    pointerEvent_->SetActionTime(time(nullptr));
}

int32_t InputHandlerManagerGlobal::MonitorCollection::GetPriority() const
{
    return IInputEventHandler::DEFAULT_MONITOR;
}

bool InputHandlerManagerGlobal::MonitorCollection::HandleEvent(std::shared_ptr<KeyEvent> keyEvent)
{
    for (const SessionMonitor& mon : monitors_) {
        mon.SendToClient(keyEvent);
    }
    return false;
}

bool InputHandlerManagerGlobal::MonitorCollection::HandleEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    auto result { false };

    if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_TOUCHSCREEN) {
        result = monitorConsumed_;
        pointerEvent_ = pointerEvent;

        if (pointerEvent->GetPointersIdList().size() == 1) {
            if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_DOWN) {
                downEvent_ = pointerEvent;
            } else if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_UP) {
                downEvent_.reset();
                pointerEvent_.reset();
                monitorConsumed_ = false;
            }
        }
    }
    for (const SessionMonitor& mon : monitors_) {
        mon.SendToClient(pointerEvent);
    }
    return monitorConsumed_;
}
} // namespace OHOS::MMI

