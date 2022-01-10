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
        MMI_LOGD("Register monitor(%{public}d) ...", handlerId);
        SessionMonitor mon { handlerId, session };
        return monitors_.AddMonitor(mon);
    }
    MMI_LOGD("AddInputHandler InputHandlerType Not MONITOR...");
    return RET_ERR;
}

void InputHandlerManagerGlobal::RemoveInputHandler(int32_t handlerId, InputHandlerType handlerType, SessionPtr session)
{
    if (InputHandlerType::MONITOR == handlerType) {
        MMI_LOGD("Unregister monitor(%{public}d) ...", handlerId);
        SessionMonitor mon { handlerId, session };
        return monitors_.RemoveMonitor(mon);
    }
}

void InputHandlerManagerGlobal::MarkConsumed(int32_t handlerId, SessionPtr session)
{
    MMI_LOGD("Mark consumed state: monitorId=%{public}d.", handlerId);
    monitors_.MarkConsumed(handlerId, session);
}

bool InputHandlerManagerGlobal::HandleEvent(std::shared_ptr<KeyEvent> keyEvent)
{
    return monitors_.HandleEvent(keyEvent);
}

bool InputHandlerManagerGlobal::HandleEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    MMI_LOGD("Handle PointerEvent ...");
    return monitors_.HandleEvent(pointerEvent);
}

void InputHandlerManagerGlobal::SessionMonitor::SendToClient(std::shared_ptr<KeyEvent> keyEvent) const
{
    NetPacket pkt(MmiMessageId::REPORT_KEY_EVENT);
    pkt << id_ << InputHandlerType::MONITOR;
    CHK((RET_OK == InputEventDataTransformation::KeyEventToNetPacket(keyEvent, pkt)),
        STREAM_BUF_WRITE_FAIL);
    CHK(session_->SendMsg(pkt), MSG_SEND_FAIL);
}

void InputHandlerManagerGlobal::SessionMonitor::SendToClient(std::shared_ptr<PointerEvent> pointerEvent) const
{
    NetPacket pkt(MmiMessageId::REPORT_POINTER_EVENT);
    MMI_LOGD("Service SendToClient id=%{public}d,InputHandlerType=%{public}d.", id_, InputHandlerType::MONITOR);
    pkt << id_ << InputHandlerType::MONITOR;
    CHK((RET_OK == OHOS::MMI::InputEventDataTransformation::SerializePointerEvent(pointerEvent, pkt)),
        STREAM_BUF_WRITE_FAIL);
    CHK(session_->SendMsg(pkt), MSG_SEND_FAIL);
}

int32_t InputHandlerManagerGlobal::MonitorCollection::AddMonitor(const SessionMonitor& mon)
{
    std::lock_guard<std::mutex> guard(lockMonitors_);
    if (monitors_.size() >= MAX_N_INPUT_MONITORS) {
        MMI_LOGE("The number of monitors exceeds the maximum...");
        return RET_ERR;
    }
    auto ret = monitors_.insert(mon);
    if (!ret.second) {
        MMI_LOGW("Duplicate monitors.");
    }
    MMI_LOGD("Service AddMonitor Success.");
    return RET_OK;
}

void InputHandlerManagerGlobal::MonitorCollection::RemoveMonitor(const SessionMonitor& mon)
{
    std::lock_guard<std::mutex> guard(lockMonitors_);
    std::set<SessionMonitor>::const_iterator tItr = monitors_.find(mon);
    if (tItr != monitors_.end()) {
        monitors_.erase(tItr);
        MMI_LOGD("Service RemoveMonitor Success.");
    }
}

void InputHandlerManagerGlobal::MonitorCollection::MarkConsumed(int32_t monitorId, SessionPtr session)
{
    if (!HasMonitor(monitorId, session)) {
        MMI_LOGW("Specified monitor(%{public}d) does not exist.", monitorId);
        return;
    }
    if (monitorConsumed_) {
        MMI_LOGW("Event consumed.");
        return;
    }
    if (!downEvent_ || !lastPointerEvent_) {
        MMI_LOGW("No event came up ever.");
        return;
    }
    monitorConsumed_ = true;
    lastPointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
    lastPointerEvent_->SetActionTime(time(nullptr));

    NetPacket rPkt(MmiMessageId::ON_POINTER_EVENT);
    CHK((RET_OK == InputEventDataTransformation::SerializePointerEvent(lastPointerEvent_, rPkt)),
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
    for (const SessionMonitor& mon : monitors_) {
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
    SessionMonitor mon { monitorId, session };
    return (monitors_.find(mon) != monitors_.end());
}

void InputHandlerManagerGlobal::MonitorCollection::UpdateConsumptionState(std::shared_ptr<PointerEvent> pointerEvent)
{
    MMI_LOGD("Update consumption state.");
    if (pointerEvent->GetSourceType() != PointerEvent::SOURCE_TYPE_TOUCHSCREEN) {
        MMI_LOGD("This is not a touch-screen event.");
        return;
    }
    lastPointerEvent_ = pointerEvent;
    const std::vector<int32_t>::size_type N_PTRS_IND_NEW_PROC { 1 };

    if (pointerEvent->GetPointersIdList().size() != N_PTRS_IND_NEW_PROC) {
        MMI_LOGD("In process.");
        return;
    }
    if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_DOWN) {
        MMI_LOGD("A new process begins.");
        downEvent_ = pointerEvent;
        monitorConsumed_ = false;
    } else if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_UP) {
        MMI_LOGD("Current process ends.");
        downEvent_.reset();
        lastPointerEvent_.reset();
    }
}

void InputHandlerManagerGlobal::MonitorCollection::Monitor(std::shared_ptr<PointerEvent> pointerEvent)
{
    std::lock_guard<std::mutex> guard(lockMonitors_);
    MMI_LOGD("There are currently %{public}d monitors.", static_cast<int32_t>(monitors_.size()));
    for (const SessionMonitor& mon : monitors_) {
        mon.SendToClient(pointerEvent);
    }
}
} // namespace OHOS::MMI

