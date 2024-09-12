/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "event_manager.h"

#include "cooperate_hisysevent.h"
#include "devicestatus_define.h"
#include "utility.h"

#undef LOG_TAG
#define LOG_TAG "EventManager"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace Cooperate {

EventManager::EventManager(IContext *env)
    : env_(env)
{}

void EventManager::RegisterListener(const RegisterListenerEvent &event)
{
    CALL_INFO_TRACE;
    std::shared_ptr<EventInfo> eventInfo = std::make_shared<EventInfo>();
    eventInfo->type = EventType::LISTENER;
    eventInfo->msgId = MessageId::COORDINATION_ADD_LISTENER;
    eventInfo->pid = event.pid;

    FI_HILOGI("Add cooperate listener (%{public}d)", eventInfo->pid);
    auto iter = std::find_if(listeners_.begin(), listeners_.end(),
        [eventInfo](const auto &item) {
            return ((item != nullptr) && (item->pid == eventInfo->pid));
        });
    if (iter != listeners_.end()) {
        *iter = eventInfo;
    } else {
        listeners_.emplace_back(eventInfo);
    }
}

void EventManager::UnregisterListener(const UnregisterListenerEvent &event)
{
    FI_HILOGI("Remove cooperate listener (%{public}d)", event.pid);
    listeners_.erase(std::remove_if(listeners_.begin(), listeners_.end(),
        [pid = event.pid](const auto &item) {
            return ((item == nullptr) || (item->pid == pid));
        }), listeners_.end());
}

void EventManager::EnableCooperate(const EnableCooperateEvent &event)
{
    CALL_INFO_TRACE;
    CooperateNotice notice {
        .pid = event.pid,
        .msgId = MessageId::COORDINATION_MESSAGE,
        .userData = event.userData,
        .msg = CoordinationMessage::PREPARE
    };
    NotifyCooperateMessage(notice);
}

void EventManager::DisableCooperate(const DisableCooperateEvent &event)
{
    CALL_INFO_TRACE;
    CooperateNotice notice {
        .pid = event.pid,
        .msgId = MessageId::COORDINATION_MESSAGE,
        .userData = event.userData,
        .msg = CoordinationMessage::UNPREPARE
    };
    NotifyCooperateMessage(notice);
}

void EventManager::StartCooperate(const StartCooperateEvent &event)
{
    CALL_INFO_TRACE;
    std::shared_ptr<EventInfo> eventInfo = std::make_shared<EventInfo>();
    eventInfo->type = EventType::START;
    eventInfo->msgId = MessageId::COORDINATION_MESSAGE;
    eventInfo->pid = event.pid;
    eventInfo->networkId = event.remoteNetworkId;
    eventInfo->userData = event.userData;
    calls_[EventType::START] = eventInfo;
}

void EventManager::StartCooperateFinish(const DSoftbusStartCooperateFinished &event)
{
    CALL_INFO_TRACE;
    std::shared_ptr<EventInfo> eventInfo = calls_[EventType::START];
    CHKPV(eventInfo);
    CooperateNotice notice {
        .pid = eventInfo->pid,
        .msgId = eventInfo->msgId,
        .userData = eventInfo->userData,
        .networkId = eventInfo->networkId,
        .msg = (event.success ? CoordinationMessage::ACTIVATE_SUCCESS : CoordinationMessage::ACTIVATE_FAIL),
        .errCode = event.errCode
    };
    calls_[EventType::START] = nullptr;
    NotifyCooperateMessage(notice);
}

void EventManager::RemoteStart(const DSoftbusStartCooperate &event)
{
    CALL_INFO_TRACE;
    OnCooperateMessage(CoordinationMessage::ACTIVATE, event.networkId);
}

void EventManager::RemoteStartFinish(const DSoftbusStartCooperateFinished &event)
{
    CALL_INFO_TRACE;
    CoordinationMessage msg { event.success ?
                              CoordinationMessage::ACTIVATE_SUCCESS :
                              CoordinationMessage::ACTIVATE_FAIL };
    OnCooperateMessage(msg, event.networkId);
    if (msg == CoordinationMessage::ACTIVATE_SUCCESS) {
        CooperateDFX::WriteRemoteStart(OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR);
    } else {
        CooperateDFX::WriteRemoteStart(OHOS::HiviewDFX::HiSysEvent::EventType::FAULT);
    }
}

void EventManager::OnUnchain(const StopCooperateEvent &event)
{
    CALL_INFO_TRACE;
    OnCooperateMessage(CoordinationMessage::SESSION_CLOSED, std::string());
}

void EventManager::StopCooperate(const StopCooperateEvent &event)
{
    CALL_INFO_TRACE;
    std::shared_ptr<EventInfo> eventInfo = std::make_shared<EventInfo>();
    eventInfo->type = EventType::STOP;
    eventInfo->msgId = MessageId::COORDINATION_MESSAGE;
    eventInfo->pid = event.pid;
    eventInfo->userData = event.userData;
    calls_[EventType::STOP] = eventInfo;
}

void EventManager::StopCooperateFinish(const DSoftbusStopCooperateFinished &event)
{
    CALL_INFO_TRACE;
    std::shared_ptr<EventInfo> eventInfo = calls_[EventType::STOP];
    CHKPV(eventInfo);
    CooperateNotice notice {
        .pid = eventInfo->pid,
        .msgId = eventInfo->msgId,
        .userData = eventInfo->userData,
        .networkId = eventInfo->networkId,
        .msg = (event.normal ? CoordinationMessage::DEACTIVATE_SUCCESS : CoordinationMessage::DEACTIVATE_FAIL),
        .errCode = event.errCode
    };
    NotifyCooperateMessage(notice);
    calls_[EventType::STOP] = nullptr;
}

void EventManager::RemoteStop(const DSoftbusStopCooperate &event)
{
    CALL_DEBUG_ENTER;
}

void EventManager::RemoteStopFinish(const DSoftbusStopCooperateFinished &event)
{
    CALL_DEBUG_ENTER;
}

void EventManager::OnProfileChanged(const DDPCooperateSwitchChanged &event)
{
    CALL_INFO_TRACE;
    FI_HILOGI("Switch status of \'%{public}s\' has changed to %{public}d",
        Utility::Anonymize(event.networkId).c_str(), event.normal);
    CoordinationMessage msg = (event.normal ? CoordinationMessage::PREPARE : CoordinationMessage::UNPREPARE);
    OnCooperateMessage(msg, event.networkId);
}

void EventManager::OnSoftbusSessionClosed(const DSoftbusSessionClosed &event)
{
    FI_HILOGI("Connection with \'%{public}s\' is closed", Utility::Anonymize(event.networkId).c_str());
    OnCooperateMessage(CoordinationMessage::SESSION_CLOSED, event.networkId);
}

void EventManager::GetCooperateState(const CooperateStateNotice &notice)
{
    CALL_INFO_TRACE;
    NotifyCooperateState(notice);
}

void EventManager::OnCooperateMessage(CoordinationMessage msg, const std::string &networkId)
{
    CALL_INFO_TRACE;
    for (auto iter = listeners_.begin(); iter != listeners_.end(); ++iter) {
        std::shared_ptr<EventInfo> listener = *iter;
        CHKPC(listener);
        FI_HILOGD("Notify cooperate listener (%{public}d, %{public}d)", listener->pid, listener->msgId);
        CooperateNotice notice {
            .pid = listener->pid,
            .msgId = listener->msgId,
            .userData = listener->userData,
            .networkId = networkId,
            .msg = msg
        };
        NotifyCooperateMessage(notice);
    }
}

void EventManager::OnClientDied(const ClientDiedEvent &event)
{
    FI_HILOGI("Remove client died listener, pid: %{public}d", event.pid);
    for (auto iter = listeners_.begin(); iter != listeners_.end();) {
        std::shared_ptr<EventInfo> listener = *iter;
        CHKPC(listener);
        if (event.pid == listener->pid) {
            iter = listeners_.erase(iter);
            break;
        } else {
            ++iter;
        }
    }
}

void EventManager::NotifyCooperateMessage(const CooperateNotice &notice)
{
    CALL_INFO_TRACE;
    auto session = env_->GetSocketSessionManager().FindSessionByPid(notice.pid);
    CHKPV(session);
    NetPacket pkt(notice.msgId);
    pkt << notice.userData << notice.networkId << static_cast<int32_t>(notice.msg) << notice.errCode;
    if (pkt.ChkRWError()) {
        FI_HILOGE("Packet write data failed");
        return;
    }
    if (!session->SendMsg(pkt)) {
        FI_HILOGE("Sending failed");
    }
}

void EventManager::NotifyCooperateState(const CooperateStateNotice &notice)
{
    CALL_INFO_TRACE;
    CHKPV(env_);
    auto session = env_->GetSocketSessionManager().FindSessionByPid(notice.pid);
    CHKPV(session);
    NetPacket pkt(notice.msgId);
    pkt << notice.userData << notice.state << static_cast<int32_t>(notice.errCode);
    if (pkt.ChkRWError()) {
        FI_HILOGE("Packet write data failed");
        return;
    }
    if (!session->SendMsg(pkt)) {
        FI_HILOGE("Sending failed");
        return;
    }
}
} // namespace Cooperate
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
