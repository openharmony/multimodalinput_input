/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "mouse_location.h"

#include "devicestatus_define.h"s
#include "dsoftbus_handler.h"
#include "utility.h"

#undef LOG_TAG
#define LOG_TAG "MouseLocation"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace Cooperate {

MouseLocation::MouseLocation(IContext *context) : context_(context) {}

void MouseLocation::AddListener(const RegisterEventListenerEvent &event)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(mutex_);
    localNetworkId_ = IDSoftbusAdapter::GetLocalNetworkId();
    if (event.networkId == localNetworkId_) {
        FI_HILOGI("Add local mouse location listener");
        localListeners_.insert(event.pid);
        return;
    }
    FI_HILOGI("Add remote mouse location listener, networkId:%{public}s", Utility::Anonymize(event.networkId).c_str());
    DSoftbusSubscribeMouseLocation softbusEvent {
        .networkId = localNetworkId_,
        .remoteNetworkId = event.networkId,
    };
    if (SubscribeMouseLocation(softbusEvent) != RET_OK) {
        FI_HILOGE("SubscribeMouseLocation failed, networkId:%{public}s", Utility::Anonymize(event.networkId).c_str());
        return;
    }
    listeners_[event.networkId].insert(event.pid);
}

void MouseLocation::RemoveListener(const UnregisterEventListenerEvent &event)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(mutex_);
    localNetworkId_ = IDSoftbusAdapter::GetLocalNetworkId();
    if (event.networkId == localNetworkId_) {
        FI_HILOGI("Remove local mouse location listener");
        localListeners_.erase(event.pid);
        return;
    }
    DSoftbusUnSubscribeMouseLocation softbusEvent {
        .networkId = localNetworkId_,
        .remoteNetworkId = event.networkId,
    };
    if (UnSubscribeMouseLocation(softbusEvent) != RET_OK) {
        FI_HILOGE("UnSubscribeMouseLocation failed, networkId:%{public}s", Utility::Anonymize(event.networkId).c_str());
    }
    if (listeners_.find(event.networkId) == listeners_.end()) {
        FI_HILOGE("No listener for networkId:%{public}s", Utility::Anonymize(event.networkId).c_str());
        return;
    }
    listeners_[event.networkId].erase(event.pid);
    if (listeners_[event.networkId].empty()) {
        listeners_.erase(event.networkId);
    }
}

void MouseLocation::OnClientDied(const ClientDiedEvent &event)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(mutex_);
    localNetworkId_ = IDSoftbusAdapter::GetLocalNetworkId();
    FI_HILOGI("Remove client died listener, pid: %{public}d", event.pid);
    localListeners_.erase(event.pid);
    for (auto it = listeners_.begin(); it != listeners_.end();) {
        it->second.erase(event.pid);
        if (it->second.empty()) {
            DSoftbusUnSubscribeMouseLocation softbusEvent {
                .networkId = localNetworkId_,
                .remoteNetworkId = it->first,
            };
            UnSubscribeMouseLocation(softbusEvent);
            it = listeners_.erase(it);
        } else {
            ++it;
        }
    }
}

void MouseLocation::OnSoftbusSessionClosed(const DSoftbusSessionClosed &notice)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(mutex_);
    FI_HILOGI("Session to %{public}s closed", Utility::Anonymize(notice.networkId).c_str());
    if (remoteSubscribers_.find(notice.networkId) != remoteSubscribers_.end()) {
        remoteSubscribers_.erase(notice.networkId);
        FI_HILOGI("Remove remote subscribers from %{public}s", Utility::Anonymize(notice.networkId).c_str());
    }
    if (listeners_.find(notice.networkId) != listeners_.end()) {
        listeners_.erase(notice.networkId);
        FI_HILOGI("Remove listeners listen to %{public}s", Utility::Anonymize(notice.networkId).c_str());
    }
}

void MouseLocation::OnSubscribeMouseLocation(const DSoftbusSubscribeMouseLocation &notice)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(mutex_);
    CHKPV(context_);
    remoteSubscribers_.insert(notice.networkId);
    FI_HILOGI("Add subscriber for networkId:%{public}s successfully", Utility::Anonymize(notice.networkId).c_str());
    DSoftbusReplySubscribeMouseLocation event = {
        .networkId = notice.remoteNetworkId,
        .remoteNetworkId = notice.networkId,
        .result = true,
    };
    FI_HILOGI("ReplySubscribeMouseLocation from networkId:%{public}s to networkId:%{public}s",
        Utility::Anonymize(event.networkId).c_str(), Utility::Anonymize(event.remoteNetworkId).c_str());
    ReplySubscribeMouseLocation(event);
}

void MouseLocation::OnUnSubscribeMouseLocation(const DSoftbusUnSubscribeMouseLocation &notice)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(mutex_);
    localNetworkId_ = IDSoftbusAdapter::GetLocalNetworkId();
    if (remoteSubscribers_.find(notice.networkId) == remoteSubscribers_.end()) {
        FI_HILOGE("No subscriber for networkId:%{public}s stored in remote subscriber",
            Utility::Anonymize(notice.networkId).c_str());
        return;
    }
    remoteSubscribers_.erase(notice.networkId);
    DSoftbusReplyUnSubscribeMouseLocation event = {
        .networkId = notice.remoteNetworkId,
        .remoteNetworkId = notice.networkId,
        .result = true,
    };
    FI_HILOGI("ReplyUnSubscribeMouseLocation from networkId:%{public}s to networkId:%{public}s",
        Utility::Anonymize(event.networkId).c_str(), Utility::Anonymize(event.remoteNetworkId).c_str());
    ReplyUnSubscribeMouseLocation(event);
}

void MouseLocation::OnReplySubscribeMouseLocation(const DSoftbusReplySubscribeMouseLocation &notice)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(mutex_);
    if (notice.result) {
        FI_HILOGI("SubscribeMouseLocation of networkId:%{public}s successfully, localNetworkId:%{public}s",
            Utility::Anonymize(notice.networkId).c_str(), Utility::Anonymize(notice.remoteNetworkId).c_str());
    } else {
        FI_HILOGI("SubscribeMouseLocation of networkId:%{public}s failed, localNetworkId:%{public}s",
            Utility::Anonymize(notice.networkId).c_str(), Utility::Anonymize(notice.remoteNetworkId).c_str());
    }
}

void MouseLocation::OnReplyUnSubscribeMouseLocation(const DSoftbusReplyUnSubscribeMouseLocation &notice)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(mutex_);
    if (notice.result) {
        FI_HILOGI("UnSubscribeMouseLocation of networkId:%{public}s successfully, localNetworkId:%{public}s",
            Utility::Anonymize(notice.networkId).c_str(), Utility::Anonymize(notice.remoteNetworkId).c_str());
    } else {
        FI_HILOGI("UnSubscribeMouseLocation of networkId:%{public}s failed, localNetworkId:%{public}s",
            Utility::Anonymize(notice.networkId).c_str(), Utility::Anonymize(notice.remoteNetworkId).c_str());
    }
}

void MouseLocation::OnRemoteMouseLocation(const DSoftbusSyncMouseLocation &notice)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    if (listeners_.find(notice.networkId) == listeners_.end()) {
        FI_HILOGE("No listener for networkId:%{public}s stored in listeners",
            Utility::Anonymize(notice.networkId).c_str());
        return;
    }
    LocationInfo locationInfo {
        .displayX = notice.mouseLocation.displayX,
        .displayY = notice.mouseLocation.displayY,
        .displayWidth = notice.mouseLocation.displayWidth,
        .displayHeight = notice.mouseLocation.displayHeight
        };
    for (auto pid : listeners_[notice.networkId]) {
        ReportMouseLocationToListener(notice.networkId, locationInfo, pid);
    }
}

void MouseLocation::ProcessData(std::shared_ptr<MMI::PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    CHKPV(pointerEvent);
    if (auto sourceType = pointerEvent->GetSourceType(); sourceType != MMI::PointerEvent::SOURCE_TYPE_MOUSE) {
        FI_HILOGD("Unexpected sourceType:%{public}d", static_cast<int32_t>(sourceType));
        return;
    }
    LocationInfo locationInfo;
    TransferToLocationInfo(pointerEvent, locationInfo);
    if (HasLocalListener()) {
        for (auto pid : localListeners_) {
            ReportMouseLocationToListener(localNetworkId_, locationInfo, pid);
        }
    }
    if (!HasRemoteSubscriber()) {
        FI_HILOGD("No remote subscriber");
        return;
    }
    for (const auto &networkId : remoteSubscribers_) {
        SyncLocationToRemote(networkId, locationInfo);
    }
}

void MouseLocation::SyncLocationToRemote(const std::string &remoteNetworkId, const LocationInfo &locationInfo)
{
    CALL_DEBUG_ENTER;
    DSoftbusSyncMouseLocation softbusEvent {
        .networkId = localNetworkId_,
        .remoteNetworkId = remoteNetworkId,
        .mouseLocation = {
            .displayX = locationInfo.displayX,
            .displayY = locationInfo.displayY,
            .displayWidth = locationInfo.displayWidth,
            .displayHeight = locationInfo.displayHeight,
        },
    };
    SyncMouseLocation(softbusEvent);
}

int32_t MouseLocation::ReplySubscribeMouseLocation(const DSoftbusReplySubscribeMouseLocation &event)
{
    CALL_INFO_TRACE;
    NetPacket packet(MessageId::DSOFTBUS_REPLY_SUBSCRIBE_MOUSE_LOCATION);
    packet << event.networkId << event.remoteNetworkId << event.result;
    if (packet.ChkRWError()) {
        FI_HILOGE("Failed to write data packet");
        return RET_ERR;
    }
    if (SendPacket(event.remoteNetworkId, packet) != RET_OK) {
        FI_HILOGE("SendPacket failed");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t MouseLocation::ReplyUnSubscribeMouseLocation(const DSoftbusReplyUnSubscribeMouseLocation &event)
{
    CALL_INFO_TRACE;
    NetPacket packet(MessageId::DSOFTBUS_REPLY_UNSUBSCRIBE_MOUSE_LOCATION);
    packet << event.networkId << event.remoteNetworkId << event.result;
    if (packet.ChkRWError()) {
        FI_HILOGE("Failed to write data packet");
        return RET_ERR;
    }
    if (SendPacket(event.remoteNetworkId, packet) != RET_OK) {
        FI_HILOGE("SendPacket failed");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t MouseLocation::SubscribeMouseLocation(const DSoftbusSubscribeMouseLocation &event)
{
    CALL_INFO_TRACE;
    NetPacket packet(MessageId::DSOFTBUS_SUBSCRIBE_MOUSE_LOCATION);
    packet << event.networkId << event.remoteNetworkId;
    if (packet.ChkRWError()) {
        FI_HILOGE("Failed to write data packet");
        return RET_ERR;
    }
    if (SendPacket(event.remoteNetworkId, packet) != RET_OK) {
        FI_HILOGE("SendPacket failed");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t MouseLocation::UnSubscribeMouseLocation(const DSoftbusUnSubscribeMouseLocation &event)
{
    CALL_INFO_TRACE;
    NetPacket packet(MessageId::DSOFTBUS_UNSUBSCRIBE_MOUSE_LOCATION);
    packet << event.networkId << event.remoteNetworkId;
    if (packet.ChkRWError()) {
        FI_HILOGE("Failed to write data packet");
        return RET_ERR;
    }
    if (SendPacket(event.remoteNetworkId, packet) != RET_OK) {
        FI_HILOGE("SendPacket failed");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t MouseLocation::SyncMouseLocation(const DSoftbusSyncMouseLocation &event)
{
    CALL_DEBUG_ENTER;
    NetPacket packet(MessageId::DSOFTBUS_MOUSE_LOCATION);
    packet << event.networkId << event.remoteNetworkId << event.mouseLocation.displayX <<
        event.mouseLocation.displayY << event.mouseLocation.displayWidth << event.mouseLocation.displayHeight;
    if (packet.ChkRWError()) {
        FI_HILOGE("Failed to write data packet");
        return RET_ERR;
    }
    if (SendPacket(event.remoteNetworkId, packet) != RET_OK) {
        FI_HILOGE("SendPacket failed");
        return RET_ERR;
    }
    return RET_OK;
}

void MouseLocation::ReportMouseLocationToListener(const std::string &networkId, const LocationInfo &locationInfo,
    int32_t pid)
{
    CALL_DEBUG_ENTER;
    CHKPV(context_);
    auto session = context_->GetSocketSessionManager().FindSessionByPid(pid);
    CHKPV(session);
    NetPacket pkt(MessageId::MOUSE_LOCATION_ADD_LISTENER);
    pkt << networkId << locationInfo.displayX << locationInfo.displayY <<
        locationInfo.displayWidth << locationInfo.displayHeight;
    if (pkt.ChkRWError()) {
        FI_HILOGE("Packet write data failed");
        return;
    }
    if (!session->SendMsg(pkt)) {
        FI_HILOGE("Sending failed");
        return;
    }
}

void MouseLocation::TransferToLocationInfo(std::shared_ptr<MMI::PointerEvent> pointerEvent, LocationInfo &locationInfo)
{
    CALL_DEBUG_ENTER;
    CHKPV(pointerEvent);
    MMI::PointerEvent::PointerItem pointerItem;
    if (!pointerEvent->GetPointerItem(pointerEvent->GetPointerId(), pointerItem)) {
        FI_HILOGE("Corrupted pointer event");
        return;
    }
    auto display = Rosen::DisplayManager::GetInstance().GetDefaultDisplay();
    CHKPV(display);
    locationInfo = {
        .displayX = pointerItem.GetDisplayX(),
        .displayY = pointerItem.GetDisplayY(),
        .displayWidth = display->GetWidth(),
        .displayHeight = display->GetHeight(),
    };
}

bool MouseLocation::HasRemoteSubscriber()
{
    CALL_DEBUG_ENTER;
    return !remoteSubscribers_.empty();
}

bool MouseLocation::HasLocalListener()
{
    CALL_DEBUG_ENTER;
    return !localListeners_.empty();
}

int32_t MouseLocation::SendPacket(const std::string &remoteNetworkId, NetPacket &packet)
{
    CALL_DEBUG_ENTER;
    CHKPR(context_, RET_ERR);
    if (!context_->GetDSoftbus().HasSessionExisted(remoteNetworkId)) {
        FI_HILOGE("No session connected to %{public}s", Utility::Anonymize(remoteNetworkId).c_str());
        return RET_ERR;
    }
    if (context_->GetDSoftbus().SendPacket(remoteNetworkId, packet) != RET_OK) {
        FI_HILOGE("SendPacket failed to %{public}s", Utility::Anonymize(remoteNetworkId).c_str());
        return RET_ERR;
    }
    return RET_OK;
}

} // namespace Cooperate
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
