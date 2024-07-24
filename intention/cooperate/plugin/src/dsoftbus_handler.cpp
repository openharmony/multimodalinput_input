/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "dsoftbus_handler.h"

#include "ipc_skeleton.h"
#include "token_setproc.h"

#include "device.h"
#include "devicestatus_define.h"
#include "utility.h"

#undef LOG_TAG
#define LOG_TAG "DSoftbusHandler"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace Cooperate {
constexpr int32_t MAX_INPUT_DEV_NUM { 100 };
constexpr int32_t INVALID_DEVICE_ID { -1 };

DSoftbusHandler::DSoftbusHandler(IContext *env)
    : env_(env)
{
    handles_ = {
        { static_cast<int32_t>(MessageId::DSOFTBUS_START_COOPERATE),
        [this] (const std::string &networkId, NetPacket &packet) {
            this->OnStartCooperate(networkId, packet);}},
        { static_cast<int32_t>(MessageId::DSOFTBUS_STOP_COOPERATE),
        [this] (const std::string &networkId, NetPacket &packet) {
            this->OnStopCooperate(networkId, packet);}},
        { static_cast<int32_t>(MessageId::DSOFTBUS_COME_BACK),
        [this] (const std::string &networkId, NetPacket &packet) {
            this->OnComeBack(networkId, packet);}},
        { static_cast<int32_t>(MessageId::DSOFTBUS_RELAY_COOPERATE),
        [this] (const std::string &networkId, NetPacket &packet) {
            this->OnRelayCooperate(networkId, packet);}},
        { static_cast<int32_t>(MessageId::DSOFTBUS_RELAY_COOPERATE_FINISHED),
        [this] (const std::string &networkId, NetPacket &packet) {
            this->OnRelayCooperateFinish(networkId, packet);}},
        { static_cast<int32_t>(MessageId::DSOFTBUS_SUBSCRIBE_MOUSE_LOCATION),
        [this] (const std::string &networkId, NetPacket &packet) {
            this->OnSubscribeMouseLocation(networkId, packet);}},
        { static_cast<int32_t>(MessageId::DSOFTBUS_UNSUBSCRIBE_MOUSE_LOCATION),
        [this] (const std::string &networkId, NetPacket &packet) {
            this->OnUnSubscribeMouseLocation(networkId, packet);}},
        { static_cast<int32_t>(MessageId::DSOFTBUS_REPLY_SUBSCRIBE_MOUSE_LOCATION),
        [this] (const std::string &networkId, NetPacket &packet) {
            this->OnReplySubscribeLocation(networkId, packet);}},
        { static_cast<int32_t>(MessageId::DSOFTBUS_REPLY_UNSUBSCRIBE_MOUSE_LOCATION),
        [this] (const std::string &networkId, NetPacket &packet) {
            this->OnReplyUnSubscribeLocation(networkId, packet);}},
        { static_cast<int32_t>(MessageId::DSOFTBUS_MOUSE_LOCATION),
        [this] (const std::string &networkId, NetPacket &packet) {
            this->OnRemoteMouseLocation(networkId, packet);}},
        { static_cast<int32_t>(MessageId::DSOFTBUS_INPUT_DEV_SYNC),
        [this] (const std::string &networkId, NetPacket &packet) {
            this->OnRemoteInputDevice(networkId, packet);}},
        { static_cast<int32_t>(MessageId::DSOFTBUS_INPUT_DEV_HOT_PLUG),
        [this] (const std::string &networkId, NetPacket &packet) {
            this->OnRemoteHotPlug(networkId, packet);}}
    };
    observer_ = std::make_shared<DSoftbusObserver>(*this);
    CHKPV(env_);
    env_->GetDSoftbus().AddObserver(observer_);
}

DSoftbusHandler::~DSoftbusHandler()
{
    CHKPV(env_);
    env_->GetDSoftbus().RemoveObserver(observer_);
}

void DSoftbusHandler::AttachSender(Channel<CooperateEvent>::Sender sender)
{
    CALL_DEBUG_ENTER;
    std::lock_guard guard(lock_);
    sender_ = sender;
}

int32_t DSoftbusHandler::OpenSession(const std::string &networkId)
{
    CALL_INFO_TRACE;
    auto tokenId = OHOS::IPCSkeleton::GetCallingTokenID();
    int ret = SetFirstCallerTokenID(tokenId);
    if (ret != RET_OK) {
        FI_HILOGW("Failed to SetFirstCallerTokenID, ret:%{public}d", ret);
    }
    return env_->GetDSoftbus().OpenSession(networkId);
}

void DSoftbusHandler::CloseSession(const std::string &networkId)
{
    CALL_INFO_TRACE;
    env_->GetDSoftbus().CloseSession(networkId);
}

void DSoftbusHandler::CloseAllSessions()
{
    CALL_INFO_TRACE;
    env_->GetDSoftbus().CloseAllSessions();
}

int32_t DSoftbusHandler::StartCooperate(const std::string &networkId, const DSoftbusStartCooperate &event)
{
    CALL_INFO_TRACE;
    NetPacket packet(MessageId::DSOFTBUS_START_COOPERATE);
    packet << event.originNetworkId << event.cursorPos.x
        << event.cursorPos.y << event.success << event.extra.priv;
    if (packet.ChkRWError()) {
        FI_HILOGE("Failed to write data packet");
        return RET_ERR;
    }
    int32_t ret = env_->GetDSoftbus().SendPacket(networkId, packet);
    if (ret != RET_OK) {
        OnCommunicationFailure(networkId);
    }
    return ret;
}

int32_t DSoftbusHandler::StopCooperate(const std::string &networkId, const DSoftbusStopCooperate &event)
{
    CALL_INFO_TRACE;
    NetPacket packet(MessageId::DSOFTBUS_STOP_COOPERATE);
    int32_t ret = env_->GetDSoftbus().SendPacket(networkId, packet);
    if (ret != RET_OK) {
        OnCommunicationFailure(networkId);
    }
    return ret;
}

int32_t DSoftbusHandler::ComeBack(const std::string &networkId, const DSoftbusComeBack &event)
{
    CALL_INFO_TRACE;
    NetPacket packet(MessageId::DSOFTBUS_COME_BACK);
    packet << event.originNetworkId << event.cursorPos.x << event.cursorPos.y << event.extra.priv;
    if (packet.ChkRWError()) {
        FI_HILOGE("Failed to write data packet");
        return RET_ERR;
    }
    int32_t ret = env_->GetDSoftbus().SendPacket(networkId, packet);
    if (ret != RET_OK) {
        OnCommunicationFailure(networkId);
    }
    return ret;
}

int32_t DSoftbusHandler::RelayCooperate(const std::string &networkId, const DSoftbusRelayCooperate &event)
{
    CALL_INFO_TRACE;
    NetPacket packet(MessageId::DSOFTBUS_RELAY_COOPERATE);
    packet << event.targetNetworkId;
    if (packet.ChkRWError()) {
        FI_HILOGE("Failed to write data packet");
        return RET_ERR;
    }
    int32_t ret = env_->GetDSoftbus().SendPacket(networkId, packet);
    if (ret != RET_OK) {
        OnCommunicationFailure(networkId);
    }
    return ret;
}

int32_t DSoftbusHandler::RelayCooperateFinish(const std::string &networkId, const DSoftbusRelayCooperateFinished &event)
{
    CALL_INFO_TRACE;
    NetPacket packet(MessageId::DSOFTBUS_RELAY_COOPERATE_FINISHED);
    packet << event.targetNetworkId << event.normal;
    if (packet.ChkRWError()) {
        FI_HILOGE("Failed to write data packet");
        return RET_ERR;
    }
    int32_t ret = env_->GetDSoftbus().SendPacket(networkId, packet);
    if (ret != RET_OK) {
        OnCommunicationFailure(networkId);
    }
    return ret;
}

std::string DSoftbusHandler::GetLocalNetworkId()
{
    return IDSoftbusAdapter::GetLocalNetworkId();
}

void DSoftbusHandler::OnBind(const std::string &networkId)
{
    FI_HILOGI("Bind to \'%{public}s\'", Utility::Anonymize(networkId).c_str());
    SendEvent(CooperateEvent(
        CooperateEventType::DSOFTBUS_SESSION_OPENED,
        DSoftbusSessionOpened {
            .networkId = networkId
        }));
}

void DSoftbusHandler::OnShutdown(const std::string &networkId)
{
    FI_HILOGI("Connection with \'%{public}s\' shutdown", Utility::Anonymize(networkId).c_str());
    SendEvent(CooperateEvent(
        CooperateEventType::DSOFTBUS_SESSION_CLOSED,
        DSoftbusSessionClosed {
            .networkId = networkId
        }));
}

void DSoftbusHandler::OnConnected(const std::string &networkId)
{
    FI_HILOGI("Connection to \'%{public}s\' successfully", Utility::Anonymize(networkId).c_str());
    SendEvent(CooperateEvent(
        CooperateEventType::DSOFTBUS_SESSION_OPENED,
        DSoftbusSessionOpened {
            .networkId = networkId
        }));
}

bool DSoftbusHandler::OnPacket(const std::string &networkId, NetPacket &packet)
{
    CALL_DEBUG_ENTER;
    int32_t messageId = static_cast<int32_t>(packet.GetMsgId());
    auto it = handles_.find(messageId);
    if (it != handles_.end()) {
        (it->second)(networkId, packet);
        return true;
    }
    FI_HILOGD("Unsupported messageId: %{public}d from %{public}s", messageId,
        Utility::Anonymize(networkId).c_str());
    return false;
}

void DSoftbusHandler::SendEvent(const CooperateEvent &event)
{
    std::lock_guard guard(lock_);
    auto ret = sender_.Send(event);
    if (ret != Channel<CooperateEvent>::NO_ERROR) {
        FI_HILOGE("Failed to send event via channel, error:%{public}d", ret);
    }
}

void DSoftbusHandler::OnCommunicationFailure(const std::string &networkId)
{
    env_->GetDSoftbus().CloseSession(networkId);
    FI_HILOGI("Notify communication failure with peer(%{public}s)", Utility::Anonymize(networkId).c_str());
    SendEvent(CooperateEvent(
        CooperateEventType::DSOFTBUS_SESSION_CLOSED,
        DSoftbusSessionClosed {
            .networkId = networkId
        }));
}

void DSoftbusHandler::OnStartCooperate(const std::string &networkId, NetPacket &packet)
{
    CALL_INFO_TRACE;
    DSoftbusStartCooperate event {
        .networkId = networkId,
    };
    packet >> event.originNetworkId >> event.cursorPos.x
        >> event.cursorPos.y >> event.success;
    if (packet.ChkRWError()) {
        FI_HILOGE("Failed to read data packet");
        return;
    }
    packet >> event.extra.priv;
    if (packet.ChkRWError()) {
        event.extra.priv = 0;
    }
    SendEvent(CooperateEvent(
        CooperateEventType::DSOFTBUS_START_COOPERATE,
        event));
}

void DSoftbusHandler::OnStopCooperate(const std::string &networkId, NetPacket &packet)
{
    CALL_INFO_TRACE;
    DSoftbusStopCooperate event {
        .networkId = networkId,
        .normal = true,
    };
    SendEvent(CooperateEvent(
        CooperateEventType::DSOFTBUS_STOP_COOPERATE,
        event));
}

void DSoftbusHandler::OnComeBack(const std::string &networkId, NetPacket &packet)
{
    CALL_INFO_TRACE;
    DSoftbusComeBack event {
        .networkId = networkId,
        .success = true,
    };
    packet >> event.originNetworkId >> event.cursorPos.x >> event.cursorPos.y;
    if (packet.ChkRWError()) {
        FI_HILOGE("Failed to read data packet");
        return;
    }
    packet >> event.extra.priv;
    if (packet.ChkRWError()) {
        event.extra.priv = 0;
    }
    SendEvent(CooperateEvent(
        CooperateEventType::DSOFTBUS_COME_BACK,
        event));
}

void DSoftbusHandler::OnRelayCooperate(const std::string &networkId, NetPacket &packet)
{
    CALL_INFO_TRACE;
    DSoftbusRelayCooperate event {
        .networkId = networkId,
        .normal = true,
    };
    packet >> event.targetNetworkId;
    if (packet.ChkRWError()) {
        FI_HILOGE("Failed to read data packet");
        return;
    }
    SendEvent(CooperateEvent(
        CooperateEventType::DSOFTBUS_RELAY_COOPERATE,
        event));
}

void DSoftbusHandler::OnRelayCooperateFinish(const std::string &networkId, NetPacket &packet)
{
    CALL_INFO_TRACE;
    DSoftbusRelayCooperate event {
        .networkId = networkId,
    };
    packet >> event.targetNetworkId >> event.normal;
    if (packet.ChkRWError()) {
        FI_HILOGE("Failed to read data packet");
        return;
    }
    SendEvent(CooperateEvent(
        CooperateEventType::DSOFTBUS_RELAY_COOPERATE_FINISHED,
        event));
}

void DSoftbusHandler::OnSubscribeMouseLocation(const std::string &networKId, NetPacket &packet)
{
    CALL_INFO_TRACE;
    DSoftbusSubscribeMouseLocation event;
    packet >> event.networkId >> event.remoteNetworkId;
    if (packet.ChkRWError()) {
        FI_HILOGE("Failed to read data packet");
        return;
    }
    SendEvent(CooperateEvent(
        CooperateEventType::DSOFTBUS_SUBSCRIBE_MOUSE_LOCATION,
        event));
}

void DSoftbusHandler::OnUnSubscribeMouseLocation(const std::string& networKId, NetPacket &packet)
{
    CALL_INFO_TRACE;
    DSoftbusUnSubscribeMouseLocation event;
    packet >> event.networkId >> event.remoteNetworkId;
    if (packet.ChkRWError()) {
        FI_HILOGE("Failed to read data packet");
        return;
    }
    SendEvent(CooperateEvent(
        CooperateEventType::DSOFTBUS_UNSUBSCRIBE_MOUSE_LOCATION,
        event));
}

void DSoftbusHandler::OnReplySubscribeLocation(const std::string& networKId, NetPacket &packet)
{
    CALL_INFO_TRACE;
    DSoftbusReplySubscribeMouseLocation event;
    packet >> event.networkId >> event.remoteNetworkId >> event.result;
    if (packet.ChkRWError()) {
        FI_HILOGE("Failed to read data packet");
        return;
    }
    SendEvent(CooperateEvent(
        CooperateEventType::DSOFTBUS_REPLY_SUBSCRIBE_MOUSE_LOCATION,
        event));
}

void DSoftbusHandler::OnReplyUnSubscribeLocation(const std::string& networKId, NetPacket &packet)
{
    CALL_INFO_TRACE;
    DSoftbusReplyUnSubscribeMouseLocation event;
    packet >> event.networkId >> event.remoteNetworkId >> event.result;
    if (packet.ChkRWError()) {
        FI_HILOGE("Failed to read data packet");
        return;
    }
    SendEvent(CooperateEvent(
        CooperateEventType::DSOFTBUS_REPLY_UNSUBSCRIBE_MOUSE_LOCATION,
        event));
}

void DSoftbusHandler::OnRemoteMouseLocation(const std::string& networKId, NetPacket &packet)
{
    CALL_DEBUG_ENTER;
    DSoftbusSyncMouseLocation event;
    packet >> event.networkId >> event.remoteNetworkId >> event.mouseLocation.displayX >>
        event.mouseLocation.displayY >> event.mouseLocation.displayWidth >> event.mouseLocation.displayHeight;
    if (packet.ChkRWError()) {
        FI_HILOGE("Failed to read data packet");
        return;
    }
    SendEvent(CooperateEvent(
        CooperateEventType::DSOFTBUS_MOUSE_LOCATION,
        event));
}

void DSoftbusHandler::OnRemoteInputDevice(const std::string& networkId, NetPacket &packet)
{
    CALL_INFO_TRACE;
    DSoftbusSyncInputDevice event;
    int32_t devNum { -1 };
    packet >> devNum;
    event.networkId = networkId;
    FI_HILOGI("devNum:%{public}d", devNum);
    if (devNum <= 0 || devNum >= MAX_INPUT_DEV_NUM) {
        FI_HILOGE("Invalid devNum:%{public}d", devNum);
        return;
    }
    for (int32_t i = 0; i < devNum; i++) {
        auto device = std::make_shared<Device>(INVALID_DEVICE_ID);
        if (DeserializeDevice(device, packet) != RET_OK) {
            FI_HILOGE("DeserializeDevice failed");
            return;
        }
        event.devices.push_back(device);
    }
    SendEvent(CooperateEvent(
        CooperateEventType::DSOFTBUS_INPUT_DEV_SYNC,
        event));
}

void DSoftbusHandler::OnRemoteHotPlug(const std::string &networkId, NetPacket &packet)
{
    CALL_INFO_TRACE;
    DSoftbusHotPlugEvent event;
    packet >> event.type;
    FI_HILOGI("Hot plug type:%{public}d", event.type);
    auto device = std::make_shared<Device>(INVALID_DEVICE_ID);
    if (DeserializeDevice(device, packet) != RET_OK) {
        FI_HILOGE("DeserializeDevice failed");
        return;
    }
    event.device = device;
    SendEvent(CooperateEvent(
        CooperateEventType::DSOFTBUS_INPUT_DEV_HOT_PLUG,
        event));
}

int32_t DSoftbusHandler::DeserializeDevice(std::shared_ptr<IDevice> device, NetPacket &packet)
{
    CALL_DEBUG_ENTER;
    CHKPR(device, RET_ERR);
    int32_t data;
    std::string str;
    packet >> data;
    device->SetId(data);
    packet >> str;
    device->SetDevPath(str);
    packet >> str;
    device->SetSysPath(str);
    packet >> data;
    device->SetBus(data);
    packet >> data;
    device->SetVendor(data);
    packet >> data;
    device->SetProduct(data);
    packet >> data;
    device->SetVersion(data);
    packet >> str;
    device->SetName(str);
    packet >> str;
    device->SetPhys(str);
    packet >> str;
    device->SetUniq(str);
    bool isPointerDevice { false };
    packet >> isPointerDevice;
    if (isPointerDevice) {
        device->AddCapability(IDevice::Capability::DEVICE_CAP_POINTER);
    }
    bool isKeyboard { false };
    packet >> isKeyboard;
    if (isKeyboard) {
        device->AddCapability(IDevice::Capability::DEVICE_CAP_KEYBOARD);
    }
    int32_t keyboardType { static_cast<int32_t> (IDevice::KeyboardType::KEYBOARD_TYPE_NONE) };
    packet >> keyboardType;
    device->SetKeyboardType(static_cast<IDevice::KeyboardType>(keyboardType));
    if (packet.ChkRWError()) {
        FI_HILOGE("Packet read type failed");
        return RET_ERR;
    }
    return RET_OK;
}
} // namespace Cooperate
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
