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

#include "socket_client.h"

#include "event_handler.h"

#include "devicestatus_define.h"
#include "intention_identity.h"
#include "socket_params.h"
#include "time_cost_chk.h"

#undef LOG_TAG
#define LOG_TAG "SocketClient"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
const std::string THREAD_NAME { "os_ClientEventHandler" };
}

SocketClient::SocketClient(std::shared_ptr<ITunnelClient> tunnel)
    : tunnel_(tunnel)
{
    auto runner = AppExecFwk::EventRunner::Create(THREAD_NAME);
    eventHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
}

bool SocketClient::RegisterEvent(MessageId id, std::function<int32_t(const StreamClient&, NetPacket&)> callback)
{
    std::lock_guard guard(lock_);
    auto [_, inserted] = callbacks_.emplace(id, callback);
    return inserted;
}

void SocketClient::Start()
{
    CALL_DEBUG_ENTER;
    Reconnect();
}

void SocketClient::Stop()
{}

bool SocketClient::Connect()
{
    CALL_DEBUG_ENTER;
    if (socket_ != nullptr) {
        return true;
    }
    auto socket = SocketConnection::Connect(
        [this] { return this->Socket(); },
        [this](NetPacket &pkt) { this->OnPacket(pkt); },
        [this] { this->OnDisconnected(); });
    CHKPF(socket);
    CHKPF(eventHandler_);
    auto errCode = eventHandler_->AddFileDescriptorListener(socket->GetFd(),
        AppExecFwk::FILE_DESCRIPTOR_INPUT_EVENT, socket, "DeviceStatusTask");
    if (errCode != ERR_OK) {
        FI_HILOGE("AddFileDescriptorListener(%{public}d) failed (%{public}u)", socket->GetFd(), errCode);
        return false;
    }
    socket_ = socket;
    FI_HILOGD("SocketClient started successfully");
    return true;
}

int32_t SocketClient::Socket()
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<ITunnelClient> tunnel = tunnel_.lock();
    CHKPR(tunnel, RET_ERR);
    AllocSocketPairParam param { GetProgramName(), CONNECT_MODULE_TYPE_FI_CLIENT };
    AllocSocketPairReply reply;

    int32_t ret = tunnel->Control(Intention::SOCKET, SocketAction::SOCKET_ACTION_CONNECT, param, reply);
    if (ret != RET_OK) {
        FI_HILOGE("ITunnelClient::Control fail");
        return -1;
    }
    FI_HILOGD("Connected to intention service (%{public}d)", reply.socketFd);
    return reply.socketFd;
}

void SocketClient::OnPacket(NetPacket &pkt)
{
    CALL_DEBUG_ENTER;
    std::lock_guard guard(lock_);
    OnMsgHandler(*this, pkt);
}

void SocketClient::OnDisconnected()
{
    CALL_DEBUG_ENTER;
    std::lock_guard guard(lock_);
    if (socket_ != nullptr) {
        eventHandler_->RemoveFileDescriptorListener(socket_->GetFd());
        eventHandler_->RemoveAllEvents();
        socket_.reset();
    }
    if (!eventHandler_->PostTask([this] { this->Reconnect(); }, CLIENT_RECONNECT_COOLING_TIME)) {
        FI_HILOGE("Failed to post reconnection task");
    }
}

void SocketClient::Reconnect()
{
    std::lock_guard guard(lock_);
    if (Connect()) {
        return;
    }
    if (!eventHandler_->PostTask([this] { this->Reconnect(); }, CLIENT_RECONNECT_COOLING_TIME)) {
        FI_HILOGE("Failed to post reconnection task");
    }
}

void SocketClient::OnMsgHandler(const StreamClient &client, NetPacket &pkt)
{
    CALL_DEBUG_ENTER;
    MessageId id = pkt.GetMsgId();
    TimeCostChk chk("SocketClient::OnMsgHandler", "overtime 300(us)", MAX_OVER_TIME, id);
    auto iter = callbacks_.find(id);
    if (iter == callbacks_.end()) {
        FI_HILOGE("Unknown msg id:%{public}d", id);
        return;
    }
    int32_t ret = iter->second(client, pkt);
    if (ret < 0) {
        FI_HILOGE("Msg handling failed, id:%{public}d, ret:%{public}d", id, ret);
    }
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS