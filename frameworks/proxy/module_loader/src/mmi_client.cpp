/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "mmi_client.h"
#include <cinttypes>
#include "mmi_log.h"
#include "proto.h"
#include "util.h"
#include "multimodal_event_handler.h"
#include "multimodal_input_connect_manager.h"
#include "mmi_fd_listener.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "MMIClient" };
} // namespace

using namespace AppExecFwk;
MMIClient::MMIClient() {}

MMIClient::~MMIClient()
{
    MMI_LOGD("enter");
}

bool MMIClient::SendMessage(const NetPacket &pkt) const
{
    return SendMsg(pkt);
}

bool MMIClient::GetCurrentConnectedStatus() const
{
    return GetConnectedStatus();
}

bool MMIClient::Start(IClientMsgHandlerPtr msgHdl, bool detachMode)
{
    MMI_LOGD("enter");
    EventManager.SetClientHandle(GetPtr());
    if (!(msgHdl->Init())) {
        MMI_LOGE("Message processing initialization failed");
        return false;
    }
    auto msgHdlImp = static_cast<ClientMsgHandler *>(msgHdl.get());
    CHKPF(msgHdlImp);
    auto callback = std::bind(&ClientMsgHandler::OnMsgHandler, msgHdlImp, std::placeholders::_1, std::placeholders::_2);
    if (!(StartClient(callback, detachMode))) {
        MMI_LOGE("Client startup failed");
        return false;
    }
    CHKF(StartEventRunner(), START_CLI_FAIL);
    return true;
}

bool MMIClient::StartEventRunner()
{
    MMI_LOGD("enter");
    auto eventRunner = EventRunner::GetMainEventRunner();
    CHKPF(eventRunner);
    eventHandler_ = std::make_shared<MMIEventHandler>(eventRunner, GetPtr());
    CHKPF(eventHandler_);
    if (isConnected_ && fd_ >= 0) {
        if (!AddFdListener(fd_)) {
            MMI_LOGE("add fd listener return false");
            return false;
        }
    } else {
        if (!eventHandler_->SendEvent(MMI_EVENT_HANDLER_ID_RECONNECT, 0, EVENT_TIME_ONRECONNECT)) {
            MMI_LOGE("send reconnect event return false.");
            return false;
        }
    }
    // if (!eventHandler_->SendEvent(MMI_EVENT_HANDLER_ID_ONTIMER, 0, EVENT_TIME_ONTIMER)) {
    //     MMI_LOGE("send ontimer event return false.");
    //     return false;
    // }
    // auto errCode = eventRunner->Run();
    // if (errCode != ERR_OK) {
    //     MMI_LOGE("event runnner run error,code:%{public}u str:%{public}s", errCode,
    //         eventHandler_->GetErrorStr(errCode).c_str());
    //     return false;
    // }
    MMI_LOGD("leave");
    return true;
}

bool MMIClient::AddFdListener(int32_t fd)
{
    MMI_LOGD("enter");
    CHKF(fd >= 0, C_INVALID_INPUT_PARAM);
    CHKPF(eventHandler_);
    auto fdListener = std::make_shared<MMIFdListener>(GetPtr());
    CHKPF(fdListener);
    auto errCode = eventHandler_->AddFileDescriptorListener(fd, FILE_DESCRIPTOR_INPUT_EVENT, fdListener);
    if (errCode != ERR_OK) {
        MMI_LOGE("add fd listener error,fd:%{public}d code:%{public}u str:%{public}s", fd, errCode,
            eventHandler_->GetErrorStr(errCode).c_str());
        return false;
    }
    uint64_t tid = GetThisThreadIdOfLL();
    int32_t pid = GetPid();
    isRunning_ = true;
    MMI_LOGI("serverFd:%{public}d was listening,mask:%{public}u pid:%{public}d threadId:%{public}" PRIu64,
        fd, FILE_DESCRIPTOR_EVENTS_MASK, pid, tid);
    return true;
}

bool MMIClient::DelFdListener(int32_t fd)
{
    MMI_LOGD("enter");
    CHKF(fd >= 0, C_INVALID_INPUT_PARAM);
    CHKPF(eventHandler_);
    eventHandler_->RemoveFileDescriptorListener(fd);
    isRunning_ = false;
    return true;
}

void MMIClient::OnRecvMsg(const char *buf, size_t size)
{
    CHKPV(buf);
    CHK(size > 0, C_INVALID_INPUT_PARAM);
    OnRecv(buf, size);
}

int32_t MMIClient::Reconnect()
{
    return ConnectTo();
}

void MMIClient::OnDisconnect()
{
    OnDisconnected();
}

void MMIClient::RegisterConnectedFunction(ConnectCallback fun)
{
    funConnected_ = fun;
}

void MMIClient::RegisterDisconnectedFunction(ConnectCallback fun)
{
    funDisconnected_ = fun;
}

void MMIClient::VirtualKeyIn(RawInputEvent virtualKeyEvent)
{
    NetPacket pkt(MmiMessageId::ON_VIRTUAL_KEY);
    pkt << virtualKeyEvent;
    SendMsg(pkt);
}

void MMIClient::ReplyMessageToServer(MmiMessageId idMsg, int64_t clientTime, int64_t endTime) const
{
    NetPacket pkt(MmiMessageId::CHECK_REPLY_MESSAGE);
    pkt << idMsg << clientTime << endTime;
    SendMsg(pkt);
}

void MMIClient::SdkGetMultimodeInputInfo()
{
    TagPackHead tagPackHead = {MmiMessageId::GET_MMI_INFO_REQ, {0}};
    NetPacket pkt(MmiMessageId::GET_MMI_INFO_REQ);
    pkt << tagPackHead;
    SendMsg(pkt);
}

void MMIClient::OnDisconnected()
{
    MMI_LOGD("Disconnected from server, fd:%{public}d", GetFd());
    CHK(eventHandler_, C_INVALID_INPUT_PARAM);
    if (funDisconnected_) {
        funDisconnected_(*this);
    }
    isConnected_ = false;
    CK(DelFdListener(fd_), C_DEL_FD_LISTENER_FAIL);
    if (!isToExit_) {
        if (!eventHandler_->SendEvent(MMI_EVENT_HANDLER_ID_RECONNECT, 0, EVENT_TIME_ONRECONNECT)) {
            MMI_LOGE("send reconnect event return false.");
        }
    } else {
        MMI_LOGW("toExit is true.Reconnection closed");
    }
}

void MMIClient::OnConnected()
{
    MMI_LOGD("Connection to server succeeded, fd:%{public}d", GetFd());
    isConnected_ = true;
    if (funConnected_) {
        funConnected_(*this);
    }
    if (!isRunning_ && fd_ >= 0 && eventHandler_ != nullptr) {
        CHK(AddFdListener(fd_), C_ADD_FD_LISTENER_FAIL);
    }
}

int32_t MMIClient::Socket()
{
    MMI_LOGD("enter");
    int32_t ret = MultimodalInputConnectManager::GetInstance()->
                        AllocSocketPair(IMultimodalInputConnect::CONNECT_MODULE_TYPE_MMI_CLIENT);
    if (ret != RET_OK) {
        MMI_LOGE("UDSSocket::Socket, call MultimodalInputConnectManager::AllocSocketPair return %{public}d", ret);
        return -1;
    }
    fd_ = MultimodalInputConnectManager::GetInstance()->GetClientSocketFdOfAllocedSocketPair();
    if (fd_ == IMultimodalInputConnect::INVALID_SOCKET_FD) {
        MMI_LOGE("UDSSocket::Socket, call MultimodalInputConnectManager::GetClientSocketFdOfAllocedSocketPair"
                 " return invalid fd");
    } else {
        MMI_LOGD("UDSSocket::Socket, call MultimodalInputConnectManager::GetClientSocketFdOfAllocedSocketPair"
                 " return fd:%{public}d", fd_);
    }

    return fd_;
}

void MMIClient::Stop()
{
    UDSClient::Stop();
    if (eventHandler_) {
        eventHandler_->SendSyncEvent(MMI_EVENT_HANDLER_ID_STOP);
    }
}
} // namespace MMI
} // namespace OHOS

