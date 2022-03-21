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
#include <condition_variable>

#include "mmi_log.h"
#include "proto.h"
#include "util.h"

#include "multimodal_event_handler.h"
#include "multimodal_input_connect_manager.h"

namespace OHOS {
namespace MMI {
namespace {
std::mutex mtx;
std::condition_variable cv;
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "MMIClient" };
} // namespace

using namespace AppExecFwk;
MMIClient::MMIClient() {}

MMIClient::~MMIClient()
{
    CALL_LOG_ENTER;
}

bool MMIClient::SendMessage(const NetPacket &pkt) const
{
    return SendMsg(pkt);
}

bool MMIClient::GetCurrentConnectedStatus() const
{
    return GetConnectedStatus();
}

bool MMIClient::Start()
{
    CALL_LOG_ENTER;
    msgHandler_.Init();
    EventManager.SetClientHandle(GetSharedPtr());
    auto callback = std::bind(&ClientMsgHandler::OnMsgHandler, &msgHandler_, 
        std::placeholders::_1, std::placeholders::_2);
    if (!(StartClient(callback))) {
        MMI_LOGE("Client startup failed");
        Stop();
        return false;
    }
    if (!StartEventRunner()) {
        MMI_LOGE("Start runner failed");
        Stop();
        return false;
    }
    return true;
}

bool MMIClient::StartEventRunner()
{
    CALL_LOG_ENTER;
    int32_t pid = GetPid();
    uint64_t tid = GetThisThreadId();
    MMI_LOGI("pid:%{public}d threadId:%{public}" PRIu64, pid, tid);

    MMI_LOGI("step 1");
    ehThread_ = std::thread(std::bind(&MMIClient::OnEventHandlerThread, this));
    ehThread_.detach();
    std::unique_lock <std::mutex> lck(mtx);
    if (cv.wait_for(lck, std::chrono::seconds(3)) == std::cv_status::timeout) {
        MMI_LOGE("EventThandler thread start timeout");
        Stop();
        return false;
    }
    MMI_LOGI("step 3");
    return true;
}

void MMIClient::OnEventHandlerThread()
{
    CALL_LOG_ENTER;
    SetThreadName("mmi_client");
    int32_t pid = GetPid();
    uint64_t tid = GetThisThreadId();
    MMI_LOGI("pid:%{public}d threadId:%{public}" PRIu64, pid, tid);

    auto eventHandler = MEventHandler->GetSharedPtr();
    CHKPV(eventHandler);
    auto eventRunner = eventHandler->GetEventRunner();
    CHKPV(eventRunner);
    MMI_LOGI("step 2");
    cv.notify_one();

    MMI_LOGI("step 4");
    eventRunner->Run();
    MMI_LOGI("step 5");
}

void MMIClient::OnMsgHandler(NetPacket& pkt)
{
    CALL_LOG_ENTER;
    CHKPV(eventHandler_);
    int32_t pid = GetPid();
    uint64_t tid = GetThisThreadId();
    MMI_LOGI("pid:%{public}d threadId:%{public}" PRIu64, pid, tid);

    auto callMsgHandler = [this, &pkt] () {
        int32_t pid = GetPid();
        uint64_t tid = GetThisThreadId();
        MMI_LOGI("callMsgHandler pid:%{public}d threadId:%{public}" PRIu64, pid, tid);
        msgHandler_.OnMsgHandler(*this, pkt);
    };
    bool ret = eventHandler_->PostHighPriorityTask(callMsgHandler);
    if (!ret) {
        MMI_LOGE("post task failed");
    }
}

void MMIClient::OnRecvMsg(const char *buf, size_t size)
{
    CHKPV(buf);
    if (size == 0) {
        MMI_LOGE("Invalid input param size");
        return;
    }
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

void MMIClient::OnDisconnected()
{
    MMI_LOGD("Disconnected from server, fd:%{public}d", GetFd());
    isConnected_ = false;
    if (funDisconnected_) {
        funDisconnected_(*this);
    }
}

void MMIClient::OnConnected()
{
    MMI_LOGD("Connection to server succeeded, fd:%{public}d", GetFd());
    isConnected_ = true;
    if (funConnected_) {
        funConnected_(*this);
    }
}

int32_t MMIClient::Socket()
{
    CALL_LOG_ENTER;
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
    CALL_LOG_ENTER;
    UDSClient::Stop();
    if (eventHandler_ && selfRunner_) {
        eventHandler_->SendSyncEvent(MMI_EVENT_HANDLER_ID_STOP, 0, EventHandler::Priority::IMMEDIATE);
    }
}
} // namespace MMI
} // namespace OHOS
