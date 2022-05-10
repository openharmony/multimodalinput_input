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

#include "uds_client.h"
#include <cinttypes>
#include "util.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "UDSClient" }; // namepace
}

UDSClient::UDSClient()
{
    MMI_LOGD("enter");
}

UDSClient::~UDSClient()
{
    MMI_LOGD("enter");
    Stop();
    MMI_LOGD("leave");
}

int32_t UDSClient::ConnectTo()
{
    CHKR(Socket() >= 0, SOCKET_CREATE_FAIL, RET_ERR);
    if (epollFd_ < 0) {
        CHKR(EpollCreat(MAX_EVENT_SIZE) >= 0, EPOLL_CREATE_FAIL, RET_ERR);
    }
    SetNonBlockMode(fd_);

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = fd_;
    CHKR(EpollCtl(fd_, EPOLL_CTL_ADD, ev) >= 0, EPOLL_CREATE_FAIL, RET_ERR);
    OnConnected();
    return RET_OK;
}

bool UDSClient::SendMsg(const char *buf, size_t size) const
{
    CHKPF(buf);
    if ((size == 0) || (size > MAX_PACKET_BUF_SIZE)) {
        MMI_LOGE("Stream buffer size out of range");
        return false;
    }
    if (fd_ < 0) {
        MMI_LOGE("fd_ is less than 0");
        return false;
    }

    int32_t idx = 0;
    int32_t retryCount = 0;
    const int32_t bufSize = static_cast<int32_t>(size);
    int32_t remSize = bufSize;
    while (remSize > 0 && retryCount < SEND_RETRY_LIMIT) {
        retryCount += 1;
        auto count = send(fd_, &buf[idx], remSize, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (count < 0) {
            if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK) {
                MMI_LOGW("continue for errno EAGAIN|EINTR|EWOULDBLOCK, errno:%{public}d", errno);
                usleep(SEND_RETRY_SLEEP_TIME);
                continue;
            }
            MMI_LOGE("Send return failed,error:%{public}d fd:%{public}d", errno, fd_);
            return false;
        }
        idx += count;
        remSize -= count;
        if (remSize > 0) {
            usleep(SEND_RETRY_SLEEP_TIME);
        }
    }
    if (retryCount >= SEND_RETRY_LIMIT || remSize != 0) {
        MMI_LOGE("Send too many times:%{public}d/%{public}d,size:%{public}d/%{public}d fd:%{public}d",
            retryCount, SEND_RETRY_LIMIT, idx, bufSize, fd_);
        return false;
    }
    return true;
}

bool UDSClient::SendMsg(const NetPacket& pkt) const
{
    CHKF(!pkt.ChkRWError(), PACKET_WRITE_FAIL);
    StreamBuffer buf;
    pkt.MakeData(buf);
    return SendMsg(buf.Data(), buf.Size());
}

bool UDSClient::StartClient(MsgClientFunCallback fun, bool detachMode)
{
    MMI_LOGD("enter detachMode = %d", detachMode);
    recvFun_ = fun;
    isRunning_ = true;
    isConnected_ = true;
    if (ConnectTo() < 0) {
        MMI_LOGW("Client connection failed, Try again later");
        isConnected_ = false;

        if (IsFirstConnectFailExit()) {
            MMI_LOGE("first connection faild");
            return false;
        }
    }
    t_ = std::thread(std::bind(&UDSClient::OnThread, this));
    if (detachMode) {
        MMI_LOGW("uds client thread detach");
        t_.detach();
    } else {
        MMI_LOGW("uds client thread join");
    }
    return true;
}

void UDSClient::Disconnected(int32_t fd)
{
    OnDisconnected();
    struct epoll_event event = {};
    EpollCtl(fd, EPOLL_CTL_DEL, event);
    close(fd);
    fd_ = -1;
    isConnected_ = false;
}

void UDSClient::Stop()
{
    MMI_LOGD("enter");
    Close();
    isRunning_ = false;
    struct epoll_event ev = {};
    if (fd_ >= 0) {
        EpollCtl(fd_, EPOLL_CTL_DEL, ev);
    }
    EpollClose();
    if (t_.joinable()) {
        MMI_LOGD("thread join");
        t_.join();
    }
    MMI_LOGD("leave");
}

void UDSClient::OnPacket(NetPacket& pkt)
{
    recvFun_(*this, pkt);
}

void UDSClient::OnRecvMsg(const char *buf, size_t size)
{
    CHKPV(buf);
    if (size == 0 || size > MAX_PACKET_BUF_SIZE) {
        MMI_LOGE("Invalid input param size. size:%{public}zu", size);
        return;
    }
    if (!circBuf_.Write(buf, size)) {
        MMI_LOGW("Write data faild. size:%{public}zu", size);
    }
    OnReadPackets(circBuf_, std::bind(&UDSClient::OnPacket, this, std::placeholders::_1));
}

void UDSClient::OnEvent(const struct epoll_event& ev)
{
    auto fd = ev.data.fd;
    if ((ev.events & EPOLLERR) || (ev.events & EPOLLHUP)) {
        MMI_LOGI("ev.events:0x%{public}x,fd:%{public}d same as fd_:%{public}d", ev.events, fd, fd_);
        Disconnected(fd);
        return;
    }

    char szBuff[MAX_PACKET_BUF_SIZE] = {};
    for (size_t j = 0; j < MAX_RECV_LIMIT; j++) {
        auto size = recv(fd, szBuff, MAX_PACKET_BUF_SIZE, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (size > 0) {
            OnRecvMsg(szBuff, size);
        } else if (size < 0) {
            if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK) {
                MMI_LOGD("continue for errno EAGAIN|EINTR|EWOULDBLOCK size:%{public}zu errno:%{public}d",
                    size, errno);
                continue;
            }
            MMI_LOGE("recv return %{public}zu errno:%{public}d", size, errno);
            break;
        } else {
            MMI_LOGE("The server side disconnect with the client. size:0 errno:%{public}d", errno);
            Disconnected(fd);
            break;
        }

        if (size < MAX_PACKET_BUF_SIZE) {
            break;
        }
    }
}

void UDSClient::OnThread()
{
    MMI_LOGD("begin");
    SetThreadName("uds_client");
    isThreadHadRun_ = true;
    struct epoll_event events[MAX_EVENT_SIZE] = {};
    while (isRunning_) {
        if (isConnected_) {
            auto count = EpollWait(events[0], MAX_EVENT_SIZE, DEFINE_EPOLL_TIMEOUT);
            for (auto i = 0; i < count; i++) {
                OnEvent(events[i]);
            }
        } else {
            if (ConnectTo() < 0) {
                MMI_LOGW("Client reconnection failed, Try again after %{public}d ms",
                         CLIENT_RECONNECT_COOLING_TIME);
                std::this_thread::sleep_for(std::chrono::milliseconds(CLIENT_RECONNECT_COOLING_TIME));
                continue;
            }
            isConnected_ = true;
        }

        OnThreadLoop();

        if (isToExit_) {
            isRunning_ = false;
            MMI_LOGW("Client thread exit");
            break;
        }
    }
    MMI_LOGD("end");
}

void UDSClient::SetToExit()
{
    isToExit_ = true;
}
} // namespace MMI
} // namespace OHOS