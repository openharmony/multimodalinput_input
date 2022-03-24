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
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "UDSClient" };
} // namespace

UDSClient::UDSClient()
{
    CALL_LOG_ENTER;
}

UDSClient::~UDSClient()
{
    CALL_LOG_ENTER;
    Stop();
}

int32_t UDSClient::ConnectTo()
{
    if (Socket() < 0) {
        MMI_HILOGE("Socket failed");
        return RET_ERR;
    }
    if (epollFd_ < 0) {
        if (EpollCreat(MAX_EVENT_SIZE) < 0) {
            MMI_HILOGE("Epoll creat failed");
            return RET_ERR;
        }
    }
    SetNonBlockMode(fd_);

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = fd_;
    if (EpollCtl(fd_, EPOLL_CTL_ADD, ev) < 0) {
        MMI_HILOGE("EpollCtl failed");
        return RET_ERR;
    }
    OnConnected();
    return RET_OK;
}

bool UDSClient::SendMsg(const char *buf, size_t size) const
{
    CHKPF(buf);
    if ((size == 0) || (size > MAX_PACKET_BUF_SIZE)) {
        MMI_HILOGE("Stream buffer size out of range");
        return false;
    }
    if (fd_ < 0) {
        MMI_HILOGE("fd_ is less than 0");
        return false;
    }

    int32_t retryTimes = 32;
    while (size > 0 && retryTimes > 0) {
        retryTimes--;
        auto count = send(fd_, buf, size, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (count < 0) {
            if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK) {
                MMI_HILOGW("send msg failed, errno:%{public}d", errno);
                continue;
            }
            MMI_HILOGE("Send return failed,error:%{public}d fd:%{public}d", errno, fd_);
            return false;
        }

        size_t ucount = static_cast<size_t>(count);
        if (ucount >= size) {
            return true;
        }
        size -= ucount;
        buf += ucount;
        int32_t sleepTime = 10000;
        usleep(sleepTime);
    }
    MMI_HILOGE("send msg failed");
    return false;
}

bool UDSClient::SendMsg(const NetPacket& pkt) const
{
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Read and write status is error");
        return false;
    }
    StreamBuffer buf;
    pkt.MakeData(buf);
    return SendMsg(buf.Data(), buf.Size());
}

bool UDSClient::StartClient(MsgClientFunCallback fun, bool detachMode)
{
    CALL_LOG_ENTER;
    recvFun_ = fun;
    isRunning_ = true;
    isConnected_ = true;
    if (ConnectTo() < 0) {
        MMI_HILOGW("Client connection failed, Try again later");
        isConnected_ = false;

        if (IsFirstConnectFailExit()) {
            MMI_HILOGE("first connection faild");
            return false;
        }
    }
    t_ = std::thread(std::bind(&UDSClient::OnThread, this));
    if (detachMode) {
        MMI_HILOGW("uds client thread detach");
        t_.detach();
    } else {
        MMI_HILOGW("uds client thread join");
    }
    return true;
}

void UDSClient::Stop()
{
    CALL_LOG_ENTER;
    Close();
    isRunning_ = false;
    struct epoll_event ev = {};
    if (fd_ >= 0) {
        EpollCtl(fd_, EPOLL_CTL_DEL, ev);
    }
    EpollClose();
    if (t_.joinable()) {
        MMI_HILOGD("thread join");
        t_.join();
    }
}

void UDSClient::OnRecv(const char *buf, size_t size)
{
    CHKPV(buf);
    int32_t readIdx = 0;
    int32_t packSize = 0;
    int32_t bufSize = static_cast<int32_t>(size);
    const int32_t headSize = static_cast<int32_t>(sizeof(PackHead));
    if (bufSize < headSize) {
        MMI_HILOGE("The in parameter size is error, errCode:%{public}d", VAL_NOT_EXP);
        return;
    }
    while (bufSize > 0 && recvFun_) {
        if (bufSize < headSize) {
            MMI_HILOGE("The size is less than headSize, errCode:%{public}d", VAL_NOT_EXP);
            return;
        }
        auto head = reinterpret_cast<PackHead *>(const_cast<char *>(&buf[readIdx]));
        if (head->size < 0 || head->size >= bufSize) {
            MMI_HILOGE("Head size is error, head->size:%{public}d, errCode:%{public}d", head->size, VAL_NOT_EXP);
            return;
        }
        packSize = headSize + head->size;

        NetPacket pkt(head->idMsg);
        if (head->size > 0) {
            if (!pkt.Write(&buf[readIdx + headSize], static_cast<size_t>(head->size))) {
                MMI_HILOGE("Write to the stream failed, errCode:%{public}d", STREAM_BUF_WRITE_FAIL);
                return;
            }
        }
        recvFun_(*this, pkt);
        bufSize -= packSize;
        readIdx += packSize;
    }
}

void UDSClient::OnEvent(const struct epoll_event& ev, StreamBuffer& buf)
{
    auto fd = ev.data.fd;
    if ((ev.events & EPOLLERR) || (ev.events & EPOLLHUP)) {
        MMI_HILOGI("ev.events:0x%{public}x,fd:%{public}d same as fd_:%{public}d", ev.events, fd, fd_);
        OnDisconnected();
        struct epoll_event event = {};
        EpollCtl(fd, EPOLL_CTL_DEL, event);
        close(fd);
        fd_ = -1;
        isConnected_ = false;
        return;
    }

    char szBuf[MAX_PACKET_BUF_SIZE] = {};
    const size_t maxCount = MAX_STREAM_BUF_SIZE / MAX_PACKET_BUF_SIZE + 1;
    if (maxCount <= 0) {
        MMI_HILOGE("The maxCount is error, maxCount:%{public}zu, errCode:%{public}d", maxCount, VAL_NOT_EXP);
    }
    auto isoverflow = false;
    for (size_t j = 0; j < maxCount; j++) {
        auto size = read(fd, static_cast<void *>(szBuf), MAX_PACKET_BUF_SIZE);
        if (size < 0) {
            MMI_HILOGE("size:%{public}zu", size);
            return;
        }
        if (size > 0) {
            if (!buf.Write(szBuf, size)) {
                isoverflow = true;
                MMI_HILOGW("size:%{public}zu", size);
                break;
            }
        }
        if (size < MAX_PACKET_BUF_SIZE) {
            MMI_HILOGW("size:%{public}zu", size);
            break;
        }
        if (isoverflow) {
            break;
        }
    }
    if (!isoverflow && buf.Size() > 0) {
        OnRecv(buf.Data(), buf.Size());
    }
}

void UDSClient::OnThread()
{
    CALL_LOG_ENTER;
    SetThreadName("uds_client");
    isThreadHadRun_ = true;
    StreamBuffer streamBuf;
    struct epoll_event events[MAX_EVENT_SIZE] = {};

    while (isRunning_) {
        if (isConnected_) {
            streamBuf.Clean();
            auto count = EpollWait(*events, MAX_EVENT_SIZE, DEFINE_EPOLL_TIMEOUT);
            for (auto i = 0; i < count; i++) {
                OnEvent(events[i], streamBuf);
            }
        } else {
            if (ConnectTo() < 0) {
                MMI_HILOGW("Client reconnection failed, Try again after %{public}d ms",
                           CLIENT_RECONNECT_COOLING_TIME);
                std::this_thread::sleep_for(std::chrono::milliseconds(CLIENT_RECONNECT_COOLING_TIME));
                continue;
            }
            isConnected_ = true;
        }

        OnThreadLoop();

        if (isToExit_) {
            isRunning_ = false;
            MMI_HILOGW("Client thread exit");
            break;
        }
    }
}

void UDSClient::SetToExit()
{
    isToExit_ = true;
}
} // namespace MMI
} // namespace OHOS