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
    if (Socket() < 0) {
        MMI_LOGE("Socket failed");
        return RET_ERR;
    }
    if (epollFd_ < 0) {
        if (EpollCreat(MAX_EVENT_SIZE) < 0) {
            MMI_LOGE("Epoll creat failed");
            return RET_ERR;
        }
    }
    SetNonBlockMode(fd_);

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = fd_;
    if (EpollCtl(fd_, EPOLL_CTL_ADD, ev) < 0) {
        MMI_LOGE("EpollCtl failed");
        return RET_ERR;
    }
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
    ssize_t ret = write(fd_, static_cast<const void *>(buf), size);
    if (ret < 0) {
        MMI_LOGE("SendMsg write errCode:%{public}d,return %{public}zd", MSG_SEND_FAIL, ret);
        return false;
    }
    return true;
}

bool UDSClient::SendMsg(const NetPacket& pkt) const
{
    if (pkt.ChkRWError()) {
        MMI_LOGE("Read and write status is error");
        return false;
    }
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

void UDSClient::OnRecv(const char *buf, size_t size)
{
    CHKPV(buf);
    int32_t readIdx = 0;
    int32_t packSize = 0;
    int32_t bufSize = static_cast<int32_t>(size);
    const int32_t headSize = static_cast<int32_t>(sizeof(PackHead));
    if (bufSize < headSize) {
        MMI_LOGE("The in parameter size is error, errCode:%{public}d", VAL_NOT_EXP);
        return;
    }
    while (bufSize > 0 && recvFun_) {
        if (bufSize < headSize) {
            MMI_LOGE("The size is less than headSize, errCode:%{public}d", VAL_NOT_EXP);
            return;
        }
        auto head = reinterpret_cast<PackHead *>(const_cast<char *>(&buf[readIdx]));
        if (head->size[0] < 0 || head->size[0] >= bufSize) {
            MMI_LOGE("Head size[0] is error, head->size[0]:%{public}d, errCode:%{public}d", head->size[0], VAL_NOT_EXP);
            return;
        }
        packSize = headSize + head->size[0];

        NetPacket pkt(head->idMsg);
        if (head->size[0] > 0) {
            if (!pkt.Write(&buf[readIdx + headSize], static_cast<size_t>(head->size[0]))) {
                MMI_LOGE("Write to the stream failed, errCode:%{public}d", STREAM_BUF_WRITE_FAIL);
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
        MMI_LOGI("ev.events:0x%{public}x,fd:%{public}d same as fd_:%{public}d", ev.events, fd, fd_);
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
        MMI_LOGE("The maxCount is error, maxCount:%{public}d, errCode:%{public}d", maxCount, VAL_NOT_EXP);
    }
    auto isoverflow = false;
    for (size_t j = 0; j < maxCount; j++) {
        auto size = read(fd, static_cast<void *>(szBuf), MAX_PACKET_BUF_SIZE);
        if (size < 0) {
            MMI_LOGE("size:%{public}zu", size);
        }
        if (size > 0) {
            if (!buf.Write(szBuf, size)) {
                isoverflow = true;
                break;
            }
        }
        if (size < MAX_PACKET_BUF_SIZE) {
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
    MMI_LOGD("begin");
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