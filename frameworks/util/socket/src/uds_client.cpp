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
    static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "UDSClient" };
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
    SetBlockMode(fd_); // 设置非阻塞模式

    epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = fd_;
    CHKR(EpollCtl(fd_, EPOLL_CTL_ADD, ev) >= 0, EPOLL_CREATE_FAIL, RET_ERR);
    OnConnected();
    return RET_OK;
}

bool UDSClient::SendMsg(const char *buf, size_t size) const
{
    CHKPF(buf);
    CHKF(size > 0 && size <= MAX_PACKET_BUF_SIZE, PARAM_INPUT_INVALID);
    CHKF(fd_ >= 0, PARAM_INPUT_INVALID);
    ssize_t ret = write(fd_, static_cast<const void *>(buf), size);
    if (ret < 0) {
        MMI_LOGE("SendMsg write errCode:%{public}d,return %{public}zd", MSG_SEND_FAIL, ret);
        return false;
    }
    return true;
}

bool UDSClient::SendMsg(const NetPacket& pkt) const
{
    CHKF(!pkt.ChkError(), PACKET_WRITE_FAIL);
    StreamBuffer buf;
    pkt.MakeData(buf);
    return SendMsg(buf.Data(), buf.Size());
}

bool UDSClient::ThreadIsEnd()
{
    if (!isThreadHadRun_) {
        MMI_LOGI("thread is not run. this: %p, isThreadHadRun_: %p, isThreadHadRun_: %d",
                 this, &isThreadHadRun_, isThreadHadRun_);
        return false;
    }

    const bool ret = threadFutureHadEnd_.get();
    MMI_LOGI("thread is end, ret = %d.", ret);
    return true;
}

bool UDSClient::StartClient(MsgClientFunCallback fun, bool detachMode)
{
    MMI_LOGT("enter detachMode = %d", detachMode);
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
    t_ = std::thread(std::bind(&UDSClient::OnThread, this, std::ref(threadPromiseHadEnd_)));
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
    epoll_event ev = {};
    if (fd_ >= 0) {
        EpollCtl(fd_, EPOLL_CTL_DEL, ev);
    }
    EpollClose();
    if (t_.joinable()) {
        MMI_LOGT("thread join");
        t_.join();
    }
    MMI_LOGD("leave");
}

void UDSClient::OnRecv(const char *buf, size_t size)
{
    CHKPV(buf);
    int32_t readIdx = 0;
    int32_t packSize = 0;
    const size_t headSize = sizeof(PackHead);
    CHK(size >= headSize, VAL_NOT_EXP);
    while (size > 0 && recvFun_) {
        CHK(size >= headSize, VAL_NOT_EXP);
        auto head = reinterpret_cast<PackHead *>(const_cast<char *>(&buf[readIdx]));
        CHK(head->size[0] >= 0 && head->size[0] < static_cast<int32_t>(size), VAL_NOT_EXP);
        packSize = headSize + head->size[0];

        NetPacket pkt(head->idMsg);
        if (head->size[0] > 0) {
            CHK(pkt.Write(&buf[readIdx + headSize], head->size[0]), STREAM_BUF_WRITE_FAIL);
        }
        recvFun_(*this, pkt);
        size -= packSize;
        readIdx += packSize;
    }
}

void UDSClient::OnEvent(const epoll_event& ev, StreamBuffer& buf)
{
    auto fd = ev.data.fd;
    if ((ev.events & EPOLLERR) || (ev.events & EPOLLHUP)) {
        MMI_LOGI("ev.events:0x%{public}x,fd:%{public}d same as fd_:%{public}d", ev.events, fd, fd_);
        OnDisconnected();
        epoll_event event = {};
        EpollCtl(fd, EPOLL_CTL_DEL, event);
        close(fd);
        fd_ = -1;
        isConnected_ = false;
        return;
    }

    char szBuf[MAX_PACKET_BUF_SIZE] = {};
    const size_t maxCount = MAX_STREAM_BUF_SIZE / MAX_PACKET_BUF_SIZE + 1;
    CHK(maxCount > 0, VAL_NOT_EXP);
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

void UDSClient::OnThread(std::promise<bool>& threadPromise)
{
    MMI_LOGD("begin");
    SetThreadName("uds_client");
    isThreadHadRun_ = true;
    StreamBuffer streamBuf;
    epoll_event events[MAX_EVENT_SIZE] = {};

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
    threadPromise.set_value(true);
    MMI_LOGD("end");
}

void UDSClient::SetToExit()
{
    isToExit_ = true;
}
} // namespace MMI
} // namespace OHOS