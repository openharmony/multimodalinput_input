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
}

int32_t UDSClient::ConnectTo()
{
    CALL_LOG_ENTER;
    if (Socket() < 0) {
        MMI_HILOGE("Socket failed");
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

    int32_t idx = 0;
    int32_t retryCount = 0;
    const int32_t bufSize = static_cast<int32_t>(size);
    int32_t remSize = bufSize;
    while (remSize > 0 && retryCount < SEND_RETRY_LIMIT) {
        retryCount += 1;
        auto count = send(fd_, &buf[idx], remSize, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (count < 0) {
            if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK) {
                MMI_HILOGW("continue for errno EAGAIN|EINTR|EWOULDBLOCK, errno:%{public}d", errno);
                usleep(SEND_RETRY_SLEEP_TIME);
                continue;
            }
            MMI_HILOGE("Send return failed,error:%{public}d fd:%{public}d", errno, fd_);
            return false;
        }
        idx += count;
        remSize -= count;
        if (remSize > 0) {
            usleep(SEND_RETRY_SLEEP_TIME);
        }
    }
    if (retryCount >= SEND_RETRY_LIMIT || remSize != 0) {
        MMI_HILOGE("Send too many times:%{public}d/%{public}d,size:%{public}d/%{public}d fd:%{public}d",
            retryCount, SEND_RETRY_LIMIT, idx, bufSize, fd_);
        return false;
    }
    return true;
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

bool UDSClient::StartClient(MsgClientFunCallback fun)
{
    CALL_LOG_ENTER;
    if (isRunning_ || isConnected_) {
        MMI_HILOGE("Client is connected or started.");
        return false;
    }
    isExit = false;
    recvFun_ = fun;
    if (ConnectTo() < 0) {
        MMI_HILOGW("Client connection failed, Try again later");
    }
    return true;
}

void UDSClient::Stop()
{
    CALL_LOG_ENTER;
    isExit = true;
    isRunning_ = false;
    Close();
}

void UDSClient::OnRecv(const char *buf, size_t size)
{
    CHKPV(buf);
    int32_t readIdx = 0;
    int32_t packSize = 0;
    int32_t bufSize = static_cast<int32_t>(size);
    constexpr int32_t headSize = static_cast<int32_t>(sizeof(PackHead));
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
        NetPacket pkt(head->idMsg);
        if (head->size > 0) {
            if (!pkt.Write(&buf[readIdx + headSize], static_cast<size_t>(head->size))) {
                MMI_HILOGE("Write to the stream failed, errCode:%{public}d", STREAM_BUF_WRITE_FAIL);
                return;
            }
        }
        recvFun_(*this, pkt);
        packSize = headSize + head->size;
        bufSize -= packSize;
        readIdx += packSize;
    }
}
} // namespace MMI
} // namespace OHOS