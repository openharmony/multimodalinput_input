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
}

UDSClient::~UDSClient()
{
}

int32_t UDSClient::ConnectTo()
{
    if (Socket() < 0) {
        MMI_LOGE("Socket failed");
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
    ssize_t ret = send(fd_, buf, size, SOCKET_FLAGS);
    if (ret < 0) {
        MMI_LOGE("SendMsg write errCode:%{public}d,return %{public}zd,errno:%{public}d",
            MSG_SEND_FAIL, ret, errno);
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
    if (ConnectTo() < 0) {
        MMI_LOGW("Client connection failed, Try again later");
    }
    return true;
}

void UDSClient::Stop()
{
    MMI_LOGD("enter");
    Close();
    isRunning_ = false;
    isToExit_ = true;
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
        NetPacket pkt(head->idMsg);
        if (head->size[0] > 0) {
            if (!pkt.Write(&buf[readIdx + headSize], static_cast<size_t>(head->size[0]))) {
                MMI_LOGE("Write to the stream failed, errCode:%{public}d", STREAM_BUF_WRITE_FAIL);
                return;
            }
        }
        recvFun_(*this, pkt);
        packSize = headSize + head->size[0];
        bufSize -= packSize;
        readIdx += packSize;
    }
}

void UDSClient::SetToExit()
{
    isToExit_ = true;
}
} // namespace MMI
} // namespace OHOS