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

#include "socket_session.h"

#include <sstream>

#include <sys/socket.h>
#include <unistd.h>

#include "proto.h"

#undef LOG_TAG
#define LOG_TAG "SocketSession"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

SocketSession::SocketSession(const std::string &programName, int32_t moduleType,
                             int32_t tokenType, int32_t fd, int32_t uid, int32_t pid)
    : fd_(fd), uid_(uid), pid_(pid), tokenType_(tokenType), programName_(programName)
{}

SocketSession::~SocketSession()
{
    if ((fd_ >= 0) && (::close(fd_) != 0)) {
        FI_HILOGE("close(%{public}d) failed:%{public}s", fd_, ::strerror(errno));
    }
}

bool SocketSession::SendMsg(NetPacket &pkt) const
{
    if (pkt.ChkRWError()) {
        FI_HILOGE("Read and write status is error");
        return false;
    }
    StreamBuffer buf;
    if (!pkt.MakeData(buf)) {
        FI_HILOGE("Failed to buffer packet");
        return false;
    }
    return SendMsg(buf.Data(), buf.Size());
}

bool SocketSession::SendMsg(const char *buf, size_t size) const
{
    CALL_INFO_TRACE;
    CHKPF(buf);
    if ((size == 0) || (size > MAX_PACKET_BUF_SIZE)) {
        FI_HILOGE("buf size:%{public}zu", size);
        return false;
    }
    if (fd_ < 0) {
        FI_HILOGE("The fd_ is less than 0");
        return false;
    }

    int32_t idx = 0;
    int32_t retryCount = 0;
    const int32_t bufSize = static_cast<int32_t>(size);
    int32_t remSize = bufSize;
    FI_HILOGI("Rem size:%{public}d", remSize);
    while (remSize > 0 && retryCount < SEND_RETRY_LIMIT) {
        retryCount += 1;
        FI_HILOGD("Send message to client (%{public}d, %{public}d)", fd_, pid_);
        ssize_t count = send(fd_, &buf[idx], remSize, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (count < 0) {
            if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK) {
                usleep(SEND_RETRY_SLEEP_TIME);
                FI_HILOGW("Continue for errno EAGAIN|EINTR|EWOULDBLOCK, errno:%{public}d, pid:%{public}d", errno, pid_);
                continue;
            }
            FI_HILOGE("Send return failed, error:%{public}d, fd:%{public}d, pid:%{public}d", errno, fd_, pid_);
            return false;
        }
        idx += count;
        remSize -= count;
        if (remSize > 0) {
            usleep(SEND_RETRY_SLEEP_TIME);
        }
    }
    if (retryCount >= SEND_RETRY_LIMIT || remSize != 0) {
        FI_HILOGE("Send too many times:%{public}d/%{public}d, size:%{public}d/%{public}d, fd:%{public}d,"
            "pid:%{public}d", retryCount, SEND_RETRY_LIMIT, idx, bufSize, fd_, pid_);
        return false;
    }
    return true;
}

std::string SocketSession::ToString() const
{
    std::ostringstream oss;
    oss << "fd = " << fd_
        << ((fd_ < 0) ? ", closed" : ", opened")
        << ", pid = " << pid_
        << ", tokenType = " << tokenType_
        << std::endl;
    return oss.str();
}

void SocketSession::Dispatch(const struct epoll_event &ev)
{
    if ((ev.events & EPOLLIN) == EPOLLIN) {
        FI_HILOGD("Data received (%{public}d)", fd_);
    } else if ((ev.events & (EPOLLHUP | EPOLLERR)) != 0) {
        FI_HILOGE("Epoll hangup:%{public}s", ::strerror(errno));
    }
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS