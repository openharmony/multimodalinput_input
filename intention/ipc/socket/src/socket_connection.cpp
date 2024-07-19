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

#include "socket_connection.h"

#include <sys/socket.h>
#include <unistd.h>

#include "devicestatus_define.h"
#include "include/util.h"

#undef LOG_TAG
#define LOG_TAG "SocketConnection"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

SocketConnection::SocketConnection(int32_t socketFd,
                                   std::function<void(NetPacket&)> recv,
                                   std::function<void()> onDisconnected)
    : socketFd_(socketFd), recv_(recv), onDisconnected_(onDisconnected)
{}

SocketConnection::~SocketConnection()
{
    if ((socketFd_ >= 0) && (::close(socketFd_) != 0)) {
        FI_HILOGE("close(%{public}d) failed:%{public}s", socketFd_, ::strerror(errno));
    }
}

std::shared_ptr<SocketConnection> SocketConnection::Connect(std::function<int32_t()> socket,
    std::function<void(NetPacket&)> recv, std::function<void()> onDisconnected)
{
    CALL_DEBUG_ENTER;
    CHKPP(socket);
    int32_t sockFd = socket();
    if (sockFd < 0) {
        return nullptr;
    }
    return std::make_shared<SocketConnection>(sockFd, recv, onDisconnected);
}

void SocketConnection::OnReadable(int32_t fd)
{
    CALL_DEBUG_ENTER;
    char buf[MAX_PACKET_BUF_SIZE] {};
    ssize_t numRead;

    do {
        numRead = ::recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (numRead > 0) {
            buffer_.Write(buf, numRead);
            OnReadPackets(buffer_, recv_);
        } else if (numRead < 0) {
            if (errno == EINTR) {
                FI_HILOGD("recv was interrupted, read again");
                continue;
            }
            if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
                FI_HILOGW("No available data");
            } else {
                FI_HILOGE("recv failed:%{public}s", ::strerror(errno));
            }
            break;
        } else {
            FI_HILOGE("EOF happened");
            OnShutdown(fd);
            break;
        }
    } while (numRead == sizeof(buf));
}

void SocketConnection::OnShutdown(int32_t fd)
{
    if (onDisconnected_) {
        onDisconnected_();
    }
}

void SocketConnection::OnException(int32_t fd)
{
    OnShutdown(fd);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS