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

#ifndef SOCKET_CONNECTION_H
#define SOCKET_CONNECTION_H

#include <functional>
#include <memory>

#include "file_descriptor_listener.h"
#include "nocopyable.h"

#include "circle_stream_buffer.h"
#include "net_packet.h"
#include "stream_socket.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class SocketConnection final : public AppExecFwk::FileDescriptorListener, StreamSocket {
public:
    SocketConnection(int32_t socketFd,
                     std::function<void(NetPacket&)> recv,
                     std::function<void()> onDisconnected);
    ~SocketConnection();
    DISALLOW_COPY_AND_MOVE(SocketConnection);

    int32_t GetFd() const;

    void OnReadable(int32_t fd) override;
    void OnShutdown(int32_t fd) override;
    void OnException(int32_t fd) override;

    static std::shared_ptr<SocketConnection> Connect(std::function<int32_t()> socket,
        std::function<void(NetPacket&)> recv, std::function<void()> onDisconnected);

private:
    int32_t socketFd_ { -1 };
    std::function<void(NetPacket&)> recv_;
    std::function<void()> onDisconnected_;
    CircleStreamBuffer buffer_;
};

inline int32_t SocketConnection::GetFd() const
{
    return socketFd_;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // SOCKET_CONNECTION_H