/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef DSOFTBUS_ADAPTER_IMPL_H
#define DSOFTBUS_ADAPTER_IMPL_H

#include <map>
#include <set>

#include "nocopyable.h"
#include "socket.h"

#include "circle_stream_buffer.h"
#include "i_dsoftbus_adapter.h"
#include "net_packet.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class DSoftbusAdapterImpl final : public IDSoftbusAdapter {
    class Observer final {
    public:
        explicit Observer(std::shared_ptr<IDSoftbusObserver> observer)
            : observer_(observer) {}

        Observer() = default;
        ~Observer() = default;
        DISALLOW_COPY_AND_MOVE(Observer);

        std::shared_ptr<IDSoftbusObserver> Lock() const noexcept
        {
            return observer_.lock();
        }

        bool operator<(const Observer &other) const noexcept
        {
            return (observer_.lock() < other.observer_.lock());
        }

    private:
        std::weak_ptr<IDSoftbusObserver> observer_;
    };

    struct Session {
        Session(int32_t socket) : socket_(socket) {}
        Session(const Session &other) : socket_(other.socket_) {}
        DISALLOW_MOVE(Session);

        Session& operator=(const Session &other) = delete;

        int32_t socket_;
        CircleStreamBuffer buffer_;
    };

public:
    DSoftbusAdapterImpl() = default;
    ~DSoftbusAdapterImpl();
    DISALLOW_COPY_AND_MOVE(DSoftbusAdapterImpl);

    int32_t Enable() override;
    void Disable() override;

    void AddObserver(std::shared_ptr<IDSoftbusObserver> observer) override;
    void RemoveObserver(std::shared_ptr<IDSoftbusObserver> observer) override;

    int32_t OpenSession(const std::string &networkId) override;
    void CloseSession(const std::string &networkId) override;
    void CloseAllSessions() override;

    int32_t SendPacket(const std::string &networkId, NetPacket &packet) override;
    int32_t SendParcel(const std::string &networkId, Parcel &parcel) override;
    int32_t BroadcastPacket(NetPacket &packet) override;

    void OnBind(int32_t socket, PeerSocketInfo info);
    void OnShutdown(int32_t socket, ShutdownReason reason);
    void OnBytes(int32_t socket, const void *data, uint32_t dataLen);

    static std::shared_ptr<DSoftbusAdapterImpl> GetInstance();
    static void DestroyInstance();

private:
    int32_t InitSocket(SocketInfo info, int32_t socketType, int32_t &socket);
    int32_t SetupServer();
    void ShutdownServer();
    int32_t OpenSessionLocked(const std::string &networkId);
    void CloseAllSessionsLocked();
    void OnConnectedLocked(const std::string &networkId);
    void ConfigTcpAlive(int32_t socket);
    int32_t FindConnection(const std::string &networkId);
    void HandleSessionData(const std::string &networkId, CircleStreamBuffer &circleBuffer);
    void HandlePacket(const std::string &networkId, NetPacket &packet);
    void HandleRawData(const std::string &networkId, const void *data, uint32_t dataLen);
    bool CheckDeviceOnline(const std::string &networkId);

    std::recursive_mutex lock_;
    int32_t socketFd_ { -1 };
    std::string localSessionName_;
    std::set<Observer> observers_;
    std::map<std::string, Session> sessions_;

    static std::mutex mutex_;
    static std::shared_ptr<DSoftbusAdapterImpl> instance_;
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // DSOFTBUS_ADAPTER_IMPL_H
