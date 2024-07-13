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

#ifndef DSOFTBUS_HANDLER_H
#define DSOFTBUS_HANDLER_H

#include "nocopyable.h"

#include "channel.h"
#include "cooperate_events.h"
#include "i_context.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace Cooperate {
class DSoftbusHandler final {
    class DSoftbusObserver final : public IDSoftbusObserver {
    public:
        DSoftbusObserver(DSoftbusHandler &parent) : parent_(parent) {}
        ~DSoftbusObserver() = default;

        void OnBind(const std::string &networkId) override
        {
            parent_.OnBind(networkId);
        }

        void OnShutdown(const std::string &networkId) override
        {
            parent_.OnShutdown(networkId);
        }

        void OnConnected(const std::string &networkId) override
        {
            parent_.OnConnected(networkId);
        }

        bool OnPacket(const std::string &networkId, NetPacket &packet) override
        {
            return parent_.OnPacket(networkId, packet);
        }

        bool OnRawData(const std::string &networkId, const void *data, uint32_t dataLen) override
        {
            return false;
        }

    private:
        DSoftbusHandler &parent_;
    };

public:
    DSoftbusHandler(IContext *env);
    ~DSoftbusHandler();
    DISALLOW_COPY_AND_MOVE(DSoftbusHandler);

    void AttachSender(Channel<CooperateEvent>::Sender sender);
    int32_t OpenSession(const std::string &networkId);
    void CloseSession(const std::string &networkId);
    void CloseAllSessions();

    int32_t StartCooperate(const std::string &networkId, const DSoftbusStartCooperate &event);
    int32_t StopCooperate(const std::string &networkId, const DSoftbusStopCooperate &event);
    int32_t ComeBack(const std::string &networkId, const DSoftbusComeBack &event);
    int32_t RelayCooperate(const std::string &networkId, const DSoftbusRelayCooperate &event);
    int32_t RelayCooperateFinish(const std::string &networkId, const DSoftbusRelayCooperateFinished &event);
    static std::string GetLocalNetworkId();

private:
    void OnBind(const std::string &networkId);
    void OnShutdown(const std::string &networkId);
    void OnConnected(const std::string &networkId);
    bool OnPacket(const std::string &networkId, NetPacket &packet);
    void SendEvent(const CooperateEvent &event);
    void OnCommunicationFailure(const std::string &networkId);
    void OnStartCooperate(const std::string &networkId, NetPacket &packet);
    void OnStopCooperate(const std::string &networkId, NetPacket &packet);
    void OnComeBack(const std::string &networkId, NetPacket &packet);
    void OnRelayCooperate(const std::string &networkId, NetPacket &packet);
    void OnRelayCooperateFinish(const std::string &networkId, NetPacket &packet);
    void OnSubscribeMouseLocation(const std::string& networKId, NetPacket &packet);
    void OnUnSubscribeMouseLocation(const std::string& networKId, NetPacket &packet);
    void OnReplySubscribeLocation(const std::string& networKId, NetPacket &packet);
    void OnReplyUnSubscribeLocation(const std::string& networKId, NetPacket &packet);
    void OnRemoteMouseLocation(const std::string& networKId, NetPacket &packet);
    void OnRemoteInputDevice(const std::string& networKId, NetPacket &packet);
    void OnRemoteHotPlug(const std::string& networKId, NetPacket &packet);
    int32_t DeserializeDevice(std::shared_ptr<IDevice> device, NetPacket &packet);

    IContext *env_ { nullptr };
    std::mutex lock_;
    Channel<CooperateEvent>::Sender sender_;
    std::shared_ptr<DSoftbusObserver> observer_;
    std::map<int32_t, std::function<void(const std::string &networkId, NetPacket &packet)>> handles_;
};
} // namespace Cooperate
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // DSOFTBUS_HANDLER_H
