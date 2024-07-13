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

#ifndef COOPERATE_CLIENT_H
#define COOPERATE_CLIENT_H

#include <functional>
#include <list>
#include <map>
#include <mutex>
#include <set>
#ifdef ENABLE_PERFORMANCE_CHECK
#include <chrono>
#include <vector>
#endif // ENABLE_PERFORMANCE_CHECK

#include "nocopyable.h"

#include "coordination_message.h"
#include "i_coordination_listener.h"
#include "i_event_listener.h"
#include "i_hotarea_listener.h"
#include "i_tunnel_client.h"
#include "net_packet.h"
#include "socket_client.h"
#include "stream_client.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class CooperateClient final {
public:
    using CooperateMessageCallback = std::function<void(const std::string&, const CoordinationMsgInfo&)>;
    using CooperateStateCallback = std::function<void(bool)>;
    using CooperateListenerPtr = std::shared_ptr<ICoordinationListener>;
    using HotAreaListenerPtr = std::shared_ptr<IHotAreaListener>;
    using MouseLocationListenerPtr = std::shared_ptr<IEventListener>;

    struct CooperateEvent {
        CooperateEvent(CooperateMessageCallback callback) : msgCb(callback) {}
        CooperateEvent(CooperateStateCallback callback) : stateCb(callback) {}

        CooperateMessageCallback msgCb;
        CooperateStateCallback stateCb;
    };

    CooperateClient() = default;
    ~CooperateClient() = default;
    DISALLOW_COPY_AND_MOVE(CooperateClient);

    int32_t RegisterListener(ITunnelClient &tunnel,
        CooperateListenerPtr listener, bool isCheckPermission = false);
    int32_t UnregisterListener(ITunnelClient &tunnel,
        CooperateListenerPtr listener, bool isCheckPermission = false);
    int32_t Enable(ITunnelClient &tunnel,
        CooperateMessageCallback callback, bool isCheckPermission = false);
    int32_t Disable(ITunnelClient &tunnel,
        CooperateMessageCallback callback, bool isCheckPermission = false);
    int32_t Start(ITunnelClient &tunnel,
        const std::string &remoteNetworkId, int32_t startDeviceId,
        CooperateMessageCallback callback, bool isCheckPermission = false);
    int32_t Stop(ITunnelClient &tunnel,
        bool isUnchained, CooperateMessageCallback callback,
        bool isCheckPermission = false);
    int32_t GetCooperateState(ITunnelClient &tunnel,
        const std::string &networkId, CooperateStateCallback callback,
        bool isCheckPermission = false);
    int32_t GetCooperateState(ITunnelClient &tunnel, const std::string &udId, bool &state);
    int32_t RegisterEventListener(ITunnelClient &tunnel, const std::string &networkId,
        MouseLocationListenerPtr listener);
    int32_t UnregisterEventListener(ITunnelClient &tunnel, const std::string &networkId,
        MouseLocationListenerPtr listener = nullptr);
    int32_t AddHotAreaListener(ITunnelClient &tunnel, HotAreaListenerPtr listener);
    int32_t RemoveHotAreaListener(ITunnelClient &tunnel, HotAreaListenerPtr listener = nullptr);

    int32_t OnCoordinationListener(const StreamClient &client, NetPacket &pkt);
    int32_t OnCoordinationMessage(const StreamClient &client, NetPacket &pkt);
    int32_t OnCoordinationState(const StreamClient &client, NetPacket &pkt);
    int32_t OnHotAreaListener(const StreamClient &client, NetPacket &pkt);
    int32_t OnMouseLocationListener(const StreamClient &client, NetPacket &pkt);

private:
    int32_t GenerateRequestID();
    void OnDevCooperateListener(const std::string &networkId, CoordinationMessage msg);
    void OnCooperateMessageEvent(int32_t userData, const std::string &networkId, const CoordinationMsgInfo &msgInfo);
    void OnCooperateStateEvent(int32_t userData, bool state);
    void OnDevHotAreaListener(int32_t displayX, int32_t displayY, HotAreaType type, bool isEdge);
    void OnDevMouseLocationListener(const std::string &networkId, const Event &event);
#ifdef ENABLE_PERFORMANCE_CHECK
    void StartTrace(int32_t userData);
    void FinishTrace(int32_t userData, CoordinationMessage msg);
    int32_t GetFirstSuccessIndex();
    void DumpPerformanceInfo();
#endif // ENABLE_PERFORMANCE_CHECK

    std::list<CooperateListenerPtr> devCooperateListener_;
    std::map<std::string, std::set<MouseLocationListenerPtr>> eventListener_;
    std::list<HotAreaListenerPtr> devHotAreaListener_;
    std::map<int32_t, CooperateEvent> devCooperateEvent_;
    mutable std::mutex mtx_;
    std::atomic_bool isListeningProcess_ { false };

#ifdef ENABLE_PERFORMANCE_CHECK
    struct PerformanceInfo {
        std::map<int32_t, std::chrono::time_point<std::chrono::steady_clock>> traces_;
        int32_t activateNum { 0 };
        int32_t successNum { -1 };
        int32_t failNum { -1 };
        float successRate { 0.0f };
        int32_t averageDuration { -1 };
        int32_t failBeforeSuccess { -1 };
        int32_t firstSuccessDuration { -1 };
        int32_t maxDuration { std::numeric_limits<int32_t>::min() };
        int32_t minDuration { std::numeric_limits<int32_t>::max() };
        std::vector<int32_t> durationList;
    };
    std::mutex performanceLock_;
    PerformanceInfo performanceInfo_;
#endif // ENABLE_PERFORMANCE_CHECK
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // COOPERATE_CLIENT_H
