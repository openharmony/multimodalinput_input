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

#ifndef COOPERATE_EVENT_MANAGER_H
#define COOPERATE_EVENT_MANAGER_H

#include <list>
#include <mutex>

#include "nocopyable.h"

#include "cooperate_events.h"
#include "coordination_message.h"
#include "i_context.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace Cooperate {
class EventManager final {
public:
    enum EventType {
        LISTENER,
        ENABLE,
        START,
        STOP,
        STATE,
    };

    struct EventInfo {
        EventType type { LISTENER };
        MessageId msgId { MessageId::INVALID };
        int32_t pid { -1 };
        int32_t userData { -1 };
        std::string networkId;
        CoordinationMessage msg { CoordinationMessage::PREPARE };
        bool state { false };
    };

    struct CooperateNotice {
        int32_t pid { -1 };
        MessageId msgId { MessageId::INVALID };
        int32_t userData { -1 };
        std::string networkId;
        CoordinationMessage msg { CoordinationMessage::PREPARE };
        int32_t errCode { static_cast<int32_t>(CoordinationErrCode::COORDINATION_OK) };
    };

    struct CooperateStateNotice {
        int32_t pid { -1 };
        MessageId msgId { MessageId::INVALID };
        int32_t userData { -1 };
        bool state{ false };
        int32_t errCode { static_cast<int32_t>(CoordinationErrCode::COORDINATION_OK) };
    };

    EventManager(IContext *env);
    ~EventManager() = default;
    DISALLOW_COPY_AND_MOVE(EventManager);

    void RegisterListener(const RegisterListenerEvent &event);
    void UnregisterListener(const UnregisterListenerEvent &event);
    void EnableCooperate(const EnableCooperateEvent &event);
    void DisableCooperate(const DisableCooperateEvent &event);
    void StartCooperate(const StartCooperateEvent &event);
    void StartCooperateFinish(const DSoftbusStartCooperateFinished &event);
    void RemoteStart(const DSoftbusStartCooperate &event);
    void RemoteStartFinish(const DSoftbusStartCooperateFinished &event);
    void OnUnchain(const StopCooperateEvent &event);
    void StopCooperate(const StopCooperateEvent &event);
    void StopCooperateFinish(const DSoftbusStopCooperateFinished &event);
    void RemoteStop(const DSoftbusStopCooperate &event);
    void RemoteStopFinish(const DSoftbusStopCooperateFinished &event);
    void OnProfileChanged(const DDPCooperateSwitchChanged &event);
    void OnSoftbusSessionClosed(const DSoftbusSessionClosed &event);
    void GetCooperateState(const CooperateStateNotice &notice);
    void OnClientDied(const ClientDiedEvent &event);

private:
    void OnCooperateMessage(CoordinationMessage msg, const std::string &networkId);
    void NotifyCooperateMessage(const CooperateNotice &notice);
    void NotifyCooperateState(const CooperateStateNotice &notice);

private:
    IContext *env_ { nullptr };
    std::list<std::shared_ptr<EventInfo>> listeners_;
    std::map<EventType, std::shared_ptr<EventInfo>> calls_ {
        { EventType::ENABLE, nullptr },
        { EventType::START, nullptr },
        { EventType::STOP, nullptr },
        { EventType::STATE, nullptr }
    };
};
} // namespace Cooperate
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // COOPERATE_EVENT_MANAGER_H
