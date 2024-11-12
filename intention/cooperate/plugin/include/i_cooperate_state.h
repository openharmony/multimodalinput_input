/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef I_COOPERATE_STATE_H
#define I_COOPERATE_STATE_H

#include "cooperate_context.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace Cooperate {
class IStateMachine {
public:
    IStateMachine() = default;
    virtual ~IStateMachine() = default;

    virtual void TransiteTo(Context &context, CooperateState state) = 0;
};

class ICooperateState {
public:
    ICooperateState(IStateMachine &parent) : parent_(parent) {}
    virtual ~ICooperateState() = default;

    virtual void OnEvent(Context &context, const CooperateEvent &event) = 0;
    virtual void OnEnterState(Context &context) = 0;
    virtual void OnLeaveState(Context &context) = 0;

protected:
    class ICooperateStep {
    public:
        ICooperateStep(ICooperateState &parent, std::shared_ptr<ICooperateStep> prev);
        virtual ~ICooperateStep() = default;

        virtual void OnEvent(Context &context, const CooperateEvent &event);
        virtual void OnProgress(Context &context, const CooperateEvent &event) = 0;
        virtual void OnReset(Context &context, const CooperateEvent &event) = 0;

        void SetNext(std::shared_ptr<ICooperateStep> next);

    protected:
        void AddHandler(CooperateEventType event, std::function<void(Context&, const CooperateEvent&)> handler)
        {
            handlers_.emplace(event, handler);
        }

        void TransiteTo(Context &context, CooperateState state);
        void Switch(std::shared_ptr<ICooperateStep> step);
        void Proceed(Context &context, const CooperateEvent &event);
        void Reset(Context &context, const CooperateEvent &event);

        ICooperateState &parent_;
        std::shared_ptr<ICooperateStep> prev_ { nullptr };
        std::shared_ptr<ICooperateStep> next_ { nullptr };
        std::map<CooperateEventType, std::function<void(Context&, const CooperateEvent&)>> handlers_;
    };

    class Process final {
    public:
        Process() = default;
        ~Process() = default;

        std::string Peer() const;
        int32_t StartDeviceId() const;

        bool IsPeer(const std::string &networkId) const;

        void StartCooperate(Context &context, const StartCooperateEvent &event);
        void RemoteStart(Context &context, const DSoftbusStartCooperate &event);
        void RelayCooperate(Context &context, const DSoftbusRelayCooperate &event);

    private:
        std::string remoteNetworkId_;
        int32_t startDeviceId_ { -1 };
    };

    void TransiteTo(Context &context, CooperateState state);
    void Switch(std::shared_ptr<ICooperateStep> step);

    IStateMachine &parent_;
    std::shared_ptr<ICooperateStep> current_ { nullptr };
    Process process_;
};
} // namespace Cooperate
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // I_COOPERATE_STATE_H
