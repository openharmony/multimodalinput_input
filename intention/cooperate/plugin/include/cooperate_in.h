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

#ifndef COOPERATE_IN_H
#define COOPERATE_IN_H

#include "i_cooperate_state.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace Cooperate {
class CooperateIn final : public ICooperateState {
public:
    CooperateIn(IStateMachine &parent, IContext *env);
    ~CooperateIn();

    void OnEvent(Context &context, const CooperateEvent &event) override;
    void OnEnterState(Context &context) override;
    void OnLeaveState(Context &context) override;

private:
    class Initial final : public ICooperateStep {
    public:
        Initial(CooperateIn &parent);
        ~Initial() = default;

        void OnProgress(Context &context, const CooperateEvent &event) override;
        void OnReset(Context &context, const CooperateEvent &event) override;

        static void BuildChains(std::shared_ptr<Initial> self, CooperateIn &parent);
        static void RemoveChains(std::shared_ptr<Initial> self);

    private:
        void OnDisable(Context &context, const CooperateEvent &event);
        void OnStart(Context &context, const CooperateEvent &event);
        void OnComeBack(Context &context, const CooperateEvent &event);
        void OnRelay(Context &context, const CooperateEvent &event);
        void OnStop(Context &context, const CooperateEvent &event);
        void OnRemoteStart(Context &context, const CooperateEvent &event);
        void OnRemoteStop(Context &context, const CooperateEvent &event);
        void OnAppClosed(Context &context, const CooperateEvent &event);
        void OnPointerEvent(Context &context, const CooperateEvent &event);
        void OnBoardOffline(Context &context, const CooperateEvent &event);
        void OnSwitchChanged(Context &context, const CooperateEvent &event);
        void OnSoftbusSessionClosed(Context &context, const CooperateEvent &event);
        void OnUpdateCooperateFlag(Context &context, const CooperateEvent &event);
        void OnRemoteHotPlug(Context &context, const CooperateEvent &event);
        void OnRemoteInputDevice(Context &context, const CooperateEvent &event);

        CooperateIn &parent_;
        static std::set<int32_t> filterPointerActions_;
        std::shared_ptr<ICooperateStep> relay_ { nullptr };
    };

    class RelayConfirmation : public ICooperateStep {
    public:
        RelayConfirmation(CooperateIn &parent, std::shared_ptr<ICooperateStep> prev);
        ~RelayConfirmation() = default;

        void OnProgress(Context &context, const CooperateEvent &event) override;
        void OnReset(Context &context, const CooperateEvent &event) override;

    private:
        void OnDisable(Context &context, const CooperateEvent &event);
        void OnStop(Context &context, const CooperateEvent &event);
        void OnResponse(Context &context, const CooperateEvent &event);
        void OnNormal(Context &context, const CooperateEvent &event);
        void OnRemoteStart(Context &context, const CooperateEvent &event);
        void OnRemoteStop(Context &context, const CooperateEvent &event);
        void OnAppClosed(Context &context, const CooperateEvent &event);
        void OnPointerEvent(Context &context, const CooperateEvent &event);
        void OnBoardOffline(Context &context, const CooperateEvent &event);
        void OnSwitchChanged(Context &context, const CooperateEvent &event);
        void OnSoftbusSessionClosed(Context &context, const CooperateEvent &event);

        CooperateIn &parent_;
        int32_t timerId_ { -1 };
    };

    void StopCooperate(Context &context, const CooperateEvent &event);
    void UnchainConnections(Context &context, const StopCooperateEvent &event) const;

    IContext *env_ { nullptr };
    std::shared_ptr<Initial> initial_ { nullptr };
};
} // namespace Cooperate
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // COOPERATE_IN_H
