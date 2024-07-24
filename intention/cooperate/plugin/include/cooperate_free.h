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

#ifndef COOPERATE_FREE_H
#define COOPERATE_FREE_H

#include "nocopyable.h"

#include "i_cooperate_state.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace Cooperate {
class CooperateFree final : public ICooperateState {
public:
    CooperateFree(IStateMachine &parent, IContext *env);
    ~CooperateFree();
    DISALLOW_COPY_AND_MOVE(CooperateFree);

    void OnEvent(Context &context, const CooperateEvent &event) override;
    void OnEnterState(Context &context) override;
    void OnLeaveState(Context &context) override;
    IDeviceManager& GetDeviceManager()
    {
        return env_->GetDeviceManager();
    }

private:
    class Initial final : public ICooperateStep {
    public:
        Initial(CooperateFree &parent);
        ~Initial() = default;

        void OnProgress(Context &context, const CooperateEvent &event) override;
        void OnReset(Context &context, const CooperateEvent &event) override;

        static void BuildChains(std::shared_ptr<Initial> initial, CooperateFree &parent);
        static void RemoveChains(std::shared_ptr<Initial> initial);

    private:
        void OnStart(Context &context, const CooperateEvent &event);
        void OnStop(Context &context, const CooperateEvent &event);
        void OnAppClosed(Context &context, const CooperateEvent &event);
        void OnRemoteStart(Context &context, const CooperateEvent &event);
        void OnPointerEvent(Context &context, const CooperateEvent &event);

        CooperateFree &parent_;
    };

    void SetPointerVisible(Context &context);
    void UnchainConnections(Context &context, const StopCooperateEvent &event) const;
    void OnSetCooperatePriv(uint32_t priv);

    IContext *env_ { nullptr };
    std::shared_ptr<Initial> initial_ { nullptr };
};
} // namespace Cooperate
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // COOPERATE_FREE_H
