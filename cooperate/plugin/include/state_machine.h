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

#ifndef COOPERATE_STATE_MACHINE_H
#define COOPERATE_STATE_MACHINE_H

#include "nocopyable.h"

#include "accesstoken_kit.h"
#include "app_mgr_interface.h"
#include "application_state_observer_stub.h"
#include "iapplication_state_observer.h"

#include "i_common_event_adapter.h"
#include "i_cooperate_state.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace Cooperate {
class StateMachine final : public IStateMachine {
public:
    StateMachine(IContext *env);
    ~StateMachine() = default;
    DISALLOW_COPY_AND_MOVE(StateMachine);

    void OnEvent(Context &context, const CooperateEvent &event);

private:
    class AppStateObserver final : public AppExecFwk::ApplicationStateObserverStub {
    public:
        AppStateObserver(Channel<CooperateEvent>::Sender sender, int32_t clientPid);
        ~AppStateObserver() = default;
        void OnProcessDied(const AppExecFwk::ProcessData &processData) override;
        void UpdateClientPid(int32_t clientPid);

    private:
        Channel<CooperateEvent>::Sender sender_;
        int32_t clientPid_;
    };

private:
    void TransiteTo(Context &context, CooperateState state) override;
    void AddHandler(CooperateEventType event, std::function<void(Context&, const CooperateEvent&)> handler);
    void OnQuit(Context &context);
    void AddObserver(Context &context, const CooperateEvent &event);
    void RemoveObserver(Context &context, const CooperateEvent &event);
    void RegisterListener(Context &context, const CooperateEvent &event);
    void UnregisterListener(Context &context, const CooperateEvent &event);
    void RegisterHotAreaListener(Context &context, const CooperateEvent &event);
    void UnregisterHotAreaListener(Context &context, const CooperateEvent &event);
    void EnableCooperate(Context &context, const CooperateEvent &event);
    void DisableCooperate(Context &context, const CooperateEvent &event);
    void StartCooperate(Context &context, const CooperateEvent &event);
    void GetCooperateState(Context &context, const CooperateEvent &event);
    void RegisterEventListener(Context &context, const CooperateEvent &event);
    void UnregisterEventListener(Context &context, const CooperateEvent &event);
    void OnBoardOnline(Context &context, const CooperateEvent &event);
    void OnBoardOffline(Context &context, const CooperateEvent &event);
    void OnProfileChanged(Context &context, const CooperateEvent &event);
    void OnPointerEvent(Context &context, const CooperateEvent &event);
    void OnSoftbusSubscribeMouseLocation(Context &context, const CooperateEvent &event);
    void OnProcessClientDied(Context &context, const CooperateEvent &event);
    void OnSoftbusUnSubscribeMouseLocation(Context &context, const CooperateEvent &event);
    void OnSoftbusReplySubscribeMouseLocation(Context &context, const CooperateEvent &event);
    void OnSoftbusReplyUnSubscribeMouseLocation(Context &context, const CooperateEvent &event);
    void OnSoftbusMouseLocation(Context &context, const CooperateEvent &event);
    void OnSoftbusSessionClosed(Context &context, const CooperateEvent &event);
    void OnSoftbusSessionOpened(Context &context, const CooperateEvent &event);
    void OnHotPlugEvent(Context &context, const CooperateEvent &event);
    void OnRemoteStart(Context &context, const CooperateEvent &event);
    void OnRemoteHotPlug(Context &context, const CooperateEvent &event);
    void OnRemoteInputDevice(Context &context, const CooperateEvent &event);
    void Transfer(Context &context, const CooperateEvent &event);
    sptr<AppExecFwk::IAppMgr> GetAppMgr();
    int32_t RegisterApplicationStateObserver(Channel<CooperateEvent>::Sender sender, const EnableCooperateEvent &event);
    std::string GetPackageName(Security::AccessToken::AccessTokenID tokenId);
    void UnregisterApplicationStateObserver();
    void UpdateApplicationStateObserver(int32_t clientPid);
    void AddSessionObserver(Context &context, const EnableCooperateEvent &event);
    void RemoveSessionObserver(Context &context, const DisableCooperateEvent &event);
    void OnCommonEvent(Context &context, const std::string &commonEvent);
    void AddMonitor(Context &context);
    void RemoveMonitor(Context &context);
    void RemoveWatches(Context &context);

    IContext *env_ { nullptr };
    std::map<CooperateEventType, std::function<void(Context&, const CooperateEvent&)>> handlers_;
    size_t current_ { COOPERATE_STATE_FREE };
    std::array<std::shared_ptr<ICooperateState>, N_COOPERATE_STATES> states_;
    std::set<std::string> onlineBoards_;
    int32_t monitorId_ { -1 };
    std::vector<std::string> clientBundleNames_;
    sptr<AppStateObserver> appStateObserver_ { nullptr };
    std::shared_ptr<ICommonEventObserver> observer_ { nullptr };
};
} // namespace Cooperate
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // COOPERATE_STATE_MACHINE_H
