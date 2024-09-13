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

#include "cooperate_free.h"

#include "devicestatus_define.h"
#include "utility.h"

#undef LOG_TAG
#define LOG_TAG "CooperateFree"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace Cooperate {

namespace {
const std::string FINGER_PRINT { "hw_fingerprint_mouse" };
}

CooperateFree::CooperateFree(IStateMachine &parent, IContext *env)
    : ICooperateState(parent), env_(env)
{
    initial_ = std::make_shared<Initial>(*this);
    Initial::BuildChains(initial_, *this);
    current_ = initial_;
}

CooperateFree::~CooperateFree()
{
    Initial::RemoveChains(initial_);
}

void CooperateFree::OnEvent(Context &context, const CooperateEvent &event)
{
    current_->OnEvent(context, event);
}

void CooperateFree::OnEnterState(Context &context)
{
    CALL_INFO_TRACE;
    bool hasLocalPointerDevice =  HasLocalPointerDevice();
    FI_HILOGI("HasLocalPointerDevice:%{public}s", hasLocalPointerDevice ? "true" : "false");
    bool visible = !context.NeedHideCursor() && hasLocalPointerDevice;
    env_->GetInput().SetPointerVisibility(visible, 1);
}

void CooperateFree::OnLeaveState(Context &context)
{
    CALL_INFO_TRACE;
    UpdateCooperateFlagEvent event {
        .mask = COOPERATE_FLAG_HIDE_CURSOR,
    };
    context.UpdateCooperateFlag(event);
}

bool CooperateFree::HasLocalPointerDevice() const
{
    return env_->GetDeviceManager().AnyOf([this](std::shared_ptr<IDevice> dev) {
        if ((dev == nullptr) || (dev->GetName() == FINGER_PRINT)) {
            return false;
        }
        return (dev->IsPointerDevice() && !dev->IsRemote());
    });
}

bool CooperateFree::HasLocalKeyboardDevice() const
{
    return env_->GetDeviceManager().AnyOf([this](std::shared_ptr<IDevice> dev) {
        CHKPR(dev, false);
        return (dev->IsKeyboard() && !dev->IsRemote());
    });
}

void CooperateFree::UnchainConnections(Context &context, const StopCooperateEvent &event) const
{
    CALL_INFO_TRACE;
    if (event.isUnchained) {
        FI_HILOGI("Unchain all connections");
        context.dsoftbus_.CloseAllSessions();
        context.eventMgr_.OnUnchain(event);
    }
}

CooperateFree::Initial::Initial(CooperateFree &parent)
    : ICooperateStep(parent, nullptr), parent_(parent)
{
    AddHandler(CooperateEventType::START, [this](Context &context, const CooperateEvent &event) {
        this->OnStart(context, event);
    });
    AddHandler(CooperateEventType::STOP, [this](Context &context, const CooperateEvent &event) {
        this->OnStop(context, event);
    });
    AddHandler(CooperateEventType::APP_CLOSED, [this](Context &context, const CooperateEvent &event) {
        this->OnAppClosed(context, event);
    });
    AddHandler(CooperateEventType::DSOFTBUS_START_COOPERATE, [this](Context &context, const CooperateEvent &event) {
        this->OnRemoteStart(context, event);
    });
}

void CooperateFree::Initial::OnProgress(Context &context, const CooperateEvent &event)
{}

void CooperateFree::Initial::OnReset(Context &context, const CooperateEvent &event)
{}

void CooperateFree::Initial::BuildChains(std::shared_ptr<Initial> initial, CooperateFree &parent)
{}

void CooperateFree::Initial::RemoveChains(std::shared_ptr<Initial> initial)
{}

void CooperateFree::Initial::OnStart(Context &context, const CooperateEvent &event)
{
    CALL_INFO_TRACE;
    StartCooperateEvent notice = std::get<StartCooperateEvent>(event.event);
    FI_HILOGI("[start cooperation] With \'%{public}s\'", Utility::Anonymize(notice.remoteNetworkId).c_str());
    context.StartCooperate(notice);
    context.eventMgr_.StartCooperate(notice);

    int32_t ret = context.dsoftbus_.OpenSession(context.Peer());
    if (ret != RET_OK) {
        FI_HILOGE("[start cooperation] Failed to connect to \'%{public}s\'",
            Utility::Anonymize(context.Peer()).c_str());
        int32_t errNum = (ret == RET_ERR ? static_cast<int32_t>(CoordinationErrCode::OPEN_SESSION_FAILED) : ret);
        DSoftbusStartCooperateFinished failNotice {
            .success = false,
            .errCode = errNum
        };
        context.eventMgr_.StartCooperateFinish(failNotice);
        return;
    }
    DSoftbusStartCooperate startNotice {
        .originNetworkId = context.Local(),
        .success = true,
        .cursorPos = context.NormalizedCursorPosition(),
    };
    context.OnStartCooperate(startNotice.extra);
    context.dsoftbus_.StartCooperate(context.Peer(), startNotice);
    context.inputEventInterceptor_.Enable(context);
    context.eventMgr_.StartCooperateFinish(startNotice);
    FI_HILOGI("[start cooperation] Cooperation with \'%{public}s\' established",
        Utility::Anonymize(context.Peer()).c_str());
    TransiteTo(context, CooperateState::COOPERATE_STATE_OUT);
    context.OnTransitionOut();
#ifdef ENABLE_PERFORMANCE_CHECK
    std::ostringstream ss;
    ss << "start_cooperation_with_ " << Utility::Anonymize(context.Peer()).c_str();
    context.FinishTrace(ss.str());
#endif // ENABLE_PERFORMANCE_CHECK
}

void CooperateFree::Initial::OnStop(Context &context, const CooperateEvent &event)
{
    CALL_INFO_TRACE;
    StopCooperateEvent notice = std::get<StopCooperateEvent>(event.event);
    parent_.UnchainConnections(context, notice);
}

void CooperateFree::Initial::OnAppClosed(Context &context, const CooperateEvent &event)
{
    FI_HILOGI("[app closed] Close all connections");
    context.dsoftbus_.CloseAllSessions();
}

void CooperateFree::Initial::OnRemoteStart(Context &context, const CooperateEvent &event)
{
    CALL_INFO_TRACE;
    DSoftbusStartCooperate notice = std::get<DSoftbusStartCooperate>(event.event);
    context.OnRemoteStartCooperate(notice.extra);
    context.eventMgr_.RemoteStart(notice);
    context.RemoteStartSuccess(notice);
    context.inputEventBuilder_.Enable(context);
    context.eventMgr_.RemoteStartFinish(notice);
    context.inputDevMgr_.AddVirtualInputDevice(context.Peer());
    FI_HILOGI("[remote start] Cooperation with \'%{public}s\' established", Utility::Anonymize(context.Peer()).c_str());
    TransiteTo(context, CooperateState::COOPERATE_STATE_IN);
    context.OnTransitionIn();
}
} // namespace Cooperate
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
