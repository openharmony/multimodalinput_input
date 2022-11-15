/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "input_device_cooperate_state_in.h"

#include "cooperation_message.h"
#include "device_cooperate_softbus_adapter.h"
#include "distributed_input_adapter.h"
#include "input_device_cooperate_sm.h"
#include "input_device_cooperate_util.h"
#include "input_device_manager.h"
#include "mouse_event_normalize.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "InputDeviceCooperateStateIn"};
} // namespace

InputDeviceCooperateStateIn::InputDeviceCooperateStateIn(const std::string &startDhid) : startDhid_(startDhid) {}

int32_t InputDeviceCooperateStateIn::StartInputDeviceCooperate(const std::string &remoteNetworkId,
    int32_t startInputDeviceId)
{
    CALL_INFO_TRACE;
    if (remoteNetworkId.empty()) {
        MMI_HILOGE("RemoteNetworkId is empty");
        return static_cast<int32_t>(CooperationMessage::COOPERATION_DEVICE_ERROR);
    }
    std::string localNetworkId = GetLocalDeviceId();
    if (localNetworkId.empty() || remoteNetworkId == localNetworkId) {
        MMI_HILOGE("Input Parameters error");
        return static_cast<int32_t>(CooperationMessage::COOPERATION_DEVICE_ERROR);
    }
    int32_t ret = DevCooperateSoftbusAdapter->StartRemoteCooperate(localNetworkId, remoteNetworkId);
    if (ret != RET_OK) {
        MMI_HILOGE("Start input device cooperate fail");
        return static_cast<int32_t>(CooperationMessage::COOPERATE_FAIL);
    }
    std::string taskName = "process_start_task";
    std::function<void()> handleProcessStartFunc =
        std::bind(&InputDeviceCooperateStateIn::ProcessStart, this, remoteNetworkId, startInputDeviceId);
    CHKPR(eventHandler_, RET_ERR);
    eventHandler_->ProxyPostTask(handleProcessStartFunc, taskName, 0);
    return RET_OK;
}

int32_t InputDeviceCooperateStateIn::ProcessStart(const std::string &remoteNetworkId, int32_t startInputDeviceId)
{
    CALL_DEBUG_ENTER;
    std::string originNetworkId = InputDevMgr->GetOriginNetworkId(startInputDeviceId);
    if (remoteNetworkId == originNetworkId) {
        ComeBack(remoteNetworkId, startInputDeviceId);
        return RET_OK;
    } else {
        return RelayComeBack(remoteNetworkId, startInputDeviceId);
    }
}

int32_t InputDeviceCooperateStateIn::StopInputDeviceCooperate(const std::string &networkId)
{
    CALL_DEBUG_ENTER;
    int32_t ret = DevCooperateSoftbusAdapter->StopRemoteCooperate(networkId);
    if (ret != RET_OK) {
        MMI_HILOGE("Stop input device cooperate fail");
        return ret;
    }
    std::string taskName = "process_stop_task";
    std::function<void()> handleProcessStopFunc = std::bind(&InputDeviceCooperateStateIn::ProcessStop, this);
    CHKPR(eventHandler_, RET_ERR);
    eventHandler_->ProxyPostTask(handleProcessStopFunc, taskName, 0);
    return RET_OK;
}

int32_t InputDeviceCooperateStateIn::ProcessStop()
{
    CALL_DEBUG_ENTER;
    std::vector<std::string> dhids = InputDevMgr->GetCooperateDhids(startDhid_);
    std::string sink = InputDevMgr->GetOriginNetworkId(startDhid_);
    int32_t ret = DistributedAdapter->StopRemoteInput(
        sink, dhids, [this, sink](bool isSuccess) { this->OnStopRemoteInput(isSuccess, sink, -1); });
    if (ret != RET_OK) {
        InputDevCooSM->OnStopFinish(false, sink);
    }
    return RET_OK;
}

void InputDeviceCooperateStateIn::OnStartRemoteInput(
    bool isSuccess, const std::string &srcNetworkId, int32_t startInputDeviceId)
{
    CALL_DEBUG_ENTER;
    if (!isSuccess) {
        IInputDeviceCooperateState::OnStartRemoteInput(isSuccess, srcNetworkId, startInputDeviceId);
        return;
    }
    std::string sinkNetworkId = InputDevMgr->GetOriginNetworkId(startInputDeviceId);
    std::vector<std::string> dhid = InputDevMgr->GetCooperateDhids(startInputDeviceId);

    std::string taskName = "relay_stop_task";
    std::function<void()> handleRelayStopFunc = std::bind(&InputDeviceCooperateStateIn::StopRemoteInput,
        this, sinkNetworkId, srcNetworkId, dhid, startInputDeviceId);
    CHKPV(eventHandler_);
    eventHandler_->ProxyPostTask(handleRelayStopFunc, taskName, 0);
}

void InputDeviceCooperateStateIn::StopRemoteInput(const std::string &sinkNetworkId,
    const std::string &srcNetworkId, const std::vector<std::string> &dhid, int32_t startInputDeviceId)
{
    int32_t ret = DistributedAdapter->StopRemoteInput(sinkNetworkId, dhid,
        [this, srcNetworkId, startInputDeviceId](bool isSuccess) {
            this->OnStopRemoteInput(isSuccess, srcNetworkId, startInputDeviceId);
    });
    if (ret != RET_OK) {
        InputDevCooSM->OnStartFinish(false, sinkNetworkId, startInputDeviceId);
    }
}

void InputDeviceCooperateStateIn::OnStopRemoteInput(bool isSuccess,
    const std::string &remoteNetworkId, int32_t startInputDeviceId)
{
    CALL_DEBUG_ENTER;
    if (InputDevCooSM->IsStarting()) {
        std::string taskName = "start_finish_task";
        std::function<void()> handleStartFinishFunc = std::bind(&InputDeviceCooperateSM::OnStartFinish,
            InputDevCooSM, isSuccess, remoteNetworkId, startInputDeviceId);
        CHKPV(eventHandler_);
        eventHandler_->ProxyPostTask(handleStartFinishFunc, taskName, 0);
    } else if (InputDevCooSM->IsStopping()) {
        std::string taskName = "stop_finish_task";
        std::function<void()> handleStopFinishFunc =
            std::bind(&InputDeviceCooperateSM::OnStopFinish, InputDevCooSM, isSuccess, remoteNetworkId);
        CHKPV(eventHandler_);
        eventHandler_->ProxyPostTask(handleStopFinishFunc, taskName, 0);
    }
}

void InputDeviceCooperateStateIn::ComeBack(const std::string &sinkNetworkId, int32_t startInputDeviceId)
{
    CALL_DEBUG_ENTER;
    std::vector<std::string> dhids = InputDevMgr->GetCooperateDhids(startInputDeviceId);
    if (dhids.empty()) {
       InputDevCooSM->OnStartFinish(false, sinkNetworkId, startInputDeviceId);
    }
    int32_t ret = DistributedAdapter->StopRemoteInput(sinkNetworkId, dhids,
        [this, sinkNetworkId, startInputDeviceId](bool isSuccess) {
            this->OnStopRemoteInput(isSuccess, sinkNetworkId, startInputDeviceId);
            });
    if (ret != RET_OK) {
        InputDevCooSM->OnStartFinish(false, sinkNetworkId, startInputDeviceId);
    }
}

int32_t InputDeviceCooperateStateIn::RelayComeBack(const std::string &srcNetworkId, int32_t startInputDeviceId)
{
    CALL_DEBUG_ENTER;
    return PrepareAndStart(srcNetworkId, startInputDeviceId);
}
} // namespace MMI
} // namespace OHOS
