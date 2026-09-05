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

#include "cooperate_hisysevent.h"

#include "fi_log.h"

#undef LOG_TAG
#define LOG_TAG "CooperateHiSysEvent"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

std::map<CooperateState, std::string> CooperateDFX::CooperateState_ = {
    { CooperateState::COOPERATE_STATE_FREE, "STATE_FREE" },
    { CooperateState::COOPERATE_STATE_IN, "STATE_IN" },
    { CooperateState::COOPERATE_STATE_OUT, "STATE_OUT" },
};

std::map<CooperateType, std::pair<std::string, std::string>> CooperateDFX::serialStr_ = {
    { CooperateType::ENABLE_SUCC, { "ENABLE_SUCCESS", "Enable cooperate successfully" } },
    { CooperateType::ENABLE_FAIL, { "ENABLE_FAILED", "Enable cooperate failed" } },
    { CooperateType::DISABLE_SUCC, { "DISABLE_SUCCESS", "Disenable cooperate successfully" } },
    { CooperateType::DISABLE_FAIL, { "DISABLE_FAILED", "Disenable cooperate failed" } },
    { CooperateType::LOCAL_ACTIVATE_SUCC, { "LOCAL_ACTIVATE_SUCCESS", "Local start cooperate successfully" } },
    { CooperateType::LOCAL_ACTIVATE_FAIL, { "LOCAL_ACTIVATEE_FAILED", "Local start cooperate failed" } },
    { CooperateType::REMOTE_ACTIVATE_SUCC, { "REMOTE_ACTIVATE_SUCCESS", "Remote start cooperate successfully" } },
    { CooperateType::REMOTE_ACTIVATE_FAIL, { "REMOTE_ACTIVATE_FAILED", "Remote start cooperate failed" } },
    { CooperateType::LOCAL_DEACTIVATE_SUCC, { "LOCAL_DEACTIVATE_SUCCESS", "Local stop cooperate successfully" } },
    { CooperateType::LOCAL_DEACTIVATE_FAIL, { "LOCAL_DEACTIVATE_FAILED", "Local stop cooperate failed" } },
    { CooperateType::REMOTE_DEACTIVATE_SUCC, { "REMOTE_DEACTIVATE_SUCCESS", "Remote stop cooperate successfully" } },
    { CooperateType::REMOTE_DEACTIVATE_FAIL, { "REMOTE_DEACTIVATE_FAILED", "Remote stop cooperate failed" } },
    { CooperateType::OPENSESSION_SUCC, { "OPENSESSION_SUCCESS", "Open session successfully" } },
    { CooperateType::OPENSESSION_FAIL, { "OPENSESSION_FAILED", "Open session failed" } },
    { CooperateType::UPDATESTATE_SUCC, { "UPDATESTATE_SUCCESS", "Update cooperatestate successfully" } },
    { CooperateType::START_SUCC, { "START_SUCCESS", "Start client successfully" } },
    { CooperateType::START_FAIL, { "START_FAILED", "Start client failed" } },
    { CooperateType::STOP_SUCC, { "STOP_SUCCESS", "Stop client successfully" } },
    { CooperateType::STOP_FAIL, { "STOP_FAILED", "Stop client failed" } },
};


template<typename... Types>
int32_t CooperateDFX::WriteInputFunc(const CooperateType &cooperateType,
    OHOS::HiviewDFX::HiSysEvent::EventType eventType, Types... paras)
{
    if (serialStr_.find(cooperateType) == serialStr_.end()) {
        FI_HILOGE("serialStr_ can't find the cooperate hisysevent type");
        return RET_ERR;
    }
    auto &[label, dec] = serialStr_[cooperateType];
    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::MSDP,
        label,
        eventType,
        paras...,
        "MSG",
        dec);
    if (ret != RET_OK) {
        FI_HILOGE("HiviewDFX write failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t CooperateDFX::WriteEnable(OHOS::HiviewDFX::HiSysEvent::EventType type)
{
    if (type == OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR) {
        return WriteInputFunc(CooperateType::ENABLE_SUCC, type);
    }
    return WriteInputFunc(CooperateType::ENABLE_FAIL, type);
}

int32_t CooperateDFX::WriteDisable(OHOS::HiviewDFX::HiSysEvent::EventType type)
{
    if (type == OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR) {
        return WriteInputFunc(CooperateType::DISABLE_SUCC, type);
    }
    return WriteInputFunc(CooperateType::DISABLE_FAIL, type);
}

int32_t CooperateDFX::WriteLocalStart(OHOS::HiviewDFX::HiSysEvent::EventType type)
{
    if (type == OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR) {
        return WriteInputFunc(CooperateType::LOCAL_ACTIVATE_SUCC, type);
    }
    return WriteInputFunc(CooperateType::LOCAL_ACTIVATE_FAIL, type);
}

int32_t CooperateDFX::WriteRemoteStart(OHOS::HiviewDFX::HiSysEvent::EventType type)
{
    if (type == OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR) {
        return WriteInputFunc(CooperateType::REMOTE_ACTIVATE_SUCC, type);
    }
    return WriteInputFunc(CooperateType::REMOTE_ACTIVATE_FAIL, type);
}

int32_t CooperateDFX::WriteLocalStop(OHOS::HiviewDFX::HiSysEvent::EventType type)
{
    if (type == OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR) {
        return WriteInputFunc(CooperateType::LOCAL_DEACTIVATE_SUCC, type);
    }
    return WriteInputFunc(CooperateType::LOCAL_DEACTIVATE_FAIL, type);
}

int32_t CooperateDFX::WriteRemoteStop(OHOS::HiviewDFX::HiSysEvent::EventType type)
{
    if (type == OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR) {
        return WriteInputFunc(CooperateType::REMOTE_DEACTIVATE_SUCC, type);
    }
    return WriteInputFunc(CooperateType::REMOTE_DEACTIVATE_FAIL, type);
}

int32_t CooperateDFX::WriteOpenSession(OHOS::HiviewDFX::HiSysEvent::EventType type)
{
    if (type == OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR) {
        return WriteInputFunc(CooperateType::OPENSESSION_SUCC, type);
    }
    return WriteInputFunc(CooperateType::OPENSESSION_FAIL, type);
}

int32_t CooperateDFX::WriteStart(OHOS::HiviewDFX::HiSysEvent::EventType type)
{
    if (type == OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR) {
        return WriteInputFunc(CooperateType::START_SUCC, type);
    }
    return WriteInputFunc(CooperateType::START_FAIL, type);
}

int32_t CooperateDFX::WriteStop(OHOS::HiviewDFX::HiSysEvent::EventType type)
{
    if (type == OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR) {
        return WriteInputFunc(CooperateType::STOP_SUCC, type);
    }
    return WriteInputFunc(CooperateType::STOP_FAIL, type);
}

int32_t CooperateDFX::WriteCooperateState(CooperateState curState)
{
    if (curState == CooperateState::N_COOPERATE_STATES) {
        return RET_ERR;
    }
    if (CooperateState_.find(curState) == CooperateState_.end()) {
        FI_HILOGE("CooperateState_ can't find the current cooperate state");
        return RET_ERR;
    }
    auto type = OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR;
    std::string currentState = CooperateState_[curState];
    return WriteInputFunc(CooperateType::UPDATESTATE_SUCC, type, "CurrentState", currentState);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
