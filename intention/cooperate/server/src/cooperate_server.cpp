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

#include "cooperate_server.h"

#include <chrono>

#include <tokenid_kit.h>

#include "accesstoken_kit.h"
#include "cooperate_params.h"
#include "default_params.h"
#include "devicestatus_define.h"
#include "ipc_skeleton.h"
#include "utility.h"

#undef LOG_TAG
#define LOG_TAG "CooperateServer"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
constexpr int32_t REPEAT_ONCE { 1 };
constexpr int32_t DEFAULT_UNLOAD_COOLING_TIME_MS { 60000 };
constexpr int32_t SYNC_TASK_TIMEOUT_DURATION { 2500 };
}

CooperateServer::CooperateServer(IContext *context)
    : context_(context)
{}

int32_t CooperateServer::Enable(CallingContext &context, MessageParcel &data, MessageParcel &reply)
{
    CALL_DEBUG_ENTER;
    if (int32_t ret = CheckPermission(context); ret != RET_OK) {
        FI_HILOGE("CheckPermission failed, ret:%{public}d", ret);
        return ret;
    }
    DefaultParam param;
    if (!param.Unmarshalling(data)) {
        FI_HILOGE("DefaultParam::Unmarshalling fail");
        return RET_ERR;
    }
    CHKPR(context_, RET_ERR);
    if (unloadTimerId_ >= 0) {
        context_->GetTimerManager().RemoveTimer(unloadTimerId_);
    }
    ICooperate* cooperate = context_->GetPluginManager().LoadCooperate();
    CHKPR(cooperate, RET_ERR);
    cooperate->Enable(context.tokenId, context.pid, param.userData);
    return RET_OK;
}

int32_t CooperateServer::Disable(CallingContext &context, MessageParcel &data, MessageParcel &reply)
{
    CALL_DEBUG_ENTER;
    if (int32_t ret = CheckPermission(context); ret != RET_OK) {
        FI_HILOGE("CheckPermission failed, ret:%{public}d", ret);
        return ret;
    }
    DefaultParam param;
    if (!param.Unmarshalling(data)) {
        FI_HILOGE("DefaultParam::Unmarshalling fail");
        return RET_ERR;
    }
    CHKPR(context_, RET_ERR);
    ICooperate* cooperate = context_->GetPluginManager().LoadCooperate();
    CHKPR(cooperate, RET_ERR);
    cooperate->Disable(context.pid, param.userData);
    unloadTimerId_ = context_->GetTimerManager().AddTimer(DEFAULT_UNLOAD_COOLING_TIME_MS, REPEAT_ONCE,
        []() {
            FI_HILOGI("Unload \'cooperate\' module");
        });
    if (unloadTimerId_ < 0) {
        FI_HILOGE("AddTimer failed, will not unload Cooperate");
    }
    return RET_OK;
}

int32_t CooperateServer::Start(CallingContext &context, MessageParcel &data, MessageParcel &reply)
{
    CALL_DEBUG_ENTER;
    if (int32_t ret = CheckPermission(context); ret != RET_OK) {
        FI_HILOGE("CheckPermission failed, ret:%{public}d", ret);
        return ret;
    }
    StartCooperateParam param;
    if (!param.Unmarshalling(data)) {
        FI_HILOGE("StartCooperateParam::Unmarshalling fail");
        return RET_ERR;
    }
    CHKPR(context_, RET_ERR);
    ICooperate* cooperate = context_->GetPluginManager().LoadCooperate();
    CHKPR(cooperate, RET_ERR);
    return cooperate->Start(context.pid, param.userData, param.remoteNetworkId, param.startDeviceId);
}

int32_t CooperateServer::Stop(CallingContext &context, MessageParcel &data, MessageParcel &reply)
{
    CALL_DEBUG_ENTER;
    if (int32_t ret = CheckPermission(context); ret != RET_OK) {
        FI_HILOGE("CheckPermission failed, ret:%{public}d", ret);
        return ret;
    }
    StopCooperateParam param;
    if (!param.Unmarshalling(data)) {
        FI_HILOGE("StopCooperateParam::Unmarshalling fail");
        return RET_ERR;
    }
    CHKPR(context_, RET_ERR);
    ICooperate* cooperate = context_->GetPluginManager().LoadCooperate();
    CHKPR(cooperate, RET_ERR);
    return cooperate->Stop(context.pid, param.userData, param.isUnchained);
}

int32_t CooperateServer::AddWatch(CallingContext &context, uint32_t id, MessageParcel &data, MessageParcel &reply)
{
    CALL_DEBUG_ENTER;
    if (int32_t ret = CheckPermission(context); ret != RET_OK) {
        FI_HILOGE("CheckPermission failed, ret:%{public}d", ret);
        return ret;
    }
    CHKPR(context_, RET_ERR);
    ICooperate* cooperate = context_->GetPluginManager().LoadCooperate();
    CHKPR(cooperate, RET_ERR);
    switch (id) {
        case CooperateRequestID::REGISTER_LISTENER: {
            return cooperate->RegisterListener(context.pid);
        }
        case CooperateRequestID::REGISTER_HOTAREA_LISTENER: {
            return cooperate->RegisterHotAreaListener(context.pid);
        }
        case CooperateRequestID::REGISTER_EVENT_LISTENER: {
            RegisterEventListenerParam param;
            if (!param.Unmarshalling(data)) {
                FI_HILOGE("RegisterEventListenerParam::Unmarshalling fail");
                return RET_ERR;
            }
            return cooperate->RegisterEventListener(context.pid, param.networkId);
        }
        default: {
            FI_HILOGE("Unexpected request ID (%{public}u)", id);
            return RET_ERR;
        }
    }
}

int32_t CooperateServer::RemoveWatch(CallingContext &context, uint32_t id, MessageParcel &data, MessageParcel &reply)
{
    CALL_DEBUG_ENTER;
    if (int32_t ret = CheckPermission(context); ret != RET_OK) {
        FI_HILOGE("CheckPermission failed, ret:%{public}d", ret);
        return ret;
    }
    CHKPR(context_, RET_ERR);
    ICooperate* cooperate = context_->GetPluginManager().LoadCooperate();
    CHKPR(cooperate, RET_ERR);
    switch (id) {
        case CooperateRequestID::UNREGISTER_LISTENER: {
            return cooperate->UnregisterListener(context.pid);
        }
        case CooperateRequestID::UNREGISTER_HOTAREA_LISTENER: {
            return cooperate->UnregisterHotAreaListener(context.pid);
        }
        case CooperateRequestID::UNREGISTER_EVENT_LISTENER: {
            UnregisterEventListenerParam param;
            if (!param.Unmarshalling(data)) {
                FI_HILOGE("UnregisterEventListenerParam::Unmarshalling fail");
                return RET_ERR;
            }
            return cooperate->UnregisterEventListener(context.pid, param.networkId);
        }
        default: {
            FI_HILOGE("Unexpected request ID (%{public}u)", id);
            return RET_ERR;
        }
    }
}

int32_t CooperateServer::SetParam(CallingContext &context, uint32_t id, MessageParcel &data, MessageParcel &reply)
{
    CALL_DEBUG_ENTER;
    return RET_ERR;
}

int32_t CooperateServer::GetParam(CallingContext &context, uint32_t id, MessageParcel &data, MessageParcel &reply)
{
    CALL_DEBUG_ENTER;
    if (int32_t ret = CheckPermission(context); ret != RET_OK) {
        FI_HILOGE("CheckPermission failed, ret:%{public}d", ret);
        return ret;
    }
    CHKPR(context_, RET_ERR);
    ICooperate* cooperate = context_->GetPluginManager().LoadCooperate();
    CHKPR(cooperate, RET_ERR);
    auto enterStamp = std::chrono::steady_clock::now();
    auto checkParcelValid = [&enterStamp] () {
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - enterStamp).count();
            return duration < SYNC_TASK_TIMEOUT_DURATION;
    };
    switch (id) {
        case CooperateRequestID::GET_COOPERATE_STATE: {
            GetCooperateStateParam param;
            if (!param.Unmarshalling(data)) {
                FI_HILOGE("GetCooperateStateParam::Unmarshalling fail");
                return RET_ERR;
            }
            return cooperate->GetCooperateState(context.pid, param.userData, param.networkId);
        }
        case CooperateRequestID::GET_COOPERATE_STATE_SYNC: {
            GetCooperateStateSyncParam param;
            if (!param.Unmarshalling(data)) {
                FI_HILOGE("GetCooperateStateParam::Unmarshalling fail");
                return RET_ERR;
            }
            bool state { false };
            if (cooperate->GetCooperateState(param.udId, state) != RET_OK) {
                FI_HILOGE("GetCooperateState failed");
                return RET_ERR;
            }
            FI_HILOGI("GetCooperateState for udId:%{public}s successfully, state:%{public}s",
                Utility::Anonymize(param.udId).c_str(), state ? "true" : "false");
            if (!checkParcelValid()) {
                FI_HILOGE("CheckParcelValid failed");
                return RET_ERR;
            }
            if (!BooleanReply(state).Marshalling(reply)) {
                FI_HILOGE("Marshalling state failed");
                return RET_ERR;
            }
            return RET_OK;
        }
        default: {
            FI_HILOGE("Unexpected request ID (%{public}u)", id);
            return RET_ERR;
        }
    }
}

int32_t CooperateServer::Control(CallingContext &context, uint32_t id, MessageParcel &data, MessageParcel &reply)
{
    CALL_DEBUG_ENTER;
    return RET_ERR;
}

bool CooperateServer::CheckCooperatePermission(CallingContext &context)
{
    CALL_DEBUG_ENTER;
    Security::AccessToken::AccessTokenID callerToken = context.tokenId;
    int32_t result = Security::AccessToken::AccessTokenKit::VerifyAccessToken(callerToken,
        COOPERATE_PERMISSION);
    return result == Security::AccessToken::PERMISSION_GRANTED;
}

bool CooperateServer::IsSystemServiceCalling(CallingContext &context)
{
    const auto flag = Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(context.tokenId);
    if (flag == Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE ||
        flag == Security::AccessToken::ATokenTypeEnum::TOKEN_SHELL) {
        FI_HILOGD("system service calling, flag:%{public}u", flag);
        return true;
    }
    return false;
}

bool CooperateServer::IsSystemCalling(CallingContext &context)
{
    if (IsSystemServiceCalling(context)) {
        return true;
    }
    return Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(context.fullTokenId);
}

int32_t CooperateServer::CheckPermission(CallingContext &context)
{
    if (!IsSystemCalling(context)) {
        FI_HILOGE("The caller is not system hap");
        return COMMON_NOT_SYSTEM_APP;
    }
    if (!CheckCooperatePermission(context)) {
        FI_HILOGE("The caller has no COOPERATE_MANAGER permission");
        return COMMON_PERMISSION_CHECK_ERROR;
    }
    return RET_OK;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS