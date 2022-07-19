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

#include "call_dinput_proxy.h"

#include "message_option.h"
#include "string_ex.h"

#include "error_multimodal.h"
#include "mmi_log.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "CallDinputProxy" };
} // namespace

int32_t CallDinputProxy::HandlePrepareDinput(const std::string &deviceId, int32_t status)
{
    CALL_INFO_TRACE;
    MessageParcel data;
    if (!data.WriteInterfaceToken(CallDinputProxy::GetDescriptor())) {
        MMI_HILOGW("Failed to write descriptor");
        return false;
    }
    WRITESTRING(data, deviceId, RET_ERR);
    WRITEINT32(data, status, RET_ERR);
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, ERROR_NULL_POINTER);
    int32_t ret = remote->SendRequest(HANDLE_PREPARE_DINPUT, data, reply, option);
    if (ret != NO_ERROR) {
        MMI_HILOGW("send request fail, result:%{public}d", ret);
        return false;
    }
    return ret;
}

int32_t CallDinputProxy::HandleUnprepareDinput(const std::string &deviceId, int32_t status)
{
    CALL_INFO_TRACE;
    MessageParcel data;
    if (!data.WriteInterfaceToken(CallDinputProxy::GetDescriptor())) {
        MMI_HILOGW("Failed to write descriptor");
        return false;
    }
    WRITESTRING(data, deviceId, RET_ERR);
    WRITEINT32(data, status, RET_ERR);
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, ERROR_NULL_POINTER);
    int32_t ret = remote->SendRequest(HANDLE_UNPREPARE_DINPUT, data, reply, option);
    if (ret != NO_ERROR) {
        MMI_HILOGW("send request fail, result:%{public}d", ret);
        return false;
    }
    return ret;
}

int32_t CallDinputProxy::HandleStartDinput(const std::string &deviceId, uint32_t inputTypes, int32_t status)
{
    CALL_INFO_TRACE;
    MessageParcel data;
    if (!data.WriteInterfaceToken(CallDinputProxy::GetDescriptor())) {
        MMI_HILOGW("Failed to write descriptor");
        return false;
    }
    WRITESTRING(data, deviceId, RET_ERR);
    WRITEINT32(data, inputTypes, RET_ERR);
    WRITEINT32(data, status, RET_ERR);
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, ERROR_NULL_POINTER);
    int32_t ret = remote->SendRequest(HANDLE_START_DINPUT, data, reply, option);
    if (ret != NO_ERROR) {
        MMI_HILOGW("send request fail, result:%{public}d", ret);
        return false;
    }
    return ret;
}

int32_t CallDinputProxy::HandleStopDinput(const std::string &deviceId, uint32_t inputTypes, int32_t status)
{
    CALL_INFO_TRACE;
    MessageParcel data;
    if (!data.WriteInterfaceToken(CallDinputProxy::GetDescriptor())) {
        MMI_HILOGW("Failed to write descriptor");
        return false;
    }
    WRITESTRING(data, deviceId, RET_ERR);
    WRITEINT32(data, inputTypes, RET_ERR);
    WRITEINT32(data, status, RET_ERR);
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, ERROR_NULL_POINTER);
    int32_t ret = remote->SendRequest(HANDLE_STOP_DINPUT, data, reply, option);
    if (ret != NO_ERROR) {
        MMI_HILOGW("send request fail, result:%{public}d", ret);
        return false;
    }
    return ret;
}

int32_t CallDinputProxy::HandleRemoteInputAbility(const std::set<int32_t> &remoteInputAbility)
{
    CALL_INFO_TRACE;
    MessageParcel data;
    if (!data.WriteInterfaceToken(CallDinputProxy::GetDescriptor())) {
        MMI_HILOGW("Failed to write descriptor");
        return false;
    }
    WRITEINT32(data, remoteInputAbility.size(), RET_ERR);
    for (const auto& item : remoteInputAbility) {
        WRITEINT32(data, item, RET_ERR);
    }
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, ERROR_NULL_POINTER);
    int32_t ret = remote->SendRequest(HANDLE_REMOTE_INPUT_ABILITY, data, reply, option);
    if (ret != NO_ERROR) {
        MMI_HILOGW("send request fail, result:%{public}d", ret);
        return false;
    }
    return ret;
}
} // namespace MMI
} // namespace OHOS
