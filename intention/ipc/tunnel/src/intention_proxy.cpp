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

#include "intention_proxy.h"

#include "iremote_object.h"
#include "message_option.h"
#include "message_parcel.h"

#include "devicestatus_define.h"
#include "intention_identity.h"

#undef LOG_TAG
#define LOG_TAG "IntentionProxy"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

IntentionProxy::IntentionProxy(const sptr<IRemoteObject>& impl)
    : IRemoteProxy<IIntention>(impl)
{}

int32_t IntentionProxy::Enable(Intention intention, MessageParcel &data, MessageParcel &reply)
{
    CALL_DEBUG_ENTER;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    MessageOption option;

    int32_t ret = remote->SendRequest(
        PARAMID(CommonAction::ENABLE, static_cast<uint32_t>(intention), 0u),
        data, reply, option);
    if (ret != RET_OK) {
        FI_HILOGE("SendRequest is failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t IntentionProxy::Disable(Intention intention, MessageParcel &data, MessageParcel &reply)
{
    CALL_DEBUG_ENTER;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    MessageOption option;

    int32_t ret = remote->SendRequest(
        PARAMID(CommonAction::DISABLE, static_cast<uint32_t>(intention), 0u),
        data, reply, option);
    if (ret != RET_OK) {
        FI_HILOGE("SendRequest is failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t IntentionProxy::Start(Intention intention, MessageParcel &data, MessageParcel &reply)
{
    CALL_DEBUG_ENTER;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    MessageOption option;

    int32_t ret = remote->SendRequest(
        PARAMID(CommonAction::START, static_cast<uint32_t>(intention), 0u),
        data, reply, option);
    if (ret != RET_OK) {
        FI_HILOGE("SendRequest is failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t IntentionProxy::Stop(Intention intention, MessageParcel &data, MessageParcel &reply)
{
    CALL_DEBUG_ENTER;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    MessageOption option;

    int32_t ret = remote->SendRequest(
        PARAMID(CommonAction::STOP, static_cast<uint32_t>(intention), 0u),
        data, reply, option);
    if (ret != RET_OK) {
        FI_HILOGE("SendRequest is failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t IntentionProxy::AddWatch(Intention intention, uint32_t id, MessageParcel &data, MessageParcel &reply)
{
    CALL_DEBUG_ENTER;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    MessageOption option;

    int32_t ret = remote->SendRequest(
        PARAMID(CommonAction::ADD_WATCH, static_cast<uint32_t>(intention), id),
        data, reply, option);
    if (ret != RET_OK) {
        FI_HILOGE("SendRequest is failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t IntentionProxy::RemoveWatch(Intention intention, uint32_t id, MessageParcel &data, MessageParcel &reply)
{
    CALL_DEBUG_ENTER;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    MessageOption option;

    int32_t ret = remote->SendRequest(
        PARAMID(CommonAction::REMOVE_WATCH, static_cast<uint32_t>(intention), id),
        data, reply, option);
    if (ret != RET_OK) {
        FI_HILOGE("SendRequest is failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t IntentionProxy::SetParam(Intention intention, uint32_t id, MessageParcel &data, MessageParcel &reply)
{
    CALL_DEBUG_ENTER;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    MessageOption option;

    int32_t ret = remote->SendRequest(
        PARAMID(CommonAction::SET_PARAM, static_cast<uint32_t>(intention), id),
        data, reply, option);
    if (ret != RET_OK) {
        FI_HILOGE("SendRequest is failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t IntentionProxy::GetParam(Intention intention, uint32_t id, MessageParcel &data, MessageParcel &reply)
{
    CALL_DEBUG_ENTER;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    MessageOption option;

    int32_t ret = remote->SendRequest(
        PARAMID(CommonAction::GET_PARAM, static_cast<uint32_t>(intention), id),
        data, reply, option);
    if (ret != RET_OK) {
        FI_HILOGE("SendRequest is failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t IntentionProxy::Control(Intention intention, uint32_t id, MessageParcel &data, MessageParcel &reply)
{
    CALL_DEBUG_ENTER;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    MessageOption option;

    int32_t ret = remote->SendRequest(
        PARAMID(CommonAction::CONTROL, static_cast<uint32_t>(intention), id),
        data, reply, option);
    if (ret != RET_OK) {
        FI_HILOGE("SendRequest is failed, ret:%{public}d", ret);
    }
    return ret;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
