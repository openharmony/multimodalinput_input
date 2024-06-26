/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "anco_channel_proxy.h"

#include "message_option.h"
#include "mmi_log.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "AncoChannelProxy"

namespace OHOS {
namespace MMI {

AncoChannelProxy::AncoChannelProxy(const sptr<IRemoteObject> &remoteObj)
    : IRemoteProxy<IAncoChannel>(remoteObj)
{}

int32_t AncoChannelProxy::SyncInputEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_INFO_TRACE;
    MessageParcel data;
    if (!data.WriteInterfaceToken(IAncoChannel::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return RET_ERR;
    }
    if (!pointerEvent->WriteToParcel(data)) {
        MMI_HILOGE("Failed to marshal PointerEvent");
        return RET_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(
        static_cast<uint32_t>(AncoRequestId::SYNC_POINTER_EVENT), data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("SendRequest fail, error:%{public}d", ret);
        return ret;
    }
    READINT32(reply, ret, RET_ERR);
    return ret;
}

int32_t AncoChannelProxy::SyncInputEvent(std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_INFO_TRACE;
    MessageParcel data;
    if (!data.WriteInterfaceToken(IAncoChannel::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return RET_ERR;
    }
    if (!keyEvent->WriteToParcel(data)) {
        MMI_HILOGE("Failed to marshal KeyEvent");
        return RET_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(
        static_cast<uint32_t>(AncoRequestId::SYNC_KEY_EVENT), data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("SendRequest fail, error:%{public}d", ret);
        return ret;
    }
    READINT32(reply, ret, RET_ERR);
    return ret;
}

int32_t AncoChannelProxy::UpdateWindowInfo(std::shared_ptr<AncoWindows> windows)
{
    CALL_INFO_TRACE;
    MessageParcel data;
    if (!data.WriteInterfaceToken(IAncoChannel::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return RET_ERR;
    }
    if (!AncoWindows::Marshalling(*windows, data)) {
        MMI_HILOGE("Failed to marshal windows");
        return RET_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(
        static_cast<uint32_t>(AncoRequestId::UPDATE_WINDOW_INFO), data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("SendRequest fail, error:%{public}d", ret);
        return ret;
    }
    READINT32(reply, ret, RET_ERR);
    return ret;
}
} // namespace MMI
} // namespace OHOS
