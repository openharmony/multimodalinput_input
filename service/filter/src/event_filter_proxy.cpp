/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "event_filter_proxy.h"

#include "mmi_log.h"
#include "multimodalinput_ipc_interface_code.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "EventFilterProxy"

namespace OHOS {
namespace MMI {
EventFilterProxy::EventFilterProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<IEventFilter>(impl)
{
    MMI_HILOGI("EventFilterProxy()");
}

bool EventFilterProxy::HandleKeyEvent(const std::shared_ptr<KeyEvent> event)
{
    CALL_DEBUG_ENTER;
    CHKPF(event);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(EventFilterProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return false;
    }

    if (!event->WriteToParcel(data)) {
        MMI_HILOGE("Failed to write event to req");
        return false;
    }

    sptr<IRemoteObject> remote = Remote();
    CHKPF(remote);
    const uint32_t code = static_cast<uint32_t>(MultimodalinputEventInterfaceCode::HANDLE_KEY_EVENT);
    int32_t ret = remote->SendRequest(code, data, reply, option);
    if (ret != NO_ERROR) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
        return false;
    }

    bool result = false;
    READBOOL(reply, result);
    return result;
}

bool EventFilterProxy::HandlePointerEvent(const std::shared_ptr<PointerEvent> event)
{
    CALL_DEBUG_ENTER;
    CHKPF(event);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(EventFilterProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return false;
    }

    if (!event->WriteToParcel(data)) {
        MMI_HILOGE("Failed to write event to req");
        return false;
    }

    sptr<IRemoteObject> remote = Remote();
    CHKPF(remote);
    const uint32_t code = static_cast<uint32_t>(MultimodalinputEventInterfaceCode::HANDLE_POINTER_EVENT);
    int32_t ret = remote->SendRequest(code, data, reply, option);
    if (ret != NO_ERROR) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
        return false;
    }

    bool result = false;
    READBOOL(reply, result);
    return result;
}
} // namespace MMI
} // namespace OHOS
