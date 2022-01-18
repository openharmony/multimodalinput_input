/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "event_filter_proxy.h"
#include "event_filter_parcel.h"
#include "log.h"
#include "message_option.h"
#include "string_ex.h"

namespace OHOS {
namespace MMI {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "EventFilterProxy" };
}

// 获取其他设备注册的SA的Proxy
EventFilterProxy::EventFilterProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<IEventFilter>(impl)
{
    MMI_LOGI("EventFilterProxy()");
}

EventFilterProxy::~EventFilterProxy()
{
    MMI_LOGI("~EventFilterProxy()");
}

bool EventFilterProxy::HandlePointerEvent(const std::shared_ptr<PointerEvent> event)
{
    MMI_LOGT("enter");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (event == nullptr) {
        MMI_LOGE("event is nullptr");
        return false;
    }

    if (!data.WriteInterfaceToken(EventFilterProxy::GetDescriptor())) {
        MMI_LOGE("Failed to write descriptor");
        return false;
    }

    if (!event->WriteToParcel(data)) {
        MMI_LOGE("Failed to write event to req");
        return false;
    }

    const uint32_t code = static_cast<uint32_t>(OPERATOR_TYPE::HANDLE_POINTER_EVENT);
    int requestResult = Remote()->SendRequest(code, data, reply, option);
    if (requestResult != NO_ERROR) {
        MMI_LOGE("send request fail, result: %{public}d", requestResult);
        return false;
    }

    MMI_LOGT("have recieve message from server");

    bool result = false;
    if (!reply.ReadBool(result)) {
        MMI_LOGE("reply ReadBool fail");
        return false;
    }

    MMI_LOGT("leave");
    return result;
}
} // namespace MMI
} // namespace OHOS
