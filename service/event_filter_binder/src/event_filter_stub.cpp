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

#include "event_filter_stub.h"
#include <sys/socket.h>
#include <sys/types.h>
#include "event_filter_parcel.h"
#include "ipc_skeleton.h"
#include "log.h"
#include "string_ex.h"

namespace OHOS {
namespace MMI {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "EventFilterStub" };
}

int32_t EventFilterStub::OnRemoteRequest(
    uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option)
{
    MMI_LOGT("enter, code: %{public}d", code);

    std::u16string descriptor = data.ReadInterfaceToken();
    if (descriptor != IEventFilter::GetDescriptor()) {
        MMI_LOGE("get unexpect descriptor: %{public}s", Str16ToStr8(descriptor).c_str());
        return ERR_INVALID_STATE;
    }

    switch (code) {
        case static_cast<uint32_t>(IEventFilter::OPERATOR_TYPE::HANDLE_POINTER_EVENT):
            return StubHandlePointerEvent(data, reply);
        default:
            MMI_LOGE("unknown code: %{public}u, go switch defaut", code);
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
}

bool EventFilterStub::StubHandlePointerEvent(MessageParcel& data, MessageParcel& reply)
{     
    std::shared_ptr<PointerEvent> event = PointerEvent::Create();
    if (event == nullptr) {
        MMI_LOGE("event is nullptr.");
        return false;
    }

    if (!event->ReadFromParcel(data)) {
        MMI_LOGE("read data error.");
        return false;
    }

    return HandlePointerEvent(event);
}
} // namespace MMI
} // namespace OHOS