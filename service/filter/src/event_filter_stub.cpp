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

#include "event_filter_stub.h"

#include <sys/socket.h>
#include <sys/types.h>

#include "ipc_skeleton.h"
#include "string_ex.h"

#include "mmi_log.h"
#include "multimodalinput_ipc_interface_code.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "EventFilterStub"

namespace OHOS {
namespace MMI {
int32_t EventFilterStub::OnRemoteRequest(
    uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option)
{
    CALL_DEBUG_ENTER;
    MMI_HILOGD("code:%{public}u", code);

    std::u16string descriptor = data.ReadInterfaceToken();
    if (descriptor != IEventFilter::GetDescriptor()) {
        MMI_HILOGE("Get unexpect descriptor:%{public}s", Str16ToStr8(descriptor).c_str());
        return ERR_INVALID_STATE;
    }

    switch (code) {
        case static_cast<uint32_t>(MultimodalinputEventInterfaceCode::HANDLE_KEY_EVENT): {
            return StubHandleKeyEvent(data, reply);
        }
        case static_cast<uint32_t>(MultimodalinputEventInterfaceCode::HANDLE_POINTER_EVENT): {
            return StubHandlePointerEvent(data, reply);
        }
        default: {
            MMI_HILOGE("Unknown code:%{public}u, go switch default", code);
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
        }
    }
}

int32_t EventFilterStub::StubHandleKeyEvent(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<KeyEvent> event = KeyEvent::Create();
    CHKPR(event, RET_ERR);

    if (!event->ReadFromParcel(data)) {
        MMI_HILOGE("Read data error");
        return RET_ERR;
    }

    bool ret = HandleKeyEvent(event);
    WRITEBOOL(reply, ret, RET_ERR);
    return RET_OK;
}

int32_t EventFilterStub::StubHandlePointerEvent(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<PointerEvent> event = PointerEvent::Create();
    CHKPR(event, RET_ERR);

    if (!event->ReadFromParcel(data)) {
        MMI_HILOGE("Read data error");
        return RET_ERR;
    }

    bool ret = HandlePointerEvent(event);
    WRITEBOOL(reply, ret, RET_ERR);
    return RET_OK;
}
} // namespace MMI
} // namespace OHOS