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

#include "anco_channel_stub.h"

#include "string_ex.h"

#include "define_multimodal.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "AncoChannelStub"

namespace OHOS {
namespace MMI {

AncoChannelStub::AncoChannelStub()
{
    handlers_ = {
        { AncoRequestId::SYNC_POINTER_EVENT, &AncoChannelStub::StubSyncPointerEvent },
        { AncoRequestId::SYNC_KEY_EVENT, &AncoChannelStub::StubSyncKeyEvent },
        { AncoRequestId::UPDATE_WINDOW_INFO, &AncoChannelStub::StubUpdateWindowInfo },
    };
}

int32_t AncoChannelStub::OnRemoteRequest(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    CALL_INFO_TRACE;
    std::u16string descriptor = data.ReadInterfaceToken();
    if (descriptor != IAncoChannel::GetDescriptor()) {
        MMI_HILOGE("Got unexpected descriptor:%{public}s", Str16ToStr8(descriptor).c_str());
        return ERR_INVALID_STATE;
    }
    int32_t ret = RET_ERR;
    auto cbIter = handlers_.find(static_cast<AncoRequestId>(code));

    if (cbIter == handlers_.end()) {
        MMI_HILOGE("Unexpected request: %{public}u", code);
    } else {
        ret = (this->*(cbIter->second))(data, reply);
    }
    WRITEINT32(reply, ret);
    return ret;
}

int32_t AncoChannelStub::StubSyncPointerEvent(MessageParcel &data, MessageParcel &reply)
{
    CALL_INFO_TRACE;
    auto pointerEvent = PointerEvent::Create();
    CHKPR(pointerEvent, RET_ERR);
    if (!pointerEvent->ReadFromParcel(data)) {
        MMI_HILOGE("Failed to unmarshal PointerEvent");
        return RET_ERR;
    }
    return SyncInputEvent(pointerEvent);
}

int32_t AncoChannelStub::StubSyncKeyEvent(MessageParcel &data, MessageParcel &reply)
{
    auto keyEvent = KeyEvent::Create();
    CHKPR(keyEvent, RET_ERR);
    if (!keyEvent->ReadFromParcel(data)) {
        MMI_HILOGE("Failed to unmarshal KeyEvent");
        return RET_ERR;
    }
    return SyncInputEvent(keyEvent);
}

int32_t AncoChannelStub::StubUpdateWindowInfo(MessageParcel &data, MessageParcel &reply)
{
    auto windows = std::make_shared<AncoWindows>();
    if (!AncoWindows::Unmarshalling(data, *windows)) {
        MMI_HILOGE("Failed to unmarshal anco windows");
        return RET_ERR;
    }
    return UpdateWindowInfo(windows);
}
} // namespace MMI
} // namespace OHOS
