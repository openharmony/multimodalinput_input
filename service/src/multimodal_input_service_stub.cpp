/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "multimodal_input_service_stub.h"

#include <codecvt>
#include <locale>

#include "key_event.h"
#include "mmi_log.h"
#include "multimodal_input_errors.h"

namespace OHOS {
namespace {
const std::string PERMISSION_INPUT_ABILITY = "ohos.permission.MULTIMODAL_INPUT_ABILITY";
}

int MultimodalInputServiceStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    MMI_LOGD("OnReceived, cmd = %{public}u", code);
    if (!IsPermissionValid()) {
        MMI_LOGE("calling app not acquired multimodal permission");
        return MMI_PERMISSION_ERR;
    }

    std::u16string myDescripter = MultimodalInputServiceStub::GetDescriptor();
    std::u16string remoteDescripter = data.ReadInterfaceToken();
    if (myDescripter != remoteDescripter) {
        MMI_LOGE("descriptor checked fail");
        return MMI_BAD_TYPE;
    }

    switch (code) {
        case INJECT_EVENT: {
            int32_t type = data.ReadInt32();
            if (type == MultimodalEvent::KEYBOARD) {
                sptr<MultimodalEvent> event = data.ReadParcelable<KeyEvent>();
                return InjectEvent(event);
            }
            MMI_LOGE("recv bad type %{public}d", type);
            return MMI_BAD_TYPE;
        }
        default: {
            MMI_LOGE("default case, need check");
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
        }
    }
}

bool MultimodalInputServiceStub::IsPermissionValid()
{
    return true;
}
} // namespace OHOS
