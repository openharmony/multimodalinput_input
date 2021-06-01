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

#include "multimodal_input_service_proxy.h"

#include <codecvt>
#include <locale>

#include "hilog/log.h"

namespace OHOS {
using namespace OHOS::HiviewDFX;

namespace {
    constexpr HiLogLabel LABEL = { LOG_CORE, 0xD002800, "MultimodalInputServiceProxy" };
}

MultimodalInputServiceProxy::MultimodalInputServiceProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IMultimodalInputService>(impl)
{
}

int32_t MultimodalInputServiceProxy::InjectEvent(const sptr<MultimodalEvent> &event)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    if (!data.WriteInterfaceToken(MultimodalInputServiceProxy::GetDescriptor())) {
        HiLog::Error(LABEL, "write descriptor fail");
        return ERR_INVALID_VALUE;
    }

    if (!data.WriteInt32(MultimodalEvent::KEYBOARD)) {
        HiLog::Error(LABEL, "write descriptor fail");
        return ERR_INVALID_VALUE;
    }

    if (!data.WriteParcelable(event)) {
        HiLog::Error(LABEL, "inject event fail, write event error");
        return ERR_INVALID_VALUE;
    }
    int error = Remote()->SendRequest(INJECT_EVENT, data, reply, option);
    if (error != ERR_NONE) {
        HiLog::Error(LABEL, "inject event fail, error: %{public}d", error);
    }
    return error;
}
} // namespace OHOS
