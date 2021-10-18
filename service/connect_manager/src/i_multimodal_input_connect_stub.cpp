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

#include "i_multimodal_input_connect_stub.h"
#include <sys/types.h>
#include <sys/socket.h>
#include "ipc_skeleton.h"
#include "string_ex.h"
#include "log.h"
#include "multimodal_input_connect_define.h"

namespace OHOS {
namespace MMI {
    namespace {
        static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN,
                                                              "IMultimodalInputConnectStub" };
    }
int32_t IMultimodalInputConnectStub::OnRemoteRequest(
    uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option)
{
    MMI_LOGT("enter, code: %{public}d", code);

    std::u16string descriptor = data.ReadInterfaceToken();
    if (descriptor != IMultimodalInputConnect::GetDescriptor()) {
        MMI_LOGE("get unexpect descriptor: %{public}s", Str16ToStr8(descriptor).c_str());
        return ERR_INVALID_STATE;
    }

    int ret = RET_OK;
    switch (code) {
        case static_cast<uint32_t>(IMultimodalInputConnect::ALLOC_SOCKET_FD):
            MMI_LOGE("code = ALLOC_SOCKET_FD");
            ret = HandleAllocSocketFd(data, reply);
            break;
        default:
            MMI_LOGE("code != ALLOC_SOCKET_FD, go switch defaut");
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    return ret;
}

bool IMultimodalInputConnectStub::IsAuthorizedCalling() const
{
    int callingUid = IPCSkeleton::GetCallingUid();
    MMI_LOGIK("Calling uid: %{public}d", callingUid);
    return true;
}
} // namespace MMI
} // namespace OHOS