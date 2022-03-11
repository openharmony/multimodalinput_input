/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "multimodal_input_connect_stub.h"

#include <sys/types.h>
#include <sys/socket.h>

#include "string_ex.h"

#include "error_multimodal.h"
#include "mmi_log.h"
#include "multimodal_input_connect_define.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "MultimodalInputConnectStub" };
} // namespace

int32_t MultimodalInputConnectStub::OnRemoteRequest(
    uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option)
{
    CALL_LOG_ENTER;
    MMI_LOGD("request ode:%{public}d", code);

    std::u16string descriptor = data.ReadInterfaceToken();
    if (descriptor != IMultimodalInputConnect::GetDescriptor()) {
        MMI_LOGE("get unexpect descriptor:%{public}s", Str16ToStr8(descriptor).c_str());
        return ERR_INVALID_STATE;
    }

    switch (code) {
        case IMultimodalInputConnect::ALLOC_SOCKET_FD:
            return StubHandleAllocSocketFd(data, reply);
        case IMultimodalInputConnect::SET_EVENT_POINTER_FILTER:
            return StubAddInputEventFilter(data, reply);
        default:
            MMI_LOGE("unknown code:%{public}u, go switch defaut", code);
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
}

int32_t MultimodalInputConnectStub::StubAddInputEventFilter(MessageParcel& data, MessageParcel& reply)
{
    CALL_LOG_ENTER;
    int32_t ret = RET_OK;

    do {
        const int32_t uid = IPCSkeleton::GetCallingUid();
        if (uid != SYSTEM_UID && uid != ROOT_UID) {
            MMI_LOGE("check failed, uid is not root or system");
            ret = SASERVICE_PERMISSION_FAIL;
            break;
        }

        sptr<IRemoteObject> client = data.ReadRemoteObject();
        if (client == nullptr) {
            MMI_LOGE("mouse client is nullptr");
            ret = ERR_INVALID_VALUE;
            break;
        }

        sptr<IEventFilter> filter = iface_cast<IEventFilter>(client);
        if (filter == nullptr) {
            MMI_LOGE("filter is nullptr");
            ret = ERROR_NULL_POINTER;
            break;
        }

        MMI_LOGD("filter iface_cast succeeded");

        ret = AddInputEventFilter(filter);
    } while (0);
    
    if (!reply.WriteInt32(ret)) {
        MMI_LOGE("WriteInt32:%{public}d fail", ret);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }

    MMI_LOGD("ret:%{public}d", ret);
    return RET_OK;
}
} // namespace MMI
} // namespace OHOS