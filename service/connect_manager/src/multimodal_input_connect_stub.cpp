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

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "string_ex.h"

#include "error_multimodal.h"
#include "multimodal_input_connect_def_parcel.h"
#include "time_cost_chk.h"
#include "permission_helper.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "MultimodalInputConnectStub" };
} // namespace

int32_t MultimodalInputConnectStub::OnRemoteRequest(
    uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option)
{
    int32_t pid = GetCallingPid();
    TimeCostChk chk("IPC-OnRemoteRequest", "overtime 300(us)", MAX_OVER_TIME, pid,
        static_cast<int64_t>(code));
    MMI_HILOGD("RemoteRequest code:%{public}d tid:%{public}" PRIu64 " pid:%{public}d", code, GetThisThreadId(), pid);

    std::u16string descriptor = data.ReadInterfaceToken();
    if (descriptor != IMultimodalInputConnect::GetDescriptor()) {
        MMI_HILOGE("get unexpect descriptor:%{public}s", Str16ToStr8(descriptor).c_str());
        return ERR_INVALID_STATE;
    }
    switch (code) {
        case IMultimodalInputConnect::ALLOC_SOCKET_FD: {
            return StubHandleAllocSocketFd(data, reply);
        }
        case IMultimodalInputConnect::ADD_INPUT_EVENT_FILTER: {
            return StubAddInputEventFilter(data, reply);
        }
        case IMultimodalInputConnect::SET_POINTER_VISIBLE: {
            return StubSetPointerVisible(data, reply);
        }
        case IMultimodalInputConnect::IS_POINTER_VISIBLE: {
            return StubIsPointerVisible(data, reply);
        }
        case IMultimodalInputConnect::MARK_EVENT_PROCESSED: {
            return StubMarkEventProcessed(data, reply);
        }
        default: {
            MMI_HILOGE("unknown code:%{public}u, go switch default", code);
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
        }
    }
}

int32_t MultimodalInputConnectStub::StubHandleAllocSocketFd(MessageParcel& data, MessageParcel& reply)
{
    int32_t pid = GetCallingPid();
    if (!IsRunning()) {
        MMI_HILOGE("service is not running. pid:%{public}d, go switch default", pid);
        return MMISERVICE_NOT_RUNNING;
    }
    sptr<ConnectReqParcel> req = data.ReadParcelable<ConnectReqParcel>();
    CHKPR(req, ERROR_NULL_POINTER);
    MMI_HILOGD("clientName:%{public}s,moduleId:%{public}d", req->data.clientName.c_str(), req->data.moduleId);
    
    int32_t clientFd = INVALID_SOCKET_FD;
    int32_t ret = AllocSocketFd(req->data.clientName, req->data.moduleId, clientFd);
    if (ret != RET_OK) {
        MMI_HILOGE("AllocSocketFd failed pid:%{public}d, go switch default", pid);
        if (clientFd >= 0) {
            close(clientFd);
        }
        return ret;
    }
    reply.WriteFileDescriptor(clientFd);
    MMI_HILOGI("send clientFd to client, clientFd = %{public}d", clientFd);
    close(clientFd);
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubAddInputEventFilter(MessageParcel& data, MessageParcel& reply)
{
    CALL_LOG_ENTER;
    if (!PerHelper->CheckPermission(PermissionHelper::APL_SYSTEM_CORE)) {
        MMI_HILOGE("permission check fail");
        return CHECK_PERMISSION_FAIL;
    }

    sptr<IRemoteObject> client = data.ReadRemoteObject();
    CHKPR(client, ERR_INVALID_VALUE);
    sptr<IEventFilter> filter = iface_cast<IEventFilter>(client);
    CHKPR(filter, ERROR_NULL_POINTER);

    int32_t ret = AddInputEventFilter(filter);
    if (ret != RET_OK) {
        MMI_HILOGE("call AddInputEventFilter failed ret:%{public}d", ret);
        return ret;
    }
    MMI_HILOGD("success pid:%{public}d", GetCallingPid());
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubSetPointerVisible(MessageParcel& data, MessageParcel& reply)
{
    CALL_LOG_ENTER;
    if (!PerHelper->CheckPermission(PermissionHelper::APL_SYSTEM_BASIC_CORE)) {
        MMI_HILOGE("permission check fail");
        return CHECK_PERMISSION_FAIL;
    }

    bool visible = false;
    if (!data.ReadBool(visible)) {
        MMI_HILOGE("data ReadBool fail");
        return IPC_PROXY_DEAD_OBJECT_ERR;
    }
    int32_t ret = SetPointerVisible(visible);
    if (ret != RET_OK) {
        MMI_HILOGE("call SetPointerVisible failed ret:%{public}d", ret);
        return ret;
    }
    MMI_HILOGD("success visible:%{public}d,pid:%{public}d", visible, GetCallingPid());
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubIsPointerVisible(MessageParcel& data, MessageParcel& reply)
{
    CALL_LOG_ENTER;
    if (!PerHelper->CheckPermission(PermissionHelper::APL_SYSTEM_BASIC_CORE)) {
        MMI_HILOGE("permission check fail");
        return CHECK_PERMISSION_FAIL;
    }

    bool visible = false;
    int32_t ret = IsPointerVisible(visible);
    if (ret != RET_OK) {
        MMI_HILOGE("call IsPointerVisible failed ret:%{public}d", ret);
        return ret;
    }
    if (!reply.WriteBool(visible)) {
        MMI_HILOGE("WriteBool:%{public}d fail", ret);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    MMI_HILOGD("visible:%{public}d,ret:%{public}d,pid:%{public}d", visible, ret, GetCallingPid());
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubMarkEventProcessed(MessageParcel& data, MessageParcel& reply)
{
    CALL_LOG_ENTER;
    if (!IsRunning()) {
        MMI_HILOGE("service is not running");
        return MMISERVICE_NOT_RUNNING;
    }
    int32_t eventId;
    if (!data.ReadInt32(eventId)) {
        MMI_HILOGE("Read eventId failed");
        return IPC_PROXY_DEAD_OBJECT_ERR;
    }
    int32_t ret = MarkEventProcessed(eventId);
    if (ret != RET_OK) {
        MMI_HILOGE("MarkEventProcessed failed, ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}
} // namespace MMI
} // namespace OHOS