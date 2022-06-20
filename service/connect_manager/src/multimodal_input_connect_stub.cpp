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
using ConnFunc = int32_t (MultimodalInputConnectStub::*)(MessageParcel& data, MessageParcel& reply);
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
    const static std::map<int32_t, ConnFunc> mapConnFunc = {
        {IMultimodalInputConnect::ALLOC_SOCKET_FD, &MultimodalInputConnectStub::StubHandleAllocSocketFd},
        {IMultimodalInputConnect::ADD_INPUT_EVENT_FILTER, &MultimodalInputConnectStub::StubAddInputEventFilter},
        {IMultimodalInputConnect::SET_POINTER_VISIBLE, &MultimodalInputConnectStub::StubSetPointerVisible},
        {IMultimodalInputConnect::IS_POINTER_VISIBLE, &MultimodalInputConnectStub::StubIsPointerVisible},
        {IMultimodalInputConnect::SUBSCRIBE_KEY_EVENT, &MultimodalInputConnectStub::StubSubscribeKeyEvent},
        {IMultimodalInputConnect::UNSUBSCRIBE_KEY_EVENT, &MultimodalInputConnectStub::StubUnsubscribeKeyEvent},
        {IMultimodalInputConnect::MARK_EVENT_PROCESSED, &MultimodalInputConnectStub::StubMarkEventProcessed},
        {IMultimodalInputConnect::ADD_INPUT_HANDLER, &MultimodalInputConnectStub::StubAddInputHandler},
        {IMultimodalInputConnect::REMOVE_INPUT_HANDLER, &MultimodalInputConnectStub::StubRemoveInputHandler},
        {IMultimodalInputConnect::MARK_EVENT_CONSUMED, &MultimodalInputConnectStub::StubMarkEventConsumed},
        {IMultimodalInputConnect::MOVE_MOUSE, &MultimodalInputConnectStub::StubMoveMouseEvent},
        {IMultimodalInputConnect::INJECT_KEY_EVENT, &MultimodalInputConnectStub::StubInjectKeyEvent},
        {IMultimodalInputConnect::INJECT_POINTER_EVENT, &MultimodalInputConnectStub::StubInjectPointerEvent}
    };
    auto it = mapConnFunc.find(code);
    if (it != mapConnFunc.end()) {
        return (this->*it->second)(data, reply);
    }
    MMI_HILOGE("unknown code:%{public}u, go switch default", code);
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
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
    READBOOL(data, visible, IPC_PROXY_DEAD_OBJECT_ERR);
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
    WRITEBOOL(reply, visible, IPC_STUB_WRITE_PARCEL_ERR);
    MMI_HILOGD("visible:%{public}d,ret:%{public}d,pid:%{public}d", visible, ret, GetCallingPid());
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubMarkEventProcessed(MessageParcel& data, MessageParcel& reply)
{
    CALL_LOG_ENTER;
    if (!IsRunning()) {
        MMI_HILOGE("service is not running");
    }
    int32_t eventId;
    READINT32(data, eventId, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t ret = MarkEventProcessed(eventId);
    if (ret != RET_OK) {
        MMI_HILOGE("MarkEventProcessed failed, ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubAddInputHandler(MessageParcel& data, MessageParcel& reply)
{
    CALL_LOG_ENTER;
    if (!IsRunning()) {
        MMI_HILOGE("service is not running");
        return MMISERVICE_NOT_RUNNING;
    }
    int32_t handlerId;
    READINT32(data, handlerId, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t handlerType;
    READINT32(data, handlerType, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t eventType;
    READINT32(data, eventType, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t ret = AddInputHandler(handlerId, static_cast<InputHandlerType>(handlerType),
        static_cast<HandleEventType>(eventType));
    if (ret != RET_OK) {
        MMI_HILOGE("call AddInputHandler failed ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubRemoveInputHandler(MessageParcel& data, MessageParcel& reply)
{
    CALL_LOG_ENTER;
    if (!IsRunning()) {
        MMI_HILOGE("service is not running");
        return MMISERVICE_NOT_RUNNING;
    }
    int32_t handlerId;
    READINT32(data, handlerId, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t handlerType;
    READINT32(data, handlerType, IPC_PROXY_DEAD_OBJECT_ERR);
    if ((handlerType == InputHandlerType::INTERCEPTOR) &&
        (!PerHelper->CheckPermission(PermissionHelper::APL_SYSTEM_CORE))) {
        MMI_HILOGE("interceptor permission check fail");
        return CHECK_PERMISSION_FAIL;
    }
    if ((handlerType == InputHandlerType::MONITOR) && (!PerHelper->CheckMonitor())) {
        MMI_HILOGE("monitor permission check fail");
        return CHECK_PERMISSION_FAIL;
    }
    int32_t ret = RemoveInputHandler(handlerId, static_cast<InputHandlerType>(handlerType));
    if (ret != RET_OK) {
        MMI_HILOGE("call RemoveInputHandler failed ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubMarkEventConsumed(MessageParcel& data, MessageParcel& reply)
{
    CALL_LOG_ENTER;
    if (!PerHelper->CheckMonitor()) {
        MMI_HILOGE("permission check fail");
        return CHECK_PERMISSION_FAIL;
    }

    if (!IsRunning()) {
        MMI_HILOGE("service is not running");
        return MMISERVICE_NOT_RUNNING;
    }
    int32_t monitorId;
    READINT32(data, monitorId, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t eventId;
    READINT32(data, eventId, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t ret = MarkEventConsumed(monitorId, eventId);
    if (ret != RET_OK) {
        MMI_HILOGE("call MarkEventConsumed failed ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubSubscribeKeyEvent(MessageParcel& data, MessageParcel& reply)
{
    CALL_LOG_ENTER;
    if (!IsRunning()) {
        MMI_HILOGE("service is not running");
        return MMISERVICE_NOT_RUNNING;
    }

    int32_t subscribeId;
    READINT32(data, subscribeId, IPC_PROXY_DEAD_OBJECT_ERR);

    auto keyOption = std::make_shared<KeyOption>();
    CHKPR(keyOption, IPC_STUB_WRITE_PARCEL_ERR);
    if (!keyOption->ReadFromParcel(data)) {
        MMI_HILOGE("Read keyOption failed");
        return IPC_PROXY_DEAD_OBJECT_ERR;
    }
    int32_t ret = SubscribeKeyEvent(subscribeId, keyOption);
    if (ret != RET_OK) {
        MMI_HILOGE("SubscribeKeyEvent failed, ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubUnsubscribeKeyEvent(MessageParcel& data, MessageParcel& reply)
{
    CALL_LOG_ENTER;
    if (!IsRunning()) {
        MMI_HILOGE("service is not running");
        return MMISERVICE_NOT_RUNNING;
    }

    int32_t subscribeId;
    READINT32(data, subscribeId, IPC_PROXY_DEAD_OBJECT_ERR);

    int32_t ret = UnsubscribeKeyEvent(subscribeId);
    if (ret != RET_OK) {
        MMI_HILOGE("UnsubscribeKeyEvent failed, ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubMoveMouseEvent(MessageParcel& data, MessageParcel& reply)
{
    CALL_LOG_ENTER;
    if (!IsRunning()) {
        MMI_HILOGE("service is not running");
        return MMISERVICE_NOT_RUNNING;
    }
    int32_t offsetX;
    READINT32(data, offsetX, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t offsetY;
    READINT32(data, offsetY, IPC_PROXY_DEAD_OBJECT_ERR);

    int32_t ret = MoveMouseEvent(offsetX, offsetY);
    if (ret != RET_OK) {
        MMI_HILOGE("MoveMouseEvent failed, ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubInjectKeyEvent(MessageParcel& data, MessageParcel& reply)
{
    CALL_LOG_ENTER;
    if (!IsRunning()) {
        MMI_HILOGE("service is not running");
        return MMISERVICE_NOT_RUNNING;
    }
    auto event = KeyEvent::Create();
    CHKPR(event, ERROR_NULL_POINTER);
    if (!event->ReadFromParcel(data)) {
        MMI_HILOGE("Read Key Event failed");
        return IPC_PROXY_DEAD_OBJECT_ERR;
    }
    int32_t ret = InjectKeyEvent(event);
    if (ret != RET_OK) {
        MMI_HILOGE("InjectKeyEvent failed, ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubInjectPointerEvent(MessageParcel& data, MessageParcel& reply)
{
    CALL_LOG_ENTER;
    if (!IsRunning()) {
        MMI_HILOGE("service is not running");
        return MMISERVICE_NOT_RUNNING;
    }
    auto pointerEvent = PointerEvent::Create();
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    if (!pointerEvent->ReadFromParcel(data)) {
        MMI_HILOGE("Read Pointer Event failed");
        return IPC_PROXY_DEAD_OBJECT_ERR;
    }
    int32_t ret = InjectPointerEvent(pointerEvent);
    if (ret != RET_OK) {
        MMI_HILOGE("call InjectPointerEvent failed ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}
} // namespace MMI
} // namespace OHOS