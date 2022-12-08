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

int32_t MultimodalInputConnectStub::OnRemoteRequest(uint32_t code, MessageParcel& data,
    MessageParcel& reply, MessageOption& option)
{
    int32_t pid = GetCallingPid();
    TimeCostChk chk("IPC-OnRemoteRequest", "overtime 300(us)", MAX_OVER_TIME, pid,
        static_cast<int64_t>(code));
    MMI_HILOGD("RemoteRequest code:%{public}d tid:%{public}" PRIu64 " pid:%{public}d", code, GetThisThreadId(), pid);

    std::u16string descriptor = data.ReadInterfaceToken();
    if (descriptor != IMultimodalInputConnect::GetDescriptor()) {
        MMI_HILOGE("Get unexpect descriptor:%{public}s", Str16ToStr8(descriptor).c_str());
        return ERR_INVALID_STATE;
    }
    const static std::map<int32_t, ConnFunc> mapConnFunc = {
        {IMultimodalInputConnect::ALLOC_SOCKET_FD, &MultimodalInputConnectStub::StubHandleAllocSocketFd},
        {IMultimodalInputConnect::ADD_INPUT_EVENT_FILTER, &MultimodalInputConnectStub::StubAddInputEventFilter},
        {IMultimodalInputConnect::SET_POINTER_VISIBLE, &MultimodalInputConnectStub::StubSetPointerVisible},
        {IMultimodalInputConnect::SET_POINTER_STYLE, &MultimodalInputConnectStub::StubSetPointerStyle},
        {IMultimodalInputConnect::GET_POINTER_STYLE, &MultimodalInputConnectStub::StubGetPointerStyle},
        {IMultimodalInputConnect::IS_POINTER_VISIBLE, &MultimodalInputConnectStub::StubIsPointerVisible},
        {IMultimodalInputConnect::REGISTER_DEV_MONITOR, &MultimodalInputConnectStub::StubRegisterInputDeviceMonitor},
        {IMultimodalInputConnect::UNREGISTER_DEV_MONITOR,
            &MultimodalInputConnectStub::StubUnregisterInputDeviceMonitor},
        {IMultimodalInputConnect::GET_DEVICE_IDS, &MultimodalInputConnectStub::StubGetDeviceIds},
        {IMultimodalInputConnect::GET_DEVICE, &MultimodalInputConnectStub::StubGetDevice},
        {IMultimodalInputConnect::SUPPORT_KEYS, &MultimodalInputConnectStub::StubSupportKeys},
        {IMultimodalInputConnect::GET_KEYBOARD_TYPE, &MultimodalInputConnectStub::StubGetKeyboardType},
        {IMultimodalInputConnect::SET_POINTER_SPEED, &MultimodalInputConnectStub::StubSetPointerSpeed},
        {IMultimodalInputConnect::GET_POINTER_SPEED, &MultimodalInputConnectStub::StubGetPointerSpeed},
        {IMultimodalInputConnect::SUBSCRIBE_KEY_EVENT, &MultimodalInputConnectStub::StubSubscribeKeyEvent},
        {IMultimodalInputConnect::UNSUBSCRIBE_KEY_EVENT, &MultimodalInputConnectStub::StubUnsubscribeKeyEvent},
        {IMultimodalInputConnect::ADD_INPUT_HANDLER, &MultimodalInputConnectStub::StubAddInputHandler},
        {IMultimodalInputConnect::REMOVE_INPUT_HANDLER, &MultimodalInputConnectStub::StubRemoveInputHandler},
        {IMultimodalInputConnect::MARK_EVENT_CONSUMED, &MultimodalInputConnectStub::StubMarkEventConsumed},
        {IMultimodalInputConnect::MOVE_MOUSE, &MultimodalInputConnectStub::StubMoveMouseEvent},
        {IMultimodalInputConnect::INJECT_KEY_EVENT, &MultimodalInputConnectStub::StubInjectKeyEvent},
        {IMultimodalInputConnect::INJECT_POINTER_EVENT, &MultimodalInputConnectStub::StubInjectPointerEvent},
        {IMultimodalInputConnect::SET_ANR_OBSERVER, &MultimodalInputConnectStub::StubSetAnrListener},
        {IMultimodalInputConnect::REGISTER_COOPERATE_MONITOR,
            &MultimodalInputConnectStub::StubRegisterCooperateMonitor},
        {IMultimodalInputConnect::UNREGISTER_COOPERATE_MONITOR,
            &MultimodalInputConnectStub::StubUnregisterCooperateMonitor},
        {IMultimodalInputConnect::ENABLE_INPUT_DEVICE_COOPERATE,
            &MultimodalInputConnectStub::StubEnableInputDeviceCooperate},
        {IMultimodalInputConnect::START_INPUT_DEVICE_COOPERATE,
            &MultimodalInputConnectStub::StubStartInputDeviceCooperate},
        {IMultimodalInputConnect::STOP_DEVICE_COOPERATE, &MultimodalInputConnectStub::StubStopDeviceCooperate},
        {IMultimodalInputConnect::GET_INPUT_DEVICE_COOPERATE_STATE,
            &MultimodalInputConnectStub::StubGetInputDeviceCooperateState},
        {IMultimodalInputConnect::SET_INPUT_DEVICE_TO_SCREEN, &MultimodalInputConnectStub::StubSetInputDevice},
        {IMultimodalInputConnect::GET_FUNCTION_KEY_STATE, &MultimodalInputConnectStub::StubGetFunctionKeyState},
        {IMultimodalInputConnect::SET_FUNCTION_KEY_STATE, &MultimodalInputConnectStub::StubSetFunctionKeyState}
    };
    auto it = mapConnFunc.find(code);
    if (it != mapConnFunc.end()) {
        return (this->*it->second)(data, reply);
    }
    MMI_HILOGE("Unknown code:%{public}u, go switch default", code);
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t MultimodalInputConnectStub::StubHandleAllocSocketFd(MessageParcel& data, MessageParcel& reply)
{
    int32_t pid = GetCallingPid();
    if (!IsRunning()) {
        MMI_HILOGE("Service is not running. pid:%{public}d, go switch default", pid);
        return MMISERVICE_NOT_RUNNING;
    }
    sptr<ConnectReqParcel> req = data.ReadParcelable<ConnectReqParcel>();
    CHKPR(req, ERROR_NULL_POINTER);
    MMI_HILOGD("clientName:%{public}s,moduleId:%{public}d", req->data.clientName.c_str(), req->data.moduleId);

    int32_t clientFd = INVALID_SOCKET_FD;
    int32_t tokenType = PerHelper->GetTokenType();
    int32_t ret = AllocSocketFd(req->data.clientName, req->data.moduleId, clientFd, tokenType);
    if (ret != RET_OK) {
        MMI_HILOGE("AllocSocketFd failed pid:%{public}d, go switch default", pid);
        if (clientFd >= 0) {
            close(clientFd);
        }
        return ret;
    }
    reply.WriteFileDescriptor(clientFd);
    WRITEINT32(reply, tokenType, IPC_STUB_WRITE_PARCEL_ERR);
    MMI_HILOGI("Send clientFd to client, clientFd:%{public}d, tokenType:%{public}d", clientFd, tokenType);
    close(clientFd);
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubAddInputEventFilter(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!PerHelper->CheckPermission(PermissionHelper::APL_SYSTEM_CORE)) {
        MMI_HILOGE("Permission check failed");
        return CHECK_PERMISSION_FAIL;
    }

    sptr<IRemoteObject> client = data.ReadRemoteObject();
    CHKPR(client, ERR_INVALID_VALUE);
    sptr<IEventFilter> filter = iface_cast<IEventFilter>(client);
    CHKPR(filter, ERROR_NULL_POINTER);

    int32_t ret = AddInputEventFilter(filter);
    if (ret != RET_OK) {
        MMI_HILOGE("Call AddInputEventFilter failed ret:%{public}d", ret);
        return ret;
    }
    MMI_HILOGD("Success pid:%{public}d", GetCallingPid());
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubSetPointerVisible(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    bool visible = false;
    READBOOL(data, visible, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t ret = SetPointerVisible(visible);
    if (ret != RET_OK) {
        MMI_HILOGE("Call SetPointerVisible failed ret:%{public}d", ret);
        return ret;
    }
    MMI_HILOGD("Success visible:%{public}d,pid:%{public}d", visible, GetCallingPid());
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubIsPointerVisible(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    bool visible = false;
    int32_t ret = IsPointerVisible(visible);
    if (ret != RET_OK) {
        MMI_HILOGE("Call IsPointerVisible failed ret:%{public}d", ret);
        return ret;
    }
    WRITEBOOL(reply, visible, IPC_STUB_WRITE_PARCEL_ERR);
    MMI_HILOGD("visible:%{public}d,ret:%{public}d,pid:%{public}d", visible, ret, GetCallingPid());
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubSetPointerSpeed(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!PerHelper->CheckPermission(PermissionHelper::APL_SYSTEM_BASIC_CORE)) {
        MMI_HILOGE("Permission check failed");
        return CHECK_PERMISSION_FAIL;
    }
    int32_t speed;
    READINT32(data, speed, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t ret = SetPointerSpeed(speed);
    if (ret != RET_OK) {
        MMI_HILOGE("Set pointer speed failed ret:%{public}d", ret);
        return RET_ERR;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubGetPointerSpeed(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!PerHelper->CheckPermission(PermissionHelper::APL_SYSTEM_BASIC_CORE)) {
        MMI_HILOGE("Permission check failed");
        return CHECK_PERMISSION_FAIL;
    }
    int32_t speed;
    int32_t ret = GetPointerSpeed(speed);
    if (ret != RET_OK) {
        MMI_HILOGE("Call get pointer speed failed ret:%{public}d", ret);
        return RET_ERR;
    }
    WRITEINT32(reply, speed, IPC_STUB_WRITE_PARCEL_ERR);
    MMI_HILOGD("Pointer speed:%{public}d,ret:%{public}d", speed, ret);
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubSetPointerStyle(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    int32_t windowId;
    READINT32(data, windowId, RET_ERR);
    int32_t pointerStyle;
    READINT32(data, pointerStyle, RET_ERR);
    int32_t ret = SetPointerStyle(windowId, pointerStyle);
    if (ret != RET_OK) {
        MMI_HILOGE("Call SetPointerStyle failed ret:%{public}d", ret);
        return ret;
    }
    MMI_HILOGD("Successfully set window:%{public}d, icon:%{public}d", windowId, pointerStyle);
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubGetPointerStyle(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    int32_t windowId;
    READINT32(data, windowId, RET_ERR);
    int32_t pointerStyle;
    int32_t ret = GetPointerStyle(windowId, pointerStyle);
    if (ret != RET_OK) {
        MMI_HILOGE("Call GetPointerStyle failed ret:%{public}d", ret);
        return ret;
    }
    WRITEINT32(reply, pointerStyle, RET_ERR);
    MMI_HILOGD("Successfully get window:%{public}d, icon:%{public}d", windowId, pointerStyle);
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubSupportKeys(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    int32_t userData = 0;
    READINT32(data, userData, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t deviceId = -1;
    READINT32(data, deviceId, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t size = 0;
    READINT32(data, size, IPC_PROXY_DEAD_OBJECT_ERR);
    std::vector<int32_t> keys;
    int32_t key = 0;
    for (int32_t i = 0; i < size; ++i) {
        READINT32(data, key, IPC_PROXY_DEAD_OBJECT_ERR);
        keys.push_back(key);
    }
    int32_t ret = SupportKeys(userData, deviceId, keys);
    if (ret != RET_OK) {
        MMI_HILOGE("Call SupportKeys failed ret:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectStub::StubGetDeviceIds(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    int32_t userData = 0;
    READINT32(data, userData, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t ret = GetDeviceIds(userData);
    if (ret != RET_OK) {
        MMI_HILOGE("Call GetDeviceIds failed ret:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectStub::StubGetDevice(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    int32_t userData = 0;
    READINT32(data, userData, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t deviceId = -1;
    READINT32(data, deviceId, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t ret = GetDevice(userData, deviceId);
    if (ret != RET_OK) {
        MMI_HILOGE("Call GetDevice failed ret:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectStub::StubRegisterInputDeviceMonitor(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    int32_t ret = RegisterDevListener();
    if (ret != RET_OK) {
        MMI_HILOGE("Call RegisterInputDeviceMonitor failed ret:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectStub::StubUnregisterInputDeviceMonitor(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    int32_t ret = UnregisterDevListener();
    if (ret != RET_OK) {
        MMI_HILOGE("Call UnregisterInputDeviceMonitor failed ret:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectStub::StubGetKeyboardType(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    int32_t userData = 0;
    READINT32(data, userData, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t deviceId = -1;
    READINT32(data, deviceId, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t ret = GetKeyboardType(userData, deviceId);
    if (ret != RET_OK) {
        MMI_HILOGE("Call GetKeyboardType failed ret:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectStub::StubAddInputHandler(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
        return MMISERVICE_NOT_RUNNING;
    }
    int32_t handlerType;
    READINT32(data, handlerType, IPC_PROXY_DEAD_OBJECT_ERR);
    if ((handlerType == InputHandlerType::INTERCEPTOR) &&
        (!PerHelper->CheckPermission(PermissionHelper::APL_SYSTEM_BASIC_CORE))) {
        MMI_HILOGE("Interceptor permission check failed");
        return CHECK_PERMISSION_FAIL;
    }
    if ((handlerType == InputHandlerType::MONITOR) && (!PerHelper->CheckMonitor())) {
        MMI_HILOGE("Monitor permission check failed");
        return ERROR_NO_PERMISSION;
    }
    uint32_t eventType;
    READUINT32(data, eventType, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t ret = AddInputHandler(static_cast<InputHandlerType>(handlerType), eventType);
    if (ret != RET_OK) {
        MMI_HILOGE("Call AddInputHandler failed ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubRemoveInputHandler(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
        return MMISERVICE_NOT_RUNNING;
    }
    int32_t handlerType;
    READINT32(data, handlerType, IPC_PROXY_DEAD_OBJECT_ERR);
    if ((handlerType == InputHandlerType::INTERCEPTOR) &&
        (!PerHelper->CheckPermission(PermissionHelper::APL_SYSTEM_BASIC_CORE))) {
        MMI_HILOGE("Interceptor permission check failed");
        return CHECK_PERMISSION_FAIL;
    }
    if ((handlerType == InputHandlerType::MONITOR) && (!PerHelper->CheckMonitor())) {
        MMI_HILOGE("Monitor permission check failed");
        return CHECK_PERMISSION_FAIL;
    }
    uint32_t eventType;
    READUINT32(data, eventType, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t ret = RemoveInputHandler(static_cast<InputHandlerType>(handlerType), eventType);
    if (ret != RET_OK) {
        MMI_HILOGE("Call RemoveInputHandler failed ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubMarkEventConsumed(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!PerHelper->CheckMonitor()) {
        MMI_HILOGE("Permission check failed");
        return CHECK_PERMISSION_FAIL;
    }

    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
        return MMISERVICE_NOT_RUNNING;
    }
    int32_t eventId;
    READINT32(data, eventId, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t ret = MarkEventConsumed(eventId);
    if (ret != RET_OK) {
        MMI_HILOGE("Call MarkEventConsumed failed ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubSubscribeKeyEvent(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!PerHelper->CheckPermission(PermissionHelper::APL_SYSTEM_BASIC_CORE)) {
        MMI_HILOGE("Permission check failed");
        return CHECK_PERMISSION_FAIL;
    }

    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
        return MMISERVICE_NOT_RUNNING;
    }

    int32_t subscribeId;
    READINT32(data, subscribeId, IPC_PROXY_DEAD_OBJECT_ERR);

    auto keyOption = std::make_shared<KeyOption>();
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
    CALL_DEBUG_ENTER;
    if (!PerHelper->CheckPermission(PermissionHelper::APL_SYSTEM_BASIC_CORE)) {
        MMI_HILOGE("Permission check failed");
        return CHECK_PERMISSION_FAIL;
    }

    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
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
    CALL_DEBUG_ENTER;
    if (!PerHelper->CheckPermission(PermissionHelper::APL_SYSTEM_BASIC_CORE)) {
        MMI_HILOGE("Permission check failed");
        return CHECK_PERMISSION_FAIL;
    }

    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
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
    CALL_DEBUG_ENTER;
    if (!PerHelper->CheckPermission(PermissionHelper::APL_SYSTEM_BASIC_CORE)) {
        MMI_HILOGE("Permission check failed");
        return CHECK_PERMISSION_FAIL;
    }
    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
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
    CALL_DEBUG_ENTER;
    if (!PerHelper->CheckPermission(PermissionHelper::APL_SYSTEM_BASIC_CORE)) {
        MMI_HILOGE("Permission check failed");
        return CHECK_PERMISSION_FAIL;
    }
    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
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
        MMI_HILOGE("Call InjectPointerEvent failed ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubSetAnrListener(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!PerHelper->CheckPermission(PermissionHelper::APL_SYSTEM_BASIC_CORE)) {
        MMI_HILOGE("Permission check failed");
        return CHECK_PERMISSION_FAIL;
    }
    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
        return MMISERVICE_NOT_RUNNING;
    }
    int32_t ret = SetAnrObserver();
    if (ret != RET_OK) {
        MMI_HILOGE("Call SetAnrObserver failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectStub::StubRegisterCooperateMonitor(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!PerHelper->CheckPermission(PermissionHelper::APL_SYSTEM_BASIC_CORE)) {
        MMI_HILOGE("Permission check failed");
        return CHECK_PERMISSION_FAIL;
    }
    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
        return MMISERVICE_NOT_RUNNING;
    }
    int32_t ret = RegisterCooperateListener();
    if (ret != RET_OK) {
        MMI_HILOGE("Call RegisterCooperateEvent failed ret:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectStub::StubUnregisterCooperateMonitor(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!PerHelper->CheckPermission(PermissionHelper::APL_SYSTEM_BASIC_CORE)) {
        MMI_HILOGE("Permission check failed");
        return CHECK_PERMISSION_FAIL;
    }
    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
        return MMISERVICE_NOT_RUNNING;
    }
    int32_t ret = UnregisterCooperateListener();
    if (ret != RET_OK) {
        MMI_HILOGE("Call RegisterCooperateEvent failed ret:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectStub::StubEnableInputDeviceCooperate(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!PerHelper->CheckPermission(PermissionHelper::APL_SYSTEM_BASIC_CORE)) {
        MMI_HILOGE("Permission check failed");
        return CHECK_PERMISSION_FAIL;
    }
    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
        return MMISERVICE_NOT_RUNNING;
    }
    int32_t userData;
    bool enabled;
    READINT32(data, userData, IPC_PROXY_DEAD_OBJECT_ERR);
    READBOOL(data, enabled, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t ret = EnableInputDeviceCooperate(userData, enabled);
    if (ret != RET_OK) {
        MMI_HILOGE("Call RegisterCooperateEvent failed ret:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectStub::StubStartInputDeviceCooperate(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!PerHelper->CheckPermission(PermissionHelper::APL_SYSTEM_BASIC_CORE)) {
        MMI_HILOGE("Permission check failed");
        return CHECK_PERMISSION_FAIL;
    }
    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
        return MMISERVICE_NOT_RUNNING;
    }
    int32_t userData;
    READINT32(data, userData, IPC_PROXY_DEAD_OBJECT_ERR);
    std::string sinkDeviceId;
    READSTRING(data, sinkDeviceId, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t srcInputDeviceId;
    READINT32(data, srcInputDeviceId, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t ret = StartInputDeviceCooperate(userData, sinkDeviceId, srcInputDeviceId);
    if (ret != RET_OK) {
        MMI_HILOGE("Call StartInputDeviceCooperate failed ret:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectStub::StubStopDeviceCooperate(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!PerHelper->CheckPermission(PermissionHelper::APL_SYSTEM_BASIC_CORE)) {
        MMI_HILOGE("Permission check failed");
        return CHECK_PERMISSION_FAIL;
    }
    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
        return MMISERVICE_NOT_RUNNING;
    }
    int32_t userData;
    READINT32(data, userData, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t ret = StopDeviceCooperate(userData);
    if (ret != RET_OK) {
        MMI_HILOGE("Call RegisterCooperateEvent failed ret:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectStub::StubGetInputDeviceCooperateState(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!PerHelper->CheckPermission(PermissionHelper::APL_SYSTEM_BASIC_CORE)) {
        MMI_HILOGE("Permission check failed");
        return CHECK_PERMISSION_FAIL;
    }
    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
        return MMISERVICE_NOT_RUNNING;
    }
    int32_t userData;
    READINT32(data, userData, IPC_PROXY_DEAD_OBJECT_ERR);
    std::string deviceId;
    READSTRING(data, deviceId, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t ret = GetInputDeviceCooperateState(userData, deviceId);
    if (ret != RET_OK) {
        MMI_HILOGE("Call RegisterCooperateEvent failed ret:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectStub::StubSetInputDevice(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!PerHelper->CheckPermission(PermissionHelper::APL_SYSTEM_BASIC_CORE)) {
        MMI_HILOGE("Permission check failed");
        return CHECK_PERMISSION_FAIL;
    }
    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
        return MMISERVICE_NOT_RUNNING;
    }
    std::string dhid;
    READSTRING(data, dhid, IPC_PROXY_DEAD_OBJECT_ERR);
    std::string screenId;
    READSTRING(data, screenId, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t ret = SetInputDevice(dhid, screenId);
    if (ret != RET_OK) {
        MMI_HILOGE("Call SetInputDevice failed ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubGetFunctionKeyState(MessageParcel &data, MessageParcel &reply)
{
    CALL_DEBUG_ENTER;
    if (!PerHelper->CheckPermission(PermissionHelper::APL_SYSTEM_BASIC_CORE)) {
        MMI_HILOGE("Permission check failed");
        return CHECK_PERMISSION_FAIL;
    }
    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
        return MMISERVICE_NOT_RUNNING;
    }

    int32_t funcKey { 0 };
    bool state  { false };
    READINT32(data, funcKey, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t ret = GetFunctionKeyState(funcKey, state);
    if (ret != RET_OK) {
        MMI_HILOGE("Call GetKeyboardEnableState failed ret:%{public}d", ret);
        return ret;
    }

    WRITEBOOL(reply, state, IPC_PROXY_DEAD_OBJECT_ERR);
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubSetFunctionKeyState(MessageParcel &data, MessageParcel &reply)
{
    CALL_DEBUG_ENTER;
    if (!PerHelper->CheckPermission(PermissionHelper::APL_SYSTEM_BASIC_CORE)) {
        MMI_HILOGE("Permission check failed");
        return CHECK_PERMISSION_FAIL;
    }
    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
        return MMISERVICE_NOT_RUNNING;
    }

    int32_t funcKey { 0 };
    bool enable  { false };
    READINT32(data, funcKey, IPC_PROXY_DEAD_OBJECT_ERR);
    READBOOL(data, enable, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t ret = SetFunctionKeyState(funcKey, enable);
    if (ret != RET_OK) {
        MMI_HILOGE("Call SetFunctionKeyState failed ret:%{public}d", ret);
    }
    return ret;
}
} // namespace MMI
} // namespace OHOS
