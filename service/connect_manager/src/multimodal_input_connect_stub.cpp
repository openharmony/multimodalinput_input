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

#include "multimodal_input_connect_stub.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include "string_ex.h"

#include "error_multimodal.h"
#include "multimodal_input_connect_def_parcel.h"
#include "permission_helper.h"
#include "time_cost_chk.h"

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
        {IMultimodalInputConnect::RMV_INPUT_EVENT_FILTER, &MultimodalInputConnectStub::StubRemoveInputEventFilter},
        {IMultimodalInputConnect::SET_MOUSE_SCROLL_ROWS, &MultimodalInputConnectStub::StubSetMouseScrollRows},
        {IMultimodalInputConnect::GET_MOUSE_SCROLL_ROWS, &MultimodalInputConnectStub::StubGetMouseScrollRows},
        {IMultimodalInputConnect::SET_MOUSE_PRIMARY_BUTTON, &MultimodalInputConnectStub::StubSetMousePrimaryButton},
        {IMultimodalInputConnect::GET_MOUSE_PRIMARY_BUTTON, &MultimodalInputConnectStub::StubGetMousePrimaryButton},
        {IMultimodalInputConnect::SET_HOVER_SCROLL_STATE, &MultimodalInputConnectStub::StubSetHoverScrollState},
        {IMultimodalInputConnect::GET_HOVER_SCROLL_STATE, &MultimodalInputConnectStub::StubGetHoverScrollState},
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
        {IMultimodalInputConnect::SUBSCRIBE_SWITCH_EVENT, &MultimodalInputConnectStub::StubSubscribeSwitchEvent},
        {IMultimodalInputConnect::UNSUBSCRIBE_SWITCH_EVENT, &MultimodalInputConnectStub::StubUnsubscribeSwitchEvent},
        {IMultimodalInputConnect::MARK_PROCESSED, &MultimodalInputConnectStub::StubMarkProcessed},
        {IMultimodalInputConnect::ADD_INPUT_HANDLER, &MultimodalInputConnectStub::StubAddInputHandler},
        {IMultimodalInputConnect::REMOVE_INPUT_HANDLER, &MultimodalInputConnectStub::StubRemoveInputHandler},
        {IMultimodalInputConnect::MARK_EVENT_CONSUMED, &MultimodalInputConnectStub::StubMarkEventConsumed},
        {IMultimodalInputConnect::MOVE_MOUSE, &MultimodalInputConnectStub::StubMoveMouseEvent},
        {IMultimodalInputConnect::INJECT_KEY_EVENT, &MultimodalInputConnectStub::StubInjectKeyEvent},
        {IMultimodalInputConnect::INJECT_POINTER_EVENT, &MultimodalInputConnectStub::StubInjectPointerEvent},
        {IMultimodalInputConnect::SET_ANR_OBSERVER, &MultimodalInputConnectStub::StubSetAnrListener},
        {IMultimodalInputConnect::GET_DISPLAY_BIND_INFO, &MultimodalInputConnectStub::StubGetDisplayBindInfo},
        {IMultimodalInputConnect::SET_DISPLAY_BIND, &MultimodalInputConnectStub::StubSetDisplayBind},
        {IMultimodalInputConnect::GET_FUNCTION_KEY_STATE, &MultimodalInputConnectStub::StubGetFunctionKeyState},
        {IMultimodalInputConnect::SET_FUNCTION_KEY_STATE, &MultimodalInputConnectStub::StubSetFunctionKeyState},
        {IMultimodalInputConnect::SET_POINTER_LOCATION, &MultimodalInputConnectStub::StubSetPointerLocation},
        {IMultimodalInputConnect::SET_CAPTURE_MODE, &MultimodalInputConnectStub::StubSetMouseCaptureMode},
        {IMultimodalInputConnect::GET_WINDOW_PID, &MultimodalInputConnectStub::StubGetWindowPid},
        {IMultimodalInputConnect::APPEND_EXTRA_DATA, &MultimodalInputConnectStub::StubAppendExtraData},
        {IMultimodalInputConnect::ENABLE_INPUT_DEVICE, &MultimodalInputConnectStub::StubEnableInputDevice},
        {IMultimodalInputConnect::SET_KEY_DOWN_DURATION, &MultimodalInputConnectStub::StubSetKeyDownDuration},
        {IMultimodalInputConnect::SET_TP_SCROLL_SWITCH, &MultimodalInputConnectStub::StubSetTouchpadScrollSwitch},
        {IMultimodalInputConnect::GET_TP_SCROLL_SWITCH, &MultimodalInputConnectStub::StubGetTouchpadScrollSwitch},
        {IMultimodalInputConnect::SET_TP_SCROLL_DIRECT_SWITCH,
            &MultimodalInputConnectStub::StubSetTouchpadScrollDirection},
        {IMultimodalInputConnect::GET_TP_SCROLL_DIRECT_SWITCH,
            &MultimodalInputConnectStub::StubGetTouchpadScrollDirection},
        {IMultimodalInputConnect::SET_TP_TAP_SWITCH, &MultimodalInputConnectStub::StubSetTouchpadTapSwitch},
        {IMultimodalInputConnect::GET_TP_TAP_SWITCH, &MultimodalInputConnectStub::StubGetTouchpadTapSwitch},
        {IMultimodalInputConnect::SET_TP_POINTER_SPEED, &MultimodalInputConnectStub::StubSetTouchpadPointerSpeed},
        {IMultimodalInputConnect::GET_TP_POINTER_SPEED, &MultimodalInputConnectStub::StubGetTouchpadPointerSpeed},
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

    if (!reply.WriteFileDescriptor(clientFd)) {
        MMI_HILOGE("Write file descriptor failed");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }

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
    int32_t filterId = -1;
    READINT32(data, filterId, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t priority = 0;
    READINT32(data, priority, IPC_PROXY_DEAD_OBJECT_ERR);
    uint32_t deviceTags = 0;
    READUINT32(data, deviceTags, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t ret = AddInputEventFilter(filter, filterId, priority, deviceTags);
    if (ret != RET_OK) {
        MMI_HILOGE("Call AddInputEventFilter failed ret:%{public}d", ret);
        return ret;
    }
    MMI_HILOGD("Success pid:%{public}d", GetCallingPid());
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubRemoveInputEventFilter(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!PerHelper->CheckPermission(PermissionHelper::APL_SYSTEM_CORE)) {
        MMI_HILOGE("Permission check failed");
        return CHECK_PERMISSION_FAIL;
    }
    int32_t filterId = -1;
    READINT32(data, filterId, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t ret = RemoveInputEventFilter(filterId);
    if (ret != RET_OK) {
        MMI_HILOGE("Call RemoveInputEventFilter failed ret:%{public}d", ret);
        return ret;
    }
    MMI_HILOGD("Success pid:%{public}d", GetCallingPid());
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubSetMouseScrollRows(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
        return MMISERVICE_NOT_RUNNING;
    }

    if (!PerHelper->VerifySystemApp()) {
        MMI_HILOGE("verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }

    if (!PerHelper->CheckPermission(PermissionHelper::APL_SYSTEM_BASIC_CORE)) {
        MMI_HILOGE("Permission check failed");
        return CHECK_PERMISSION_FAIL;
    }
    int32_t rows = 3; // the initial number of scrolling rows is 3.
    READINT32(data, rows, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t ret = SetMouseScrollRows(rows);
    if (ret != RET_OK) {
        MMI_HILOGE("Call SetMouseScrollRows failed ret:%{public}d", ret);
        return ret;
    }
    MMI_HILOGD("Success rows:%{public}d, pid:%{public}d", rows, GetCallingPid());
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubGetMouseScrollRows(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
        return MMISERVICE_NOT_RUNNING;
    }

    if (!PerHelper->VerifySystemApp()) {
        MMI_HILOGE("verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }

    if (!PerHelper->CheckPermission(PermissionHelper::APL_SYSTEM_BASIC_CORE)) {
        MMI_HILOGE("Permission check failed");
        return CHECK_PERMISSION_FAIL;
    }
    int32_t rows = 3; // the initial number of scrolling rows is 3.
    int32_t ret = GetMouseScrollRows(rows);
    if (ret != RET_OK) {
        MMI_HILOGE("Call GetMouseScrollRows failed ret:%{public}d", ret);
        return ret;
    }
    WRITEINT32(reply, rows, IPC_STUB_WRITE_PARCEL_ERR);
    MMI_HILOGD("mouse scroll rows:%{public}d, ret:%{public}d", rows, ret);
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubSetMousePrimaryButton(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!PerHelper->VerifySystemApp()) {
        MMI_HILOGE("verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }

    if (!PerHelper->CheckPermission(PermissionHelper::APL_SYSTEM_BASIC_CORE)) {
        MMI_HILOGE("Permission check failed");
        return CHECK_PERMISSION_FAIL;
    }
    int32_t primaryButton = -1;
    READINT32(data, primaryButton, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t ret = SetMousePrimaryButton(primaryButton);
    if (ret != RET_OK) {
        MMI_HILOGE("Call SetMousePrimaryButton failed ret:%{public}d", ret);
        return ret;
    }
    MMI_HILOGD("Success primaryButton:%{public}d,pid:%{public}d", primaryButton, GetCallingPid());
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubGetMousePrimaryButton(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!PerHelper->VerifySystemApp()) {
        MMI_HILOGE("verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }

    if (!PerHelper->CheckPermission(PermissionHelper::APL_SYSTEM_BASIC_CORE)) {
        MMI_HILOGE("Permission check failed");
        return CHECK_PERMISSION_FAIL;
    }
    int32_t primaryButton = -1;
    int32_t ret = GetMousePrimaryButton(primaryButton);
    if (ret != RET_OK) {
        MMI_HILOGE("Call GetMousePrimaryButton failed ret:%{public}d", ret);
        return ret;
    }
    WRITEINT32(reply, primaryButton, IPC_STUB_WRITE_PARCEL_ERR);
    MMI_HILOGD("mouse primaryButton:%{public}d,ret:%{public}d", primaryButton, ret);
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubSetHoverScrollState(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!PerHelper->VerifySystemApp()) {
        MMI_HILOGE("verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }

    if (!PerHelper->CheckPermission(PermissionHelper::APL_SYSTEM_BASIC_CORE)) {
        MMI_HILOGE("Permission check failed");
        return CHECK_PERMISSION_FAIL;
    }
    bool state = true;
    READBOOL(data, state, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t ret = SetHoverScrollState(state);
    if (ret != RET_OK) {
        MMI_HILOGE("Call SetHoverScrollState failed, ret:%{public}d", ret);
        return ret;
    }
    MMI_HILOGD("Success state:%{public}d, pid:%{public}d", state, GetCallingPid());
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubGetHoverScrollState(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!PerHelper->VerifySystemApp()) {
        MMI_HILOGE("verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }

    if (!PerHelper->CheckPermission(PermissionHelper::APL_SYSTEM_BASIC_CORE)) {
        MMI_HILOGE("Permission check failed");
        return CHECK_PERMISSION_FAIL;
    }
    bool state = true;
    int32_t ret = GetHoverScrollState(state);
    if (ret != RET_OK) {
        MMI_HILOGE("Call GetHoverScrollState failed, ret:%{public}d", ret);
        return ret;
    }
    WRITEBOOL(reply, state, IPC_STUB_WRITE_PARCEL_ERR);
    MMI_HILOGD("mouse hover scroll state:%{public}d, ret:%{public}d", state, ret);
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

int32_t MultimodalInputConnectStub::StubMarkProcessed(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
    }
    int32_t eventType;
    READINT32(data, eventType, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t eventId;
    READINT32(data, eventId, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t ret = MarkProcessed(eventType, eventId);
    if (ret != RET_OK) {
        MMI_HILOGE("MarkProcessed failed, ret:%{public}d", ret);
        return ret;
    }
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
    PointerStyle pointerStyle;
    READINT32(data, pointerStyle.size, RET_ERR);
    READUINT8(data, pointerStyle.color.r, RET_ERR);
    READUINT8(data, pointerStyle.color.g, RET_ERR);
    READUINT8(data, pointerStyle.color.b, RET_ERR);
    READINT32(data, pointerStyle.id, RET_ERR);
    int32_t ret = SetPointerStyle(windowId, pointerStyle);
    if (ret != RET_OK) {
        MMI_HILOGE("Call SetPointerStyle failed ret:%{public}d", ret);
        return ret;
    }
    MMI_HILOGD("Successfully set window:%{public}d, icon:%{public}d", windowId, pointerStyle.id);
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubGetPointerStyle(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    int32_t windowId;
    READINT32(data, windowId, RET_ERR);
    PointerStyle pointerStyle;
    int32_t ret = GetPointerStyle(windowId, pointerStyle);
    if (ret != RET_OK) {
        MMI_HILOGE("Call GetPointerStyle failed ret:%{public}d", ret);
        return ret;
    }
    WRITEINT32(reply, pointerStyle.size, RET_ERR);
    WRITEUINT8(reply, pointerStyle.color.r, RET_ERR);
    WRITEUINT8(reply, pointerStyle.color.g, RET_ERR);
    WRITEUINT8(reply, pointerStyle.color.b, RET_ERR);
    WRITEINT32(reply, pointerStyle.id, RET_ERR);
    MMI_HILOGD("Successfully get window:%{public}d, icon:%{public}d", windowId, pointerStyle.id);
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubSupportKeys(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    int32_t deviceId = -1;
    READINT32(data, deviceId, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t size = 0;
    READINT32(data, size, IPC_PROXY_DEAD_OBJECT_ERR);
    if (size < 0 || size > ExtraData::MAX_BUFFER_SIZE) {
        MMI_HILOGE("Invalid size: %{public}d", size);
        return RET_ERR;
    }
    std::vector<int32_t> keys;
    int32_t key = 0;
    for (int32_t i = 0; i < size; ++i) {
        READINT32(data, key, IPC_PROXY_DEAD_OBJECT_ERR);
        keys.push_back(key);
    }
    std::vector<bool> keystroke;
    int32_t ret = SupportKeys(deviceId, keys, keystroke);
    if (ret != RET_OK) {
        MMI_HILOGE("Call SupportKeys failed ret:%{public}d", ret);
        return RET_ERR;
    }
    if (!reply.WriteBoolVector(keystroke)) {
        MMI_HILOGE("Write keyStroke failed");
        return RET_ERR;
    }
    return ret;
}

int32_t MultimodalInputConnectStub::StubGetDeviceIds(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    std::vector<int32_t> ids;
    int32_t ret = GetDeviceIds(ids);
    if (ret != RET_OK) {
        MMI_HILOGE("Call GetDeviceIds failed ret:%{public}d", ret);
        return RET_ERR;
    }
    if (!reply.WriteInt32Vector(ids)) {
        MMI_HILOGE("Write ids failed");
        return RET_ERR;
    }
    return ret;
}

int32_t MultimodalInputConnectStub::StubGetDevice(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    int32_t deviceId = -1;
    READINT32(data, deviceId, IPC_PROXY_DEAD_OBJECT_ERR);
    std::shared_ptr<InputDevice> inputDevice = std::make_shared<InputDevice>();
    int32_t ret = GetDevice(deviceId, inputDevice);
    if (ret != RET_OK) {
        MMI_HILOGE("Call GetDevice failed ret:%{public}d", ret);
        return RET_ERR;
    }
    WRITEINT32(reply, inputDevice->GetId(), IPC_STUB_WRITE_PARCEL_ERR);
    WRITEINT32(reply, inputDevice->GetType(), IPC_STUB_WRITE_PARCEL_ERR);
    WRITESTRING(reply, inputDevice->GetName(), IPC_STUB_WRITE_PARCEL_ERR);
    WRITEINT32(reply, inputDevice->GetBus(), IPC_STUB_WRITE_PARCEL_ERR);
    WRITEINT32(reply, inputDevice->GetVersion(), IPC_STUB_WRITE_PARCEL_ERR);
    WRITEINT32(reply, inputDevice->GetProduct(), IPC_STUB_WRITE_PARCEL_ERR);
    WRITEINT32(reply, inputDevice->GetVendor(), IPC_STUB_WRITE_PARCEL_ERR);
    WRITESTRING(reply, inputDevice->GetPhys(), IPC_STUB_WRITE_PARCEL_ERR);
    WRITESTRING(reply, inputDevice->GetUniq(), IPC_STUB_WRITE_PARCEL_ERR);
    WRITEUINT64(reply, static_cast<uint64_t>(inputDevice->GetCapabilities()), IPC_STUB_WRITE_PARCEL_ERR);
    WRITEUINT32(reply, static_cast<uint32_t>(inputDevice->GetAxisInfo().size()), IPC_STUB_WRITE_PARCEL_ERR);
    for (const auto &item : inputDevice->GetAxisInfo()) {
        WRITEINT32(reply, item.GetMinimum(), IPC_STUB_WRITE_PARCEL_ERR);
        WRITEINT32(reply, item.GetMaximum(), IPC_STUB_WRITE_PARCEL_ERR);
        WRITEINT32(reply, item.GetAxisType(), IPC_STUB_WRITE_PARCEL_ERR);
        WRITEINT32(reply, item.GetFuzz(), IPC_STUB_WRITE_PARCEL_ERR);
        WRITEINT32(reply, item.GetFlat(), IPC_STUB_WRITE_PARCEL_ERR);
        WRITEINT32(reply, item.GetResolution(), IPC_STUB_WRITE_PARCEL_ERR);
    }
    return RET_OK;
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
    int32_t deviceId = -1;
    READINT32(data, deviceId, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t keyboardType = 0;
    int32_t ret = GetKeyboardType(deviceId, keyboardType);
    if (ret != RET_OK) {
        MMI_HILOGE("Call GetKeyboardType failed ret:%{public}d", ret);
        return RET_ERR;
    }
    WRITEINT32(reply, keyboardType, IPC_STUB_WRITE_PARCEL_ERR);
    return ret;
}

int32_t MultimodalInputConnectStub::StubAddInputHandler(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!PerHelper->VerifySystemApp()) {
        MMI_HILOGE("verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }

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
    int32_t priority;
    READINT32(data, priority, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t deviceTags;
    READINT32(data, deviceTags, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t ret = AddInputHandler(static_cast<InputHandlerType>(handlerType), eventType, priority,
        deviceTags);
    if (ret != RET_OK) {
        MMI_HILOGE("Call AddInputHandler failed ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubRemoveInputHandler(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!PerHelper->VerifySystemApp()) {
        MMI_HILOGE("verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }

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
    int32_t priority;
    READINT32(data, priority, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t deviceTags;
    READINT32(data, deviceTags, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t ret = RemoveInputHandler(static_cast<InputHandlerType>(handlerType), eventType, priority,
        deviceTags);
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
    if (!PerHelper->VerifySystemApp()) {
        MMI_HILOGE("verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }

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
    if (!PerHelper->VerifySystemApp()) {
        MMI_HILOGE("verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }

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

int32_t MultimodalInputConnectStub::StubSubscribeSwitchEvent(MessageParcel& data, MessageParcel& reply)
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

    int32_t ret = SubscribeSwitchEvent(subscribeId);
    if (ret != RET_OK) {
        MMI_HILOGE("SubscribeSwitchEvent failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectStub::StubUnsubscribeSwitchEvent(MessageParcel& data, MessageParcel& reply)
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

    int32_t ret = UnsubscribeSwitchEvent(subscribeId);
    if (ret != RET_OK) {
        MMI_HILOGE("UnsubscribeSwitchEvent failed, ret:%{public}d", ret);
    }
    return ret;
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
    if (!PerHelper->VerifySystemApp()) {
        MMI_HILOGE("verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }

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
    event->UpdateId();
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


int32_t MultimodalInputConnectStub::StubGetDisplayBindInfo(MessageParcel& data, MessageParcel& reply)
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
    DisplayBindInfos infos;
    int32_t ret = GetDisplayBindInfo(infos);
    if (ret != RET_OK) {
        MMI_HILOGE("Call GetDisplayBindInfo failed, ret:%{public}d", ret);
        return ret;
    }
    int32_t size = static_cast<int32_t>(infos.size());
    WRITEINT32(reply, size, ERR_INVALID_VALUE);
    infos.reserve(size);
    for (const auto &info : infos) {
        WRITEINT32(reply, info.inputDeviceId, ERR_INVALID_VALUE);
        WRITESTRING(reply, info.inputDeviceName, ERR_INVALID_VALUE);
        WRITEINT32(reply, info.displayId, ERR_INVALID_VALUE);
        WRITESTRING(reply, info.displayName, ERR_INVALID_VALUE);
    }
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubSetDisplayBind(MessageParcel& data, MessageParcel& reply)
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
    int32_t inputDeviceId = -1;
    READINT32(data, inputDeviceId, ERR_INVALID_VALUE);
    int32_t displayId = -1;
    READINT32(data, displayId, ERR_INVALID_VALUE);
    std::string msg;
    int32_t ret = SetDisplayBind(inputDeviceId, displayId, msg);
    if (ret != RET_OK) {
        MMI_HILOGE("Call SetDisplayBind failed, ret:%{public}d", ret);
    }
    WRITESTRING(reply, msg, ERR_INVALID_VALUE);
    return ret;
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

int32_t MultimodalInputConnectStub::StubSetPointerLocation(MessageParcel &data, MessageParcel &reply)
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

    int32_t x = 0;
    int32_t y = 0;
    READINT32(data, x, IPC_PROXY_DEAD_OBJECT_ERR);
    READINT32(data, y, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t ret = SetPointerLocation(x, y);
    if (ret != RET_OK) {
        MMI_HILOGE("Call SetFunctionKeyState failed ret:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectStub::StubSetMouseCaptureMode(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    int32_t windowId = -1;
    bool isCaptureMode = false;
    READINT32(data, windowId, IPC_PROXY_DEAD_OBJECT_ERR);
    READBOOL(data, isCaptureMode, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t ret = SetMouseCaptureMode(windowId, isCaptureMode);
    if (ret != RET_OK) {
        MMI_HILOGE("Fail to call SetMouseCaptureMode, ret:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectStub::StubGetWindowPid(MessageParcel& data, MessageParcel& reply)
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

    int32_t windowId = 0;
    READINT32(data, windowId, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t ret = GetWindowPid(windowId);
    if (ret == RET_ERR) {
        MMI_HILOGE("Get window pid failed");
    }
    WRITEINT32(reply, ret, ERR_INVALID_VALUE);
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubAppendExtraData(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
        return MMISERVICE_NOT_RUNNING;
    }
    ExtraData extraData;
    READBOOL(data, extraData.appended, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t size = 0;
    READINT32(data, size, IPC_PROXY_DEAD_OBJECT_ERR);
    if (size > ExtraData::MAX_BUFFER_SIZE) {
        MMI_HILOGE("Append extra data failed, buffer is oversize:%{public}d", size);
        return ERROR_OVER_SIZE_BUFFER;
    }
    uint8_t buffer = 0;
    for (int32_t i = 0; i < size; ++i) {
        READUINT8(data, buffer, IPC_PROXY_DEAD_OBJECT_ERR);
        extraData.buffer.push_back(buffer);
    }
    READINT32(data, extraData.sourceType, IPC_PROXY_DEAD_OBJECT_ERR);
    READINT32(data, extraData.pointerId, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t ret = AppendExtraData(extraData);
    if (ret != RET_OK) {
        MMI_HILOGE("Fail to call AppendExtraData, ret:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectStub::StubEnableInputDevice(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
        return MMISERVICE_NOT_RUNNING;
    }
    bool enable;
    READBOOL(data, enable, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t ret = EnableInputDevice(enable);
    if (ret != RET_OK) {
        MMI_HILOGE("Call EnableInputDevice failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectStub::StubSetKeyDownDuration(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!PerHelper->VerifySystemApp()) {
        MMI_HILOGE("verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }

    if (!PerHelper->CheckPermission(PermissionHelper::APL_SYSTEM_BASIC_CORE)) {
        MMI_HILOGE("Permission check failed");
        return CHECK_PERMISSION_FAIL;
    }
    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
        return MMISERVICE_NOT_RUNNING;
    }
    std::string businessId;
    READSTRING(data, businessId, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t delay;
    READINT32(data, delay, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t ret = SetKeyDownDuration(businessId, delay);
    if (ret != RET_OK) {
        MMI_HILOGE("Set key down duration failed ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectStub::VerifyTouchPadSetting(void)
{
    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
        return MMISERVICE_NOT_RUNNING;
    }

    if (!PerHelper->VerifySystemApp()) {
        MMI_HILOGE("Verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }

    if (!PerHelper->CheckPermission(PermissionHelper::APL_SYSTEM_BASIC_CORE)) {
        MMI_HILOGE("Permission check failed");
        return CHECK_PERMISSION_FAIL;
    }

    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubSetTouchpadScrollSwitch(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    int32_t ret = VerifyTouchPadSetting();
    if (ret != RET_OK) {
        MMI_HILOGE("Verify touchpad setting failed.");
        return ret;
    }

    bool switchFlag = true;
    READBOOL(data, switchFlag, IPC_PROXY_DEAD_OBJECT_ERR);
    ret = SetTouchpadScrollSwitch(switchFlag);
    if (ret != RET_OK) {
        MMI_HILOGE("Set touch pad scroll switch failed ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubGetTouchpadScrollSwitch(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    int32_t ret = VerifyTouchPadSetting();
    if (ret != RET_OK) {
        MMI_HILOGE("Verify touchpad setting failed.");
        return ret;
    }

    bool switchFlag = true;
    ret = GetTouchpadScrollSwitch(switchFlag);
    if (ret != RET_OK) {
        MMI_HILOGE("Call GetTouchpadScrollSwitch failed ret:%{public}d", ret);
        return ret;
    }
    WRITEBOOL(reply, switchFlag, IPC_STUB_WRITE_PARCEL_ERR);
    MMI_HILOGD("Touch pad scroll switch :%{public}d, ret:%{public}d", switchFlag, ret);
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubSetTouchpadScrollDirection(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    int32_t ret = VerifyTouchPadSetting();
    if (ret != RET_OK) {
        MMI_HILOGE("Verify touchpad setting failed.");
        return ret;
    }

    bool state = true;
    READBOOL(data, state, IPC_PROXY_DEAD_OBJECT_ERR);
    ret = SetTouchpadScrollDirection(state);
    if (ret != RET_OK) {
        MMI_HILOGE("Set touch pad scroll direct switch failed ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubGetTouchpadScrollDirection(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    int32_t ret = VerifyTouchPadSetting();
    if (ret != RET_OK) {
        MMI_HILOGE("Verify touchpad setting failed.");
        return ret;
    }

    bool state = true;
    ret = GetTouchpadScrollDirection(state);
    if (ret != RET_OK) {
        MMI_HILOGE("Call GetTouchpadScrollDirection failed ret:%{public}d", ret);
        return ret;
    }
    WRITEBOOL(reply, state, IPC_STUB_WRITE_PARCEL_ERR);
    MMI_HILOGD("Touch pad scroll direct switch :%{public}d, ret:%{public}d", state, ret);
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubSetTouchpadTapSwitch(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    int32_t ret = VerifyTouchPadSetting();
    if (ret != RET_OK) {
        MMI_HILOGE("Verify touchpad setting failed.");
        return ret;
    }

    bool switchFlag = true;
    READBOOL(data, switchFlag, IPC_PROXY_DEAD_OBJECT_ERR);
    ret = SetTouchpadTapSwitch(switchFlag);
    if (ret != RET_OK) {
        MMI_HILOGE("Set touch pad tap switch failed ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubGetTouchpadTapSwitch(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    int32_t ret = VerifyTouchPadSetting();
    if (ret != RET_OK) {
        MMI_HILOGE("Verify touchpad setting failed.");
        return ret;
    }

    bool switchFlag = true;
    ret = GetTouchpadTapSwitch(switchFlag);
    if (ret != RET_OK) {
        MMI_HILOGE("Call GetTouchpadTapSwitch failed ret:%{public}d", ret);
        return ret;
    }
    WRITEBOOL(reply, switchFlag, IPC_STUB_WRITE_PARCEL_ERR);
    MMI_HILOGD("Touch pad tap switch :%{public}d, ret:%{public}d", switchFlag, ret);
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubSetTouchpadPointerSpeed(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    int32_t ret = VerifyTouchPadSetting();
    if (ret != RET_OK) {
        MMI_HILOGE("Verify touchpad setting failed.");
        return ret;
    }

    int32_t speed = true;
    READINT32(data, speed, IPC_PROXY_DEAD_OBJECT_ERR);
    ret = SetTouchpadPointerSpeed(speed);
    if (ret != RET_OK) {
        MMI_HILOGE("Set touch pad pointer speed failed ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubGetTouchpadPointerSpeed(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    int32_t ret = VerifyTouchPadSetting();
    if (ret != RET_OK) {
        MMI_HILOGE("Verify touchpad setting failed.");
        return ret;
    }

    int32_t speed = 1;
    ret = GetTouchpadPointerSpeed(speed);
    if (ret != RET_OK) {
        MMI_HILOGE("Call GetTouchpadPointerSpeed failed ret:%{public}d", ret);
        return ret;
    }
    WRITEINT32(reply, speed, IPC_STUB_WRITE_PARCEL_ERR);
    MMI_HILOGD("Touch pad pointer speed :%{public}d, ret:%{public}d", speed, ret);
    return RET_OK;
}
} // namespace MMI
} // namespace OHOS
