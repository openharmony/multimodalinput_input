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

#include "bytrace_adapter.h"
#include "error_multimodal.h"
#include "multimodal_input_connect_def_parcel.h"
#include "multimodalinput_ipc_interface_code.h"
#include "nap_process.h"
#include "permission_helper.h"
#include "pixel_map.h"
#include "time_cost_chk.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_SERVER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "MultimodalInputConnectStub"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t MAX_AXIS_INFO { 64 };
constexpr int32_t MIN_ROWS { 1 };
constexpr int32_t MAX_ROWS { 100 };
constexpr int32_t TOUCHPAD_SCROLL_ROWS { 3 };

int32_t g_parseInputDevice(MessageParcel &data, std::shared_ptr<InputDevice> &inputDevice)
{
    CHKPR(inputDevice, RET_ERR);
    int32_t value = 0;
    READINT32(data, value, IPC_PROXY_DEAD_OBJECT_ERR);
    inputDevice->SetId(value);
    READINT32(data, value, IPC_PROXY_DEAD_OBJECT_ERR);
    inputDevice->SetType(value);
    std::string element;
    READSTRING(data, element, IPC_PROXY_DEAD_OBJECT_ERR);
    inputDevice->SetName(element);
    READINT32(data, value, IPC_PROXY_DEAD_OBJECT_ERR);
    inputDevice->SetBus(value);
    READINT32(data, value, IPC_PROXY_DEAD_OBJECT_ERR);
    inputDevice->SetVersion(value);
    READINT32(data, value, IPC_PROXY_DEAD_OBJECT_ERR);
    inputDevice->SetProduct(value);
    READINT32(data, value, IPC_PROXY_DEAD_OBJECT_ERR);
    inputDevice->SetVendor(value);
    READSTRING(data, element, IPC_PROXY_DEAD_OBJECT_ERR);
    inputDevice->SetPhys(element);
    READSTRING(data, element, IPC_PROXY_DEAD_OBJECT_ERR);
    inputDevice->SetUniq(element);
    uint64_t caps;
    READUINT64(data, caps, IPC_PROXY_DEAD_OBJECT_ERR);
    inputDevice->SetCapabilities(static_cast<unsigned long>(caps));
    uint32_t size = 0;
    READUINT32(data, size, IPC_PROXY_DEAD_OBJECT_ERR);
    if (size > MAX_AXIS_INFO) {
        return RET_ERR;
    }
    InputDevice::AxisInfo axis;
    for (uint32_t i = 0; i < size; ++i) {
        int32_t val = 0;
        READINT32(data, val, IPC_PROXY_DEAD_OBJECT_ERR);
        axis.SetMinimum(val);
        READINT32(data, val, IPC_PROXY_DEAD_OBJECT_ERR);
        axis.SetMaximum(val);
        READINT32(data, val, IPC_PROXY_DEAD_OBJECT_ERR);
        axis.SetAxisType(val);
        READINT32(data, val, IPC_PROXY_DEAD_OBJECT_ERR);
        axis.SetFuzz(val);
        READINT32(data, val, IPC_PROXY_DEAD_OBJECT_ERR);
        axis.SetFlat(val);
        READINT32(data, val, IPC_PROXY_DEAD_OBJECT_ERR);
        axis.SetResolution(val);
        inputDevice->AddAxisInfo(axis);
    }
    return RET_OK;
}
} // namespace
const int32_t TUPLE_PID { 0 };
const int32_t TUPLE_UID { 1 };
const int32_t TUPLE_NAME { 2 };
const int32_t DEFAULT_POINTER_COLOR { 0x000000 };
constexpr int32_t MAX_N_TRANSMIT_INFRARED_PATTERN { 500 };

int32_t MultimodalInputConnectStub::OnRemoteRequest(uint32_t code, MessageParcel& data,
    MessageParcel& reply, MessageOption& option)
{
    int32_t pid = GetCallingPid();
    TimeCostChk chk("IPC-OnRemoteRequest", "overtime 300(us)", MAX_OVER_TIME, pid,
        static_cast<int64_t>(code));
    MMI_HILOGD("RemoteRequest code:%{public}d, tid:%{public}" PRIu64 ", pid:%{public}d", code, GetThisThreadId(), pid);

    std::u16string descriptor = data.ReadInterfaceToken();
    if (descriptor != IMultimodalInputConnect::GetDescriptor()) {
        MMI_HILOGE("Get unexpect descriptor:%{public}s", Str16ToStr8(descriptor).c_str());
        return ERR_INVALID_STATE;
    }
    BytraceAdapter::StartIpcServer(code);
    int32_t ret = RET_ERR;
    switch (code) {
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::ALLOC_SOCKET_FD):
            ret =  StubHandleAllocSocketFd(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::ADD_INPUT_EVENT_FILTER):
            ret = StubAddInputEventFilter(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::RMV_INPUT_EVENT_FILTER):
            ret = StubRemoveInputEventFilter(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_MOUSE_SCROLL_ROWS):
            ret = StubSetMouseScrollRows(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_MOUSE_SCROLL_ROWS):
            ret = StubGetMouseScrollRows(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_POINTER_SIZE):
            ret = StubSetPointerSize(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_POINTER_SIZE):
            ret = StubGetPointerSize(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_CUSTOM_CURSOR):
            ret = StubSetCustomCursor(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_MOUSE_ICON):
            ret = StubSetMouseIcon(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_MOUSE_PRIMARY_BUTTON):
            ret = StubSetMousePrimaryButton(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_MOUSE_PRIMARY_BUTTON):
            ret = StubGetMousePrimaryButton(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_HOVER_SCROLL_STATE):
            ret = StubSetHoverScrollState(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_HOVER_SCROLL_STATE):
            ret = StubGetHoverScrollState(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_POINTER_VISIBLE):
            ret = StubSetPointerVisible(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_POINTER_STYLE):
            ret = StubSetPointerStyle(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::NOTIFY_NAP_ONLINE):
            ret = StubNotifyNapOnline(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::RMV_INPUT_EVENT_OBSERVER):
            ret = StubRemoveInputEventObserver(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_NAP_STATUS):
            ret = StubSetNapStatus(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::CLEAN_WIDNOW_STYLE):
            ret = StubClearWindowPointerStyle(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_POINTER_STYLE):
            ret = StubGetPointerStyle(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::IS_POINTER_VISIBLE):
            ret = StubIsPointerVisible(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::REGISTER_DEV_MONITOR):
            ret = StubRegisterInputDeviceMonitor(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::UNREGISTER_DEV_MONITOR):
            ret = StubUnregisterInputDeviceMonitor(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_DEVICE_IDS):
            ret = StubGetDeviceIds(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_DEVICE):
            ret = StubGetDevice(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SUPPORT_KEYS):
            ret = StubSupportKeys(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_KEYBOARD_TYPE):
            ret = StubGetKeyboardType(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_POINTER_COLOR):
            ret = StubSetPointerColor(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_POINTER_COLOR):
            ret = StubGetPointerColor(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_POINTER_SPEED):
            ret = StubSetPointerSpeed(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_POINTER_SPEED):
            ret = StubGetPointerSpeed(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SUBSCRIBE_KEY_EVENT):
            ret = StubSubscribeKeyEvent(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::UNSUBSCRIBE_KEY_EVENT):
            ret = StubUnsubscribeKeyEvent(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SUBSCRIBE_SWITCH_EVENT):
            ret = StubSubscribeSwitchEvent(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::UNSUBSCRIBE_SWITCH_EVENT):
            ret = StubUnsubscribeSwitchEvent(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::MARK_PROCESSED):
            ret = StubMarkProcessed(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::ADD_INPUT_HANDLER):
            ret = StubAddInputHandler(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::REMOVE_INPUT_HANDLER):
            ret = StubRemoveInputHandler(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::MARK_EVENT_CONSUMED):
            ret = StubMarkEventConsumed(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::MOVE_MOUSE):
            ret = StubMoveMouseEvent(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::INJECT_KEY_EVENT):
            ret = StubInjectKeyEvent(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::INJECT_POINTER_EVENT):
            ret = StubInjectPointerEvent(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_ANR_OBSERVER):
            ret = StubSetAnrListener(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_DISPLAY_BIND_INFO):
            ret = StubGetDisplayBindInfo(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_ALL_NAPSTATUS_DATA):
            ret = StubGetAllMmiSubscribedEvents(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_DISPLAY_BIND):
            ret = StubSetDisplayBind(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_FUNCTION_KEY_STATE):
            ret = StubGetFunctionKeyState(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_FUNCTION_KEY_STATE):
            ret = StubSetFunctionKeyState(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_POINTER_LOCATION):
            ret = StubSetPointerLocation(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_CAPTURE_MODE):
            ret = StubSetMouseCaptureMode(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_WINDOW_PID):
            ret = StubGetWindowPid(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::APPEND_EXTRA_DATA):
            ret = StubAppendExtraData(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::ENABLE_INPUT_DEVICE):
            ret = StubEnableInputDevice(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::ENABLE_COMBINE_KEY):
            ret = StubEnableCombineKey(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_KEY_DOWN_DURATION):
            ret = StubSetKeyDownDuration(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_TP_SCROLL_SWITCH):
            ret = StubSetTouchpadScrollSwitch(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_TP_SCROLL_SWITCH):
            ret = StubGetTouchpadScrollSwitch(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_TP_SCROLL_DIRECT_SWITCH):
            ret = StubSetTouchpadScrollDirection(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_TP_SCROLL_DIRECT_SWITCH):
            ret = StubGetTouchpadScrollDirection(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_TP_TAP_SWITCH):
            ret = StubSetTouchpadTapSwitch(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_TP_TAP_SWITCH):
            ret = StubGetTouchpadTapSwitch(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_TP_POINTER_SPEED):
            ret = StubSetTouchpadPointerSpeed(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_TP_POINTER_SPEED):
            ret = StubGetTouchpadPointerSpeed(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_KEYBOARD_REPEAT_DELAY):
            ret = StubSetKeyboardRepeatDelay(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_KEYBOARD_REPEAT_RATE):
            ret = StubSetKeyboardRepeatRate(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_TP_PINCH_SWITCH):
            ret = StubSetTouchpadPinchSwitch(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_TP_PINCH_SWITCH):
            ret = StubGetTouchpadPinchSwitch(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_TP_SWIPE_SWITCH):
            ret = StubSetTouchpadSwipeSwitch(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_TP_SWIPE_SWITCH):
            ret = StubGetTouchpadSwipeSwitch(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_TP_RIGHT_CLICK_TYPE):
            ret = StubSetTouchpadRightClickType(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_TP_RIGHT_CLICK_TYPE):
            ret = StubGetTouchpadRightClickType(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_TP_ROTATE_SWITCH):
            ret = StubSetTouchpadRotateSwitch(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_TP_ROTATE_SWITCH):
            ret = StubGetTouchpadRotateSwitch(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_KEYBOARD_REPEAT_DELAY):
            ret = StubGetKeyboardRepeatDelay(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_KEYBOARD_REPEAT_RATE):
            ret = StubGetKeyboardRepeatRate(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_MOUSE_HOT_SPOT):
            ret = StubSetMouseHotSpot(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_SHIELD_STATUS):
            ret = StubSetShieldStatus(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_SHIELD_STATUS):
            ret = StubGetShieldStatus(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_KEY_STATE):
            ret = StubGetKeyState(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::NATIVE_AUTHORIZE):
            ret = StubAuthorize(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::NATIVE_CANCEL_INJECTION):
            ret = StubCancelInjection(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::NATIVE_INFRARED_OWN):
            ret = StubHasIrEmitter(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::NATIVE_INFRARED_FREQUENCY):
            ret = StubGetInfraredFrequencies(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::NATIVE_CANCEL_TRANSMIT):
            ret = StubTransmitInfrared(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_PIXEL_MAP_DATA):
            ret = StubSetPixelMapData(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_MOVE_EVENT_FILTERS):
            ret = StubSetMoveEventFilters(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_CURRENT_USERID):
            ret = StubSetCurrentUser(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::ENABLE_HARDWARE_CURSOR_STATS):
            ret = StubEnableHardwareCursorStats(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_HARDWARE_CURSOR_STATS):
            ret = StubGetHardwareCursorStats(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_TOUCHPAD_SCROLL_ROWS):
            ret = StubSetTouchpadScrollRows(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_TOUCHPAD_SCROLL_ROWS):
            ret = StubGetTouchpadScrollRows(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_POINTER_SNAPSHOT):
            ret = StubGetPointerSnapshot(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::ADD_VIRTUAL_INPUT_DEVICE):
            ret = StubAddVirtualInputDevice(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::REMOVE_VIRTUAL_INPUT_DEVICE):
            ret = StubRemoveVirtualInputDevice(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_THREE_GINGERS_TAPSWITCH):
            ret = StubSetTouchpadThreeFingersTapSwitch(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_THREE_GINGERS_TAPSWITCH):
            ret = StubGetTouchpadThreeFingersTapSwitch(data, reply);
            break;
#ifdef OHOS_BUILD_ENABLE_ANCO
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::ADD_ANCO_CHANNEL):
            ret = StubAncoAddChannel(data, reply);
            break;
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::REMOVE_ANCO_CHANNEL):
            ret = StubAncoRemoveChannel(data, reply);
            break;
#endif // OHOS_BUILD_ENABLE_ANCO
        case static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::TRANSFER_BINDER_CLIENT_SERVICE):
            ret = StubTransferBinderClientService(data, reply);
            break;
        default: {
            MMI_HILOGE("Unknown code:%{public}u, go switch default", code);
            ret = IPCObjectStub::OnRemoteRequest(code, data, reply, option);
        }
    }
    BytraceAdapter::StopIpcServer();
    return ret;
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
    MMI_HILOGD("clientName:%{public}s, moduleId:%{public}d", req->data.clientName.c_str(), req->data.moduleId);

    int32_t clientFd = INVALID_SOCKET_FD;
    int32_t tokenType = PER_HELPER->GetTokenType();
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
        close(clientFd);
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
    if (!PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("Verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }
    if (!PER_HELPER->CheckInputEventFilter()) {
        MMI_HILOGE("Filter permission check failed");
        return ERROR_NO_PERMISSION;
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
        MMI_HILOGE("Call AddInputEventFilter failed:%{public}d", ret);
        return ret;
    }
    MMI_HILOGD("Success pid:%{public}d", GetCallingPid());
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubRemoveInputEventFilter(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("Verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }
    if (!PER_HELPER->CheckInputEventFilter()) {
        MMI_HILOGE("Filter permission check failed");
        return ERROR_NO_PERMISSION;
    }
    int32_t filterId = -1;
    READINT32(data, filterId, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t ret = RemoveInputEventFilter(filterId);
    if (ret != RET_OK) {
        MMI_HILOGE("Call RemoveInputEventFilter failed:%{public}d", ret);
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

    if (!PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("Verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }

    int32_t rows = 3; // the initial number of scrolling rows is 3.
    READINT32(data, rows, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t ret = SetMouseScrollRows(rows);
    if (ret != RET_OK) {
        MMI_HILOGE("Call SetMouseScrollRows failed:%{public}d", ret);
        return ret;
    }
    MMI_HILOGD("Success rows:%{public}d, pid:%{public}d", rows, GetCallingPid());
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubSetCustomCursor(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
        return MMISERVICE_NOT_RUNNING;
    }
    int32_t windowId = 0;
    int32_t windowPid = INVALID_PID;
    int32_t focusX = 0;
    int32_t focusY = 0;
    READINT32(data, windowPid, IPC_PROXY_DEAD_OBJECT_ERR);
    READINT32(data, windowId, IPC_PROXY_DEAD_OBJECT_ERR);
    READINT32(data, focusX, IPC_PROXY_DEAD_OBJECT_ERR);
    READINT32(data, focusY, IPC_PROXY_DEAD_OBJECT_ERR);
    if (windowId <= 0) {
        MMI_HILOGE("Invalid windowId:%{public}d", windowId);
        return RET_ERR;
    }
    OHOS::Media::PixelMap* pixelMap = Media::PixelMap::Unmarshalling(data);
    CHKPR(pixelMap, RET_ERR);
    int32_t ret = SetCustomCursor(windowPid, windowId, focusX, focusY, (void*)pixelMap);
    if (ret != RET_OK) {
        MMI_HILOGE("Call SetCustomCursor failed:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubSetMouseIcon(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
        return MMISERVICE_NOT_RUNNING;
    }
    int32_t windowId = 0;
    OHOS::Media::PixelMap *pixelMap = OHOS::Media::PixelMap::Unmarshalling(data);
    CHKPR(pixelMap, RET_ERR);
    READINT32(data, windowId, IPC_PROXY_DEAD_OBJECT_ERR);
    MMI_HILOGD("Reading windowid the tlv count:%{public}d", windowId);
    if (windowId <= 0) {
        MMI_HILOGE("Invalid windowId:%{public}d", windowId);
        return RET_ERR;
    }

    int32_t ret = SetMouseIcon(windowId, (void*)pixelMap);
    if (ret != RET_OK) {
        MMI_HILOGE("Call SetMouseIcon failed:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubSetMouseHotSpot(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("Verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }
    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
        return MMISERVICE_NOT_RUNNING;
    }
    int32_t windowId = 0;
    int32_t winPid = -1;
    READINT32(data, winPid, IPC_PROXY_DEAD_OBJECT_ERR);
    READINT32(data, windowId, IPC_PROXY_DEAD_OBJECT_ERR);
    if (windowId <= 0) {
        MMI_HILOGE("Invalid windowId:%{public}d", windowId);
        return RET_ERR;
    }
    int32_t hotSpotX = 0;
    READINT32(data, hotSpotX, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t hotSpotY = 0;
    READINT32(data, hotSpotY, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t ret = SetMouseHotSpot(winPid, windowId, hotSpotX, hotSpotY);
    if (ret != RET_OK) {
        MMI_HILOGE("Call SetMouseHotSpot failed:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubGetMouseScrollRows(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
        return MMISERVICE_NOT_RUNNING;
    }

    if (!PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("Verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }

    int32_t rows = 3; // the initial number of scrolling rows is 3.
    int32_t ret = GetMouseScrollRows(rows);
    if (ret != RET_OK) {
        MMI_HILOGE("Call GetMouseScrollRows failed ret:%{public}d", ret);
        return ret;
    }
    WRITEINT32(reply, rows, IPC_STUB_WRITE_PARCEL_ERR);
    MMI_HILOGD("Mouse scroll rows:%{public}d, ret:%{public}d", rows, ret);
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubSetPointerSize(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
        return MMISERVICE_NOT_RUNNING;
    }

    if (!PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("Verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }

    int32_t size = 1; // the initial pointer size is 1.
    READINT32(data, size, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t ret = SetPointerSize(size);
    if (ret != RET_OK) {
        MMI_HILOGE("Call SetPointerSize failed ret:%{public}d", ret);
        return ret;
    }
    MMI_HILOGD("Success size:%{public}d, pid:%{public}d", size, GetCallingPid());
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubSetNapStatus(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("Verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }
    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
        return MMISERVICE_NOT_RUNNING;
    }
    int32_t napPid = -1;
    int32_t napUid = -1;
    std::string napBundleName;
    int32_t napStatus = 0;
    READINT32(data, napPid, IPC_PROXY_DEAD_OBJECT_ERR);
    READINT32(data, napUid, IPC_PROXY_DEAD_OBJECT_ERR);
    READSTRING(data, napBundleName, IPC_PROXY_DEAD_OBJECT_ERR);
    READINT32(data, napStatus, IPC_PROXY_DEAD_OBJECT_ERR);

    int32_t ret = SetNapStatus(napPid, napUid, napBundleName, napStatus);
    if (ret != RET_OK) {
        MMI_HILOGE("Call StubSetNapStatus failed ret:%{public}d", ret);
        return ret;
    }
    MMI_HILOGD("Success set napStatus:%{public}d, pid:%{public}d", napStatus, GetCallingPid());
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubGetPointerSize(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
        return MMISERVICE_NOT_RUNNING;
    }

    if (!PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("Verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }

    int32_t size = 1; // the initial pointer size is 1.
    int32_t ret = GetPointerSize(size);
    if (ret != RET_OK) {
        MMI_HILOGE("Call GetPoinerSize failed ret:%{public}d", ret);
        return ret;
    }
    WRITEINT32(reply, size, IPC_STUB_WRITE_PARCEL_ERR);
    MMI_HILOGD("Pointer size:%{public}d, ret:%{public}d", size, ret);
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubSetMousePrimaryButton(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("Verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }

    int32_t primaryButton = -1;
    READINT32(data, primaryButton, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t ret = SetMousePrimaryButton(primaryButton);
    if (ret != RET_OK) {
        MMI_HILOGE("Call SetMousePrimaryButton failed ret:%{public}d", ret);
        return ret;
    }
    MMI_HILOGD("Success primaryButton:%{public}d, pid:%{public}d", primaryButton, GetCallingPid());
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubGetMousePrimaryButton(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("Verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }

    int32_t primaryButton = -1;
    int32_t ret = GetMousePrimaryButton(primaryButton);
    if (ret != RET_OK) {
        MMI_HILOGE("Call GetMousePrimaryButton failed ret:%{public}d", ret);
        return ret;
    }
    WRITEINT32(reply, primaryButton, IPC_STUB_WRITE_PARCEL_ERR);
    MMI_HILOGD("Mouse primaryButton:%{public}d, ret:%{public}d", primaryButton, ret);
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubSetHoverScrollState(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("Verify system APP failed");
        return ERROR_NOT_SYSAPI;
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
    if (!PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("Verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }

    bool state = true;
    int32_t ret = GetHoverScrollState(state);
    if (ret != RET_OK) {
        MMI_HILOGE("Call GetHoverScrollState failed, ret:%{public}d", ret);
        return ret;
    }
    WRITEBOOL(reply, state, IPC_STUB_WRITE_PARCEL_ERR);
    MMI_HILOGD("Mouse hover scroll state:%{public}d, ret:%{public}d", state, ret);
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubSetPointerVisible(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    bool visible = false;
    READBOOL(data, visible, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t priority = 0;
    READINT32(data, priority, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t ret = SetPointerVisible(visible, priority);
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
    MMI_HILOGD("visible:%{public}d, ret:%{public}d, pid:%{public}d", visible, ret, GetCallingPid());
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubMarkProcessed(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
        return MMISERVICE_NOT_RUNNING;
    }
    int32_t eventType;
    READINT32(data, eventType, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t eventId;
    READINT32(data, eventId, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t ret = MarkProcessed(eventType, eventId);
    if (ret != RET_OK) {
        MMI_HILOGD("MarkProcessed failed, ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubSetPointerColor(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
        return MMISERVICE_NOT_RUNNING;
    }

    if (!PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("Verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }

    int32_t color = DEFAULT_POINTER_COLOR;
    READINT32(data, color, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t ret = SetPointerColor(color);
    if (ret != RET_OK) {
        MMI_HILOGE("Call SetPointerColor failed ret:%{public}d", ret);
        return ret;
    }
    MMI_HILOGD("Success color:%{public}d, pid:%{public}d", color, GetCallingPid());
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubGetPointerColor(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
        return MMISERVICE_NOT_RUNNING;
    }

    if (!PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("Verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }

    int32_t color = DEFAULT_POINTER_COLOR;
    int32_t ret = GetPointerColor(color);
    if (ret != RET_OK) {
        MMI_HILOGE("Call GetPointerColor failed ret:%{public}d", ret);
        return ret;
    }
    WRITEINT32(reply, color, IPC_STUB_WRITE_PARCEL_ERR);
    MMI_HILOGD("Pointer color:%{public}d, ret:%{public}d", color, ret);
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubSetPointerSpeed(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("Verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }

    int32_t speed = 0;
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
    if (!PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("Verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }

    int32_t speed = 0;
    int32_t ret = GetPointerSpeed(speed);
    if (ret != RET_OK) {
        MMI_HILOGE("Call get pointer speed failed ret:%{public}d", ret);
        return RET_ERR;
    }
    WRITEINT32(reply, speed, IPC_STUB_WRITE_PARCEL_ERR);
    MMI_HILOGD("Pointer speed:%{public}d, ret:%{public}d", speed, ret);
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubNotifyNapOnline(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    int32_t ret = NotifyNapOnline();
    return ret;
}

int32_t MultimodalInputConnectStub::StubRemoveInputEventObserver(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("Verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }
    int32_t ret = RemoveInputEventObserver();
    return ret;
}

int32_t MultimodalInputConnectStub::StubSetPointerStyle(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    int32_t windowId = 0;
    READINT32(data, windowId, RET_ERR);
    PointerStyle pointerStyle;
    READINT32(data, pointerStyle.size, RET_ERR);
    READINT32(data, pointerStyle.color, RET_ERR);
    READINT32(data, pointerStyle.id, RET_ERR);
    bool isUiExtension;
    READBOOL(data, isUiExtension, RET_ERR);
    int32_t ret = SetPointerStyle(windowId, pointerStyle, isUiExtension);
    if (ret != RET_OK) {
        MMI_HILOGE("Call SetPointerStyle failed ret:%{public}d", ret);
        return ret;
    }
    MMI_HILOGD("Successfully set windowId:%{public}d, icon:%{public}d", windowId, pointerStyle.id);
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubClearWindowPointerStyle(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("Verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }
    int32_t pid = 0;
    int32_t windowId = 0;
    READINT32(data, pid, RET_ERR);
    READINT32(data, windowId, RET_ERR);
    int32_t ret = ClearWindowPointerStyle(pid, windowId);
    if (ret != RET_OK) {
        MMI_HILOGE("Call SetPointerStyle failed ret:%{public}d", ret);
        return ret;
    }
    MMI_HILOGD("Successfully clean pointerStyle for windowId:%{public}d, pid:%{public}d", windowId, pid);
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubGetPointerStyle(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    int32_t windowId = 0;
    READINT32(data, windowId, RET_ERR);
    bool isUiExtension;
    READBOOL(data, isUiExtension, RET_ERR);
    PointerStyle pointerStyle;
    int32_t ret = GetPointerStyle(windowId, pointerStyle, isUiExtension);
    if (ret != RET_OK) {
        MMI_HILOGE("Call GetPointerStyle failed ret:%{public}d", ret);
        return ret;
    }
    WRITEINT32(reply, pointerStyle.size, RET_ERR);
    WRITEINT32(reply, pointerStyle.color, RET_ERR);
    WRITEINT32(reply, pointerStyle.id, RET_ERR);
    WRITEINT32(reply, pointerStyle.options, RET_ERR);
    MMI_HILOGD("Successfully get windowId:%{public}d, icon:%{public}d", windowId, pointerStyle.id);
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
        MMI_HILOGE("Invalid size:%{public}d", size);
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
    if (!PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("Verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }

    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
        return MMISERVICE_NOT_RUNNING;
    }
    int32_t handlerType = 0;
    READINT32(data, handlerType, IPC_PROXY_DEAD_OBJECT_ERR);
    if ((handlerType == InputHandlerType::INTERCEPTOR) && (!PER_HELPER->CheckInterceptor())) {
        MMI_HILOGE("Interceptor permission check failed");
        return ERROR_NO_PERMISSION;
    }
    if ((handlerType == InputHandlerType::MONITOR) && (!PER_HELPER->CheckMonitor())) {
        MMI_HILOGE("Monitor permission check failed");
        return ERROR_NO_PERMISSION;
    }
    uint32_t eventType = 0;
    READUINT32(data, eventType, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t priority = 0;
    READINT32(data, priority, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t deviceTags = 0;
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
    if (!PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("Verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }

    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
        return MMISERVICE_NOT_RUNNING;
    }
    int32_t handlerType = 0;
    READINT32(data, handlerType, IPC_PROXY_DEAD_OBJECT_ERR);
    if ((handlerType == InputHandlerType::INTERCEPTOR) && (!PER_HELPER->CheckInterceptor())) {
        MMI_HILOGE("Interceptor permission check failed");
        return ERROR_NO_PERMISSION;
    }
    if ((handlerType == InputHandlerType::MONITOR) && (!PER_HELPER->CheckMonitor())) {
        MMI_HILOGE("Monitor permission check failed");
        return ERROR_NO_PERMISSION;
    }
    uint32_t eventType = 0;
    READUINT32(data, eventType, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t priority = 0;
    READINT32(data, priority, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t deviceTags = 0;
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
    if (!PER_HELPER->CheckMonitor()) {
        MMI_HILOGE("Permission check failed");
        return ERROR_NO_PERMISSION;
    }

    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
        return MMISERVICE_NOT_RUNNING;
    }
    int32_t eventId = 0;
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
    if (!PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("Verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }

    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
        return MMISERVICE_NOT_RUNNING;
    }

    int32_t subscribeId = 0;
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
    if (!PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("Verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }

    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
        return MMISERVICE_NOT_RUNNING;
    }

    int32_t subscribeId = 0;
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
    if (!PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("Verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }

    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
        return MMISERVICE_NOT_RUNNING;
    }

    int32_t subscribeId = 0;
    int32_t switchType = 0;
    READINT32(data, subscribeId, IPC_PROXY_DEAD_OBJECT_ERR);
    READINT32(data, switchType, IPC_PROXY_DEAD_OBJECT_ERR);

    int32_t ret = SubscribeSwitchEvent(subscribeId, switchType);
    if (ret != RET_OK) {
        MMI_HILOGE("SubscribeSwitchEvent failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectStub::StubUnsubscribeSwitchEvent(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("Verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }

    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
        return MMISERVICE_NOT_RUNNING;
    }

    int32_t subscribeId = 0;
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
    if (!PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("Verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }
    if (!PER_HELPER->CheckMouseCursor()) {
        MMI_HILOGE("Mouse cursor permission check failed");
        return ERROR_NO_PERMISSION;
    }
    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
        return MMISERVICE_NOT_RUNNING;
    }
    int32_t offsetX = 0;
    READINT32(data, offsetX, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t offsetY = 0;
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
    LogTracer lt(event->GetId(), event->GetEventType(), event->GetKeyAction());
    bool isNativeInject { false };
    READBOOL(data, isNativeInject, IPC_PROXY_DEAD_OBJECT_ERR);
    if (!isNativeInject && !PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("Verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }
    EndLogTraceId(event->GetId());
    event->UpdateId();
    LogTracer lt1(event->GetId(), event->GetEventType(), event->GetKeyAction());
    int32_t ret = InjectKeyEvent(event, isNativeInject);
    if (ret != RET_OK) {
        MMI_HILOGE("InjectKeyEvent failed, ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubInjectPointerEvent(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
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
    bool isNativeInject { false };
    READBOOL(data, isNativeInject, IPC_PROXY_DEAD_OBJECT_ERR);
    if (!isNativeInject && !PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("Verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }
    int32_t ret = InjectPointerEvent(pointerEvent, isNativeInject);
    if (ret != RET_OK) {
        MMI_HILOGE("Call InjectPointerEvent failed ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubSetAnrListener(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("Verify system APP failed");
        return ERROR_NOT_SYSAPI;
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
    if (!PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("Verify system APP failed");
        return ERROR_NOT_SYSAPI;
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

int32_t MultimodalInputConnectStub::StubGetAllMmiSubscribedEvents(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("Verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }
    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
        return MMISERVICE_NOT_RUNNING;
    }
    std::map<std::tuple<int32_t, int32_t, std::string>, int32_t> datas;
    int32_t ret = GetAllMmiSubscribedEvents(datas);
    if (ret != RET_OK) {
        MMI_HILOGE("Call GetDisplayBindInfo failed, ret:%{public}d", ret);
        return ret;
    }
    int32_t size = static_cast<int32_t>(datas.size());
    WRITEINT32(reply, size, ERR_INVALID_VALUE);
    for (const auto &data : datas) {
        WRITEINT32(reply, std::get<TUPLE_PID>(data.first), ERR_INVALID_VALUE);
        WRITEINT32(reply, std::get<TUPLE_UID>(data.first), ERR_INVALID_VALUE);
        WRITESTRING(reply, std::get<TUPLE_NAME>(data.first), ERR_INVALID_VALUE);
        WRITEINT32(reply, data.second, ERR_INVALID_VALUE);
    }
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubSetDisplayBind(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("Verify system APP failed");
        return ERROR_NOT_SYSAPI;
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
    if (!PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("Verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }
    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
        return MMISERVICE_NOT_RUNNING;
    }

    int32_t funcKey { 0 };
    bool state { false };
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
    if (!PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("Verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }
    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
        return MMISERVICE_NOT_RUNNING;
    }

    int32_t funcKey { 0 };
    bool enable { false };
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
    if (!PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("StubSetPointerLocation Verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }
    if (!PER_HELPER->CheckMouseCursor()) {
        MMI_HILOGE("Mouse cursor permission check failed");
        return ERROR_NO_PERMISSION;
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
    if (!PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("Verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }
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
    if (!PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("Verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }
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

int32_t MultimodalInputConnectStub::StubEnableCombineKey(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("Verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }
    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
        return MMISERVICE_NOT_RUNNING;
    }
    bool enable;
    READBOOL(data, enable, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t ret = EnableCombineKey(enable);
    if (ret != RET_OK) {
        MMI_HILOGE("Call EnableCombineKey failed, ret:%{public}d", ret);
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
    if (!PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("Verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }
    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
        return MMISERVICE_NOT_RUNNING;
    }
    std::string businessId;
    READSTRING(data, businessId, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t delay = 0;
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

    if (!PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("Verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }

    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubSetTouchpadScrollSwitch(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    int32_t ret = VerifyTouchPadSetting();
    if (ret != RET_OK) {
        MMI_HILOGE("Verify touchpad setting failed");
        return ret;
    }

    bool switchFlag = true;
    READBOOL(data, switchFlag, IPC_PROXY_DEAD_OBJECT_ERR);
    ret = SetTouchpadScrollSwitch(switchFlag);
    if (ret != RET_OK) {
        MMI_HILOGE("Set touchpad scroll switch failed ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubGetTouchpadScrollSwitch(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    int32_t ret = VerifyTouchPadSetting();
    if (ret != RET_OK) {
        MMI_HILOGE("Verify touchpad setting failed");
        return ret;
    }

    bool switchFlag = true;
    ret = GetTouchpadScrollSwitch(switchFlag);
    if (ret != RET_OK) {
        MMI_HILOGE("Call GetTouchpadScrollSwitch failed ret:%{public}d", ret);
        return ret;
    }
    WRITEBOOL(reply, switchFlag, IPC_STUB_WRITE_PARCEL_ERR);
    MMI_HILOGD("Touchpad scroll switch :%{public}d, ret:%{public}d", switchFlag, ret);
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubSetTouchpadScrollDirection(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    int32_t ret = VerifyTouchPadSetting();
    if (ret != RET_OK) {
        MMI_HILOGE("Verify touchpad setting failed");
        return ret;
    }

    bool state = true;
    READBOOL(data, state, IPC_PROXY_DEAD_OBJECT_ERR);
    ret = SetTouchpadScrollDirection(state);
    if (ret != RET_OK) {
        MMI_HILOGE("Set touchpad scroll direction switch failed ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubGetTouchpadScrollDirection(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    int32_t ret = VerifyTouchPadSetting();
    if (ret != RET_OK) {
        MMI_HILOGE("Verify touchpad setting failed");
        return ret;
    }

    bool state = true;
    ret = GetTouchpadScrollDirection(state);
    if (ret != RET_OK) {
        MMI_HILOGE("Call GetTouchpadScrollDirection failed ret:%{public}d", ret);
        return ret;
    }
    WRITEBOOL(reply, state, IPC_STUB_WRITE_PARCEL_ERR);
    MMI_HILOGD("Touchpad scroll direction switch state:%{public}d, ret:%{public}d", state, ret);
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubSetTouchpadTapSwitch(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    int32_t ret = VerifyTouchPadSetting();
    if (ret != RET_OK) {
        MMI_HILOGE("Verify touchpad setting failed");
        return ret;
    }

    bool switchFlag = true;
    READBOOL(data, switchFlag, IPC_PROXY_DEAD_OBJECT_ERR);
    ret = SetTouchpadTapSwitch(switchFlag);
    if (ret != RET_OK) {
        MMI_HILOGE("Set touchpad tap switch failed ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubGetTouchpadTapSwitch(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    int32_t ret = VerifyTouchPadSetting();
    if (ret != RET_OK) {
        MMI_HILOGE("Verify touchpad setting failed");
        return ret;
    }

    bool switchFlag = true;
    ret = GetTouchpadTapSwitch(switchFlag);
    if (ret != RET_OK) {
        MMI_HILOGE("Call GetTouchpadTapSwitch failed ret:%{public}d", ret);
        return ret;
    }
    WRITEBOOL(reply, switchFlag, IPC_STUB_WRITE_PARCEL_ERR);
    MMI_HILOGD("Touchpad tap switchFlag:%{public}d, ret:%{public}d", switchFlag, ret);
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubSetTouchpadPointerSpeed(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    int32_t ret = VerifyTouchPadSetting();
    if (ret != RET_OK) {
        MMI_HILOGE("Verify touchpad setting failed");
        return ret;
    }

    int32_t speed = 1;
    READINT32(data, speed, IPC_PROXY_DEAD_OBJECT_ERR);
    ret = SetTouchpadPointerSpeed(speed);
    if (ret != RET_OK) {
        MMI_HILOGE("Set touchpad pointer speed failed ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubGetTouchpadPointerSpeed(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    int32_t ret = VerifyTouchPadSetting();
    if (ret != RET_OK) {
        MMI_HILOGE("Verify touchpad setting failed");
        return ret;
    }

    int32_t speed = 1;
    ret = GetTouchpadPointerSpeed(speed);
    if (ret != RET_OK) {
        MMI_HILOGE("Call GetTouchpadPointerSpeed failed ret:%{public}d", ret);
        return ret;
    }
    WRITEINT32(reply, speed, IPC_STUB_WRITE_PARCEL_ERR);
    MMI_HILOGD("Touchpad pointer speed:%{public}d, ret:%{public}d", speed, ret);
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubSetKeyboardRepeatDelay(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
        return MMISERVICE_NOT_RUNNING;
    }
    if (!PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("Verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }
    int32_t delay = 0;
    READINT32(data, delay, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t ret = SetKeyboardRepeatDelay(delay);
    if (ret != RET_OK) {
        MMI_HILOGE("Set keyboard repeat delay failed ret:%{public}d", ret);
        return RET_ERR;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubSetKeyboardRepeatRate(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
        return MMISERVICE_NOT_RUNNING;
    }
    if (!PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("Verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }
    int32_t rate = 0;
    READINT32(data, rate, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t ret = SetKeyboardRepeatRate(rate);
    if (ret != RET_OK) {
        MMI_HILOGE("Set keyboard repeat rate failed ret:%{public}d", ret);
        return RET_ERR;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubGetKeyboardRepeatDelay(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
        return MMISERVICE_NOT_RUNNING;
    }
    if (!PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("Verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }
    int32_t delay = 0;
    int32_t ret = GetKeyboardRepeatDelay(delay);
    if (ret != RET_OK) {
        MMI_HILOGE("Get keyboard repeat delay failed ret:%{public}d", ret);
        return RET_ERR;
    }
    WRITEINT32(reply, delay, IPC_STUB_WRITE_PARCEL_ERR);
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubGetKeyboardRepeatRate(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
        return MMISERVICE_NOT_RUNNING;
    }
    if (!PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("Verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }
    int32_t rate = 0;
    int32_t ret = GetKeyboardRepeatRate(rate);
    if (ret != RET_OK) {
        MMI_HILOGE("Get keyboard repeat rate failed ret:%{public}d", ret);
        return RET_ERR;
    }
    WRITEINT32(reply, rate, IPC_STUB_WRITE_PARCEL_ERR);
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubSetTouchpadPinchSwitch(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    int32_t ret = VerifyTouchPadSetting();
    if (ret != RET_OK) {
        MMI_HILOGE("Verify touchpad setting failed");
        return ret;
    }

    bool switchFlag = true;
    READBOOL(data, switchFlag, IPC_PROXY_DEAD_OBJECT_ERR);
    ret = SetTouchpadPinchSwitch(switchFlag);
    if (ret != RET_OK) {
        MMI_HILOGE("Set touchpad pinch switch failed ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubGetTouchpadPinchSwitch(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    int32_t ret = VerifyTouchPadSetting();
    if (ret != RET_OK) {
        MMI_HILOGE("Verify touchpad setting failed");
        return ret;
    }

    bool switchFlag = true;
    ret = GetTouchpadPinchSwitch(switchFlag);
    if (ret != RET_OK) {
        MMI_HILOGE("Call GetTouchpadPinchSwitch failed ret:%{public}d", ret);
        return ret;
    }
    WRITEBOOL(reply, switchFlag, IPC_STUB_WRITE_PARCEL_ERR);
    MMI_HILOGD("Touchpad pinch switchFlag:%{public}d, ret:%{public}d", switchFlag, ret);
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubSetTouchpadSwipeSwitch(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    int32_t ret = VerifyTouchPadSetting();
    if (ret != RET_OK) {
        MMI_HILOGE("Verify touchpad setting failed");
        return ret;
    }

    bool switchFlag = true;
    READBOOL(data, switchFlag, IPC_PROXY_DEAD_OBJECT_ERR);
    ret = SetTouchpadSwipeSwitch(switchFlag);
    if (ret != RET_OK) {
        MMI_HILOGE("Set touchpad swipe switch failed ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubGetTouchpadSwipeSwitch(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    int32_t ret = VerifyTouchPadSetting();
    if (ret != RET_OK) {
        MMI_HILOGE("Verify touchpad setting failed");
        return ret;
    }

    bool switchFlag = true;
    ret = GetTouchpadSwipeSwitch(switchFlag);
    if (ret != RET_OK) {
        MMI_HILOGE("Call GetTouchpadSwipeSwitch failed ret:%{public}d", ret);
        return ret;
    }
    WRITEBOOL(reply, switchFlag, IPC_STUB_WRITE_PARCEL_ERR);
    MMI_HILOGD("Touchpad swipe switchFlag:%{public}d, ret:%{public}d", switchFlag, ret);
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubSetTouchpadRightClickType(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    int32_t ret = VerifyTouchPadSetting();
    if (ret != RET_OK) {
        MMI_HILOGE("Verify touchpad setting failed");
        return ret;
    }

    int32_t type = 1;
    READINT32(data, type, IPC_PROXY_DEAD_OBJECT_ERR);
    ret = SetTouchpadRightClickType(type);
    if (ret != RET_OK) {
        MMI_HILOGE("Set touchpad right button menu type failed ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubGetTouchpadRightClickType(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    int32_t ret = VerifyTouchPadSetting();
    if (ret != RET_OK) {
        MMI_HILOGE("Verify touchpad setting failed");
        return ret;
    }

    int32_t type = 1;
    ret = GetTouchpadRightClickType(type);
    if (ret != RET_OK) {
        MMI_HILOGE("Call GetTouchpadRightClickType failed ret:%{public}d", ret);
        return ret;
    }
    WRITEINT32(reply, type, IPC_STUB_WRITE_PARCEL_ERR);
    MMI_HILOGD("Touchpad right button menu type:%{public}d, ret:%{public}d", type, ret);
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubSetTouchpadRotateSwitch(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    int32_t ret = VerifyTouchPadSetting();
    if (ret != RET_OK) {
        MMI_HILOGE("Verify touchpad setting failed");
        return ret;
    }

    bool rotateSwitch = true;
    READBOOL(data, rotateSwitch, IPC_PROXY_DEAD_OBJECT_ERR);
    ret = SetTouchpadRotateSwitch(rotateSwitch);
    if (ret != RET_OK) {
        MMI_HILOGE("Set touchpad rotate switch failed ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubGetTouchpadRotateSwitch(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    int32_t ret = VerifyTouchPadSetting();
    if (ret != RET_OK) {
        MMI_HILOGE("Verify touchpad setting failed");
        return ret;
    }

    bool rotateSwitch = true;
    ret = GetTouchpadRotateSwitch(rotateSwitch);
    if (ret != RET_OK) {
        MMI_HILOGE("GetTouchpadRotateSwitch failed ret:%{public}d", ret);
        return ret;
    }
    WRITEBOOL(reply, rotateSwitch, IPC_STUB_WRITE_PARCEL_ERR);
    MMI_HILOGD("Touchpad rotate switch:%{public}d, ret:%{public}d", rotateSwitch, ret);
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubSetShieldStatus(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("Verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }
    if (!PER_HELPER->CheckDispatchControl()) {
        MMI_HILOGE("input dispatch control permission check failed");
        return ERROR_NO_PERMISSION;
    }
    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
        return MMISERVICE_NOT_RUNNING;
    }

    int32_t shieldMode { 0 };
    bool isShield { false };
    READINT32(data, shieldMode, IPC_PROXY_DEAD_OBJECT_ERR);
    READBOOL(data, isShield, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t ret = SetShieldStatus(shieldMode, isShield);
    if (ret != RET_OK) {
        MMI_HILOGE("Call SetShieldStatus failed, ret:%{public}d", ret);
        return ret;
    }
    MMI_HILOGD("Success shieldMode:%{public}d, isShield:%{public}d", shieldMode, isShield);
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubGetShieldStatus(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("Verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }
    if (!PER_HELPER->CheckDispatchControl()) {
        MMI_HILOGE("input dispatch control permission check failed");
        return ERROR_NO_PERMISSION;
    }
    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
        return MMISERVICE_NOT_RUNNING;
    }

    int32_t shieldMode { 0 };
    bool state { false };
    READINT32(data, shieldMode, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t ret = GetShieldStatus(shieldMode, state);
    if (ret != RET_OK) {
        MMI_HILOGE("Call GetShieldStatus failed ret:%{public}d", ret);
        return ret;
    }
    WRITEBOOL(reply, state, IPC_PROXY_DEAD_OBJECT_ERR);
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubGetKeyState(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    std::vector<int32_t> pressedKeys;
    std::map<int32_t, int32_t> specialKeysState;
    int32_t ret = GetKeyState(pressedKeys, specialKeysState);
    if (ret != RET_OK) {
        MMI_HILOGE("Call GetKeyState failed ret:%{public}d", ret);
        return RET_ERR;
    }
    if (!reply.WriteInt32Vector(pressedKeys)) {
        MMI_HILOGE("Write pressedKeys failed");
        return RET_ERR;
    }
    std::vector<int32_t> specialKeysStateTmp;
    for (const auto &item : specialKeysState) {
        specialKeysStateTmp.push_back(item.second);
    }
    if (!reply.WriteInt32Vector(specialKeysStateTmp)) {
        MMI_HILOGE("Write specialKeysStateTmp failed");
        return RET_ERR;
    }
    return ret;
}

int32_t MultimodalInputConnectStub::StubAuthorize(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("Verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }
    if (!PER_HELPER->CheckAuthorize()) {
        MMI_HILOGE("input authorize permission check failed");
        return ERROR_NO_PERMISSION;
    }
    bool isAuthorize { false };
    READBOOL(data, isAuthorize, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t ret = Authorize(isAuthorize);
    if (ret != RET_OK) {
        MMI_HILOGE("Call Authorize failed ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubCancelInjection(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    int32_t ret = CancelInjection();
    if (ret != RET_OK) {
        MMI_HILOGE("Call CancelInjection failed ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubHasIrEmitter(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("Verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }
    bool hasIrEmitter = false;
    int32_t ret = HasIrEmitter(hasIrEmitter);
    if (ret != RET_OK) {
        MMI_HILOGE("Call StubHasIrEmitter failed ret:%{public}d", ret);
        return ret;
    }
    WRITEBOOL(reply, hasIrEmitter, IPC_STUB_WRITE_PARCEL_ERR);
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubGetInfraredFrequencies(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("GetInfraredFrequencies Verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }
    if (!PER_HELPER->CheckInfraredEmmit()) {
        MMI_HILOGE("Infrared permission check failed");
        return ERROR_NO_PERMISSION;
    }
    std::vector<InfraredFrequency> requencys;
    int32_t ret = GetInfraredFrequencies(requencys);
    if (ret != RET_OK) {
        MMI_HILOGE("Call StubGetInfraredFrequencies failed returnCode:%{public}d", ret);
        return ret;
    }
    WRITEINT64(reply, requencys.size());
    for (const auto &item : requencys) {
        WRITEINT64(reply, item.max_);
        WRITEINT64(reply, item.min_);
    }
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubTransmitInfrared(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("StubTransmitInfrared Verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }
    if (!PER_HELPER->CheckInfraredEmmit()) {
        MMI_HILOGE("StubTransmitInfrared permission check failed. returnCode:%{public}d", ERROR_NO_PERMISSION);
        return ERROR_NO_PERMISSION;
    }
    int64_t number = 0;
    READINT64(data, number, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t patternLen = 0;
    std::vector<int64_t> pattern;
    READINT32(data, patternLen, IPC_PROXY_DEAD_OBJECT_ERR);
    if (patternLen > MAX_N_TRANSMIT_INFRARED_PATTERN || patternLen <= 0) {
        MMI_HILOGE("Transmit infrared pattern len is invalid");
        return false;
    }
    for (int32_t i = 0; i < patternLen; i++) {
        int64_t value = 0;
        READINT64(data, value);
        pattern.push_back(value);
    }
    int32_t ret = TransmitInfrared(number, pattern);
    if (ret != RET_OK) {
        MMI_HILOGE("Call StubTransmitInfrared failed returnCode:%{public}d", ret);
        return ret;
    }
    WRITEINT32(reply, ret);
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubSetPixelMapData(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("Verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }
    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
        return MMISERVICE_NOT_RUNNING;
    }
    int32_t infoId = -1;
    READINT32(data, infoId, IPC_PROXY_DEAD_OBJECT_ERR);
    if (infoId <= 0) {
        MMI_HILOGE("Invalid infoId:%{public}d", infoId);
        return RET_ERR;
    }
    OHOS::Media::PixelMap* pixelMap = Media::PixelMap::Unmarshalling(data);
    CHKPR(pixelMap, RET_ERR);
    int32_t ret = SetPixelMapData(infoId, static_cast<void*>(pixelMap));
    if (ret != RET_OK) {
        MMI_HILOGE("Failed to call SetPixelMapData, ret:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectStub::StubSetMoveEventFilters(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("StubSetMoveEventFilters Verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }
    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
        return MMISERVICE_NOT_RUNNING;
    }
    bool flag = false;
    READBOOL(data, flag, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t ret = SetMoveEventFilters(flag);
    if (ret != RET_OK) {
        MMI_HILOGE("Call SetMoveEventFilters failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectStub::StubSetCurrentUser(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("StubSetCurrentUser Verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }
    int32_t userId = 0;
    READINT32(data, userId, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t ret = SetCurrentUser(userId);
    if (ret != RET_OK) {
        MMI_HILOGE("Failed to call SetCurrentUser ret:%{public}d", ret);
        return ret;
    }
    WRITEINT32(reply, ret);
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubSetTouchpadThreeFingersTapSwitch(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("StubSetTouchpadThreeFingersTapSwitch Verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }
    bool threeFingersTapSwitch = true;
    READBOOL(data, threeFingersTapSwitch, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t ret = SetTouchpadThreeFingersTapSwitch(threeFingersTapSwitch);
    if (ret != RET_OK) {
        MMI_HILOGE("Failed to call StubSetTouchpadThreeFingersTapSwitch ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubGetTouchpadThreeFingersTapSwitch(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("StubGetTouchpadThreeFingersTapSwitch Verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }
    bool switchFlag = true;
    int32_t ret = GetTouchpadThreeFingersTapSwitch(switchFlag);
    if (ret != RET_OK) {
        MMI_HILOGE("Failed to call StubGetTouchpadThreeFingersTapSwitch ret:%{public}d", ret);
    } else {
        WRITEBOOL(reply, switchFlag);
    }
    return ret;
}

int32_t MultimodalInputConnectStub::StubEnableHardwareCursorStats(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    bool enable = false;
    READBOOL(data, enable, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t ret = EnableHardwareCursorStats(enable);
    if (ret != RET_OK) {
        MMI_HILOGE("Call EnableHardwareCursorStats failed ret:%{public}d", ret);
        return ret;
    }
    MMI_HILOGD("Success enable:%{public}d, pid:%{public}d", enable, GetCallingPid());
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubGetHardwareCursorStats(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    uint32_t frameCount = 0;
    uint32_t vsyncCount = 0;
    int32_t ret = GetHardwareCursorStats(frameCount, vsyncCount);
    if (ret != RET_OK) {
        MMI_HILOGE("Call GetHardwareCursorStats failed ret:%{public}d", ret);
        return ret;
    }
    MMI_HILOGD("Success frameCount:%{public}d, vsyncCount:%{public}d, pid:%{public}d", frameCount,
        vsyncCount, GetCallingPid());
    WRITEUINT32(reply, frameCount, IPC_PROXY_DEAD_OBJECT_ERR);
    WRITEUINT32(reply, vsyncCount, IPC_PROXY_DEAD_OBJECT_ERR);
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubSetTouchpadScrollRows(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
        return MMISERVICE_NOT_RUNNING;
    }
    if (!PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("Verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }
    int32_t rows = TOUCHPAD_SCROLL_ROWS;
    READINT32(data, rows, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t newRows = std::clamp(rows, MIN_ROWS, MAX_ROWS);
    int32_t ret = SetTouchpadScrollRows(newRows);
    if (ret != RET_OK) {
        MMI_HILOGE("Call SetTouchpadScrollRows failed ret:%{public}d, pid:%{public}d", ret, GetCallingPid());
    }
    MMI_HILOGD("Success rows:%{public}d, pid:%{public}d", newRows, GetCallingPid());
    return ret;
}

int32_t MultimodalInputConnectStub::StubGetTouchpadScrollRows(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
        return MMISERVICE_NOT_RUNNING;
    }
    if (!PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("Verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }
    int32_t rows = TOUCHPAD_SCROLL_ROWS;
    int32_t ret = GetTouchpadScrollRows(rows);
    if (rows < MIN_ROWS || rows > MAX_ROWS) {
        MMI_HILOGD("Invalid touchpad scroll rows:%{public}d, ret:%{public}d", rows, ret);
        return ret;
    }
    if (ret != RET_OK) {
        MMI_HILOGE("Call GetTouchpadScrollRows failed, ret:%{public}d", ret);
        return ret;
    }
    WRITEINT32(reply, rows, IPC_STUB_WRITE_PARCEL_ERR);
    MMI_HILOGD("Touchpad scroll rows:%{public}d, ret:%{public}d", rows, ret);
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubGetPointerSnapshot(MessageParcel &data, MessageParcel &reply)
{
    CALL_DEBUG_ENTER;
    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
        return MMISERVICE_NOT_RUNNING;
    }
    std::shared_ptr<Media::PixelMap> pixelMap;
    int32_t ret = GetPointerSnapshot(&pixelMap);
    if (ret != RET_OK) {
        MMI_HILOGE("Call GetPointerSnapshot failed ret:%{public}d", ret);
        return ret;
    }
    CHKPR(pixelMap, ERR_INVALID_VALUE);
    if (pixelMap->GetCapacity() == 0) {
        MMI_HILOGE("pixelMap is empty, we dont have to pass it to the server");
        return ERR_INVALID_VALUE;
    }
    pixelMap->Marshalling(reply);
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubAddVirtualInputDevice(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("Verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }
    auto device = std::make_shared<InputDevice>();
    if (g_parseInputDevice(data, device) != RET_OK) {
        MMI_HILOGE("ParseInputDevice failed");
        return RET_ERR;
    }
    int32_t deviceId { -1 };
    int32_t ret = AddVirtualInputDevice(device, deviceId);
    if (ret != RET_OK) {
        MMI_HILOGE("AddVirtualInputDevice failed");
        return ret;
    }
    WRITEINT32(reply, deviceId);
    return RET_OK;
}

int32_t MultimodalInputConnectStub::StubRemoveVirtualInputDevice(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("Verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }
    int32_t deviceId { -1 };
    READINT32(data, deviceId, IPC_PROXY_DEAD_OBJECT_ERR);
    int32_t ret = RemoveVirtualInputDevice(deviceId);
    if (ret != RET_OK) {
        MMI_HILOGE("RemoveVirtualInputDevice failed");
        return ret;
    }
    WRITEINT32(reply, ret);
    return RET_OK;
}

#ifdef OHOS_BUILD_ENABLE_ANCO
int32_t MultimodalInputConnectStub::StubAncoAddChannel(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("Verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }
    sptr<IRemoteObject> remoteObj = data.ReadRemoteObject();
    CHKPR(remoteObj, ERR_INVALID_VALUE);
    sptr<IAncoChannel> channel = iface_cast<IAncoChannel>(remoteObj);
    CHKPR(channel, ERROR_NULL_POINTER);
    int32_t ret = AncoAddChannel(channel);
    if (ret != RET_OK) {
        MMI_HILOGE("AncoAddChannel fail, error:%{public}d", ret);
    }
    WRITEINT32(reply, ret);
    return ret;
}

int32_t MultimodalInputConnectStub::StubAncoRemoveChannel(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    if (!PER_HELPER->VerifySystemApp()) {
        MMI_HILOGE("Verify system APP failed");
        return ERROR_NOT_SYSAPI;
    }
    sptr<IRemoteObject> remoteObj = data.ReadRemoteObject();
    CHKPR(remoteObj, ERR_INVALID_VALUE);
    sptr<IAncoChannel> channel = iface_cast<IAncoChannel>(remoteObj);
    CHKPR(channel, ERROR_NULL_POINTER);
    int32_t ret = AncoRemoveChannel(channel);
    if (ret != RET_OK) {
        MMI_HILOGE("AncoRemoveChannel fail, error:%{public}d", ret);
    }
    WRITEINT32(reply, ret);
    return ret;
}
#endif // OHOS_BUILD_ENABLE_ANCO

int32_t MultimodalInputConnectStub::StubTransferBinderClientService(MessageParcel& data, MessageParcel& reply)
{
    CALL_DEBUG_ENTER;
    sptr<IRemoteObject> remoteObj = data.ReadRemoteObject();
    CHKPR(remoteObj, ERROR_NULL_POINTER);
    int32_t ret = TransferBinderClientSrv(remoteObj);
    if (ret != RET_OK) {
        MMI_HILOGE("TransferBinderClientSrv failed");
        return ret;
    }
    WRITEINT32(reply, ret);
    return RET_OK;
}
} // namespace MMI
} // namespace OHOS
