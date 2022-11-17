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

#include "multimodal_input_connect_proxy.h"

#include "message_option.h"
#include "mmi_log.h"
#include "multimodal_input_connect_def_parcel.h"
#include "multimodal_input_connect_define.h"
#include "string_ex.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "MultimodalInputConnectProxy" };
} // namespace

MultimodalInputConnectProxy::MultimodalInputConnectProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IMultimodalInputConnect>(impl)
{
    MMI_HILOGD("Enter MultimodalInputConnectProxy");
}

MultimodalInputConnectProxy::~MultimodalInputConnectProxy()
{
    MMI_HILOGD("Enter ~MultimodalInputConnectProxy");
}

int32_t MultimodalInputConnectProxy::AllocSocketFd(const std::string &programName,
    const int32_t moduleType, int32_t &socketFd, int32_t &tokenType)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }

    ConnectReqParcel req;
    req.data.moduleId = moduleType;
    req.data.clientName = programName;
    if (!data.WriteParcelable(&req)) {
        MMI_HILOGE("Failed to write programName");
        return ERR_INVALID_VALUE;
    }

    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(ALLOC_SOCKET_FD, data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
        return RET_ERR;
    }
    socketFd = reply.ReadFileDescriptor();
    READINT32(reply, tokenType, IPC_PROXY_DEAD_OBJECT_ERR);
    MMI_HILOGD("socketFd:%{public}d tokenType:%{public}d", socketFd, tokenType);
    return RET_OK;
}

int32_t MultimodalInputConnectProxy::AddInputEventFilter(sptr<IEventFilter> filter)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }

    if (!data.WriteRemoteObject(filter->AsObject().GetRefPtr())) {
        MMI_HILOGE("Failed to write filter");
        return ERR_INVALID_VALUE;
    }

    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(ADD_INPUT_EVENT_FILTER, data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Reply readint32 error:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectProxy::SetPointerVisible(bool visible)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }

    WRITEBOOL(data, visible, ERR_INVALID_VALUE);

    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(SET_POINTER_VISIBLE, data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectProxy::IsPointerVisible(bool &visible)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }

    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(IS_POINTER_VISIBLE, data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
        return ret;
    }
    visible = reply.ReadBool();
    return RET_OK;
}

int32_t MultimodalInputConnectProxy::SetPointerSpeed(int32_t speed)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    WRITEINT32(data, speed, ERR_INVALID_VALUE);
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(SET_POINTER_SPEED, data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
        return RET_ERR;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectProxy::GetPointerSpeed(int32_t &speed)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(GET_POINTER_SPEED, data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
        return RET_ERR;
    }
    speed = reply.ReadInt32();
    return RET_OK;
}

int32_t MultimodalInputConnectProxy::SetPointerStyle(int32_t windowId, int32_t pointerStyle)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return RET_ERR;
    }

    WRITEINT32(data, windowId, RET_ERR);
    WRITEINT32(data, pointerStyle, RET_ERR);

    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(SET_POINTER_STYLE, data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request fail, ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectProxy::GetPointerStyle(int32_t windowId, int32_t &pointerStyle)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return RET_ERR;
    }
    WRITEINT32(data, windowId, RET_ERR);
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(GET_POINTER_STYLE, data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request fail, ret:%{public}d", ret);
        return ret;
    }
    pointerStyle = reply.ReadInt32();
    return RET_OK;
}

int32_t MultimodalInputConnectProxy::RegisterDevListener()
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }

    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(REGISTER_DEV_MONITOR, data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectProxy::UnregisterDevListener()
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }

    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(UNREGISTER_DEV_MONITOR, data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectProxy::SupportKeys(int32_t userData, int32_t deviceId, std::vector<int32_t> &keys)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return RET_ERR;
    }
    WRITEINT32(data, userData);
    WRITEINT32(data, deviceId);
    WRITEINT32(data, static_cast<int32_t>(keys.size()));
    for (const auto &item : keys) {
        WRITEINT32(data, item);
    }

    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(SUPPORT_KEYS, data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectProxy::GetDeviceIds(int32_t userData)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return RET_ERR;
    }
    WRITEINT32(data, userData);
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(GET_DEVICE_IDS, data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectProxy::GetDevice(int32_t userData, int32_t deviceId)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return RET_ERR;
    }
    WRITEINT32(data, userData);
    WRITEINT32(data, deviceId);
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(GET_DEVICE, data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectProxy::GetKeyboardType(int32_t userData, int32_t deviceId)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return RET_ERR;
    }
    WRITEINT32(data, userData);
    WRITEINT32(data, deviceId);
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(GET_KEYBOARD_TYPE, data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectProxy::AddInputHandler(InputHandlerType handlerType,
    HandleEventType eventType)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    WRITEINT32(data, handlerType, ERR_INVALID_VALUE);
    WRITEUINT32(data, eventType, ERR_INVALID_VALUE);
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(ADD_INPUT_HANDLER, data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectProxy::RemoveInputHandler(InputHandlerType handlerType, HandleEventType eventType)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    WRITEINT32(data, handlerType, ERR_INVALID_VALUE);
    WRITEUINT32(data, eventType, ERR_INVALID_VALUE);
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(REMOVE_INPUT_HANDLER, data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectProxy::MarkEventConsumed(int32_t eventId)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    WRITEINT32(data, eventId, ERR_INVALID_VALUE);
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(MARK_EVENT_CONSUMED, data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectProxy::MoveMouseEvent(int32_t offsetX, int32_t offsetY)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    WRITEINT32(data, offsetX, ERR_INVALID_VALUE);
    WRITEINT32(data, offsetY, ERR_INVALID_VALUE);

    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(MOVE_MOUSE, data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectProxy::InjectKeyEvent(const std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPR(keyEvent, ERR_INVALID_VALUE);
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    if (!keyEvent->WriteToParcel(data)) {
        MMI_HILOGE("Failed to write inject event");
        return ERR_INVALID_VALUE;
    }
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(INJECT_KEY_EVENT, data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectProxy::SubscribeKeyEvent(int32_t subscribeId, const std::shared_ptr<KeyOption> keyOption)
{
    CALL_DEBUG_ENTER;
    CHKPR(keyOption, ERR_INVALID_VALUE);

    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    WRITEINT32(data, subscribeId, ERR_INVALID_VALUE);
    if (!keyOption->WriteToParcel(data)) {
        MMI_HILOGE("Failed to write key option");
        return ERR_INVALID_VALUE;
    }

    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(SUBSCRIBE_KEY_EVENT, data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, result:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectProxy::UnsubscribeKeyEvent(int32_t subscribeId)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    WRITEINT32(data, subscribeId, ERR_INVALID_VALUE);

    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(UNSUBSCRIBE_KEY_EVENT, data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, result:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectProxy::InjectPointerEvent(const std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    CHKPR(pointerEvent, ERR_INVALID_VALUE);
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    if (!pointerEvent->WriteToParcel(data)) {
        MMI_HILOGE("Failed to write inject point event");
        return ERR_INVALID_VALUE;
    }
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(INJECT_POINTER_EVENT, data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectProxy::SetAnrObserver()
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(SET_ANR_OBSERVER, data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectProxy::SetInputDevice(const std::string& dhid, const std::string& screenId)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }

    WRITESTRING(data, dhid, ERR_INVALID_VALUE);
    WRITESTRING(data, screenId, ERR_INVALID_VALUE);

    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(SET_INPUT_DEVICE_TO_SCREEN, data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request fail, result:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectProxy::RegisterCooperateListener()
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(REGISTER_COOPERATE_MONITOR, data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request fail, ret:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectProxy::UnregisterCooperateListener()
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(UNREGISTER_COOPERATE_MONITOR, data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request fail, ret:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectProxy::EnableInputDeviceCooperate(int32_t userData, bool enabled)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    WRITEINT32(data, userData, ERR_INVALID_VALUE);
    WRITEBOOL(data, enabled, ERR_INVALID_VALUE);
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(ENABLE_INPUT_DEVICE_COOPERATE, data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request fail, ret:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectProxy::StartInputDeviceCooperate(int32_t userData, const std::string &sinkDeviceId,
    int32_t srcInputDeviceId)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    WRITEINT32(data, userData, ERR_INVALID_VALUE);
    WRITESTRING(data, sinkDeviceId, ERR_INVALID_VALUE);
    WRITEINT32(data, srcInputDeviceId, ERR_INVALID_VALUE);
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(START_INPUT_DEVICE_COOPERATE, data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request fail, ret:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectProxy::StopDeviceCooperate(int32_t userData)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    WRITEINT32(data, userData, ERR_INVALID_VALUE);
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(STOP_DEVICE_COOPERATE, data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request fail, ret:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectProxy::GetInputDeviceCooperateState(int32_t userData, const std::string &deviceId)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    WRITEINT32(data, userData, ERR_INVALID_VALUE);
    WRITESTRING(data, deviceId, ERR_INVALID_VALUE);
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(GET_INPUT_DEVICE_COOPERATE_STATE, data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request fail, ret:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectProxy::GetFunctionKeyState(int32_t funcKey, bool &state)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    MessageParcel reply;
    MessageOption option;
    WRITEINT32(data, funcKey, ERR_INVALID_VALUE);
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(GET_FUNCTION_KEY_STATE, data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
        return ret;
    }
    READBOOL(reply, state, ERR_INVALID_VALUE);
    return RET_OK;
}

int32_t MultimodalInputConnectProxy::SetFunctionKeyState(int32_t funcKey, bool enable)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    MessageParcel reply;
    MessageOption option;
    WRITEINT32(data, funcKey, ERR_INVALID_VALUE);
    WRITEBOOL(data, enable, ERR_INVALID_VALUE);
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(SET_FUNCTION_KEY_STATE, data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
    }
    return ret;
}
} // namespace MMI
} // namespace OHOS
