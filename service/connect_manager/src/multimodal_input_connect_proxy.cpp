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

int32_t ParseInputDevice(MessageParcel &reply, std::shared_ptr<InputDevice> &inputDevice)
{
    int32_t value;
    READINT32(reply, value, IPC_PROXY_DEAD_OBJECT_ERR);
    inputDevice->SetId(value);
    READINT32(reply, value, IPC_PROXY_DEAD_OBJECT_ERR);
    inputDevice->SetType(value);
    std::string name;
    READSTRING(reply, name, IPC_PROXY_DEAD_OBJECT_ERR);
    inputDevice->SetName(name);
    READINT32(reply, value, IPC_PROXY_DEAD_OBJECT_ERR);
    inputDevice->SetBus(value);
    READINT32(reply, value, IPC_PROXY_DEAD_OBJECT_ERR);
    inputDevice->SetVersion(value);
    READINT32(reply, value, IPC_PROXY_DEAD_OBJECT_ERR);
    inputDevice->SetProduct(value);
    READINT32(reply, value, IPC_PROXY_DEAD_OBJECT_ERR);
    inputDevice->SetVendor(value);
    std::string phys;
    READSTRING(reply, phys, IPC_PROXY_DEAD_OBJECT_ERR);
    inputDevice->SetPhys(phys);
    std::string uniq;
    READSTRING(reply, uniq, IPC_PROXY_DEAD_OBJECT_ERR);
    inputDevice->SetUniq(uniq);
    uint64_t caps;
    READUINT64(reply, caps, IPC_PROXY_DEAD_OBJECT_ERR);
    inputDevice->SetCapabilities(static_cast<unsigned long>(caps));

    uint32_t size;
    READUINT32(reply, size, IPC_PROXY_DEAD_OBJECT_ERR);
    InputDevice::AxisInfo axis;
    for (uint32_t i = 0; i < size; ++i) {
        int32_t val;
        READINT32(reply, val, IPC_PROXY_DEAD_OBJECT_ERR);
        axis.SetMinimum(val);
        READINT32(reply, val, IPC_PROXY_DEAD_OBJECT_ERR);
        axis.SetMaximum(val);
        READINT32(reply, val, IPC_PROXY_DEAD_OBJECT_ERR);
        axis.SetAxisType(val);
        READINT32(reply, val, IPC_PROXY_DEAD_OBJECT_ERR);
        axis.SetFuzz(val);
        READINT32(reply, val, IPC_PROXY_DEAD_OBJECT_ERR);
        axis.SetFlat(val);
        READINT32(reply, val, IPC_PROXY_DEAD_OBJECT_ERR);
        axis.SetResolution(val);
        inputDevice->AddAxisInfo(axis);
    }
    return RET_OK;
}
} // namespace

MultimodalInputConnectProxy::MultimodalInputConnectProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IMultimodalInputConnect>(impl)
{
    MMI_HILOGD("Enter MultimodalInputConnectProxy");
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
    if (socketFd < RET_OK) {
        MMI_HILOGE("Read file descriptor failed, fd: %{public}d", socketFd);
        return IPC_PROXY_DEAD_OBJECT_ERR;
    }
    READINT32(reply, tokenType, IPC_PROXY_DEAD_OBJECT_ERR);
    MMI_HILOGD("socketFd:%{public}d tokenType:%{public}d", socketFd, tokenType);
    return RET_OK;
}

int32_t MultimodalInputConnectProxy::AddInputEventFilter(sptr<IEventFilter> filter, int32_t filterId, int32_t priority)
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
    WRITEINT32(data, filterId, ERR_INVALID_VALUE);
    WRITEINT32(data, priority, ERR_INVALID_VALUE);
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(ADD_INPUT_EVENT_FILTER, data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request message failed, ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectProxy::RemoveInputEventFilter(int32_t filterId)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    WRITEINT32(data, filterId, ERR_INVALID_VALUE);
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(RMV_INPUT_EVENT_FILTER, data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request message failed, ret:%{public}d", ret);
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
    READBOOL(reply, visible, IPC_PROXY_DEAD_OBJECT_ERR);
    return RET_OK;
}

int32_t MultimodalInputConnectProxy::MarkProcessed(int32_t eventType, int32_t eventId)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    WRITEINT32(data, eventType, ERR_INVALID_VALUE);
    WRITEINT32(data, eventId, ERR_INVALID_VALUE);
    
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(MARK_PROCESSED, data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request fail, ret:%{public}d", ret);
        return ret;
    }
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
    READINT32(reply, speed, IPC_PROXY_DEAD_OBJECT_ERR);
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
    READINT32(reply, pointerStyle, IPC_PROXY_DEAD_OBJECT_ERR);
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

int32_t MultimodalInputConnectProxy::SupportKeys(int32_t deviceId, std::vector<int32_t> &keys,
    std::vector<bool> &keystroke)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return RET_ERR;
    }
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
    if (!reply.ReadBoolVector(&keystroke)) {
        MMI_HILOGE("Read ids failed");
        return RET_ERR;
    }
    MMI_HILOGE("keystroke size:%{public}zu", keystroke.size());
    return RET_OK;
}

int32_t MultimodalInputConnectProxy::GetDeviceIds(std::vector<int32_t> &ids)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return RET_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(GET_DEVICE_IDS, data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
        return ret;
    }
    if (!reply.ReadInt32Vector(&ids)) {
        MMI_HILOGE("Read vector failed");
        return RET_ERR;
    }
    MMI_HILOGE("ids size:%{public}zu", ids.size());
    return RET_OK;
}

int32_t MultimodalInputConnectProxy::GetDevice(int32_t deviceId, std::shared_ptr<InputDevice> &inputDevice)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return RET_ERR;
    }
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
    ret = ParseInputDevice(reply, inputDevice);
    if (ret != RET_OK) {
        MMI_HILOGE("ParseInputDevice failed");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectProxy::GetKeyboardType(int32_t deviceId, int32_t &keyboardType)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return RET_ERR;
    }
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
    READINT32(reply, keyboardType, IPC_PROXY_DEAD_OBJECT_ERR);
    return RET_OK;
}

int32_t MultimodalInputConnectProxy::AddInputHandler(InputHandlerType handlerType,
    HandleEventType eventType, int32_t priority, uint32_t deviceTags)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    WRITEINT32(data, handlerType, ERR_INVALID_VALUE);
    WRITEUINT32(data, eventType, ERR_INVALID_VALUE);
    WRITEINT32(data, priority, ERR_INVALID_VALUE);
    WRITEUINT32(data, deviceTags, ERR_INVALID_VALUE);
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

int32_t MultimodalInputConnectProxy::RemoveInputHandler(InputHandlerType handlerType,
    HandleEventType eventType, int32_t priority, uint32_t deviceTags)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    WRITEINT32(data, handlerType, ERR_INVALID_VALUE);
    WRITEUINT32(data, eventType, ERR_INVALID_VALUE);
    WRITEINT32(data, priority, ERR_INVALID_VALUE);
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

int32_t MultimodalInputConnectProxy::GetDisplayBindInfo(DisplayBindInfos &infos)
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
    int32_t ret = remote->SendRequest(GET_DISPLAY_BIND_INFO, data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
        return ret;
    }
    int32_t size = 0;
    READINT32(reply, size, ERR_INVALID_VALUE);
    infos.reserve(size);
    for (int32_t i = 0; i < size; ++i) {
        DisplayBindInfo info;
        READINT32(reply, info.inputDeviceId, ERR_INVALID_VALUE);
        READSTRING(reply, info.inputDeviceName, ERR_INVALID_VALUE);
        READINT32(reply, info.displayId, ERR_INVALID_VALUE);
        READSTRING(reply, info.displayName, ERR_INVALID_VALUE);
        infos.push_back(info);
    }
    return RET_OK;
}

int32_t MultimodalInputConnectProxy::SetDisplayBind(int32_t deviceId, int32_t displayId, std::string &msg)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }

    WRITEINT32(data, deviceId, ERR_INVALID_VALUE);
    WRITEINT32(data, displayId, ERR_INVALID_VALUE);

    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(SET_DISPLAY_BIND, data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request fail, result:%{public}d", ret);
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

int32_t MultimodalInputConnectProxy::SetPointerLocation(int32_t x, int32_t y)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    MessageParcel reply;
    MessageOption option;
    WRITEINT32(data, x, ERR_INVALID_VALUE);
    WRITEINT32(data, y, ERR_INVALID_VALUE);
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(SET_POINTER_LOCATION, data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectProxy::SetMouseCaptureMode(int32_t windowId, bool isCaptureMode)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    WRITEINT32(data, windowId, ERR_INVALID_VALUE);
    WRITEBOOL(data, isCaptureMode, ERR_INVALID_VALUE);
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(SET_CAPTURE_MODE, data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request fail, ret:%{public}d", ret);
    }
    return ret;
}
} // namespace MMI
} // namespace OHOS
