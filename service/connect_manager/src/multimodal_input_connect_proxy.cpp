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

#include <unistd.h>

#include "input_scene_board_judgement.h"
#include "infrared_frequency_info.h"
#include "message_option.h"
#include "mmi_log.h"
#include "multimodalinput_ipc_interface_code.h"
#include "multimodal_input_connect_def_parcel.h"
#include "multimodal_input_connect_define.h"
#include "multimodal_input_connect_proxy.h"
#include "pixel_map.h"
#include "string_ex.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_SERVER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "MultimodalInputConnectProxy"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t SPECIAL_KEY_SIZE { 3 };
constexpr int32_t SPECIAL_ARRAY_INDEX0 { 0 };
constexpr int32_t SPECIAL_ARRAY_INDEX1 { 1 };
constexpr int32_t SPECIAL_ARRAY_INDEX2 { 2 };
constexpr int32_t MAX_AXIS_INFO { 64 };

int32_t ParseInputDevice(MessageParcel &reply, std::shared_ptr<InputDevice> &inputDevice)
{
    CHKPR(inputDevice, RET_ERR);
    int32_t value = 0;
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

    uint32_t size = 0;
    READUINT32(reply, size, IPC_PROXY_DEAD_OBJECT_ERR);
    InputDevice::AxisInfo axis;
    for (uint32_t i = 0; i < size; ++i) {
        int32_t val = 0;
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
    MMI_HILOGI("Construct MMI proxy");
}

MultimodalInputConnectProxy::~MultimodalInputConnectProxy()
{
    MMI_HILOGI("Destruct MMI proxy");
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
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::ALLOC_SOCKET_FD),
        data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
        return ret;
    }
    socketFd = reply.ReadFileDescriptor();
    if (socketFd < RET_OK) {
        MMI_HILOGE("Read file descriptor failed, fd:%{public}d", socketFd);
        return IPC_PROXY_DEAD_OBJECT_ERR;
    }
    READINT32(reply, tokenType, IPC_PROXY_DEAD_OBJECT_ERR);
    MMI_HILOGD("socketFd:%{public}d, tokenType:%{public}d", socketFd, tokenType);
    return RET_OK;
}

int32_t MultimodalInputConnectProxy::AddInputEventFilter(sptr<IEventFilter> filter, int32_t filterId, int32_t priority,
    uint32_t deviceTags)
{
    CALL_DEBUG_ENTER;
    CHKPR(filter, ERR_INVALID_VALUE);
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
    WRITEUINT32(data, deviceTags, ERR_INVALID_VALUE);
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::
        ADD_INPUT_EVENT_FILTER), data, reply, option);
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
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::
        RMV_INPUT_EVENT_FILTER), data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request message failed, ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectProxy::SetMouseScrollRows(int32_t rows)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }

    WRITEINT32(data, rows, ERR_INVALID_VALUE);

    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_MOUSE_SCROLL_ROWS),
        data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectProxy::SetCustomCursor(int32_t pid, int32_t windowId, int32_t focusX, int32_t focusY,
    void* pixelMap)
{
    CALL_DEBUG_ENTER;
    CHKPR(pixelMap, ERR_INVALID_VALUE);
    OHOS::Media::PixelMap* pixelMapPtr = static_cast<OHOS::Media::PixelMap*>(pixelMap);
    if (pixelMapPtr->GetCapacity() == 0) {
        MMI_HILOGE("pixelMap is empty");
        return ERR_INVALID_VALUE;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    WRITEINT32(data, pid, ERR_INVALID_VALUE);
    WRITEINT32(data, windowId, ERR_INVALID_VALUE);
    WRITEINT32(data, focusX, ERR_INVALID_VALUE);
    WRITEINT32(data, focusY, ERR_INVALID_VALUE);
    pixelMapPtr->Marshalling(data);

    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_CUSTOM_CURSOR),
        data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectProxy::SetMouseIcon(int32_t windowId, void* pixelMap)
{
    CALL_DEBUG_ENTER;
    CHKPR(pixelMap, ERR_INVALID_VALUE);
    OHOS::Media::PixelMap* pixelMapPtr = static_cast<OHOS::Media::PixelMap*>(pixelMap);
    if (pixelMapPtr->GetCapacity() == 0) {
        MMI_HILOGE("pixelMap is empty, we dont have to pass it to the server");
        return ERR_INVALID_VALUE;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    pixelMapPtr->Marshalling(data);
    MMI_HILOGD("Send windowId:%{public}d", windowId);
    WRITEINT32(data, windowId, ERR_INVALID_VALUE);

    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_MOUSE_ICON),
        data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectProxy::SetMouseHotSpot(int32_t pid, int32_t windowId, int32_t hotSpotX, int32_t hotSpotY)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    WRITEINT32(data, pid, ERR_INVALID_VALUE);
    WRITEINT32(data, windowId, ERR_INVALID_VALUE);
    WRITEINT32(data, hotSpotX, ERR_INVALID_VALUE);
    WRITEINT32(data, hotSpotY, ERR_INVALID_VALUE);
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_MOUSE_HOT_SPOT),
        data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectProxy::GetMouseScrollRows(int32_t &rows)
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
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_MOUSE_SCROLL_ROWS),
        data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
        return ret;
    }
    READINT32(reply, rows, IPC_PROXY_DEAD_OBJECT_ERR);
    return RET_OK;
}

int32_t MultimodalInputConnectProxy::SetPointerSize(int32_t size)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }

    WRITEINT32(data, size, ERR_INVALID_VALUE);

    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_POINTER_SIZE),
        data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectProxy::SetNapStatus(int32_t pid, int32_t uid, std::string bundleName, int32_t napStatus)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }

    WRITEINT32(data, pid, ERR_INVALID_VALUE);
    WRITEINT32(data, uid, ERR_INVALID_VALUE);
    WRITESTRING(data, bundleName, ERR_INVALID_VALUE);
    WRITEINT32(data, napStatus, ERR_INVALID_VALUE);

    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::
        SET_NAP_STATUS), data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectProxy::GetPointerSize(int32_t &size)
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
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_POINTER_SIZE),
        data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
        return ret;
    }
    READINT32(reply, size, IPC_PROXY_DEAD_OBJECT_ERR);
    return RET_OK;
}

int32_t MultimodalInputConnectProxy::SetMousePrimaryButton(int32_t primaryButton)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }

    WRITEINT32(data, primaryButton, ERR_INVALID_VALUE);

    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::
        SET_MOUSE_PRIMARY_BUTTON), data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectProxy::GetMousePrimaryButton(int32_t &primaryButton)
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
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::
        GET_MOUSE_PRIMARY_BUTTON), data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
        return ret;
    }
    READINT32(reply, primaryButton, IPC_PROXY_DEAD_OBJECT_ERR);
    return RET_OK;
}

int32_t MultimodalInputConnectProxy::SetHoverScrollState(bool state)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }

    WRITEBOOL(data, state, ERR_INVALID_VALUE);

    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::
        SET_HOVER_SCROLL_STATE), data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectProxy::GetHoverScrollState(bool &state)
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
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::
        GET_HOVER_SCROLL_STATE), data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
        return ret;
    }
    READBOOL(reply, state, IPC_PROXY_DEAD_OBJECT_ERR);
    return RET_OK;
}

int32_t MultimodalInputConnectProxy::SetPointerVisible(bool visible, int32_t priority)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }

    WRITEBOOL(data, visible, ERR_INVALID_VALUE);
    WRITEINT32(data, priority, ERR_INVALID_VALUE);

    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_POINTER_VISIBLE),
        data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
    }
    return ret;
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
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::IS_POINTER_VISIBLE),
        data, reply, option);
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
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::MARK_PROCESSED),
        data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGD("Send request fail, ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectProxy::SetPointerColor(int32_t color)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }

    WRITEINT32(data, color, ERR_INVALID_VALUE);

    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_POINTER_COLOR),
        data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectProxy::GetPointerColor(int32_t &color)
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
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_POINTER_COLOR),
        data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
        return ret;
    }
    READINT32(reply, color, IPC_PROXY_DEAD_OBJECT_ERR);
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
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_POINTER_SPEED),
        data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
    }
    return ret;
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
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_POINTER_SPEED),
        data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
        return ret;
    }
    READINT32(reply, speed, IPC_PROXY_DEAD_OBJECT_ERR);
    return RET_OK;
}

int32_t MultimodalInputConnectProxy::NotifyNapOnline()
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
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::NOTIFY_NAP_ONLINE),
        data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request fail, ret:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectProxy::RemoveInputEventObserver()
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
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::
        RMV_INPUT_EVENT_OBSERVER), data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request fail, ret:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectProxy::SetPointerStyle(int32_t windowId, PointerStyle pointerStyle, bool isUiExtension)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return RET_ERR;
    }

    WRITEINT32(data, windowId, RET_ERR);
    WRITEINT32(data, pointerStyle.size, RET_ERR);
    WRITEINT32(data, pointerStyle.color, RET_ERR);
    WRITEINT32(data, pointerStyle.id, RET_ERR);
    WRITEBOOL(data, isUiExtension, RET_ERR);

    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_POINTER_STYLE),
        data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request fail, ret:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectProxy::ClearWindowPointerStyle(int32_t pid, int32_t windowId)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return RET_ERR;
    }

    WRITEINT32(data, pid, RET_ERR);
    WRITEINT32(data, windowId, RET_ERR);

    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::CLEAN_WIDNOW_STYLE),
        data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request fail, ret:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectProxy::GetPointerStyle(int32_t windowId, PointerStyle &pointerStyle, bool isUiExtension)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return RET_ERR;
    }
    WRITEINT32(data, windowId, RET_ERR);
    WRITEBOOL(data, isUiExtension, RET_ERR);
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_POINTER_STYLE),
        data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request fail, ret:%{public}d", ret);
        return ret;
    }
    READINT32(reply, pointerStyle.size, IPC_PROXY_DEAD_OBJECT_ERR);
    READINT32(reply, pointerStyle.color, IPC_PROXY_DEAD_OBJECT_ERR);
    READINT32(reply, pointerStyle.id, IPC_PROXY_DEAD_OBJECT_ERR);
    READINT32(reply, pointerStyle.options, IPC_PROXY_DEAD_OBJECT_ERR);
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
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::REGISTER_DEV_MONITOR),
        data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
    }
    return ret;
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
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::
        UNREGISTER_DEV_MONITOR), data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
    }
    return ret;
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
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SUPPORT_KEYS),
        data, reply, option);
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
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_DEVICE_IDS),
        data, reply, option);
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
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_DEVICE),
        data, reply, option);
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
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_KEYBOARD_TYPE),
        data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
        return ret;
    }
    READINT32(reply, keyboardType, IPC_PROXY_DEAD_OBJECT_ERR);
    return RET_OK;
}

int32_t MultimodalInputConnectProxy::SetKeyboardRepeatDelay(int32_t delay)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    WRITEINT32(data, delay, ERR_INVALID_VALUE);
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::
        SET_KEYBOARD_REPEAT_DELAY), data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectProxy::SetKeyboardRepeatRate(int32_t rate)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    WRITEINT32(data, rate, ERR_INVALID_VALUE);
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::
        SET_KEYBOARD_REPEAT_RATE), data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectProxy::GetKeyboardRepeatDelay(int32_t &delay)
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
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::
        GET_KEYBOARD_REPEAT_DELAY), data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
        return ret;
    }
    READINT32(reply, delay, IPC_PROXY_DEAD_OBJECT_ERR);
    return RET_OK;
}

int32_t MultimodalInputConnectProxy::GetKeyboardRepeatRate(int32_t &rate)
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
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::
        GET_KEYBOARD_REPEAT_RATE), data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
        return ret;
    }
    READINT32(reply, rate, IPC_PROXY_DEAD_OBJECT_ERR);
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
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::ADD_INPUT_HANDLER),
        data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
    }
    return ret;
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
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::REMOVE_INPUT_HANDLER),
        data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
    }
    return ret;
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
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::MARK_EVENT_CONSUMED),
        data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
    }
    return ret;
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
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::MOVE_MOUSE),
        data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectProxy::InjectKeyEvent(const std::shared_ptr<KeyEvent> keyEvent, bool isNativeInject)
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
    WRITEBOOL(data, isNativeInject, ERR_INVALID_VALUE);
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::INJECT_KEY_EVENT),
        data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
    }
    return ret;
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
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SUBSCRIBE_KEY_EVENT),
        data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, result:%{public}d", ret);
    }
    return ret;
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
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::UNSUBSCRIBE_KEY_EVENT),
        data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, result:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectProxy::SubscribeSwitchEvent(int32_t subscribeId, int32_t switchType)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    WRITEINT32(data, subscribeId, ERR_INVALID_VALUE);
    WRITEINT32(data, switchType, ERR_INVALID_VALUE);

    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::
        SUBSCRIBE_SWITCH_EVENT), data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, result:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectProxy::UnsubscribeSwitchEvent(int32_t subscribeId)
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
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::
        UNSUBSCRIBE_SWITCH_EVENT), data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, result:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectProxy::InjectPointerEvent(const std::shared_ptr<PointerEvent> pointerEvent,
    bool isNativeInject)
{
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
    WRITEBOOL(data, isNativeInject, ERR_INVALID_VALUE);
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::INJECT_POINTER_EVENT),
        data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
    }
    return ret;
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
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_ANR_OBSERVER),
        data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
    }
    return ret;
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
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_DISPLAY_BIND_INFO),
        data, reply, option);
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

int32_t MultimodalInputConnectProxy::GetAllMmiSubscribedEvents(std::map<std::tuple<int32_t, int32_t, std::string>,
    int32_t> &datas)
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
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::
        GET_ALL_NAPSTATUS_DATA), data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
        return ret;
    }
    int32_t size = 0;
    READINT32(reply, size, ERR_INVALID_VALUE);
    for (int32_t i = 0; i < size; ++i) {
        NapProcess::NapStatusData data;
        int32_t syncState = 0;
        READINT32(reply, data.pid, ERR_INVALID_VALUE);
        READINT32(reply, data.uid, ERR_INVALID_VALUE);
        READSTRING(reply, data.bundleName, ERR_INVALID_VALUE);
        READINT32(reply, syncState, ERR_INVALID_VALUE);
        std::tuple<int32_t, int32_t, std::string> tuple(data.pid, data.uid, data.bundleName);
        datas.emplace(tuple, syncState);
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
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_DISPLAY_BIND),
        data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request fail, result:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectProxy::GetWindowPid(int32_t windowId)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }

    WRITEINT32(data, windowId, ERR_INVALID_VALUE);

    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_WINDOW_PID),
        data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request fail, result:%{public}d", ret);
        return ret;
    }
    int32_t windowPid = INVALID_PID;
    READINT32(reply, windowPid, ERR_INVALID_VALUE);
    return windowPid;
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
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::
        GET_FUNCTION_KEY_STATE), data, reply, option);
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
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::
        SET_FUNCTION_KEY_STATE), data, reply, option);
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
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_POINTER_LOCATION),
        data, reply, option);
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
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_CAPTURE_MODE),
        data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request fail, ret:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectProxy::AppendExtraData(const ExtraData& extraData)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    WRITEBOOL(data, extraData.appended, ERR_INVALID_VALUE);
    WRITEINT32(data, static_cast<int32_t>(extraData.buffer.size()));
    for (const auto &item : extraData.buffer) {
        WRITEUINT8(data, item);
    }
    WRITEINT32(data, extraData.sourceType, ERR_INVALID_VALUE);
    WRITEINT32(data, extraData.pointerId, ERR_INVALID_VALUE);
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::APPEND_EXTRA_DATA),
        data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request fail, ret:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectProxy::EnableCombineKey(bool enable)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    WRITEBOOL(data, enable, ERR_INVALID_VALUE);
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::ENABLE_COMBINE_KEY),
        data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request fail, ret:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectProxy::EnableInputDevice(bool enable)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    WRITEBOOL(data, enable, ERR_INVALID_VALUE);
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::ENABLE_INPUT_DEVICE),
        data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request fail, ret:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectProxy::SetKeyDownDuration(const std::string &businessId, int32_t delay)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    WRITESTRING(data, businessId, ERR_INVALID_VALUE);
    WRITEINT32(data, delay, ERR_INVALID_VALUE);
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_KEY_DOWN_DURATION),
        data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectProxy::SetTouchpadBoolData(bool switchFlag, int32_t type)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }

    WRITEBOOL(data, switchFlag, ERR_INVALID_VALUE);

    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(type, data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectProxy::GetTouchpadBoolData(bool &switchFlag, int32_t type)
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
    int32_t ret = remote->SendRequest(type, data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
        return ret;
    }
    READBOOL(reply, switchFlag, IPC_PROXY_DEAD_OBJECT_ERR);
    return RET_OK;
}

int32_t MultimodalInputConnectProxy::SetTouchpadInt32Data(int32_t value, int32_t type)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }

    WRITEINT32(data, value, ERR_INVALID_VALUE);

    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(type, data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectProxy::GetTouchpadInt32Data(int32_t &value, int32_t type)
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
    int32_t ret = remote->SendRequest(type, data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
        return ret;
    }
    READINT32(reply, value, IPC_PROXY_DEAD_OBJECT_ERR);
    return RET_OK;
}

int32_t MultimodalInputConnectProxy::SetTouchpadScrollSwitch(bool switchFlag)
{
    return SetTouchpadBoolData(switchFlag, static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::
        SET_TP_SCROLL_SWITCH));
}

int32_t MultimodalInputConnectProxy::GetTouchpadScrollSwitch(bool &switchFlag)
{
    return GetTouchpadBoolData(switchFlag, static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::
        GET_TP_SCROLL_SWITCH));
}

int32_t MultimodalInputConnectProxy::SetTouchpadScrollDirection(bool state)
{
    return SetTouchpadBoolData(state, static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::
        SET_TP_SCROLL_DIRECT_SWITCH));
}

int32_t MultimodalInputConnectProxy::GetTouchpadScrollDirection(bool &switchFlag)
{
    return GetTouchpadBoolData(switchFlag, static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::
        GET_TP_SCROLL_DIRECT_SWITCH));
}

int32_t MultimodalInputConnectProxy::SetTouchpadTapSwitch(bool switchFlag)
{
    return SetTouchpadBoolData(switchFlag, static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::
        SET_TP_TAP_SWITCH));
}

int32_t MultimodalInputConnectProxy::GetTouchpadTapSwitch(bool &switchFlag)
{
    return GetTouchpadBoolData(switchFlag, static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::
        GET_TP_TAP_SWITCH));
}

int32_t MultimodalInputConnectProxy::SetTouchpadPointerSpeed(int32_t speed)
{
    return SetTouchpadInt32Data(speed, static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::
        SET_TP_POINTER_SPEED));
}

int32_t MultimodalInputConnectProxy::GetTouchpadPointerSpeed(int32_t &speed)
{
    return GetTouchpadInt32Data(speed, static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::
        GET_TP_POINTER_SPEED));
}

int32_t MultimodalInputConnectProxy::SetTouchpadPinchSwitch(bool switchFlag)
{
    return SetTouchpadBoolData(switchFlag, static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::
        SET_TP_PINCH_SWITCH));
}

int32_t MultimodalInputConnectProxy::GetTouchpadPinchSwitch(bool &switchFlag)
{
    return GetTouchpadBoolData(switchFlag, static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::
        GET_TP_PINCH_SWITCH));
}

int32_t MultimodalInputConnectProxy::SetTouchpadSwipeSwitch(bool switchFlag)
{
    return SetTouchpadBoolData(switchFlag, static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::
        SET_TP_SWIPE_SWITCH));
}

int32_t MultimodalInputConnectProxy::GetTouchpadSwipeSwitch(bool &switchFlag)
{
    return GetTouchpadBoolData(switchFlag, static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::
        GET_TP_SWIPE_SWITCH));
}

int32_t MultimodalInputConnectProxy::SetTouchpadRightClickType(int32_t type)
{
    return SetTouchpadInt32Data(type, static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::
        SET_TP_RIGHT_CLICK_TYPE));
}

int32_t MultimodalInputConnectProxy::GetTouchpadRightClickType(int32_t &type)
{
    return GetTouchpadInt32Data(type, static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::
        GET_TP_RIGHT_CLICK_TYPE));
}

int32_t MultimodalInputConnectProxy::SetTouchpadRotateSwitch(bool rotateSwitch)
{
    return SetTouchpadBoolData(rotateSwitch, static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::
        SET_TP_ROTATE_SWITCH));
}

int32_t MultimodalInputConnectProxy::GetTouchpadRotateSwitch(bool &rotateSwitch)
{
    return GetTouchpadBoolData(rotateSwitch, static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::
        GET_TP_ROTATE_SWITCH));
}

int32_t MultimodalInputConnectProxy::SetShieldStatus(int32_t shieldMode, bool isShield)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }

    WRITEINT32(data, shieldMode, ERR_INVALID_VALUE);
    WRITEBOOL(data, isShield, ERR_INVALID_VALUE);

    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_SHIELD_STATUS),
        data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectProxy::GetShieldStatus(int32_t shieldMode, bool &isShield)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    MessageParcel reply;
    MessageOption option;
    WRITEINT32(data, shieldMode, ERR_INVALID_VALUE);
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::
        GET_SHIELD_STATUS), data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
        return ret;
    }
    READBOOL(reply, isShield, ERR_INVALID_VALUE);
    return RET_OK;
}

int32_t MultimodalInputConnectProxy::GetKeyState(std::vector<int32_t> &pressedKeys,
    std::map<int32_t, int32_t> &specialKeysState)
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
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_KEY_STATE),
        data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
        return ret;
    }
    if (!reply.ReadInt32Vector(&pressedKeys)) {
        MMI_HILOGE("Read vector failed");
        return RET_ERR;
    }
    MMI_HILOGD("pressedKeys size:%{public}zu", pressedKeys.size());
    std::vector<int32_t> specialKeysStateTmp;
    if (!reply.ReadInt32Vector(&specialKeysStateTmp)) {
        MMI_HILOGE("Read vector failed");
        return RET_ERR;
    }
    if (specialKeysStateTmp.size() != SPECIAL_KEY_SIZE) {
        MMI_HILOGE("The number of special key is not three");
        return RET_ERR;
    }
    specialKeysState[KeyEvent::KEYCODE_CAPS_LOCK] = specialKeysStateTmp[SPECIAL_ARRAY_INDEX0];
    specialKeysState[KeyEvent::KEYCODE_SCROLL_LOCK] = specialKeysStateTmp[SPECIAL_ARRAY_INDEX1];
    specialKeysState[KeyEvent::KEYCODE_NUM_LOCK] = specialKeysStateTmp[SPECIAL_ARRAY_INDEX2];
    return RET_OK;
}

int32_t MultimodalInputConnectProxy::Authorize(bool isAuthorize)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    WRITEBOOL(data, isAuthorize, ERR_INVALID_VALUE);
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::NATIVE_AUTHORIZE),
        data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectProxy::CancelInjection()
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
    int32_t ret = remote->SendRequest(
        static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::NATIVE_CANCEL_INJECTION), data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectProxy::HasIrEmitter(bool &hasIrEmitter)
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
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::NATIVE_INFRARED_OWN),
        data, reply, option);
    READBOOL(reply, hasIrEmitter, IPC_PROXY_DEAD_OBJECT_ERR);
    if (ret != RET_OK) {
        MMI_HILOGE("MultimodalInputConnectProxy::HasIrEmitter Send request fail, ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectProxy::GetInfraredFrequencies(std::vector<InfraredFrequency>& requencys)
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
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(
                                      MultimodalinputConnectInterfaceCode::NATIVE_INFRARED_FREQUENCY),
                                      data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("MultimodalInputConnectProxy::GetInfraredFrequencies Send request fail, ret:%{public}d", ret);
        return ret;
    }
    int64_t number;
    READINT64(reply, number, IPC_PROXY_DEAD_OBJECT_ERR);
    int64_t min = 0;
    int64_t max = 0;
    for (int32_t i = 0; i < number; i++) {
        READINT64(reply, max);
        READINT64(reply, min);
        InfraredFrequency item;
        item.max_ = max;
        item.min_ = min;
        requencys.push_back(item);
    }
    return ret;
}

int32_t MultimodalInputConnectProxy::TransmitInfrared(int64_t number, std::vector<int64_t>& pattern)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    WRITEINT64(data, number, ERR_INVALID_VALUE);
    WRITEINT32(data, static_cast<int64_t>(pattern.size()), ERR_INVALID_VALUE);
    for (const auto &item : pattern) {
        WRITEINT64(data, item);
    }
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(
                                      MultimodalinputConnectInterfaceCode::NATIVE_CANCEL_TRANSMIT),
                                      data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("MultimodalInputConnectProxy::TransmitInfrared Send request fail, ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectProxy::SetPixelMapData(int32_t infoId, void* pixelMap)
{
    CALL_DEBUG_ENTER;
    CHKPR(pixelMap, RET_ERR);
    if (infoId < 0) {
        MMI_HILOGE("Invalid infoId");
        return RET_ERR;
    }
    OHOS::Media::PixelMap* pixelMapPtr = static_cast<OHOS::Media::PixelMap*>(pixelMap);
    if (pixelMapPtr->GetCapacity() == 0) {
        MMI_HILOGE("pixelMap is empty");
        return RET_ERR;
    }
    MMI_HILOGD("byteCount:%{public}d, width:%{public}d, height:%{public}d",
        pixelMapPtr->GetByteCount(), pixelMapPtr->GetWidth(), pixelMapPtr->GetHeight());

    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    WRITEINT32(data, infoId, ERR_INVALID_VALUE);
    pixelMapPtr->Marshalling(data);

    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(
        static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_PIXEL_MAP_DATA), data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Failed to send request, ret:%{public}d", ret);
    }
    return ret;
}


int32_t MultimodalInputConnectProxy::SetCurrentUser(int32_t userId)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    WRITEINT32(data, userId, ERR_INVALID_VALUE);
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(
        static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_CURRENT_USERID), data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request fail, ret:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectProxy::EnableHardwareCursorStats(bool enable)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }

    WRITEBOOL(data, enable, ERR_INVALID_VALUE);

    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(
        static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::ENABLE_HARDWARE_CURSOR_STATS), data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectProxy::GetHardwareCursorStats(uint32_t &frameCount, uint32_t &vsyncCount)
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
    int32_t ret = remote->SendRequest(
        static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_HARDWARE_CURSOR_STATS), data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed, ret:%{public}d", ret);
        return ret;
    }
    MMI_HILOGD("GetHardwareCursorStats, frameCount:%{public}d, vsyncCount:%{public}d", frameCount, vsyncCount);
    READUINT32(reply, frameCount, IPC_PROXY_DEAD_OBJECT_ERR);
    READUINT32(reply, vsyncCount, IPC_PROXY_DEAD_OBJECT_ERR);
    return ret;
}

int32_t MultimodalInputConnectProxy::AddVirtualInputDevice(std::shared_ptr<InputDevice> device, int32_t &deviceId)
{
    CALL_DEBUG_ENTER;
    CHKPR(device, ERROR_NULL_POINTER);
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    auto axisInfo = device->GetAxisInfo();
    if (axisInfo.size() > MAX_AXIS_INFO) {
        return RET_ERR;
    }
    WRITEINT32(data, device->GetId(), IPC_STUB_WRITE_PARCEL_ERR);
    WRITEINT32(data, device->GetType(), IPC_STUB_WRITE_PARCEL_ERR);
    WRITESTRING(data, device->GetName(), IPC_STUB_WRITE_PARCEL_ERR);
    WRITEINT32(data, device->GetBus(), IPC_STUB_WRITE_PARCEL_ERR);
    WRITEINT32(data, device->GetVersion(), IPC_STUB_WRITE_PARCEL_ERR);
    WRITEINT32(data, device->GetProduct(), IPC_STUB_WRITE_PARCEL_ERR);
    WRITEINT32(data, device->GetVendor(), IPC_STUB_WRITE_PARCEL_ERR);
    WRITESTRING(data, device->GetPhys(), IPC_STUB_WRITE_PARCEL_ERR);
    WRITESTRING(data, device->GetUniq(), IPC_STUB_WRITE_PARCEL_ERR);
    WRITEUINT64(data, static_cast<uint64_t>(device->GetCapabilities()), IPC_STUB_WRITE_PARCEL_ERR);
    WRITEUINT32(data, static_cast<uint32_t>(axisInfo.size()), IPC_STUB_WRITE_PARCEL_ERR);
    for (const auto &item : axisInfo) {
        WRITEINT32(data, item.GetMinimum(), IPC_STUB_WRITE_PARCEL_ERR);
        WRITEINT32(data, item.GetMaximum(), IPC_STUB_WRITE_PARCEL_ERR);
        WRITEINT32(data, item.GetAxisType(), IPC_STUB_WRITE_PARCEL_ERR);
        WRITEINT32(data, item.GetFuzz(), IPC_STUB_WRITE_PARCEL_ERR);
        WRITEINT32(data, item.GetFlat(), IPC_STUB_WRITE_PARCEL_ERR);
        WRITEINT32(data, item.GetResolution(), IPC_STUB_WRITE_PARCEL_ERR);
    }
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(
        static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::ADD_VIRTUAL_INPUT_DEVICE), data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request fail, ret:%{public}d", ret);
        return RET_ERR;
    }
    READINT32(reply, deviceId, IPC_PROXY_DEAD_OBJECT_ERR);
    return ret;
}

int32_t MultimodalInputConnectProxy::RemoveVirtualInputDevice(int32_t deviceId)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    WRITEINT32(data, deviceId, ERR_INVALID_VALUE);
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(
        static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::REMOVE_VIRTUAL_INPUT_DEVICE), data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request fail, ret:%{public}d", ret);
        return ret;
    }
    READINT32(reply, ret, IPC_PROXY_DEAD_OBJECT_ERR);
    return ret;
}

int32_t MultimodalInputConnectProxy::SetTouchpadThreeFingersTapSwitch(bool switchFlag)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    WRITEBOOL(data, switchFlag, ERR_INVALID_VALUE);
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(
                                      MultimodalinputConnectInterfaceCode::SET_THREE_GINGERS_TAPSWITCH),
                                      data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("MultimodalInputConnectProxy::SetTouchpadSwitch Send request fail, ret:%{public}d", ret);
    }
    return ret;
}

int32_t MultimodalInputConnectProxy::GetTouchpadThreeFingersTapSwitch(bool &switchFlag)
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
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(
                                      MultimodalinputConnectInterfaceCode::GET_THREE_GINGERS_TAPSWITCH),
                                      data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("MultimodalInputConnectProxy::GetTouchpadThree Send request fail, ret:%{public}d", ret);
    } else {
        READBOOL(reply, switchFlag);
    }
    return RET_OK;
}

#ifdef OHOS_BUILD_ENABLE_ANCO
int32_t MultimodalInputConnectProxy::AncoAddChannel(sptr<IAncoChannel> channel)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    if (!data.WriteRemoteObject(channel->AsObject())) {
        MMI_HILOGE("Failed to write IRemoteObject");
        return ERR_INVALID_VALUE;
    }
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(
        static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::ADD_ANCO_CHANNEL), data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request fail, ret:%{public}d", ret);
        return ret;
    }
    READINT32(reply, ret, IPC_PROXY_DEAD_OBJECT_ERR);
    return ret;
}

int32_t MultimodalInputConnectProxy::AncoRemoveChannel(sptr<IAncoChannel> channel)
{
    CALL_DEBUG_ENTER;
    MessageParcel data;
    if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) {
        MMI_HILOGE("Failed to write descriptor");
        return ERR_INVALID_VALUE;
    }
    if (!data.WriteRemoteObject(channel->AsObject())) {
        MMI_HILOGE("Failed to write IRemoteObject");
        return ERR_INVALID_VALUE;
    }
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    CHKPR(remote, RET_ERR);
    int32_t ret = remote->SendRequest(
        static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::REMOVE_ANCO_CHANNEL), data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request fail, ret:%{public}d", ret);
        return ret;
    }
    READINT32(reply, ret, IPC_PROXY_DEAD_OBJECT_ERR);
    return ret;
}
#endif // OHOS_BUILD_ENABLE_ANCO
} // namespace MMI
} // namespace OHOS
