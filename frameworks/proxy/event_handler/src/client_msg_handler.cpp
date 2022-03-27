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

#include "client_msg_handler.h"

#include <cinttypes>
#include <iostream>
#include <sstream>

#include "bytrace_adapter.h"
#include "input_device_impl.h"
#include "input_event_data_transformation.h"
#include "input_event_monitor_manager.h"
#include "input_handler_manager.h"
#include "input_manager_impl.h"
#include "input_monitor_manager.h"
#include "interceptor_manager.h"
#include "mmi_client.h"
#include "mmi_func_callback.h"
#include "multimodal_event_handler.h"
#include "proto.h"
#include "time_cost_chk.h"
#include "util.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "ClientMsgHandler"};
} // namespace

ClientMsgHandler::ClientMsgHandler()
{
    eventProcessedCallback_ = std::bind(&ClientMsgHandler::OnEventProcessed, std::placeholders::_1);
}

ClientMsgHandler::~ClientMsgHandler()
{
    eventProcessedCallback_ = std::function<void(int32_t)>();
}

bool ClientMsgHandler::Init()
{
    MsgCallback funs[] = {
        {MmiMessageId::ON_KEYEVENT, MsgCallbackBind2(&ClientMsgHandler::OnKeyEvent, this)},
        {MmiMessageId::ON_SUBSCRIBE_KEY, std::bind(&ClientMsgHandler::OnSubscribeKeyEventCallback,
                                                   this, std::placeholders::_1, std::placeholders::_2)},
        {MmiMessageId::ON_KEYMONITOR, MsgCallbackBind2(&ClientMsgHandler::OnKeyMonitor, this)},
        {MmiMessageId::ON_POINTER_EVENT, MsgCallbackBind2(&ClientMsgHandler::OnPointerEvent, this)},
        {MmiMessageId::ON_TOUCHPAD_MONITOR, MsgCallbackBind2(&ClientMsgHandler::OnTouchPadMonitor, this)},
        {MmiMessageId::GET_MMI_INFO_ACK, MsgCallbackBind2(&ClientMsgHandler::GetMultimodeInputInfo, this)},
        {MmiMessageId::INPUT_DEVICE, MsgCallbackBind2(&ClientMsgHandler::OnInputDevice, this)},
        {MmiMessageId::INPUT_DEVICE_IDS, MsgCallbackBind2(&ClientMsgHandler::OnInputDeviceIds, this)},
        {MmiMessageId::REPORT_KEY_EVENT, MsgCallbackBind2(&ClientMsgHandler::ReportKeyEvent, this)},
        {MmiMessageId::REPORT_POINTER_EVENT, MsgCallbackBind2(&ClientMsgHandler::ReportPointerEvent, this)},
        {MmiMessageId::TOUCHPAD_EVENT_INTERCEPTOR, MsgCallbackBind2(&ClientMsgHandler::TouchpadEventInterceptor, this)},
        {MmiMessageId::KEYBOARD_EVENT_INTERCEPTOR, MsgCallbackBind2(&ClientMsgHandler::KeyEventInterceptor, this)},
    };
    for (auto& it : funs) {
        if (!RegistrationEvent(it)) {
            MMI_HILOGW("Failed to register event errCode:%{public}d", EVENT_REG_FAIL);
            continue;
        }
    }
    return true;
}

void ClientMsgHandler::OnMsgHandler(const UDSClient& client, NetPacket& pkt)
{
    auto id = pkt.GetMsgId();
    TimeCostChk chk("ClientMsgHandler::OnMsgHandler", "overtime 300(us)", MAX_OVER_TIME, id);
    auto callback = GetMsgCallback(id);
    if (callback == nullptr) {
        MMI_HILOGE("Unknown msg id:%{public}d", id);
        return;
    }
    auto ret = (*callback)(client, pkt);
    if (ret < 0) {
        MMI_HILOGE("Msg handling failed. id:%{public}d,ret:%{public}d", id, ret);
        return;
    }
}

MsgClientFunCallback ClientMsgHandler::GetCallback()
{
    return std::bind(&ClientMsgHandler::OnMsgHandler, this, std::placeholders::_1, std::placeholders::_2);
}

int32_t ClientMsgHandler::OnKeyMonitor(const UDSClient& client, NetPacket& pkt)
{
    auto key = KeyEvent::Create();
    CHKPR(key, ERROR_NULL_POINTER);
    int32_t ret = InputEventDataTransformation::NetPacketToKeyEvent(pkt, key);
    if (ret != RET_OK) {
        MMI_HILOGE("read netPacket failed");
        return RET_ERR;
    }
    int32_t pid;
    pkt >> pid;
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet read pid failed");
        return PACKET_READ_FAIL;
    }
    MMI_HILOGD("Client receive the msg from server, keyCode:%{public}d,pid:%{public}d", key->GetKeyCode(), pid);
    return InputMonitorMgr.OnMonitorInputEvent(key);
}

int32_t ClientMsgHandler::OnKeyEvent(const UDSClient& client, NetPacket& pkt)
{
    auto key = KeyEvent::Create();
    CHKPR(key, ERROR_NULL_POINTER);
    int32_t ret = InputEventDataTransformation::NetPacketToKeyEvent(pkt, key);
    if (ret != RET_OK) {
        MMI_HILOGE("read netPacket failed");
        return RET_ERR;
    }
    int32_t fd = 0;
    pkt >> fd;
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet read fd failed");
        return PACKET_READ_FAIL;
    }
    MMI_HILOGD("key event dispatcher of client, KeyCode:%{public}d,"
               "ActionTime:%{public}" PRId64 ",Action:%{public}d,ActionStartTime:%{public}" PRId64 ","
               "EventType:%{public}d,Flag:%{public}u,"
               "KeyAction:%{public}d,eventNumber:%{public}d,Fd:%{public}d,",
               key->GetKeyCode(), key->GetActionTime(), key->GetAction(),
               key->GetActionStartTime(), key->GetEventType(),
               key->GetFlag(), key->GetKeyAction(), key->GetId(), fd);
    BytraceAdapter::StartBytrace(key, BytraceAdapter::TRACE_START, BytraceAdapter::KEY_DISPATCH_EVENT);
    key->SetProcessedCallback(eventProcessedCallback_);
    InputManagerImpl::GetInstance()->OnKeyEvent(key);
    key->MarkProcessed();
    return RET_OK;
}

int32_t ClientMsgHandler::OnPointerEvent(const UDSClient& client, NetPacket& pkt)
{
    CALL_LOG_ENTER;
    auto pointerEvent = PointerEvent::Create();
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    if (InputEventDataTransformation::Unmarshalling(pkt, pointerEvent) != ERR_OK) {
        MMI_HILOGE("Failed to deserialize pointer event.");
        return RET_ERR;
    }
    MMI_HILOGD("Pointer event dispatcher of client:");
    std::stringstream sStream;
    sStream << *pointerEvent;
    std::string sLine;
    while (std::getline(sStream, sLine)) {
        MMI_HILOGD("%{public}s", sLine.c_str());
    }
    if (PointerEvent::POINTER_ACTION_CANCEL == pointerEvent->GetPointerAction()) {
        MMI_HILOGD("Operation canceled.");
    }
    pointerEvent->SetProcessedCallback(eventProcessedCallback_);
    BytraceAdapter::StartBytrace(pointerEvent, BytraceAdapter::TRACE_START, BytraceAdapter::POINT_DISPATCH_EVENT);
    InputManagerImpl::GetInstance()->OnPointerEvent(pointerEvent);
    return RET_OK;
}

int32_t ClientMsgHandler::OnSubscribeKeyEventCallback(const UDSClient &client, NetPacket &pkt)
{
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    CHKPR(keyEvent, ERROR_NULL_POINTER);
    int32_t ret = InputEventDataTransformation::NetPacketToKeyEvent(pkt, keyEvent);
    if (ret != RET_OK) {
        MMI_HILOGE("read net packet failed");
        return RET_ERR;
    }
    int32_t fd = -1;
    int32_t subscribeId = -1;
    pkt >> fd >> subscribeId;
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet read fd failed");
        return PACKET_READ_FAIL;
    }
    MMI_HILOGD("Subscribe:%{public}d,Fd:%{public}d,KeyEvent:%{public}d,"
               "KeyCode:%{public}d,ActionTime:%{public}" PRId64 ",ActionStartTime:%{public}" PRId64 ","
               "Action:%{public}d,KeyAction:%{public}d,EventType:%{public}d,Flag:%{public}u",
        subscribeId, fd, keyEvent->GetId(), keyEvent->GetKeyCode(), keyEvent->GetActionTime(),
        keyEvent->GetActionStartTime(), keyEvent->GetAction(), keyEvent->GetKeyAction(),
        keyEvent->GetEventType(), keyEvent->GetFlag());
    BytraceAdapter::StartBytrace(keyEvent, BytraceAdapter::TRACE_START, BytraceAdapter::KEY_SUBSCRIBE_EVENT);
    return KeyEventInputSubscribeMgr.OnSubscribeKeyEventCallback(keyEvent, subscribeId);
}

int32_t ClientMsgHandler::OnTouchPadMonitor(const UDSClient& client, NetPacket& pkt)
{
    auto pointer = PointerEvent::Create();
    CHKPR(pointer, ERROR_NULL_POINTER);
    int32_t ret = InputEventDataTransformation::Unmarshalling(pkt, pointer);
    if (ret != RET_OK) {
        MMI_HILOGE("read netPacket failed");
        return RET_ERR;
    }
    int32_t pid = 0;
    pkt >> pid;
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet read pid failed");
        return PACKET_READ_FAIL;
    }
    MMI_HILOGD("client receive the msg from server: EventType:%{public}d,pid:%{public}d",
        pointer->GetEventType(), pid);
    return InputMonitorMgr.OnTouchpadMonitorInputEvent(pointer);
}

int32_t ClientMsgHandler::GetMultimodeInputInfo(const UDSClient& client, NetPacket& pkt)
{
    TagPackHead tagPackHeadAck;
    pkt >> tagPackHeadAck;
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet read tagPackHeadAck failed");
        return PACKET_READ_FAIL;
    }
    std::cout << "GetMultimodeInputInfo: The client fd is " << tagPackHeadAck.sizeEvent[0] << std::endl;
    return RET_OK;
}

int32_t ClientMsgHandler::OnInputDeviceIds(const UDSClient& client, NetPacket& pkt)
{
    CALL_LOG_ENTER;
    int32_t userData;
    int32_t size;
    std::vector<int32_t> inputDeviceIds;
    if (!pkt.Read(userData)) {
        MMI_HILOGE("Packet read userData failed");
        return RET_ERR;
    }
    if (!pkt.Read(size)) {
        MMI_HILOGE("Packet read size failed");
        return RET_ERR;
    }
    for (int32_t i = 0; i < size; i++) {
        int32_t deviceId = 0;
        if (!pkt.Read(deviceId)) {
            MMI_HILOGE("Packet read device failed");
            return RET_ERR;
        }
        inputDeviceIds.push_back(deviceId);
    }
    InputDeviceImpl::GetInstance().OnInputDeviceIds(userData, inputDeviceIds);
    return RET_OK;
}

int32_t ClientMsgHandler::OnInputDevice(const UDSClient& client, NetPacket& pkt)
{
    CALL_LOG_ENTER;
    int32_t userData;
    int32_t id;
    std::string name;
    int32_t deviceType;
    if (!pkt.Read(userData)) {
        MMI_HILOGE("Packet read userData failed");
        return RET_ERR;
    }
    if (!pkt.Read(id)) {
        MMI_HILOGE("Packet read data failed");
        return RET_ERR;
    }
    if (!pkt.Read(name)) {
        MMI_HILOGE("Packet read name failed");
        return RET_ERR;
    }
    if (!pkt.Read(deviceType)) {
        MMI_HILOGE("Packet read deviceType failed");
        return RET_ERR;
    }

    InputDeviceImpl::GetInstance().OnInputDevice(userData, id, name, deviceType);
    return RET_OK;
}

int32_t ClientMsgHandler::ReportKeyEvent(const UDSClient& client, NetPacket& pkt)
{
    CALL_LOG_ENTER;
    int32_t handlerId;
    if (!pkt.Read(handlerId)) {
        MMI_HILOGE("Packet read handler failed");
        return RET_ERR;
    }
    auto keyEvent = KeyEvent::Create();
    CHKPR(keyEvent, ERROR_NULL_POINTER);
    if (InputEventDataTransformation::NetPacketToKeyEvent(pkt, keyEvent) != ERR_OK) {
        MMI_HILOGE("Failed to deserialize key event.");
        return RET_ERR;
    }
    InputHandlerManager::GetInstance().OnInputEvent(handlerId, keyEvent);
    return RET_OK;
}

int32_t ClientMsgHandler::ReportPointerEvent(const UDSClient& client, NetPacket& pkt)
{
    CALL_LOG_ENTER;
    int32_t handlerId;
    InputHandlerType handlerType;
    if (!pkt.Read(handlerId)) {
        MMI_HILOGE("Packet read handler failed");
        return RET_ERR;
    }
    if (!pkt.Read(handlerType)) {
        MMI_HILOGE("Packet read handlerType failed");
        return RET_ERR;
    }
    MMI_HILOGD("Client handlerId:%{public}d,handlerType:%{public}d", handlerId, handlerType);
    auto pointerEvent = PointerEvent::Create();
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    if (InputEventDataTransformation::Unmarshalling(pkt, pointerEvent) != ERR_OK) {
        MMI_HILOGE("Failed to deserialize pointer event");
        return RET_ERR;
    }
    BytraceAdapter::StartBytrace(pointerEvent, BytraceAdapter::TRACE_START, BytraceAdapter::POINT_INTERCEPT_EVENT);
    InputHandlerManager::GetInstance().OnInputEvent(handlerId, pointerEvent);
    return RET_OK;
}

int32_t ClientMsgHandler::TouchpadEventInterceptor(const UDSClient& client, NetPacket& pkt)
{
    auto pointerEvent = PointerEvent::Create();
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    int32_t ret = InputEventDataTransformation::Unmarshalling(pkt, pointerEvent);
    if (ret != RET_OK) {
        MMI_HILOGE("read netPacket failed");
        return RET_ERR;
    }
    int32_t pid = 0;
    int32_t id = 0;
    pkt >> pid >> id;
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet read pid failed");
        return PACKET_READ_FAIL;
    }
    MMI_HILOGD("client receive the msg from server: pointId:%{public}d,pid:%{public}d",
               pointerEvent->GetPointerId(), pid);
    return InterceptorMgr.OnPointerEvent(pointerEvent, id);
}

int32_t ClientMsgHandler::KeyEventInterceptor(const UDSClient& client, NetPacket& pkt)
{
    auto keyEvent = KeyEvent::Create();
    CHKPR(keyEvent, ERROR_NULL_POINTER);
    int32_t ret = InputEventDataTransformation::NetPacketToKeyEvent(pkt, keyEvent);
    if (ret != RET_OK) {
        MMI_HILOGE("read netPacket failed");
        return RET_ERR;
    }
    int32_t pid = 0;
    pkt >> pid;
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet read pid failed");
        return PACKET_READ_FAIL;
    }
    BytraceAdapter::StartBytrace(keyEvent, BytraceAdapter::TRACE_START, BytraceAdapter::KEY_INTERCEPT_EVENT);
    MMI_HILOGD("client receive the msg from server: keyCode:%{public}d,pid:%{public}d",
        keyEvent->GetKeyCode(), pid);
    return InterceptorMgr.OnKeyEvent(keyEvent);
}

void ClientMsgHandler::OnEventProcessed(int32_t eventId)
{
    MMIClientPtr client = MMIEventHdl.GetMMIClient();
    CHKPV(client);
    NetPacket pkt(MmiMessageId::MARK_PROCESS);
    pkt << eventId;
    if (!client->SendMessage(pkt)) {
        MMI_HILOGE("Send message failed, errCode:%{public}d", MSG_SEND_FAIL);
        return;
    }
}
} // namespace MMI
} // namespace OHOS
