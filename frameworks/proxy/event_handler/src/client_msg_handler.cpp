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
#include "event_log_helper.h"
#include "input_device.h"
#ifdef OHOS_BUILD_ENABLE_COOPERATE
#include "input_device_cooperate_impl.h"
#endif // OHOS_BUILD_ENABLE_COOPERATE
#include "input_device_impl.h"
#include "input_event_data_transformation.h"
#include "input_handler_manager.h"
#include "input_manager_impl.h"
#ifdef OHOS_BUILD_ENABLE_MONITOR
#include "input_monitor_manager.h"
#endif // OHOS_BUILD_ENABLE_MONITOR
#include "mmi_client.h"
#include "mmi_func_callback.h"
#include "multimodal_event_handler.h"
#include "multimodal_input_connect_manager.h"
#include "napi_constants.h"
#include "proto.h"
#include "time_cost_chk.h"
#include "util.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "ClientMsgHandler"};
} // namespace

ClientMsgHandler::~ClientMsgHandler()
{
    dispatchCallback_ = nullptr;
}

void ClientMsgHandler::Init()
{
    MsgCallback funs[] = {
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
        {MmiMessageId::ON_KEY_EVENT, MsgCallbackBind2(&ClientMsgHandler::OnKeyEvent, this)},
        {MmiMessageId::ON_SUBSCRIBE_KEY, std::bind(&ClientMsgHandler::OnSubscribeKeyEventCallback,
                                                   this, std::placeholders::_1, std::placeholders::_2)},
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
        {MmiMessageId::ON_POINTER_EVENT, MsgCallbackBind2(&ClientMsgHandler::OnPointerEvent, this)},
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
        {MmiMessageId::INPUT_DEVICE, MsgCallbackBind2(&ClientMsgHandler::OnInputDevice, this)},
        {MmiMessageId::INPUT_DEVICE_IDS, MsgCallbackBind2(&ClientMsgHandler::OnInputDeviceIds, this)},
        {MmiMessageId::INPUT_DEVICE_SUPPORT_KEYS, MsgCallbackBind2(&ClientMsgHandler::OnSupportKeys, this)},
        {MmiMessageId::INPUT_DEVICE_KEYBOARD_TYPE, MsgCallbackBind2(&ClientMsgHandler::OnInputKeyboardType, this)},
        {MmiMessageId::ADD_INPUT_DEVICE_LISTENER, MsgCallbackBind2(&ClientMsgHandler::OnDevListener, this)},
        {MmiMessageId::NOTICE_ANR, MsgCallbackBind2(&ClientMsgHandler::OnAnr, this)},
#if defined(OHOS_BUILD_ENABLE_KEYBOARD) && (defined(OHOS_BUILD_ENABLE_INTERCEPTOR) || \
    defined(OHOS_BUILD_ENABLE_MONITOR))
        {MmiMessageId::REPORT_KEY_EVENT, MsgCallbackBind2(&ClientMsgHandler::ReportKeyEvent, this)},
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#if (defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)) && \
    (defined(OHOS_BUILD_ENABLE_INTERCEPTOR) || defined(OHOS_BUILD_ENABLE_MONITOR))
        {MmiMessageId::REPORT_POINTER_EVENT, MsgCallbackBind2(&ClientMsgHandler::ReportPointerEvent, this)},
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
#ifdef OHOS_BUILD_ENABLE_COOPERATE
        {MmiMessageId::COOPERATION_ADD_LISTENER, MsgCallbackBind2(&ClientMsgHandler::OnCooperationListiner, this)},
        {MmiMessageId::COOPERATION_MESSAGE, MsgCallbackBind2(&ClientMsgHandler::OnCooperationMessage, this)},
        {MmiMessageId::COOPERATION_GET_STATE, MsgCallbackBind2(&ClientMsgHandler::OnCooperationState, this)},
#endif // OHOS_BUILD_ENABLE_COOPERATE
    };
    for (auto &it : funs) {
        if (!RegistrationEvent(it)) {
            MMI_HILOGW("Failed to register event errCode:%{public}d", EVENT_REG_FAIL);
            continue;
        }
    }
}

void ClientMsgHandler::InitProcessedCallback()
{
    CALL_DEBUG_ENTER;
    int32_t tokenType = MultimodalInputConnMgr->GetTokenType();
    if (tokenType == TokenType::TOKEN_HAP) {
        MMI_HILOGD("Current session is hap");
        dispatchCallback_ = std::bind(&ClientMsgHandler::OnDispatchEventProcessed, std::placeholders::_1);
    } else if (tokenType == static_cast<int32_t>(TokenType::TOKEN_NATIVE)) {
        MMI_HILOGD("Current session is native");
    } else {
        MMI_HILOGE("Current session is unknown tokenType:%{public}d", tokenType);
    }
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

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
int32_t ClientMsgHandler::OnKeyEvent(const UDSClient& client, NetPacket& pkt)
{
    auto key = KeyEvent::Create();
    CHKPR(key, ERROR_NULL_POINTER);
    int32_t ret = InputEventDataTransformation::NetPacketToKeyEvent(pkt, key);
    if (ret != RET_OK) {
        MMI_HILOGE("Read netPacket failed");
        return RET_ERR;
    }
    int32_t fd = 0;
    pkt >> fd;
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet read fd failed");
        return PACKET_READ_FAIL;
    }
    MMI_HILOGI("Key event dispatcher of client, Fd:%{public}d", fd);
    EventLogHelper::PrintEventData(key);
    BytraceAdapter::StartBytrace(key, BytraceAdapter::TRACE_START, BytraceAdapter::KEY_DISPATCH_EVENT);
    key->SetProcessedCallback(dispatchCallback_);
    InputMgrImpl.OnKeyEvent(key);
    key->MarkProcessed();
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
int32_t ClientMsgHandler::OnPointerEvent(const UDSClient& client, NetPacket& pkt)
{
    CALL_DEBUG_ENTER;
    auto pointerEvent = PointerEvent::Create();
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    if (InputEventDataTransformation::Unmarshalling(pkt, pointerEvent) != ERR_OK) {
        MMI_HILOGE("Failed to deserialize pointer event.");
        return RET_ERR;
    }
    MMI_HILOGD("Pointer event dispatcher of client:");
    EventLogHelper::PrintEventData(pointerEvent);
    if (PointerEvent::POINTER_ACTION_CANCEL == pointerEvent->GetPointerAction()) {
        MMI_HILOGI("Operation canceled.");
    }
    pointerEvent->SetProcessedCallback(dispatchCallback_);
    BytraceAdapter::StartBytrace(pointerEvent, BytraceAdapter::TRACE_START, BytraceAdapter::POINT_DISPATCH_EVENT);
    InputMgrImpl.OnPointerEvent(pointerEvent);
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
int32_t ClientMsgHandler::OnSubscribeKeyEventCallback(const UDSClient &client, NetPacket &pkt)
{
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    CHKPR(keyEvent, ERROR_NULL_POINTER);
    int32_t ret = InputEventDataTransformation::NetPacketToKeyEvent(pkt, keyEvent);
    if (ret != RET_OK) {
        MMI_HILOGE("Read net packet failed");
        return RET_ERR;
    }
    int32_t fd = -1;
    int32_t subscribeId = -1;
    pkt >> fd >> subscribeId;
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet read fd failed");
        return PACKET_READ_FAIL;
    }
    if (keyEvent->GetKeyCode() == KeyEvent::KEYCODE_POWER) {
        MMI_HILOGI("Subscribe:%{public}d,Fd:%{public}d,KeyEvent:%{public}d,"
            "KeyCode:%{public}d,ActionTime:%{public}" PRId64 ",ActionStartTime:%{public}" PRId64 ","
            "Action:%{public}d,KeyAction:%{public}d,EventType:%{public}d,Flag:%{public}u",
        subscribeId, fd, keyEvent->GetId(), keyEvent->GetKeyCode(), keyEvent->GetActionTime(),
        keyEvent->GetActionStartTime(), keyEvent->GetAction(), keyEvent->GetKeyAction(),
        keyEvent->GetEventType(), keyEvent->GetFlag());
    } else {
        MMI_HILOGD("Subscribe:%{public}d,Fd:%{public}d,KeyEvent:%{public}d,"
            "KeyCode:%{public}d,ActionTime:%{public}" PRId64 ",ActionStartTime:%{public}" PRId64 ","
            "Action:%{public}d,KeyAction:%{public}d,EventType:%{public}d,Flag:%{public}u",
        subscribeId, fd, keyEvent->GetId(), keyEvent->GetKeyCode(), keyEvent->GetActionTime(),
        keyEvent->GetActionStartTime(), keyEvent->GetAction(), keyEvent->GetKeyAction(),
        keyEvent->GetEventType(), keyEvent->GetFlag());
    }

    BytraceAdapter::StartBytrace(keyEvent, BytraceAdapter::TRACE_START, BytraceAdapter::KEY_SUBSCRIBE_EVENT);
    return KeyEventInputSubscribeMgr.OnSubscribeKeyEventCallback(keyEvent, subscribeId);
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

int32_t ClientMsgHandler::OnInputDeviceIds(const UDSClient& client, NetPacket& pkt)
{
    CALL_DEBUG_ENTER;
    int32_t userData;
    std::vector<int32_t> inputDeviceIds;
    pkt >> userData >> inputDeviceIds;
    if (inputDeviceIds.size() > MAX_INPUT_DEVICE) {
        MMI_HILOGE("Device exceeds the max range");
        return RET_ERR;
    }
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet read cooperate msg failed");
        return RET_ERR;
    }
    InputDevImpl.OnInputDeviceIds(userData, inputDeviceIds);
    return RET_OK;
}

int32_t ClientMsgHandler::OnInputDevice(const UDSClient& client, NetPacket& pkt)
{
    CALL_DEBUG_ENTER;
    int32_t userData;
    pkt >> userData;
    std::shared_ptr<InputDevice> devData = InputDevImpl.DevDataUnmarshalling(pkt);
    CHKPR(devData, RET_ERR);
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet read cooperate msg failed");
        return RET_ERR;
    }
    InputDevImpl.OnInputDevice(userData, devData);
    return RET_OK;
}

int32_t ClientMsgHandler::OnSupportKeys(const UDSClient& client, NetPacket& pkt)
{
    CALL_DEBUG_ENTER;
    int32_t userData;
    size_t size;
    pkt >> userData >> size;
    if (size > MAX_SUPPORT_KEY) {
        MMI_HILOGE("Keys exceeds the max range");
        return RET_ERR;
    }
    std::vector<bool> abilityRet;
    bool ret;
    for (size_t i = 0; i < size; ++i) {
        pkt >> ret;
        abilityRet.push_back(ret);
    }
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet read key Data failed");
        return RET_ERR;
    }
    InputDevImpl.OnSupportKeys(userData, abilityRet);
    return RET_OK;
}

int32_t ClientMsgHandler::OnInputKeyboardType(const UDSClient& client, NetPacket& pkt)
{
    CALL_DEBUG_ENTER;
    int32_t userData;
    int32_t KeyboardType;
    pkt >> userData >> KeyboardType;
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet read failed");
        return PACKET_WRITE_FAIL;
    }
    InputDevImpl.OnKeyboardType(userData, KeyboardType);
    return RET_OK;
}

int32_t ClientMsgHandler::OnDevListener(const UDSClient& client, NetPacket& pkt)
{
    CALL_DEBUG_ENTER;
    std::string type;
    int32_t deviceId;
    pkt >> type >> deviceId;
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet read type failed");
        return RET_ERR;
    }
    InputDevImpl.OnDevListener(deviceId, type);
    return RET_OK;
}

#if defined(OHOS_BUILD_ENABLE_KEYBOARD) && (defined(OHOS_BUILD_ENABLE_INTERCEPTOR) || \
    defined(OHOS_BUILD_ENABLE_MONITOR))
int32_t ClientMsgHandler::ReportKeyEvent(const UDSClient& client, NetPacket& pkt)
{
    CALL_DEBUG_ENTER;
    InputHandlerType handlerType;
    pkt >> handlerType;
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet read handler failed");
        return RET_ERR;
    }
    auto keyEvent = KeyEvent::Create();
    CHKPR(keyEvent, ERROR_NULL_POINTER);
    if (InputEventDataTransformation::NetPacketToKeyEvent(pkt, keyEvent) != ERR_OK) {
        MMI_HILOGE("Failed to deserialize key event.");
        return RET_ERR;
    }
    BytraceAdapter::StartBytrace(keyEvent, BytraceAdapter::TRACE_START, BytraceAdapter::KEY_INTERCEPT_EVENT);
    switch (handlerType) {
        case INTERCEPTOR: {
#ifdef OHOS_BUILD_ENABLE_INTERCEPTOR
            InputInterMgr->OnInputEvent(keyEvent);
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR
            break;
        }
        case MONITOR: {
#ifdef OHOS_BUILD_ENABLE_MONITOR
            IMonitorMgr->OnInputEvent(keyEvent);
#endif // OHOS_BUILD_ENABLE_MONITOR
            break;
        }
        default: {
            MMI_HILOGW("Failed to intercept or monitor on the event");
            break;
        }
    }
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD && OHOS_BUILD_ENABLE_INTERCEPTOR || OHOS_BUILD_ENABLE_MONITOR

#if (defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)) && \
    (defined(OHOS_BUILD_ENABLE_INTERCEPTOR) || defined(OHOS_BUILD_ENABLE_MONITOR))
int32_t ClientMsgHandler::ReportPointerEvent(const UDSClient& client, NetPacket& pkt)
{
    CALL_DEBUG_ENTER;
    InputHandlerType handlerType;
    pkt >> handlerType;
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet read Pointer data failed");
        return RET_ERR;
    }
    MMI_HILOGD("Client handlerType:%{public}d", handlerType);
    auto pointerEvent = PointerEvent::Create();
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    if (InputEventDataTransformation::Unmarshalling(pkt, pointerEvent) != ERR_OK) {
        MMI_HILOGE("Failed to deserialize pointer event");
        return RET_ERR;
    }
    BytraceAdapter::StartBytrace(pointerEvent, BytraceAdapter::TRACE_START, BytraceAdapter::POINT_INTERCEPT_EVENT);
    switch (handlerType) {
        case INTERCEPTOR: {
#ifdef OHOS_BUILD_ENABLE_INTERCEPTOR
            InputInterMgr->OnInputEvent(pointerEvent);
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR
            break;
        }
        case MONITOR: {
#ifdef OHOS_BUILD_ENABLE_MONITOR
            IMonitorMgr->OnInputEvent(pointerEvent);
#endif // OHOS_BUILD_ENABLE_MONITOR
            break;
        }
        default: {
            MMI_HILOGW("Failed to intercept or monitor on the event");
            break;
        }
    }
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

void ClientMsgHandler::OnDispatchEventProcessed(int32_t eventId)
{
    CALL_DEBUG_ENTER;
    MMIClientPtr client = MMIEventHdl.GetMMIClient();
    CHKPV(client);
    NetPacket pkt(MmiMessageId::MARK_PROCESS);
    pkt << eventId << ANR_DISPATCH;
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet write event failed");
        return;
    }
    if (!client->SendMessage(pkt)) {
        MMI_HILOGE("Send message failed, errCode:%{public}d", MSG_SEND_FAIL);
        return;
    }
}

int32_t ClientMsgHandler::OnAnr(const UDSClient& client, NetPacket& pkt)
{
    CALL_DEBUG_ENTER;
    int32_t pid;
    pkt >> pid;
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet read data failed");
        return RET_ERR;
    }
    MMI_HILOGI("Client pid:%{public}d", pid);
    InputMgrImpl.OnAnr(pid);
    return RET_OK;
}

#ifdef OHOS_BUILD_ENABLE_COOPERATE
int32_t ClientMsgHandler::OnCooperationListiner(const UDSClient& client, NetPacket& pkt)
{
    CALL_DEBUG_ENTER;
    int32_t userData;
    std::string deviceId;
    int32_t nType;
    pkt >> userData >> deviceId >> nType;
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet read type failed");
        return RET_ERR;
    }
    InputDevCooperateImpl.OnDevCooperateListener(deviceId, CooperationMessage(nType));
    return RET_OK;
}

int32_t ClientMsgHandler::OnCooperationMessage(const UDSClient& client, NetPacket& pkt)
{
    CALL_DEBUG_ENTER;
    int32_t userData;
    std::string deviceId;
    int32_t nType;
    pkt >> userData >> deviceId >> nType;
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet read cooperate msg failed");
        return RET_ERR;
    }
    InputDevCooperateImpl.OnCooprationMessage(userData, deviceId, CooperationMessage(nType));
    return RET_OK;
}

int32_t ClientMsgHandler::OnCooperationState(const UDSClient& client, NetPacket& pkt)
{
    CALL_DEBUG_ENTER;
    int32_t userData;
    bool state;
    pkt >> userData >> state;
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet read cooperate msg failed");
        return RET_ERR;
    }
    InputDevCooperateImpl.OnCooperationState(userData, state);
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_COOPERATE
} // namespace MMI
} // namespace OHOS
