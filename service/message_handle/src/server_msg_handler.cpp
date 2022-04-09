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

#include "server_msg_handler.h"

#include <cinttypes>

#include "event_dump.h"
#include "event_package.h"
#include "hos_key_event.h"
#include "input_device_manager.h"
#include "input_event.h"
#include "input_event_data_transformation.h"
#include "input_event_monitor_manager.h"
#include "input_handler_manager_global.h"
#include "input_windows_manager.h"
#include "interceptor_manager_global.h"
#include "key_event_subscriber.h"
#include "mmi_func_callback.h"
#include "time_cost_chk.h"

#ifdef OHOS_BUILD_HDF
#include "hdi_inject.h"
#endif

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "ServerMsgHandler" };
} // namespace

ServerMsgHandler::ServerMsgHandler() {}

ServerMsgHandler::~ServerMsgHandler() {}

void ServerMsgHandler::Init(UDSServer& udsServer)
{
    udsServer_ = &udsServer;
#ifdef OHOS_BUILD_HDF
    if (!(MMIHdiInject->Init(udsServer))) {
        MMI_HILOGE("Input device initialization failed");
        return;
    }
#endif
    MsgCallback funs[] = {
        {MmiMessageId::ON_VIRTUAL_KEY, MsgCallbackBind2(&ServerMsgHandler::OnVirtualKeyEvent, this)},
        {MmiMessageId::MARK_PROCESS,
            MsgCallbackBind2(&ServerMsgHandler::MarkProcessed, this)},
        {MmiMessageId::ON_DUMP, MsgCallbackBind2(&ServerMsgHandler::OnDump, this)},
        {MmiMessageId::GET_MMI_INFO_REQ, MsgCallbackBind2(&ServerMsgHandler::GetMultimodeInputInfo, this)},
        {MmiMessageId::INJECT_KEY_EVENT, MsgCallbackBind2(&ServerMsgHandler::OnInjectKeyEvent, this) },
        {MmiMessageId::INJECT_POINTER_EVENT, MsgCallbackBind2(&ServerMsgHandler::OnInjectPointerEvent, this) },
        {MmiMessageId::INPUT_DEVICE, MsgCallbackBind2(&ServerMsgHandler::OnInputDevice, this)},
        {MmiMessageId::INPUT_DEVICE_IDS, MsgCallbackBind2(&ServerMsgHandler::OnInputDeviceIds, this)},
        {MmiMessageId::INPUT_DEVICE_KEYSTROKE_ABILITY, MsgCallbackBind2(&ServerMsgHandler::GetKeystrokeAbility, this)},
        {MmiMessageId::ADD_INPUT_DEVICE_MONITOR, MsgCallbackBind2(&ServerMsgHandler::OnAddInputDeviceMontior, this)},
        {MmiMessageId::REMOVE_INPUT_DEVICE_MONITOR, MsgCallbackBind2(&ServerMsgHandler::OnRemoveInputDeviceMontior, this)},
        {MmiMessageId::DISPLAY_INFO, MsgCallbackBind2(&ServerMsgHandler::OnDisplayInfo, this)},
        {MmiMessageId::ADD_INPUT_EVENT_MONITOR, MsgCallbackBind2(&ServerMsgHandler::OnAddInputEventMontior, this)},
        {MmiMessageId::REMOVE_INPUT_EVENT_MONITOR, MsgCallbackBind2(&ServerMsgHandler::OnRemoveInputEventMontior, this)},
        {MmiMessageId::ADD_INPUT_EVENT_TOUCHPAD_MONITOR,
            MsgCallbackBind2(&ServerMsgHandler::OnAddInputEventTouchpadMontior, this)},
        {MmiMessageId::REMOVE_INPUT_EVENT_TOUCHPAD_MONITOR,
            MsgCallbackBind2(&ServerMsgHandler::OnRemoveInputEventTouchpadMontior, this)},
        {MmiMessageId::ADD_INPUT_HANDLER, MsgCallbackBind2(&ServerMsgHandler::OnAddInputHandler, this)},
        {MmiMessageId::REMOVE_INPUT_HANDLER, MsgCallbackBind2(&ServerMsgHandler::OnRemoveInputHandler, this)},
        {MmiMessageId::MARK_CONSUMED, MsgCallbackBind2(&ServerMsgHandler::OnMarkConsumed, this)},
        {MmiMessageId::SUBSCRIBE_KEY_EVENT, MsgCallbackBind2(&ServerMsgHandler::OnSubscribeKeyEvent, this)},
        {MmiMessageId::UNSUBSCRIBE_KEY_EVENT, MsgCallbackBind2(&ServerMsgHandler::OnUnSubscribeKeyEvent, this)},
        {MmiMessageId::ADD_EVENT_INTERCEPTOR,
            MsgCallbackBind2(&ServerMsgHandler::OnAddTouchpadEventFilter, this)},
        {MmiMessageId::REMOVE_EVENT_INTERCEPTOR,
            MsgCallbackBind2(&ServerMsgHandler::OnRemoveTouchpadEventFilter, this)},
#ifdef OHOS_BUILD_HDF
        {MmiMessageId::HDI_INJECT, MsgCallbackBind2(&ServerMsgHandler::OnHdiInject, this)},
#endif // OHOS_BUILD_HDF
    };
    for (auto& it : funs) {
        if (!RegistrationEvent(it)) {
            MMI_HILOGW("Failed to register event errCode:%{public}d", EVENT_REG_FAIL);
            continue;
        }
    }
}

void ServerMsgHandler::OnMsgHandler(SessionPtr sess, NetPacket& pkt)
{
    CHKPV(sess);
    auto id = pkt.GetMsgId();
    TimeCostChk chk("ServerMsgHandler::OnMsgHandler", "overtime 300(us)", MAX_OVER_TIME, id);
    auto callback = GetMsgCallback(id);
    if (callback == nullptr) {
        MMI_HILOGE("Unknown msg id:%{public}d,errCode:%{public}d", id, UNKNOWN_MSG_ID);
        return;
    }
    auto ret = (*callback)(sess, pkt);
    if (ret < 0) {
        MMI_HILOGE("Msg handling failed. id:%{public}d,errCode:%{public}d", id, ret);
    }
}

#ifdef OHOS_BUILD_HDF
int32_t ServerMsgHandler::OnHdiInject(SessionPtr sess, NetPacket& pkt)
{
    MMI_HILOGI("hdfinject server access hditools info");
    CHKPR(sess, ERROR_NULL_POINTER);
    CHKPR(udsServer_, ERROR_NULL_POINTER);
    const int32_t processingCode = MMIHdiInject->ManageHdfInject(sess, pkt);
    NetPacket pkt(MmiMessageId::HDI_INJECT);
    pkt << processingCode;
    if (!sess->SendMsg(pkt)) {
        MMI_HILOGE("OnHdiInject reply messaage error");
        return RET_ERR;
    }
    return RET_OK;
}
#endif

int32_t ServerMsgHandler::OnVirtualKeyEvent(SessionPtr sess, NetPacket& pkt)
{
    VirtualKey virtualKeyEvent;
    pkt >> virtualKeyEvent;
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet read virtualKeyEvent failed");
        return PACKET_READ_FAIL;
    }
    if (virtualKeyEvent.keyCode == HOS_KEY_HOME) {
        MMI_HILOGD(" home press");
    } else if (virtualKeyEvent.keyCode == HOS_KEY_BACK) {
        MMI_HILOGD(" back press");
    } else if (virtualKeyEvent.keyCode == HOS_KEY_VIRTUAL_MULTITASK) {
        MMI_HILOGD(" multitask press");
    }
    return RET_OK;
}

int32_t ServerMsgHandler::OnDump(SessionPtr sess, NetPacket& pkt)
{
    CHKPR(udsServer_, ERROR_NULL_POINTER);
    int32_t fd = -1;
    pkt >> fd;
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet read fd failed");
        return PACKET_READ_FAIL;
    }
    MMIEventDump->Dump(fd);
    return RET_OK;
}

int32_t ServerMsgHandler::MarkProcessed(SessionPtr sess, NetPacket& pkt)
{
    CALL_LOG_ENTER;
    CHKPR(sess, ERROR_NULL_POINTER);
    int32_t eventId = 0;
    pkt >> eventId;
    MMI_HILOGD("event is: %{public}d", eventId);
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet read data failed");
        return PACKET_READ_FAIL;
    }
    sess->DelEvents(eventId);
    return RET_OK;
}

int32_t ServerMsgHandler::GetMultimodeInputInfo(SessionPtr sess, NetPacket& pkt)
{
    CHKPR(sess, ERROR_NULL_POINTER);
    CHKPR(udsServer_, ERROR_NULL_POINTER);
    TagPackHead tagPackHead;
    pkt >> tagPackHead;
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet read tagPackHead failed");
        return PACKET_READ_FAIL;
    }
    int32_t fd = sess->GetFd();
    if (tagPackHead.idMsg != MmiMessageId::INVALID) {
        TagPackHead tagPackHeadAck = { MmiMessageId::INVALID, {fd}};
        NetPacket pkt(MmiMessageId::GET_MMI_INFO_ACK);
        pkt << tagPackHeadAck;
        if (!udsServer_->SendMsg(fd, pkt)) {
            MMI_HILOGE("Sending message failed");
            return MSG_SEND_FAIL;
        }
    }
    return RET_OK;
}

int32_t ServerMsgHandler::OnInjectKeyEvent(SessionPtr sess, NetPacket& pkt)
{
    CHKPR(sess, ERROR_NULL_POINTER);
    auto creKey = KeyEvent::Create();
    CHKPR(creKey, ERROR_NULL_POINTER);
    int32_t errCode = InputEventDataTransformation::NetPacketToKeyEvent(pkt, creKey);
    if (errCode != RET_OK) {
        MMI_HILOGE("Deserialization is Failed, errCode:%{public}u", errCode);
        return RET_ERR;
    }
    auto result = eventDispatch_.DispatchKeyEventPid(*udsServer_, creKey);
    if (result != RET_OK) {
        MMI_HILOGE("Key event dispatch failed. ret:%{public}d,errCode:%{public}d", result, KEY_EVENT_DISP_FAIL);
    }
    MMI_HILOGD("Inject keyCode:%{public}d, action:%{public}d", creKey->GetKeyCode(), creKey->GetKeyAction());
    return RET_OK;
}

int32_t ServerMsgHandler::OnInjectPointerEvent(SessionPtr sess, NetPacket& pkt)
{
    CALL_LOG_ENTER;
    auto pointerEvent = PointerEvent::Create();
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    if (InputEventDataTransformation::Unmarshalling(pkt, pointerEvent) != RET_OK) {
        MMI_HILOGE("Unmarshalling failed");
        return RET_ERR;
    }
    pointerEvent->UpdateId();
    if (eventDispatch_.HandlePointerEvent(pointerEvent) != RET_OK) {
        MMI_HILOGE("HandlePointerEvent failed");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t ServerMsgHandler::OnDisplayInfo(SessionPtr sess, NetPacket &pkt)
{
    CALL_LOG_ENTER;
    CHKPR(sess, ERROR_NULL_POINTER);

    std::vector<PhysicalDisplayInfo> physicalDisplays;
    int32_t num = 0;
    pkt.Read(num);
    for (int32_t i = 0; i < num; i++) {
        PhysicalDisplayInfo info;
        pkt.Read(info.id);
        pkt.Read(info.leftDisplayId);
        pkt.Read(info.upDisplayId);
        pkt.Read(info.topLeftX);
        pkt.Read(info.topLeftY);
        pkt.Read(info.width);
        pkt.Read(info.height);
        pkt.Read(info.name);
        pkt.Read(info.seatId);
        pkt.Read(info.seatName);
        pkt.Read(info.logicWidth);
        pkt.Read(info.logicHeight);
        pkt.Read(info.direction);
        physicalDisplays.push_back(info);
    }

    std::vector<LogicalDisplayInfo> logicalDisplays;
    pkt.Read(num);
    for (int32_t i = 0; i < num; i++) {
        LogicalDisplayInfo info;
        pkt.Read(info.id);
        pkt.Read(info.topLeftX);
        pkt.Read(info.topLeftY);
        pkt.Read(info.width);
        pkt.Read(info.height);
        pkt.Read(info.name);
        pkt.Read(info.seatId);
        pkt.Read(info.seatName);
        pkt.Read(info.focusWindowId);

        std::vector<WindowInfo> windowInfos;
        int32_t numWindow = 0;
        pkt.Read(numWindow);
        for (int32_t j = 0; j < numWindow; j++) {
            WindowInfo info;
            pkt.Read(info);
            windowInfos.push_back(info);
        }
        info.windowsInfo = windowInfos;
        logicalDisplays.push_back(info);
    }

    InputWindowsManager::GetInstance()->UpdateDisplayInfo(physicalDisplays, logicalDisplays);
    return RET_OK;
}

int32_t ServerMsgHandler::OnAddInputHandler(SessionPtr sess, NetPacket& pkt)
{
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
    MMI_HILOGD("OnAddInputHandler handler:%{public}d,handlerType:%{public}d", handlerId, handlerType);
    return InputHandlerManagerGlobal::GetInstance().AddInputHandler(handlerId, handlerType, sess);
}

int32_t ServerMsgHandler::OnRemoveInputHandler(SessionPtr sess, NetPacket& pkt)
{
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
    MMI_HILOGD("OnRemoveInputHandler handler:%{public}d,handlerType:%{public}d", handlerId, handlerType);
    InputHandlerManagerGlobal::GetInstance().RemoveInputHandler(handlerId, handlerType, sess);
    return RET_OK;
}

int32_t ServerMsgHandler::OnMarkConsumed(SessionPtr sess, NetPacket& pkt)
{
    int32_t monitorId, eventId;
    if (!pkt.Read(monitorId)) {
        MMI_HILOGE("Packet read monitor failed");
        return RET_ERR;
    }
    if (!pkt.Read(eventId)) {
        MMI_HILOGE("Packet read event failed");
        return RET_ERR;
    }
    InputHandlerManagerGlobal::GetInstance().MarkConsumed(monitorId, eventId, sess);
    return RET_OK;
}

int32_t ServerMsgHandler::OnSubscribeKeyEvent(SessionPtr sess, NetPacket &pkt)
{
    int32_t subscribeId = -1;
    uint32_t preKeySize = 0;
    int32_t finalKey = -1;
    bool isFinalKeyDown = true;
    int32_t finalKeyDownDuration = 0;
    pkt >> subscribeId >> finalKey >> isFinalKeyDown >> finalKeyDownDuration >> preKeySize;
    std::set<int32_t> preKeys;
    for (uint32_t i = 0; i < preKeySize; ++i) {
        int32_t tmpKey = -1;
        pkt >> tmpKey;
        if (!(preKeys.insert(tmpKey).second)) {
            MMI_HILOGE("Insert value failed, tmpKey:%{public}d", tmpKey);
        }
    }
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet read subscribe failed");
        return PACKET_READ_FAIL;
    }
    auto keyOption = std::make_shared<KeyOption>();
    keyOption->SetPreKeys(preKeys);
    keyOption->SetFinalKey(finalKey);
    keyOption->SetFinalKeyDown(isFinalKeyDown);
    keyOption->SetFinalKeyDownDuration(finalKeyDownDuration);
    int32_t ret = KeyEventSubscriber_.SubscribeKeyEvent(sess, subscribeId, keyOption);
    return ret;
}

int32_t ServerMsgHandler::OnUnSubscribeKeyEvent(SessionPtr sess, NetPacket &pkt)
{
    int32_t subscribeId = -1;
    pkt >> subscribeId;
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet read subscribe failed");
        return PACKET_READ_FAIL;
    }
    int32_t ret = KeyEventSubscriber_.UnSubscribeKeyEvent(sess, subscribeId);
    return ret;
}

int32_t ServerMsgHandler::OnInputDeviceIds(SessionPtr sess, NetPacket& pkt)
{
    CALL_LOG_ENTER;
    CHKPR(sess, ERROR_NULL_POINTER);
    int32_t userData = 0;
    if (!pkt.Read(userData)) {
        MMI_HILOGE("Packet read userData failed");
        return RET_ERR;
    }
    std::vector<int32_t> ids = InputDevMgr->GetInputDeviceIds();
    int32_t size = static_cast<int32_t>(ids.size());
    NetPacket pkt2(MmiMessageId::INPUT_DEVICE_IDS);
    if (!pkt2.Write(userData)) {
        MMI_HILOGE("Packet write userData failed");
        return RET_ERR;
    }
    if (!pkt2.Write(size)) {
        MMI_HILOGE("Packet write size failed");
        return RET_ERR;
    }
    for (const auto& item : ids) {
        if (!pkt2.Write(item)) {
            MMI_HILOGE("Packet write item failed");
            return RET_ERR;
        }
    }
    if (!sess->SendMsg(pkt2)) {
        MMI_HILOGE("Sending failed");
        return MSG_SEND_FAIL;
    }
    return RET_OK;
}

int32_t ServerMsgHandler::OnInputDevice(SessionPtr sess, NetPacket& pkt)
{
    CALL_LOG_ENTER;
    CHKPR(sess, ERROR_NULL_POINTER);
    int32_t userData = 0;
    if (!pkt.Read(userData)) {
        MMI_HILOGE("Packet read userData failed");
        return RET_ERR;
    }
    int32_t deviceId = 0;
    if (!pkt.Read(deviceId)) {
        MMI_HILOGE("Packet read device failed");
        return RET_ERR;
    }
    std::shared_ptr<InputDevice> inputDevice = InputDevMgr->GetInputDevice(deviceId);
    NetPacket pkt2(MmiMessageId::INPUT_DEVICE);
    if (inputDevice == nullptr) {
        MMI_HILOGI("Input device not found");
        int32_t id = -1;
        std::string name = "null";
        int32_t deviceType = -1;
        if (!pkt2.Write(userData)) {
            MMI_HILOGE("Packet write userData failed");
            return RET_ERR;
        }
        if (!pkt2.Write(id)) {
            MMI_HILOGE("Packet write data failed");
            return RET_ERR;
        }
        if (!pkt2.Write(name)) {
            MMI_HILOGE("Packet write name failed");
            return RET_ERR;
        }
        if (!pkt2.Write(deviceType)) {
            MMI_HILOGE("Packet write deviceType failed");
            return RET_ERR;
        }
        if (!sess->SendMsg(pkt2)) {
            MMI_HILOGE("Sending failed");
            return MSG_SEND_FAIL;
        }
        return RET_OK;
    }
    int32_t id = inputDevice->GetId();
    std::string name = inputDevice->GetName();
    int32_t deviceType = inputDevice->GetType();
    if (!pkt2.Write(userData)) {
        MMI_HILOGE("Packet write userData failed");
        return RET_ERR;
    }
    if (!pkt2.Write(id)) {
        MMI_HILOGE("Packet write data failed");
        return RET_ERR;
    }
    if (!pkt2.Write(name)) {
        MMI_HILOGE("Packet write name failed");
        return RET_ERR;
    }
    if (!pkt2.Write(deviceType)) {
        MMI_HILOGE("Packet write deviceType failed");
        return RET_ERR;
    }
    if (!sess->SendMsg(pkt2)) {
        MMI_HILOGE("Sending failed");
        return MSG_SEND_FAIL;
    }
    return RET_OK;
}

int32_t ServerMsgHandler::GetKeystrokeAbility(SessionPtr sess, NetPacket& pkt)
{
    CALL_LOG_ENTER;
    CHKPR(sess, ERROR_NULL_POINTER);
    int32_t userData;
    if (!pkt.Read(userData)) {
        MMI_HILOGE("Packet read userData failed");
        return RET_ERR;
    }
    int32_t deviceId;
    if (!pkt.Read(deviceId)) {
        MMI_HILOGE("Packet read device failed");
        return RET_ERR;
    }
    size_t size;
    if (!pkt.Read(size)) {
        MMI_HILOGE("Packet read size failed");
        return RET_ERR;
    }
    int32_t sysKeyValue;
    std::vector<int32_t> keyCode;
    for (size_t i = 0 ; i < size; ++i) {
        if (!pkt.Read(sysKeyValue)) {
            MMI_HILOGE("Packet read nativeKeyValue failed");
            return RET_ERR;
        }
        keyCode.push_back(sysKeyValue);
    }

    std::map<int32_t, bool> abilityRet = InputDevMgr->GetKeystrokeAbility(deviceId, keyCode);
    std::vector<int32_t> keystroke;
    for (const auto &item : abilityRet) {
        keystroke.push_back(item.first);
        keystroke.push_back(item.second ? 1 : 0);
    }

    NetPacket pkt2(MmiMessageId::INPUT_DEVICE_KEYSTROKE_ABILITY);
    if (!pkt2.Write(userData)) {
        MMI_HILOGE("Packet write userData failed");
        return RET_ERR;
    }
    size = keystroke.size();
    if (!pkt2.Write(size)) {
        MMI_HILOGE("Packet write size failed");
        return RET_ERR;
    }
    for (const auto &item : keystroke) {
        if (!pkt2.Write(item)) {
            MMI_HILOGE("Packet write keystroke failed");
            return RET_ERR;
        }
    }
    if (!sess->SendMsg(pkt2)) {
        MMI_HILOGE("Sending failed");
        return MSG_SEND_FAIL;
    }
    return RET_OK;
}

int32_t ServerMsgHandler::OnAddInputDeviceMontior(SessionPtr sess, NetPacket& pkt)
{
    CALL_LOG_ENTER;
    CHKPR(sess, ERROR_NULL_POINTER);
    InputDevMgr->AddDevMonitor(sess, [sess](std::string type, int32_t deviceId) {
        CALL_LOG_ENTER;
        CHKPV(sess);
        NetPacket pkt2(MmiMessageId::ADD_INPUT_DEVICE_MONITOR);
        if (!pkt2.Write(type)) {
            MMI_HILOGE("Packet write type failed");
            return;
        }
        if (!pkt2.Write(deviceId)) {
            MMI_HILOGE("Packet write deviceId failed");
            return;
        }
        if (!sess->SendMsg(pkt2)) {
            MMI_HILOGE("Sending failed");
            return;
        }
    });
    return RET_OK;
}

int32_t ServerMsgHandler::OnRemoveInputDeviceMontior(SessionPtr sess, NetPacket& pkt)
{
    CALL_LOG_ENTER;
    CHKPR(sess, ERROR_NULL_POINTER);
    InputDevMgr->RemoveDevMonitor(sess);
    return RET_OK;
}

int32_t ServerMsgHandler::OnAddInputEventMontior(SessionPtr sess, NetPacket& pkt)
{
    CHKPR(sess, ERROR_NULL_POINTER);
    int32_t eventType = 0;
    pkt >> eventType;
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet read eventType failed");
        return PACKET_READ_FAIL;
    }
    if (eventType != InputEvent::EVENT_TYPE_KEY) {
        MMI_HILOGE("Wrong event type, eventType:%{public}d", eventType);
        return RET_ERR;
    }
    InputMonitorServiceMgr.AddInputEventMontior(sess, eventType);
    return RET_OK;
}

int32_t ServerMsgHandler::OnAddInputEventTouchpadMontior(SessionPtr sess, NetPacket& pkt)
{
    CALL_LOG_ENTER;
    CHKPR(sess, ERROR_NULL_POINTER);
    int32_t eventType = 0;
    pkt >> eventType;
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet read eventType failed");
        return PACKET_READ_FAIL;
    }
    if (eventType != InputEvent::EVENT_TYPE_POINTER) {
        MMI_HILOGE("Wrong event type, eventType:%{public}d", eventType);
        return RET_ERR;
    }
    InputMonitorServiceMgr.AddInputEventTouchpadMontior(eventType, sess);
    return RET_OK;
}

int32_t ServerMsgHandler::OnRemoveInputEventMontior(SessionPtr sess, NetPacket& pkt)
{
    CHKPR(sess, ERROR_NULL_POINTER);
    int32_t eventType = 0;
    pkt >> eventType;
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet read eventType failed");
        return PACKET_READ_FAIL;
    }
    if (eventType != InputEvent::EVENT_TYPE_KEY) {
        MMI_HILOGE("Wrong event type, eventType:%{public}d", eventType);
        return RET_ERR;
    }
    InputMonitorServiceMgr.RemoveInputEventMontior(sess, eventType);
    return RET_OK;
}

int32_t ServerMsgHandler::OnRemoveInputEventTouchpadMontior(SessionPtr sess, NetPacket& pkt)
{
    CHKPR(sess, ERROR_NULL_POINTER);
    int32_t eventType = 0;
    pkt >> eventType;
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet read eventType failed");
        return PACKET_READ_FAIL;
    }
    if (eventType != InputEvent::EVENT_TYPE_POINTER) {
        MMI_HILOGE("Wrong event type, eventType:%{public}d", eventType);
        return RET_ERR;
    }
    InputMonitorServiceMgr.RemoveInputEventMontior(sess, eventType);
    return RET_OK;
}
int32_t ServerMsgHandler::OnAddTouchpadEventFilter(SessionPtr sess, NetPacket& pkt)
{
    CHKPR(sess, ERROR_NULL_POINTER);
    int32_t sourceType = 0;
    int32_t id = 0;
    pkt >> sourceType >> id;
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet read sourceType failed");
        return PACKET_READ_FAIL;
    }
    InterceptorMgrGbl.OnAddInterceptor(sourceType, id, sess);
    return RET_OK;
}

int32_t ServerMsgHandler::OnRemoveTouchpadEventFilter(SessionPtr sess, NetPacket& pkt)
{
    CHKPR(sess, ERROR_NULL_POINTER);
    int32_t id = 0;
    pkt  >> id;
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet read data failed");
        return PACKET_READ_FAIL;
    }
    InterceptorMgrGbl.OnRemoveInterceptor(id);
    return RET_OK;
}
} // namespace MMI
} // namespace OHOS