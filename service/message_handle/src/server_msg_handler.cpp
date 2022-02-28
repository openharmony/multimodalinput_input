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
#include "ability_launch_manager.h"
#include "event_dump.h"
#include "event_package.h"
#include "input_device_manager.h"
#include "input_event_data_transformation.h"
#include "input_event.h"
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
    }
} // namespace MMI
} // namespace OHOS

OHOS::MMI::ServerMsgHandler::ServerMsgHandler() {}

OHOS::MMI::ServerMsgHandler::~ServerMsgHandler() {}

bool OHOS::MMI::ServerMsgHandler::Init(UDSServer& udsServer)
{
    udsServer_ = &udsServer;
#ifdef OHOS_BUILD_HDF
    CHKF(MMIHdiInject->Init(udsServer), SENIOR_INPUT_DEV_INIT_FAIL);
#endif
    MsgCallback funs[] = {
        {MmiMessageId::ON_VIRTUAL_KEY, MsgCallbackBind2(&ServerMsgHandler::OnVirtualKeyEvent, this)},
        {MmiMessageId::NEW_CHECK_REPLY_MESSAGE,
            MsgCallbackBind2(&ServerMsgHandler::NewCheckReplyMessageFormClient, this)},
        {MmiMessageId::ON_DUMP, MsgCallbackBind2(&ServerMsgHandler::OnDump, this)},
        {MmiMessageId::GET_MMI_INFO_REQ, MsgCallbackBind2(&ServerMsgHandler::GetMultimodeInputInfo, this)},
        {MmiMessageId::INJECT_KEY_EVENT, MsgCallbackBind2(&ServerMsgHandler::OnInjectKeyEvent, this) },
        {MmiMessageId::INJECT_POINTER_EVENT, MsgCallbackBind2(&ServerMsgHandler::OnInjectPointerEvent, this) },
        {MmiMessageId::INPUT_DEVICE, MsgCallbackBind2(&ServerMsgHandler::OnInputDevice, this)},
        {MmiMessageId::INPUT_DEVICE_IDS, MsgCallbackBind2(&ServerMsgHandler::OnInputDeviceIds, this)},
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
        CHKC(RegistrationEvent(it), EVENT_REG_FAIL);
    }
    return true;
}

void OHOS::MMI::ServerMsgHandler::OnMsgHandler(SessionPtr sess, NetPacket& pkt)
{
    CHKPV(sess);
    auto id = pkt.GetMsgId();
    OHOS::MMI::TimeCostChk chk("ServerMsgHandler::OnMsgHandler", "overtime 300(us)", MAX_OVER_TIME, id);
    auto callback = GetMsgCallback(id);
    if (callback == nullptr) {
        MMI_LOGE("ServerMsgHandler::OnMsgHandler Unknown msg id:%{public}d,errCode:%{public}d", id, UNKNOWN_MSG_ID);
        return;
    }
    auto ret = (*callback)(sess, pkt);
    if (ret < 0) {
        MMI_LOGE("ServerMsgHandler::OnMsgHandler Msg handling failed. id:%{public}d,errCode:%{public}d", id, ret);
    }
}

#ifdef OHOS_BUILD_HDF
int32_t OHOS::MMI::ServerMsgHandler::OnHdiInject(SessionPtr sess, NetPacket& pkt)
{
    MMI_LOGI("hdfinject server access hditools info");
    CHKPR(sess, ERROR_NULL_POINTER);
    CHKPR(udsServer_, ERROR_NULL_POINTER);
    const int32_t processingCode = MMIHdiInject->ManageHdfInject(sess, pkt);
    NetPacket pkt(MmiMessageId::HDI_INJECT);
    pkt << processingCode;
    if (!sess->SendMsg(pkt)) {
        MMI_LOGE("OnHdiInject reply messaage error");
        return RET_ERR;
    }
    return RET_OK;
}
#endif

int32_t OHOS::MMI::ServerMsgHandler::OnVirtualKeyEvent(SessionPtr sess, NetPacket& pkt)
{
    VirtualKey virtualKeyEvent;
    pkt >> virtualKeyEvent;
    CHKR(!pkt.ChkError(), PACKET_READ_FAIL, PACKET_READ_FAIL);
    if (virtualKeyEvent.keyCode == HOS_KEY_HOME) {
        MMI_LOGD(" home press");
    } else if (virtualKeyEvent.keyCode == HOS_KEY_BACK) {
        MMI_LOGD(" back press");
    } else if (virtualKeyEvent.keyCode == HOS_KEY_VIRTUAL_MULTITASK) {
        MMI_LOGD(" multitask press");
    }
    return RET_OK;
}

int32_t OHOS::MMI::ServerMsgHandler::OnDump(SessionPtr sess, NetPacket& pkt)
{
    CHKPR(udsServer_, ERROR_NULL_POINTER);
    int32_t fd = -1;
    pkt >> fd;
    CHKR(!pkt.ChkError(), PACKET_READ_FAIL, PACKET_READ_FAIL);
    MMIEventDump->Dump(fd);
    return RET_OK;
}

int32_t OHOS::MMI::ServerMsgHandler::NewCheckReplyMessageFormClient(SessionPtr sess, NetPacket& pkt)
{
    MMI_LOGD("begin");
    CHKPR(sess, ERROR_NULL_POINTER);
    int32_t id = 0;
    pkt >> id;
    CHKR(!pkt.ChkError(), PACKET_READ_FAIL, PACKET_READ_FAIL);
    sess->DelEvents(id);
    MMI_LOGD("end");
    return RET_OK;
}

int32_t OHOS::MMI::ServerMsgHandler::GetMultimodeInputInfo(SessionPtr sess, NetPacket& pkt)
{
    CHKPR(sess, ERROR_NULL_POINTER);
    CHKPR(udsServer_, ERROR_NULL_POINTER);
    TagPackHead tagPackHead;
    pkt >> tagPackHead;
    CHKR(!pkt.ChkError(), PACKET_READ_FAIL, PACKET_READ_FAIL);
    int32_t fd = sess->GetFd();
    if (tagPackHead.idMsg != MmiMessageId::INVALID) {
        TagPackHead tagPackHeadAck = { MmiMessageId::INVALID, {fd}};
        NetPacket pkt(MmiMessageId::GET_MMI_INFO_ACK);
        pkt << tagPackHeadAck;
        if (!udsServer_->SendMsg(fd, pkt)) {
            MMI_LOGE("Sending message failed");
            return MSG_SEND_FAIL;
        }
    }
    return RET_OK;
}

int32_t OHOS::MMI::ServerMsgHandler::OnInjectKeyEvent(SessionPtr sess, NetPacket& pkt)
{
    CHKPR(sess, ERROR_NULL_POINTER);
    int64_t preHandlerTime = GetSysClockTime();
    auto creKey = OHOS::MMI::KeyEvent::Create();
    int32_t errCode = InputEventDataTransformation::NetPacketToKeyEvent(pkt, creKey);
    if (errCode != RET_OK) {
        MMI_LOGE("Deserialization is Failed, errCode:%{public}u", errCode);
        return RET_ERR;
    }

    auto eventDispatchResult = eventDispatch_.DispatchKeyEventPid(*udsServer_, creKey, preHandlerTime);
    if (eventDispatchResult != RET_OK) {
        MMI_LOGE("Key event dispatch failed. ret:%{public}d,errCode:%{public}d",
            eventDispatchResult, KEY_EVENT_DISP_FAIL);
    }
    MMI_LOGD("Inject keyCode:%{public}d, action:%{public}d", creKey->GetKeyCode(), creKey->GetKeyAction());
    return RET_OK;
}

int32_t OHOS::MMI::ServerMsgHandler::OnInjectPointerEvent(SessionPtr sess, NetPacket& pkt)
{
    MMI_LOGD("enter");
    auto pointerEvent = OHOS::MMI::PointerEvent::Create();
    CHKR((RET_OK == InputEventDataTransformation::Unmarshalling(pkt, pointerEvent)),
        STREAM_BUF_READ_FAIL, RET_ERR);
    pointerEvent->UpdateId();
    CHKR((RET_OK == eventDispatch_.HandlePointerEvent(pointerEvent)), POINT_EVENT_DISP_FAIL, RET_ERR);
    MMI_LOGD("leave");
    return RET_OK;
}

int32_t OHOS::MMI::ServerMsgHandler::OnDisplayInfo(SessionPtr sess, NetPacket &pkt)
{
    MMI_LOGD("enter");
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
        info.windowsInfo_ = windowInfos;
        logicalDisplays.push_back(info);
    }

    OHOS::MMI::InputWindowsManager::GetInstance()->UpdateDisplayInfo(physicalDisplays, logicalDisplays);
    MMI_LOGD("leave");
    return RET_OK;
}

int32_t OHOS::MMI::ServerMsgHandler::OnAddInputHandler(SessionPtr sess, NetPacket& pkt)
{
    int32_t handlerId;
    InputHandlerType handlerType;
    CHKR(pkt.Read(handlerId), STREAM_BUF_READ_FAIL, RET_ERR);
    CHKR(pkt.Read(handlerType), STREAM_BUF_READ_FAIL, RET_ERR);
    MMI_LOGD("OnAddInputHandler handler:%{public}d,handlerType:%{public}d", handlerId, handlerType);
    return InputHandlerManagerGlobal::GetInstance().AddInputHandler(handlerId, handlerType, sess);
}

int32_t OHOS::MMI::ServerMsgHandler::OnRemoveInputHandler(SessionPtr sess, NetPacket& pkt)
{
    int32_t handlerId;
    InputHandlerType handlerType;
    CHKR(pkt.Read(handlerId), STREAM_BUF_READ_FAIL, RET_ERR);
    CHKR(pkt.Read(handlerType), STREAM_BUF_READ_FAIL, RET_ERR);
    MMI_LOGD("OnRemoveInputHandler handler:%{public}d,handlerType:%{public}d", handlerId, handlerType);
    InputHandlerManagerGlobal::GetInstance().RemoveInputHandler(handlerId, handlerType, sess);
    return RET_OK;
}

int32_t OHOS::MMI::ServerMsgHandler::OnMarkConsumed(SessionPtr sess, NetPacket& pkt)
{
    int32_t monitorId, eventId;
    CHKR(pkt.Read(monitorId), STREAM_BUF_READ_FAIL, RET_ERR);
    CHKR(pkt.Read(eventId), STREAM_BUF_READ_FAIL, RET_ERR);
    InputHandlerManagerGlobal::GetInstance().MarkConsumed(monitorId, eventId, sess);
    return RET_OK;
}

int32_t OHOS::MMI::ServerMsgHandler::OnSubscribeKeyEvent(SessionPtr sess, NetPacket &pkt)
{
    int32_t subscribeId = -1;
    uint32_t preKeySize = 0;
    int32_t finalKey = -1;
    bool isFinalKeyDown = true;
    int32_t finalKeyDownDuration = 0;
    pkt >> subscribeId >> finalKey >> isFinalKeyDown >> finalKeyDownDuration >> preKeySize;
    std::vector<int32_t> preKeys;
    for (uint32_t i = 0; i < preKeySize; i++) {
        int32_t tmpKey = -1;
        pkt >> tmpKey;
        preKeys.push_back(tmpKey);
    }
    CHKR(!pkt.ChkError(), PACKET_READ_FAIL, PACKET_READ_FAIL);
    auto keyOption = std::make_shared<OHOS::MMI::KeyOption>();
    keyOption->SetPreKeys(preKeys);
    keyOption->SetFinalKey(finalKey);
    keyOption->SetFinalKeyDown(isFinalKeyDown);
    keyOption->SetFinalKeyDownDuration(finalKeyDownDuration);
    int32_t ret = KeyEventSubscriber_.SubscribeKeyEvent(sess, subscribeId, keyOption);
    return ret;
}

int32_t OHOS::MMI::ServerMsgHandler::OnUnSubscribeKeyEvent(SessionPtr sess, NetPacket &pkt)
{
    int32_t subscribeId = -1;
    pkt >> subscribeId;
    CHKR(!pkt.ChkError(), PACKET_READ_FAIL, PACKET_READ_FAIL);
    int32_t ret = KeyEventSubscriber_.UnSubscribeKeyEvent(sess, subscribeId);
    return ret;
}

int32_t OHOS::MMI::ServerMsgHandler::OnInputDeviceIds(SessionPtr sess, NetPacket& pkt)
{
    MMI_LOGD("begin");
    CHKPR(sess, ERROR_NULL_POINTER);
    int32_t userData = 0;
    CHKR(pkt.Read(userData), STREAM_BUF_READ_FAIL, RET_ERR);
    std::vector<int32_t> ids = InputDevMgr->GetInputDeviceIds();
    NetPacket pkt2(MmiMessageId::INPUT_DEVICE_IDS);
    int32_t size = static_cast<int32_t>(ids.size());
    CHKR(pkt2.Write(userData), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(pkt2.Write(size), STREAM_BUF_WRITE_FAIL, RET_ERR);
    for (const auto& item : ids) {
        CHKR(pkt2.Write(item), STREAM_BUF_WRITE_FAIL, RET_ERR);
    }
    if (!sess->SendMsg(pkt2)) {
        MMI_LOGE("Sending failed");
        return MSG_SEND_FAIL;
    }
    MMI_LOGD("end");
    return RET_OK;
}

int32_t OHOS::MMI::ServerMsgHandler::OnInputDevice(SessionPtr sess, NetPacket& pkt)
{
    MMI_LOGD("begin");
    CHKPR(sess, ERROR_NULL_POINTER);
    int32_t userData = 0;
    CHKR(pkt.Read(userData), STREAM_BUF_READ_FAIL, RET_ERR);
    int32_t deviceId = 0;
    CHKR(pkt.Read(deviceId), STREAM_BUF_READ_FAIL, RET_ERR);
    std::shared_ptr<InputDevice> inputDevice = InputDevMgr->GetInputDevice(deviceId);
    NetPacket pkt2(MmiMessageId::INPUT_DEVICE);
    if (inputDevice == nullptr) {
        MMI_LOGI("Input device not found");
        int32_t id = -1;
        std::string name = "null";
        int32_t deviceType = -1;
        CHKR(pkt2.Write(userData), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(pkt2.Write(id), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(pkt2.Write(name), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(pkt2.Write(deviceType), STREAM_BUF_WRITE_FAIL, RET_ERR);
        if (!sess->SendMsg(pkt2)) {
            MMI_LOGE("Sending failed");
            return MSG_SEND_FAIL;
        }
        return RET_OK;
    }
    int32_t id = inputDevice->GetId();
    std::string name = inputDevice->GetName();
    int32_t deviceType = inputDevice->GetType();
    CHKR(pkt2.Write(userData), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(pkt2.Write(id), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(pkt2.Write(name), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(pkt2.Write(deviceType), STREAM_BUF_WRITE_FAIL, RET_ERR);
    if (!sess->SendMsg(pkt2)) {
        MMI_LOGE("Sending failed");
        return MSG_SEND_FAIL;
    }
    MMI_LOGD("end");
    return RET_OK;
}

int32_t OHOS::MMI::ServerMsgHandler::OnAddInputEventMontior(SessionPtr sess, NetPacket& pkt)
{
    CHKPR(sess, ERROR_NULL_POINTER);
    int32_t eventType = 0;
    pkt >> eventType;
    CHKR(!pkt.ChkError(), PACKET_READ_FAIL, PACKET_READ_FAIL);
    if (eventType != OHOS::MMI::InputEvent::EVENT_TYPE_KEY) {
        MMI_LOGE("Wrong event type, eventType:%{public}d", eventType);
        return RET_ERR;
    }
    InputMonitorServiceMgr.AddInputEventMontior(sess, eventType);
    return RET_OK;
}

int32_t OHOS::MMI::ServerMsgHandler::OnAddInputEventTouchpadMontior(SessionPtr sess, NetPacket& pkt)
{
    MMI_LOGD("begin");
    CHKPR(sess, ERROR_NULL_POINTER);
    int32_t eventType = 0;
    pkt >> eventType;
    CHKR(!pkt.ChkError(), PACKET_READ_FAIL, PACKET_READ_FAIL);
    if (eventType != OHOS::MMI::InputEvent::EVENT_TYPE_POINTER) {
        MMI_LOGE("Wrong event type, eventType:%{public}d", eventType);
        return RET_ERR;
    }
    InputMonitorServiceMgr.AddInputEventTouchpadMontior(eventType, sess);
    return RET_OK;
}

int32_t OHOS::MMI::ServerMsgHandler::OnRemoveInputEventMontior(SessionPtr sess, NetPacket& pkt)
{
    CHKPR(sess, ERROR_NULL_POINTER);
    int32_t eventType = 0;
    pkt >> eventType;
    CHKR(!pkt.ChkError(), PACKET_READ_FAIL, PACKET_READ_FAIL);
    if (eventType != OHOS::MMI::InputEvent::EVENT_TYPE_KEY) {
        MMI_LOGE("Wrong event type, eventType:%{public}d", eventType);
        return RET_ERR;
    }
    InputMonitorServiceMgr.RemoveInputEventMontior(sess, eventType);
    return RET_OK;
}

int32_t OHOS::MMI::ServerMsgHandler::OnRemoveInputEventTouchpadMontior(SessionPtr sess, NetPacket& pkt)
{
    CHKPR(sess, ERROR_NULL_POINTER);
    int32_t eventType = 0;
    pkt >> eventType;
    CHKR(!pkt.ChkError(), PACKET_READ_FAIL, PACKET_READ_FAIL);
    if (eventType != OHOS::MMI::InputEvent::EVENT_TYPE_POINTER) {
        MMI_LOGE("Wrong event type, eventType:%{public}d", eventType);
        return RET_ERR;
    }
    InputMonitorServiceMgr.RemoveInputEventMontior(sess, eventType);
    return RET_OK;
}
int32_t OHOS::MMI::ServerMsgHandler::OnAddTouchpadEventFilter(SessionPtr sess, NetPacket& pkt)
{
    CHKPR(sess, ERROR_NULL_POINTER);
    int32_t sourceType = 0;
    int32_t id = 0;
    pkt >> sourceType >> id;
    CHKR(!pkt.ChkError(), PACKET_READ_FAIL, PACKET_READ_FAIL);
    InterceptorMgrGbl.OnAddInterceptor(sourceType, id, sess);
    return RET_OK;
}

int32_t OHOS::MMI::ServerMsgHandler::OnRemoveTouchpadEventFilter(SessionPtr sess, NetPacket& pkt)
{
    CHKPR(sess, ERROR_NULL_POINTER);
    int32_t id = 0;
    pkt  >> id;
    CHKR(!pkt.ChkError(), PACKET_READ_FAIL, PACKET_READ_FAIL);
    InterceptorMgrGbl.OnRemoveInterceptor(id);
    return RET_OK;
}
// LCOV_EXCL_STOP
