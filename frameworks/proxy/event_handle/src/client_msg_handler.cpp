/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include <iostream>
#include <inttypes.h>
#include "time_cost_chk.h"
#include "util.h"
#include "proto.h"
#include "keyboard_event.h"
#include "stylus_event.h"
#include "multimodal_event_handler.h"
#include "event_factory.h"
#include "mmi_client.h"
#include "auto_test_multimodal.h"

namespace OHOS::MMI {
    namespace {
        static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "ClientMsgHandler"};
    }
}

OHOS::MMI::ClientMsgHandler::ClientMsgHandler()
{
}

OHOS::MMI::ClientMsgHandler::~ClientMsgHandler()
{
}

bool OHOS::MMI::ClientMsgHandler::Init()
{
    // LCOV_EXCL_START
    MsgCallback funs[] = {
        {MmiMessageId::ON_KEY,
         std::bind(&ClientMsgHandler::OnKey, this, std::placeholders::_1, std::placeholders::_2)},
        {MmiMessageId::ON_TOUCH,
         std::bind(&ClientMsgHandler::OnTouch, this, std::placeholders::_1, std::placeholders::_2)},
        {MmiMessageId::ON_COPY,
         std::bind(&ClientMsgHandler::OnCopy, this, std::placeholders::_1, std::placeholders::_2)},
        {MmiMessageId::ON_SHOW_MENU,
         std::bind(&ClientMsgHandler::OnShowMenu, this, std::placeholders::_1, std::placeholders::_2)},
        {MmiMessageId::ON_SEND,
         std::bind(&ClientMsgHandler::OnSend, this, std::placeholders::_1, std::placeholders::_2)},
        {MmiMessageId::ON_PASTE,
         std::bind(&ClientMsgHandler::OnPaste, this, std::placeholders::_1, std::placeholders::_2)},
        {MmiMessageId::ON_CUT,
         std::bind(&ClientMsgHandler::OnCut, this, std::placeholders::_1, std::placeholders::_2)},
        {MmiMessageId::ON_UNDO,
         std::bind(&ClientMsgHandler::OnUndo, this, std::placeholders::_1, std::placeholders::_2)},
        {MmiMessageId::ON_REFRESH,
         std::bind(&ClientMsgHandler::OnRefresh, this, std::placeholders::_1, std::placeholders::_2)},
        {MmiMessageId::ON_START_DRAG,
         std::bind(&ClientMsgHandler::OnStartDrag, this, std::placeholders::_1, std::placeholders::_2)},
        {MmiMessageId::ON_CANCEL,
         std::bind(&ClientMsgHandler::OnCancel, this, std::placeholders::_1, std::placeholders::_2)},
        {MmiMessageId::ON_ENTER,
         std::bind(&ClientMsgHandler::OnEnter, this, std::placeholders::_1, std::placeholders::_2)},
        {MmiMessageId::ON_PREVIOUS,
         std::bind(&ClientMsgHandler::OnPrevious, this, std::placeholders::_1, std::placeholders::_2)},
        {MmiMessageId::ON_NEXT,
         std::bind(&ClientMsgHandler::OnNext, this, std::placeholders::_1, std::placeholders::_2)},
        {MmiMessageId::ON_BACK,
         std::bind(&ClientMsgHandler::OnBack, this, std::placeholders::_1, std::placeholders::_2)},
        {MmiMessageId::ON_PRINT,
         std::bind(&ClientMsgHandler::OnPrint, this, std::placeholders::_1, std::placeholders::_2)},
        {MmiMessageId::ON_PLAY,
         std::bind(&ClientMsgHandler::OnPlay, this, std::placeholders::_1, std::placeholders::_2)},
        {MmiMessageId::ON_PAUSE,
         std::bind(&ClientMsgHandler::OnPause, this, std::placeholders::_1, std::placeholders::_2)},
        {MmiMessageId::ON_MEDIA_CONTROL,
         std::bind(&ClientMsgHandler::OnMediaControl, this, std::placeholders::_1, std::placeholders::_2)},
        {MmiMessageId::ON_SCREEN_SHOT,
         std::bind(&ClientMsgHandler::OnScreenShot, this, std::placeholders::_1, std::placeholders::_2)},
        {MmiMessageId::ON_SCREEN_SPLIT,
         std::bind(&ClientMsgHandler::OnScreenSplit, this, std::placeholders::_1, std::placeholders::_2)},
        {MmiMessageId::ON_START_SCREEN_RECORD,
         std::bind(&ClientMsgHandler::OnStartScreenRecord, this, std::placeholders::_1, std::placeholders::_2)},
        {MmiMessageId::ON_STOP_SCREEN_RECORD,
         std::bind(&ClientMsgHandler::OnStopScreenRecord, this, std::placeholders::_1, std::placeholders::_2)},
        {MmiMessageId::ON_GOTO_DESKTOP,
         std::bind(&ClientMsgHandler::OnGotoDesktop, this, std::placeholders::_1, std::placeholders::_2)},
        {MmiMessageId::ON_RECENT,
         std::bind(&ClientMsgHandler::OnRecent, this, std::placeholders::_1, std::placeholders::_2)},
        {MmiMessageId::ON_SHOW_NOTIFICATION,
         std::bind(&ClientMsgHandler::OnShowNotification, this, std::placeholders::_1, std::placeholders::_2)},
        {MmiMessageId::ON_LOCK_SCREEN,
         std::bind(&ClientMsgHandler::OnLockScreen, this, std::placeholders::_1, std::placeholders::_2)},
        {MmiMessageId::ON_SEARCH,
         std::bind(&ClientMsgHandler::OnSearch, this, std::placeholders::_1, std::placeholders::_2)},
        {MmiMessageId::ON_CLOSE_PAGE,
         std::bind(&ClientMsgHandler::OnClosePage, this, std::placeholders::_1, std::placeholders::_2)},
        {MmiMessageId::ON_LAUNCH_VOICE_ASSISTANT,
         std::bind(&ClientMsgHandler::OnLaunchVoiceAssistant, this, std::placeholders::_1, std::placeholders::_2)},
        {MmiMessageId::ON_MUTE,
         std::bind(&ClientMsgHandler::OnMute, this, std::placeholders::_1, std::placeholders::_2)},
        {MmiMessageId::ON_ANSWER,
         std::bind(&ClientMsgHandler::OnAnswer, this, std::placeholders::_1, std::placeholders::_2)},
        {MmiMessageId::ON_REFUSE,
         std::bind(&ClientMsgHandler::OnRefuse, this, std::placeholders::_1, std::placeholders::_2)},
        {MmiMessageId::ON_HANG_UP,
         std::bind(&ClientMsgHandler::OnHangup, this, std::placeholders::_1, std::placeholders::_2)},
        {MmiMessageId::ON_TELEPHONE_CONTROL,
         std::bind(&ClientMsgHandler::OnTelephoneControl, this, std::placeholders::_1, std::placeholders::_2)},
        {MmiMessageId::GET_MMI_INFO_ACK,
         std::bind(&ClientMsgHandler::GetMultimodeInputInfo, this, std::placeholders::_1, std::placeholders::_2)},
        {MmiMessageId::ON_DEVICE_ADDED,
         std::bind(&ClientMsgHandler::DeviceAdd, this, std::placeholders::_1, std::placeholders::_2)},
        {MmiMessageId::ON_DEVICE_REMOVED,
         std::bind(&ClientMsgHandler::DeviceRemove, this, std::placeholders::_1, std::placeholders::_2)},
    };
    // LCOV_EXCL_STOP
    for (auto& it : funs) {
        CHKC(RegistrationEvent(it), EVENT_REG_FAIL);
    }
    return true;
}

void OHOS::MMI::ClientMsgHandler::OnMsgHandler(const OHOS::MMI::UDSClient& client, OHOS::MMI::NetPacket& pkt)
{
    auto id = pkt.GetMsgId();
    OHOS::MMI::TimeCostChk chk("ClientMsgHandler::OnMsgHandler", "overtime 300(us)", MAX_OVER_TIME, id);
    auto fun = GetFun(id);
    if (!fun) {
        MMI_LOGE("CClientMsgHandler::OnMsgHandler Unknown msg id[%{public}d].", id);
        return;
    }
    auto ret = (*fun)(client, pkt);
    if (ret < 0) {
        MMI_LOGE("CClientMsgHandler::OnMsgHandler Msg handling failed. id[%{public}d] ret[%{public}d]", id, ret);
        return;
    }
}

int32_t OHOS::MMI::ClientMsgHandler::OnKey(const UDSClient& client, NetPacket& pkt)
{
    int32_t abilityId = 0;
    int32_t windowId = 0;
    int32_t fd = 0;
    uint64_t serverStartTime = 0;
    EventKeyboard key = {};
    pkt >> key >> abilityId >> windowId >> fd >> serverStartTime;
    MMI_LOGT("\nevent dispatcher of client:\neventKeyboard:time=%{public}" PRId64 ";key=%{public}u;deviceId=%{public}u;"
             "deviceType=%{public}u;seat_key_count=%{public}u;state=%{public}d;abilityId=%{public}d;"
             "windowId=%{public}d;fd=%{public}d\n*************************************************************\n",
             key.time, key.key, key.deviceId, key.deviceType, key.seat_key_count, key.state, abilityId, windowId, fd);

    uint64_t clientEndTime = GetSysClockTime();
    ((MMIClient *)&client)->ReplyMessageToServer(pkt.GetMsgId(), key.time, serverStartTime, clientEndTime, fd);

#ifdef OHOS_AUTO_TEST_FRAME
    // Be used by auto-test frame!
    const AutoTestClientPkt autoTestClientKeyPkt = {
        "eventKeyboard", key.key, key.state, 0, 0, "", fd, windowId, abilityId,
        0, 0, key.deviceType, key.deviceId, key.eventType, 0
    };
    ((MMIClient*)&client)->AutoTestReplyClientPktToServer(autoTestClientKeyPkt);
#endif  // OHOS_AUTO_TEST_FRAME

    /* 根据收到的key，构造keyBoardEvent对象，
    *  其中KeyBoardEvent对象的    handledByIme,unicode,isSingleNonCharacter,isTwoNonCharacters,isThreeNonCharacters五个字段
    *  和KeyEvent对象的keyDownDuration一个字段
    *  和MultimodalEvent对象的highLevelEvent, deviceId, isHighLevelEvent三个字段缺失，暂时填0
    */
    KeyBoardEvent event;
    int32_t deviceEventType = KEY_EVENT;
    event.Initialize(windowId, 0, 0, 0, 0, 0, key.state, key.key, 0, 0, key.uuid, key.eventType,
                     key.time, "", static_cast<int32_t>(key.deviceId), 0, key.deviceType, deviceEventType);
    return EventManager.OnKey(event);
}

int32_t OHOS::MMI::ClientMsgHandler::OnTouch(const UDSClient& client, NetPacket& pkt)
{
    int32_t type = 0;
    pkt >> type;
    switch (type) {
        case INPUT_DEVICE_CAP_POINTER: {
            AnalysisPointEvent(client, pkt);
            break;
        }
        case INPUT_DEVICE_CAP_TOUCH: {
            AnalysisTouchEvent(client, pkt);
            break;
        }
        case INPUT_DEVICE_CAP_JOYSTICK: {
            AnalysisJoystickEvent(client, pkt);
            break;
        }
        case INPUT_DEVICE_CAP_TOUCH_PAD: {
            AnalysisTouchPadEvent(client, pkt);
            break;
        }
        case INPUT_DEVICE_CAP_TABLET_TOOL: {
            AnalysisTabletToolEvent(client, pkt);
            break;
        }
        case INPUT_DEVICE_CAP_GESTURE: {
            AnalysisGestureEvent(client, pkt);
            break;
        }
        default: {
            MMI_LOGE("ClientMsgHandler::OnTouch unknow type:%{public}d errCode:%{public}d", type, UNKNOW_TOUCH_TYPE);
            return RET_ERR;
        }
    }
    return RET_OK;
}

int32_t OHOS::MMI::ClientMsgHandler::OnCopy(const UDSClient& client, NetPacket& pkt)
{
    MMI_LOGT("ClientMsgHandler::OnCopy\n");
    MultimodalEvent multEvent;
    PackedData(multEvent, client, pkt, __func__);
    return EventManager.OnCopy(multEvent);
}

int32_t OHOS::MMI::ClientMsgHandler::OnShowMenu(const UDSClient& client, NetPacket& pkt)
{
    MMI_LOGT("ClientMsgHandler::OnShowMenu\n");
    MultimodalEvent multEvent;
    PackedData(multEvent, client, pkt, __func__);
    return EventManager.OnShowMenu(multEvent);
}

int32_t OHOS::MMI::ClientMsgHandler::OnSend(const UDSClient& client, NetPacket& pkt)
{
    MMI_LOGT("ClientMsgHandler::OnSend\n");
    MultimodalEvent multEvent;
    PackedData(multEvent, client, pkt, __func__);
    return EventManager.OnSend(multEvent);
}

int32_t OHOS::MMI::ClientMsgHandler::OnPaste(const UDSClient& client, NetPacket& pkt)
{
    MMI_LOGT("ClientMsgHandler::OnPaste\n");
    MultimodalEvent multEvent;
    PackedData(multEvent, client, pkt, __func__);
    return EventManager.OnPaste(multEvent);
}

int32_t OHOS::MMI::ClientMsgHandler::OnCut(const UDSClient& client, NetPacket& pkt)
{
    MMI_LOGT("ClientMsgHandler::OnCut\n");
    MultimodalEvent multEvent;
    PackedData(multEvent, client, pkt, __func__);
    return EventManager.OnCut(multEvent);
}

int32_t OHOS::MMI::ClientMsgHandler::OnUndo(const UDSClient& client, NetPacket& pkt)
{
    MMI_LOGT("ClientMsgHandler::OnUndo\n");
    MultimodalEvent multEvent;
    PackedData(multEvent, client, pkt, __func__);
    return EventManager.OnUndo(multEvent);
}

int32_t OHOS::MMI::ClientMsgHandler::OnRefresh(const UDSClient& client, NetPacket& pkt)
{
    MMI_LOGT("ClientMsgHandler::OnRefresh\n");
    MultimodalEvent multEvent;
    PackedData(multEvent, client, pkt, __func__);
    return EventManager.OnRefresh(multEvent);
}

int32_t OHOS::MMI::ClientMsgHandler::OnStartDrag(const UDSClient& client, NetPacket& pkt)
{
    MMI_LOGT("ClientMsgHandler::OnStartDrag\n");
    MultimodalEvent multEvent;
    PackedData(multEvent, client, pkt, __func__);
    return EventManager.OnStartDrag(multEvent);
}

int32_t OHOS::MMI::ClientMsgHandler::OnCancel(const UDSClient& client, NetPacket& pkt)
{
    MMI_LOGT("ClientMsgHandler::OnCancel\n");
    MultimodalEvent multEvent;
    PackedData(multEvent, client, pkt, __func__);
    return EventManager.OnCancel(multEvent);
}

int32_t OHOS::MMI::ClientMsgHandler::OnEnter(const UDSClient& client, NetPacket& pkt)
{
    MMI_LOGT("ClientMsgHandler::OnEnter\n");
    MultimodalEvent multEvent;
    PackedData(multEvent, client, pkt, __func__);
    return EventManager.OnEnter(multEvent);
}

int32_t OHOS::MMI::ClientMsgHandler::OnPrevious(const UDSClient& client, NetPacket& pkt)
{
    MMI_LOGT("ClientMsgHandler::OnPrevious\n");
    MultimodalEvent multEvent;
    PackedData(multEvent, client, pkt, __func__);
    return EventManager.OnPrevious(multEvent);
}

int32_t OHOS::MMI::ClientMsgHandler::OnNext(const UDSClient& client, NetPacket& pkt)
{
    MMI_LOGT("ClientMsgHandler::OnNext\n");
    MultimodalEvent multEvent;
    PackedData(multEvent, client, pkt, __func__);
    return EventManager.OnNext(multEvent);
}

int32_t OHOS::MMI::ClientMsgHandler::OnBack(const UDSClient& client, NetPacket& pkt)
{
    MMI_LOGT("ClientMsgHandler::OnBack\n");
    MultimodalEvent multEvent;
    PackedData(multEvent, client, pkt, __func__);
    return EventManager.OnBack(multEvent);
}

int32_t OHOS::MMI::ClientMsgHandler::OnPrint(const UDSClient& client, NetPacket& pkt)
{
    MMI_LOGT("ClientMsgHandler::OnPrint\n");
    MultimodalEvent multEvent;
    PackedData(multEvent, client, pkt, __func__);
    return EventManager.OnPrint(multEvent);
}

int32_t OHOS::MMI::ClientMsgHandler::OnPlay(const UDSClient& client, NetPacket& pkt)
{
    MMI_LOGT("ClientMsgHandler::OnPlay\n");
    MultimodalEvent multEvent;
    PackedData(multEvent, client, pkt, __func__);
    return EventManager.OnPlay(multEvent);
}

int32_t OHOS::MMI::ClientMsgHandler::OnPause(const UDSClient& client, NetPacket& pkt)
{
    MMI_LOGT("ClientMsgHandler::OnPause\n");
    MultimodalEvent multEvent;
    PackedData(multEvent, client, pkt, __func__);
    return EventManager.OnPause(multEvent);
}

int32_t OHOS::MMI::ClientMsgHandler::OnMediaControl(const UDSClient& client, NetPacket& pkt)
{
    MMI_LOGT("ClientMsgHandler::OnMediaControl\n");
    MultimodalEvent multEvent;
    PackedData(multEvent, client, pkt, __func__);
    return EventManager.OnMediaControl(multEvent);
}

int32_t OHOS::MMI::ClientMsgHandler::OnScreenShot(const UDSClient& client, NetPacket& pkt)
{
    MMI_LOGT("ClientMsgHandler::OnScreenShot\n");
    MultimodalEvent multEvent;
    PackedData(multEvent, client, pkt, __func__);
    return EventManager.OnScreenShot(multEvent);
}

int32_t OHOS::MMI::ClientMsgHandler::OnScreenSplit(const UDSClient& client, NetPacket& pkt)
{
    MMI_LOGT("ClientMsgHandler::OnScreenSplit\n");
    MultimodalEvent multEvent;
    PackedData(multEvent, client, pkt, __func__);
    return EventManager.OnScreenSplit(multEvent);
}

int32_t OHOS::MMI::ClientMsgHandler::OnStartScreenRecord(const UDSClient& client, NetPacket& pkt)
{
    MMI_LOGT("ClientMsgHandler::OnStartScreenRecord\n");
    MultimodalEvent multEvent;
    PackedData(multEvent, client, pkt, __func__);
    return EventManager.OnStartScreenRecord(multEvent);
}

int32_t OHOS::MMI::ClientMsgHandler::OnStopScreenRecord(const UDSClient& client, NetPacket& pkt)
{
    MMI_LOGT("ClientMsgHandler::OnStopScreenRecord\n");
    MultimodalEvent multEvent;
    PackedData(multEvent, client, pkt, __func__);
    return EventManager.OnStopScreenRecord(multEvent);
}

int32_t OHOS::MMI::ClientMsgHandler::OnGotoDesktop(const UDSClient& client, NetPacket& pkt)
{
    MMI_LOGT("ClientMsgHandler::OnGotoDesktop\n");
    MultimodalEvent multEvent;
    PackedData(multEvent, client, pkt, __func__);
    return EventManager.OnGotoDesktop(multEvent);
}

int32_t OHOS::MMI::ClientMsgHandler::OnRecent(const UDSClient& client, NetPacket& pkt)
{
    MMI_LOGT("ClientMsgHandler::OnRecent\n");
    MultimodalEvent multEvent;
    PackedData(multEvent, client, pkt, __func__);
    return EventManager.OnRecent(multEvent);
}

int32_t OHOS::MMI::ClientMsgHandler::OnShowNotification(const UDSClient& client, NetPacket& pkt)
{
    MMI_LOGT("ClientMsgHandler::OnShowNotification\n");
    MultimodalEvent multEvent;
    PackedData(multEvent, client, pkt, __func__);
    return EventManager.OnShowNotification(multEvent);
}

int32_t OHOS::MMI::ClientMsgHandler::OnLockScreen(const UDSClient& client, NetPacket& pkt)
{
    MMI_LOGT("ClientMsgHandler::OnLockScreen\n");
    MultimodalEvent multEvent;
    PackedData(multEvent, client, pkt, __func__);
    return EventManager.OnLockScreen(multEvent);
}

int32_t OHOS::MMI::ClientMsgHandler::OnSearch(const UDSClient& client, NetPacket& pkt)
{
    MMI_LOGT("ClientMsgHandler::OnSearch\n");
    MultimodalEvent multEvent;
    PackedData(multEvent, client, pkt, __func__);
    return EventManager.OnSearch(multEvent);
}

int32_t OHOS::MMI::ClientMsgHandler::OnClosePage(const UDSClient& client, NetPacket& pkt)
{
    MMI_LOGT("ClientMsgHandler::OnClosePage\n");
    MultimodalEvent multEvent;
    PackedData(multEvent, client, pkt, __func__);
    return EventManager.OnClosePage(multEvent);
}

int32_t OHOS::MMI::ClientMsgHandler::OnLaunchVoiceAssistant(const UDSClient& client, NetPacket& pkt)
{
    MMI_LOGT("ClientMsgHandler::OnLaunchVoiceAssistant\n");
    MultimodalEvent multEvent;
    PackedData(multEvent, client, pkt, __func__);
    return EventManager.OnLaunchVoiceAssistant(multEvent);
}

int32_t OHOS::MMI::ClientMsgHandler::OnMute(const UDSClient& client, NetPacket& pkt)
{
    MMI_LOGT("ClientMsgHandler::OnMute\n");
    MultimodalEvent multEvent;
    PackedData(multEvent, client, pkt, __func__);
    return EventManager.OnMute(multEvent);
}

int32_t OHOS::MMI::ClientMsgHandler::OnAnswer(const UDSClient& client, NetPacket& pkt)
{
    MMI_LOGT("ClientMsgHandler::OnAnswer\n");
    MultimodalEvent multEvent;
    PackedData(multEvent, client, pkt, __func__);
    return EventManager.OnAnswer(multEvent);
}

int32_t OHOS::MMI::ClientMsgHandler::OnRefuse(const UDSClient& client, NetPacket& pkt)
{
    MMI_LOGT("ClientMsgHandler::OnRefuse\n");
    MultimodalEvent multEvent;
    PackedData(multEvent, client, pkt, __func__);
    return EventManager.OnRefuse(multEvent);
}

int32_t OHOS::MMI::ClientMsgHandler::OnHangup(const UDSClient& client, NetPacket& pkt)
{
    MMI_LOGT("ClientMsgHandler::OnHangup\n");
    MultimodalEvent multEvent;
    PackedData(multEvent, client, pkt, __func__);
    return EventManager.OnHangup(multEvent);
}

int32_t OHOS::MMI::ClientMsgHandler::OnTelephoneControl(const UDSClient& client, NetPacket& pkt)
{
    MMI_LOGT("ClientMsgHandler::OnTelephoneControl\n");
    MultimodalEvent multEvent;
    PackedData(multEvent, client, pkt, __func__);
    return EventManager.OnTelephoneControl(multEvent);
}

int32_t OHOS::MMI::ClientMsgHandler::PackedData(MultimodalEvent& multEvent, const UDSClient& client,
                                                NetPacket& pkt, const std::string& funName)
{
    if (isServerReqireStMessage_) {
        return RET_OK;
    }
    RegisteredEvent data = {};
    int32_t fd = 0;
    int16_t idMsg = 0;
    int32_t windowId = 0;
    int32_t abilityId = 0;
    uint64_t serverStartTime = 0;
    int32_t type = 0;
    int32_t deviceId = 0;
    uint32_t occurredTime = 0;
    std::string uuid = "";
    pkt >> type;
    if (type == INPUT_DEVICE_CAP_AISENSOR || type == INPUT_DEVICE_CAP_KNUCKLE) {
        pkt >> idMsg >> deviceId >> fd >> windowId >> abilityId >> serverStartTime >> uuid >> occurredTime;
        MMI_LOGT("\nevent dispatcher of client: manager_aisensor\n"
                 "idMsg=%{public}d,deviceId=%{public}d,fd=%{public}d,windowId = %{public}d,abilityId = %{public}d,"
                 "uuid=%{public}s,occurredTime=%{public}d;\n\n"
                 "************************************************************************\n",
                 idMsg, deviceId, fd, windowId, abilityId, uuid.c_str(), occurredTime);
        if (type == INPUT_DEVICE_CAP_KNUCKLE) {
            type = HOS_KNUCKLE;
        }
        else if (type == INPUT_DEVICE_CAP_AISENSOR) {
            type = HOS_AI_SPEECH;
        }
        multEvent.Initialize(windowId, 0, uuid, type, occurredTime, "", deviceId, 0, 0);
    } else {
        pkt >> data >> fd >> windowId >> abilityId >> serverStartTime;
        if (windowId == -1) {
            MMI_LOGT("\nevent dispatcher of client:\n occurredTime=%{public}" PRId64 ";\nsourceType=%{public}d;\n"
                     "deviceId=%{public}d;\nfd=%{public}d;\nabilityId=%{public}d;\n"
                     "\n************************************************************************\n",
                     data.occurredTime, data.eventType, data.deviceId, fd, abilityId);
        } else {
            MMI_LOGT("\nevent dispatcher of client:\n occurredTime=%{public}" PRId64 ";\nsourceType=%{public}d;\n"
                     "deviceId=%{public}d;\nfd=%{public}d;\nabilityId=%{public}d;\nwindowId=%{public}d;\n"
                     "\n**************************************************************\n",
                     data.occurredTime, data.eventType, data.deviceId, fd, abilityId, windowId);
        }
        uint64_t clientEndTime = GetSysClockTime();
        ((MMIClient *)&client)->ReplyMessageToServer(pkt.GetMsgId(), data.occurredTime, serverStartTime,
            clientEndTime, fd);
        multEvent.Initialize(windowId, 0, data.uuid, data.eventType, data.occurredTime, "", data.deviceId, 0,
            data.deviceType);
    }

#ifdef OHOS_AUTO_TEST_FRAME
    // Be used by auto-test frame!
    std::string eventType = "";
    if (type == INPUT_DEVICE_CAP_AISENSOR || type == INPUT_DEVICE_CAP_KNUCKLE) {
        eventType = "AI_KNUCKLE";
    } else {
        eventType = "MixedKey";
    }
    AutoTestClientPkt autoTestClientPkt = {
        "", 0, 0, 0, 0, "", fd, windowId, abilityId, 0, 0, data.deviceType, data.deviceId, data.eventType, 0
    };
    CHKR(strcpy_s(autoTestClientPkt.eventType, MAX_EVENTTYPE_NAME, eventType.c_str()) == EOK,
        STRCPY_S_CALLBACK_FAIL, RET_ERR);
    CHKR(strcpy_s(autoTestClientPkt.callBakeName, MAX_EVENTTYPE_NAME, funName.c_str()) == EOK,
        STRCPY_S_CALLBACK_FAIL, RET_ERR);
    ((MMIClient*)&client)->AutoTestReplyClientPktToServer(autoTestClientPkt);
#endif  // OHOS_AUTO_TEST_FRAME

    return RET_OK;
}

int32_t OHOS::MMI::ClientMsgHandler::GetMultimodeInputInfo(const UDSClient& client, NetPacket& pkt)
{
    TagPackHead tagPackHeadAck;
    pkt >> tagPackHeadAck;
    std::cout << "GetMultimodeInputInfo: The client fd is " << tagPackHeadAck.sizeEvent[0] << std::endl;
    return RET_OK;
}

int32_t OHOS::MMI::ClientMsgHandler::DeviceAdd(const UDSClient& client, NetPacket& pkt)
{
    MMI_LOGT("ClientMsgHandler::DeviceAdd\n");
    DeviceManage data = {};
    pkt >> data;
    DeviceEvent eventData = {};
    eventData.Initialize(data.deviceName, data.devicePhys, data.deviceId);
    return EventManager.OnDeviceAdd(eventData);
}

int32_t OHOS::MMI::ClientMsgHandler::DeviceRemove(const UDSClient& client, NetPacket& pkt)
{
    MMI_LOGT("ClientMsgHandler::DeviceRemove\n");
    DeviceManage data = {};
    pkt >> data;
    DeviceEvent eventData = {};
    eventData.Initialize(data.deviceName, data.devicePhys, data.deviceId);
    return EventManager.OnDeviceRemove(eventData);
}

void OHOS::MMI::ClientMsgHandler::AnalysisPointEvent(const UDSClient& client, NetPacket& pkt) const
{
    int32_t abilityId = 0;
    int32_t windowId = 0;
    int32_t fd = 0;
    int32_t deviceEventType = 0;
    uint64_t serverStartTime = 0;
    int32_t ret = RET_ERR;
    EventPointer pointData = {};
    StandardTouchStruct standardTouch = {};
    EventJoyStickAxis eventJoyStickAxis = {};
    MultimodalEventPtr mousePtr = EventFactory::CreateEvent(EVENT_MOUSE);
    CHK(mousePtr, NULL_POINTER);
    pkt >> ret >> pointData >> abilityId >> windowId >> fd >> serverStartTime;
    MMI_LOGT("\nevent dispatcher of client: mouse_data \neventPointer:time=%{public}" PRId64 "; eventType=%{public}d;"
             "buttonCode=%{public}u;deviceId=%{public}u;deviceType=%{public}u;seat_button_count=%{public}u;"
             "axes=%{public}u;buttonState=%{public}d;source=%{public}d;delta.x=%{public}lf;delta.y=%{public}lf;"
             "delta_raw.x=%{public}lf;delta_raw.y=%{public}lf;absolute.x=%{public}lf;absolute.y=%{public}lf;"
             "discYe.x=%{public}lf;discrete.y=%{public}lf;fd=%{public}d;abilityId=%{public}d;windowId=%{public}d.\n",
             pointData.time, pointData.eventType, pointData.button, pointData.deviceId, pointData.deviceType,
             pointData.seat_button_count, pointData.axes, pointData.state, pointData.source, pointData.delta.x,
             pointData.delta.y, pointData.delta_raw.x, pointData.delta_raw.y, pointData.absolute.x,
             pointData.absolute.y, pointData.discrete.x, pointData.discrete.y, fd, abilityId, windowId);
    ((MMIClient*)&client)->ReplyMessageToServer(pkt.GetMsgId(), pointData.time, serverStartTime, GetSysClockTime(), fd);

#ifdef OHOS_AUTO_TEST_FRAME
    // Be used by auto-test frame!
    const AutoTestClientPkt autoTestClientPointPkt = {
        "eventPointer", pointData.button, pointData.state, pointData.delta_raw.x, pointData.delta_raw.y, "",
        fd, windowId, abilityId, pointData.delta.x, pointData.delta.y, pointData.deviceType, pointData.deviceId,
        pointData.eventType, 0
    };
    ((MMIClient*)&client)->AutoTestReplyClientPktToServer(autoTestClientPointPkt);
#endif  // OHOS_AUTO_TEST_FRAME
    int32_t action = pointData.state;
    /* 根据收到的point，构造MouseEvent对象，
    *  其中MouseEvent对象的action,actionButton,cursorDelta,scrollingDelta四个字段
    *  和MultimodalEvent对象的highLevelEvent, deviceId, isHighLevelEvent三个字段缺失，暂时填0
    */
    MmiPoint mmiPoint;
    mmiPoint.Setxy(pointData.delta.x, pointData.delta.y);
    (reinterpret_cast<MouseEvent*> (mousePtr.GetRefPtr()))->Initialize(windowId, action,
        pointData.button, pointData.state, mmiPoint, static_cast<float>(pointData.discrete.x),
        static_cast<float>(pointData.discrete.y), 0, 0, 0, pointData.uuid, pointData.eventType,
        static_cast<int32_t>(pointData.time), "", static_cast<int32_t>(pointData.deviceId), 0,
        pointData.deviceType, eventJoyStickAxis);

    // 如果是标准化消息，则获取standardTouch
    TouchEvent touchEvent;
    deviceEventType = MOUSE_EVENT;
    fingerInfos fingersInfos[FINGER_NUM] = {};
    if (ret > 0) {
        pkt >> standardTouch;

        /* 根据收到的standardTouch数据和MouseEvent对象，构造TouchEvent对象
         * 其中TouchEvent对象的action,index,forcePrecision,maxForce,tapCount五个字段
         * 和ManipulationEvent对象的pointerId，  touchArea，touchPressure三个字段缺失，暂时填0
         */
        fingersInfos[0].mMp.Setxy(standardTouch.x, standardTouch.y);
        touchEvent.Initialize(windowId, mousePtr, deviceEventType, action, 0, 0, 0, 0,
            static_cast<int32_t>(standardTouch.time), standardTouch.buttonState, standardTouch.buttonCount,
            fingersInfos, true);
    } else { // 非标准化消息，只有mouseEvent消息，其他都没有
        touchEvent.Initialize(windowId, mousePtr, deviceEventType, action, 0, 0, 0, 0,
            0, 0, 1, fingersInfos, false);
    }
    ret = EventManager.OnTouch(touchEvent);
}

void OHOS::MMI::ClientMsgHandler::AnalysisTouchEvent(const UDSClient& client, NetPacket& pkt) const
{
    int32_t abilityId = 0;
    int32_t windowId = 0;
    int32_t fd = 0;
    int32_t fingerCount = 0;
    int32_t eventAction = 0;
    uint64_t serverStartTime = 0;
    uint64_t clientEndTime = 0;
    EventTouch touchData = {};
    MmiPoint mmiPoint;
    pkt >> fingerCount >> eventAction >> abilityId >> windowId >> fd >> serverStartTime;

    fingerInfos fingersInfos[FINGER_NUM] = {};
    /* 根据收到的touchData，构造TouchEvent对象
    *  其中TouchEvent对象的action,index,forcePrecision,maxForce,tapCount五个字段
    *  和ManipulationEvent对象的startTime,operationState,pointerCount,pointerId，  touchArea，touchPressure六个字段，
    *  和MultimodalEvent对象的highLevelEvent, deviceId, isHighLevelEvent三个字段缺失，暂时填0
    */
    for (int i = 0; i < fingerCount; i++) {
        pkt >> touchData;
        fingersInfos[i].mPointerId = i;
        fingersInfos[i].mTouchArea = static_cast<float>(touchData.area);
        fingersInfos[i].mTouchPressure = static_cast<float>(touchData.pressure);
        fingersInfos[i].mMp.Setxy(touchData.point.x, touchData.point.y);
    }

    MMI_LOGT("\nevent dispatcher of client:\neventTouch:time=%{public}" PRId64 ";deviceId=%{public}u;"
             "deviceType=%{public}u;eventType=%{public}d;slot=%{public}d;seat_slot=%{public}d;"
             "fd=%{public}d,abilityId=%{public}d,windowId=%{public}d"
             "\n************************************************************************\n",
        touchData.time, touchData.deviceId, touchData.deviceType, touchData.eventType, touchData.slot,
        touchData.seat_slot, fd, abilityId, windowId);

    TouchEvent touchEvent;
    int32_t deviceEventType = TOUCH_EVENT;
    int32_t fingerIndex = 0;
    if (PRIMARY_POINT_DOWN == eventAction || PRIMARY_POINT_UP == eventAction || 
        OTHER_POINT_DOWN == eventAction || OTHER_POINT_UP == eventAction) {
        fingerIndex = fingersInfos[0].mPointerId;
    }
    touchEvent.Initialize(windowId, eventAction, fingerIndex, 0, 0, 0, 0, 0, fingerCount, fingersInfos, 0,
        touchData.uuid, touchData.eventType, static_cast<int32_t>(touchData.time), "",
        static_cast<int32_t>(touchData.deviceId), 0, false, touchData.deviceType, deviceEventType);

    clientEndTime = GetSysClockTime();
    ((MMIClient*)&client)->ReplyMessageToServer(pkt.GetMsgId(), touchData.time, serverStartTime, clientEndTime, fd);

#ifdef OHOS_AUTO_TEST_FRAME
    // Be used by auto-test frame!
    const AutoTestClientPkt autoTestClientTouchPkt = {
        "eventTouch", 0, 0, touchData.point.x, touchData.point.y, "", fd, windowId, abilityId, 0, 0,
        touchData.deviceType, touchData.deviceId, touchData.eventType, touchData.slot
    };
    ((MMIClient*)&client)->AutoTestReplyClientPktToServer(autoTestClientTouchPkt);
#endif  // OHOS_AUTO_TEST_FRAME
    EventManager.OnTouch(touchEvent);
}

void OHOS::MMI::ClientMsgHandler::AnalysisJoystickEvent(const UDSClient& client, NetPacket& pkt) const
{
    EventJoyStickAxis eventJoyStickData = {};
    int32_t abilityId = 0;
    int32_t windowId = 0;
    int32_t fd = 0;
    int32_t mouseAction = 0;
    int32_t touchAction = 0;
    int32_t deviceEventType = 0;
    std::string nullUUid = "";
    uint64_t serverStartTime = 0;
    uint64_t clientEndTime = 0;
    MmiPoint mmiPoint;
    MultimodalEventPtr mousePtr = EventFactory::CreateEvent(EVENT_MOUSE);
    CHK(mousePtr, NULL_POINTER);
    pkt >> eventJoyStickData >> abilityId >> windowId >> fd >> serverStartTime;
    MMI_LOGT("\nevent dispatcher of client: "
             "event JoyStick: fd: %{public}d, abilityId: %{public}d ,windowId: %{public}d\n",
             fd, abilityId, windowId);
    PrintEventJoyStickAxisInfo(eventJoyStickData, fd, abilityId, windowId, serverStartTime);
    // multimodal ANR
    clientEndTime = GetSysClockTime();
    ((MMIClient*)&client)->ReplyMessageToServer(pkt.GetMsgId(), eventJoyStickData.time, serverStartTime, 
        clientEndTime, fd);

#ifdef OHOS_AUTO_TEST_FRAME
    // Be used by auto-test frame!
    const AutoTestClientPkt autoTestClientJoyStickPkt = {
        "eventJoyStickAxis", 0, 0, 0, 0, "", fd, windowId, abilityId, 0, 0,
        eventJoyStickData.deviceType, eventJoyStickData.deviceId, eventJoyStickData.eventType, 0
    };
    ((MMIClient*)&client)->AutoTestReplyClientPktToServer(autoTestClientJoyStickPkt);
#endif  // OHOS_AUTO_TEST_FRAME

    mouseAction = HOVER_MOVE;
    (reinterpret_cast<MouseEvent*>(mousePtr.GetRefPtr()))->Initialize(windowId, mouseAction, 0, 0, mmiPoint, 
        0, 0, 0, 0, 0, nullUUid, eventJoyStickData.eventType, static_cast<int32_t>(eventJoyStickData.time), "",
        static_cast<int32_t>(eventJoyStickData.deviceId), false, eventJoyStickData.deviceType, eventJoyStickData);

    deviceEventType = MOUSE_EVENT;
    touchAction = HOVER_POINTER_MOVE;
    TouchEvent touchEvent;
    touchEvent.Initialize(windowId, mousePtr, deviceEventType, touchAction, 0, 0, 0, 0, 0, 0, 1,
        nullptr, false);
    EventManager.OnTouch(touchEvent);
}

void OHOS::MMI::ClientMsgHandler::AnalysisTouchPadEvent(const UDSClient& client, NetPacket& pkt) const
{
    EventTabletPad tabletPad = {};
    int32_t abilityId = 0;
    int32_t windowId = 0;
    int32_t fd = 0;
    uint64_t serverStartTime = 0;
    uint64_t clientEndTime = 0;
    int32_t mouseAction = 0;
    int32_t touchAction = 0;
    int32_t deviceEventType = 0;
    MmiPoint mmiPoint;
    std::string nullUUid = "";
    EventJoyStickAxis eventJoyStickAxis = {};
    MultimodalEventPtr mousePtr = EventFactory::CreateEvent(EVENT_MOUSE);
    CHK(mousePtr, NULL_POINTER);
    pkt >> tabletPad >> abilityId >> windowId >> fd >> serverStartTime;
    MMI_LOGT("\nevent dispatcher of client: event tablet Pad :time=%{public}" PRId64 ";deviceType=%{public}u;"
             "deviceId=%{public}d;deviceName=%{public}s;eventType=%{public}d;\n"
             "ring.number=%{public}d;ring.position=%{public}lf;ring.source=%{public}d;\n"
             "strip.number=%{public}d;strip.position=%{public}lf;strip.source=%{public}d;\n"
             "fd=%{public}d;abilityId=%{public}d;windowId=%{public}d;preHandlerTime=%{public}" PRId64 ";\n*"
             "***********************************************************************\n",
             tabletPad.time, tabletPad.deviceType, tabletPad.deviceId, tabletPad.deviceName, tabletPad.eventType,
             tabletPad.ring.number, tabletPad.ring.position, tabletPad.ring.source, tabletPad.strip.number,
             tabletPad.strip.position, tabletPad.strip.source, fd, abilityId, windowId, serverStartTime);

    // multimodal ANR
    clientEndTime = GetSysClockTime();
    ((MMIClient*)&client)->ReplyMessageToServer(pkt.GetMsgId(), tabletPad.time, serverStartTime, clientEndTime, fd);

#ifdef OHOS_AUTO_TEST_FRAME
    // Be used by auto-test frame!
    const AutoTestClientPkt autoTestClientTabletPadPkt = {
        "eventTabletPad", 0, 0, 0, 0, "", fd, windowId, abilityId, 0, 0,
        tabletPad.deviceType, tabletPad.deviceId, tabletPad.eventType, 0
    };
    ((MMIClient*)&client)->AutoTestReplyClientPktToServer(autoTestClientTabletPadPkt);
#endif  // OHOS_AUTO_TEST_FRAME

    mouseAction = HOVER_MOVE;
    eventJoyStickAxis.abs_wheel.standardValue = static_cast<float>(tabletPad.ring.position);
    auto mouseEvent = reinterpret_cast<MouseEvent*>(mousePtr.GetRefPtr());
    mouseEvent->Initialize(windowId, mouseAction, 0, 0, mmiPoint, 0, 0, 0, 0, 0, nullUUid, tabletPad.eventType,
                           static_cast<int32_t>(tabletPad.time), "", static_cast<int32_t>(tabletPad.deviceId),
                           false, tabletPad.deviceType, eventJoyStickAxis);

    TouchEvent touchEvent;
    deviceEventType = MOUSE_EVENT;
    touchAction = HOVER_POINTER_MOVE;
    touchEvent.Initialize(windowId, mousePtr, deviceEventType, touchAction, 0, 0, 0, 0, 0, 0, 1, nullptr, false);
    EventManager.OnTouch(touchEvent);
}

void OHOS::MMI::ClientMsgHandler::PrintEventTabletToolInfo(EventTabletTool tableTool, uint64_t serverStartTime,
                                                           int32_t abilityId, int32_t windowId, int32_t fd) const
{
    MMI_LOGT("\nevent dispatcher of client: event tablet Tool :time=%{public}" PRId64 "; deviceType=%{public}u; "
             "deviceId=%{public}d; deviceName=%{public}s; eventType=%{public}d; type=%{public}u;"
             "tool_id=%{public}u; serial=%{public}u; button=%{public}d; "
             "state=%{public}d; point.x=%{public}lf; point.y=%{public}lf; tilt.x=%{public}lf;"
             "tilt.y=%{public}lf; distance=%{public}lf; pressure=%{public}lf; "
             "rotation=%{public}lf; slider=%{public}lf; wheel=%{public}lf; wheel_discrete=%{public}d;"
             "size.major=%{public}lf; size.minor=%{public}lf; "
             "proximity_state=%{public}d; tip_state=%{public}d; state=%{public}d; seat_button_count=%{public}d;"
             "fd=%{public}d; abilityId=%{public}d; windowId=%{public}d; preHandlerTime=%{public}" PRId64 ";\n"
             "***********************************************************************\n",
             tableTool.time, tableTool.deviceType, tableTool.deviceId, tableTool.deviceName,
             tableTool.eventType, tableTool.tool.type, tableTool.tool.tool_id, tableTool.tool.serial,
             tableTool.button, tableTool.state, tableTool.axes.point.x, tableTool.axes.point.y,
             tableTool.axes.tilt.x, tableTool.axes.tilt.y, tableTool.axes.distance, tableTool.axes.pressure,
             tableTool.axes.rotation, tableTool.axes.slider, tableTool.axes.wheel,
             tableTool.axes.wheel_discrete, tableTool.axes.size.major, tableTool.axes.size.minor,
             tableTool.proximity_state, tableTool.tip_state, tableTool.state, tableTool.seat_button_count,
             fd, abilityId, windowId, serverStartTime);
}

void OHOS::MMI::ClientMsgHandler::GetStandardStylusActionType(int32_t curRventType, int32_t &stylusAction,
                                                              int32_t &touchAction) const
{
    const int32_t EVENT_TOUCH_DOWN = 500;               // LIBINPUT_EVENT_TOUCH_DOWN
    const int32_t EVENT_TOUCH_UP = 501;                 // LIBINPUT_EVENT_TOUCH_UP
    const int32_t EVENT_TOUCH_MOTION = 502;             // LIBINPUT_EVENT_TOUCH_MOTION

    if (curRventType == EVENT_TOUCH_UP) {
        stylusAction = STYLUS_UP;
        touchAction = PRIMARY_POINT_UP;
    } else if (curRventType == EVENT_TOUCH_DOWN) {
        stylusAction = STYLUS_DOWN;
        touchAction = PRIMARY_POINT_DOWN;
    } else if (curRventType == EVENT_TOUCH_MOTION) {
        stylusAction = STYLUS_MOVE;
        touchAction = POINT_MOVE;
    }
}

int32_t OHOS::MMI::ClientMsgHandler::GetNonStandardStylusActionType(int32_t tableToolState) const
{
    int32_t stylusAction = tableToolState;

    if (stylusAction == BUTTON_STATE_PRESSED) {
        stylusAction = BUTTON_PRESS;
    } else {
        stylusAction = BUTTON_RELEASE;
    }
    return stylusAction;
}

void OHOS::MMI::ClientMsgHandler::GetMouseActionType(int32_t eventType, int32_t proximityState,
                                                     int32_t &mouseAction, int32_t &touchAction) const
{
    const int32_t EVENT_TABLET_TOOL_PROXIMITY = 601;    // LIBINPUT_EVENT_TABLET_TOOL_PROXIMITY
    if (eventType == EVENT_TABLET_TOOL_PROXIMITY) {
        if (TABLET_TOOL_PROXIMITY_STATE_IN == proximityState) {
            mouseAction = HOVER_ENTER;
            touchAction = HOVER_POINTER_ENTER;
        } else if (TABLET_TOOL_PROXIMITY_STATE_OUT == proximityState) {
            mouseAction = HOVER_EXIT;
            touchAction = HOVER_POINTER_EXIT;
        } else {
            mouseAction = HOVER_MOVE;
            touchAction = HOVER_POINTER_MOVE;
        }
    }
}

void OHOS::MMI::ClientMsgHandler::AnalysisStandardTabletToolEvent(NetPacket& pkt, int32_t curRventType,
                                                                  EventTabletTool tableTool, int32_t windowId) const
{
    const int32_t MOUSE_BTN_LEFT = 0x110;       // left button
    int32_t deviceEventType = 0;
    int32_t touchAction = MMNONE;
    EventJoyStickAxis eventJoyStickAxis = {};
    MmiPoint mmiPoint;
    auto mousePtr = EventFactory::CreateEvent(EVENT_MOUSE);
    CHK(mousePtr, NULL_POINTER);
    auto mouseEvent = reinterpret_cast<MouseEvent*>(mousePtr.GetRefPtr());
    auto stylusPtr = EventFactory::CreateEvent(EVENT_STYLUS);
    CHK(stylusPtr, NULL_POINTER);
    auto stylusEvent = reinterpret_cast<StylusEvent*>(stylusPtr.GetRefPtr());

    StandardTouchStruct standardTouchEvent = {};
    TouchEvent touchEvent;
    fingerInfos fingersInfos[FINGER_NUM] = {};
    if (curRventType > 0) {
        pkt >> standardTouchEvent;
        fingersInfos[0].mMp.Setxy(standardTouchEvent.x, standardTouchEvent.y);
        int32_t stylusAction = POINT_MOVE;
        deviceEventType = STYLUS_EVENT;

        GetStandardStylusActionType(curRventType, stylusAction, touchAction);
        stylusEvent->Initialize(windowId, stylusAction, tableTool.button, static_cast<int32_t>(standardTouchEvent.time),
            tableTool.state, 1, fingersInfos, 0, "", tableTool.eventType, static_cast<int32_t>(tableTool.time),
            "", static_cast<int32_t>(tableTool.deviceId),  0, tableTool.deviceType);

        touchEvent.Initialize(windowId, stylusPtr, deviceEventType, touchAction, tableTool.tool.type, 0, 0, 0,
            static_cast<int32_t>(standardTouchEvent.time), standardTouchEvent.buttonState, 1, fingersInfos, true);
    } else if (tableTool.button > 0 && tableTool.button != MOUSE_BTN_LEFT) {
        int32_t stylusAction = GetNonStandardStylusActionType(static_cast<int32_t>(tableTool.state));
        stylusEvent->Initialize(windowId, stylusAction, tableTool.button, static_cast<int32_t>(tableTool.time),
            tableTool.state, 1, fingersInfos, 0, "", tableTool.eventType, static_cast<int32_t>(tableTool.time),
            "", static_cast<int32_t>(tableTool.deviceId),  0, tableTool.deviceType);

        deviceEventType = STYLUS_EVENT;
        touchEvent.Initialize(windowId, stylusPtr, deviceEventType, touchAction, tableTool.tool.type, 0, 0, 0,
            static_cast<int32_t>(tableTool.time), 0, 1, fingersInfos, false);
    } else {
        mmiPoint.Setxy(tableTool.axes.delta.x, tableTool.axes.delta.y);
        int32_t mouseAction = HOVER_MOVE;
        GetMouseActionType(tableTool.eventType, static_cast<int32_t>(tableTool.proximity_state),
            mouseAction, touchAction);
        mouseEvent->Initialize(windowId, mouseAction, 0, tableTool.state, mmiPoint,
            static_cast<float>(tableTool.axes.tilt.x), static_cast<float>(tableTool.axes.tilt.y),
            0, 0, 0, "", tableTool.eventType, static_cast<int32_t>(tableTool.time), "",
            static_cast<int32_t>(tableTool.deviceId), 0, tableTool.deviceType, eventJoyStickAxis);

        deviceEventType = MOUSE_EVENT;
        touchEvent.Initialize(windowId, mousePtr, deviceEventType, touchAction,
            tableTool.tool.type, 0, 0, 0, 0, 0, 1, fingersInfos, false);
    }
    EventManager.OnTouch(touchEvent);
}

void OHOS::MMI::ClientMsgHandler::AnalysisTabletToolEvent(const UDSClient& client, NetPacket& pkt) const
{
    EventTabletTool tableTool = {};
    int32_t curRventType = 0;
    int32_t abilityId = 0;
    int32_t windowId = 0;
    int32_t fd = 0;
    uint64_t serverStartTime = 0;

    pkt >> curRventType >> tableTool >> abilityId >> windowId >> fd >> serverStartTime;
    PrintEventTabletToolInfo(tableTool, serverStartTime, abilityId, windowId, fd);

    // multimodal ANR
    uint64_t clientEndTime = GetSysClockTime();
    ((MMIClient*)&client)->ReplyMessageToServer(pkt.GetMsgId(), tableTool.time, serverStartTime, clientEndTime, fd);

#ifdef OHOS_AUTO_TEST_FRAME
    // Be used by auto-test frame!
    const AutoTestClientPkt autoTestClientTabletToolPkt = {
        "eventTabletTool", 0, 0, 0, 0, "", fd, windowId, abilityId, 0, 0,
        tableTool.deviceType, tableTool.deviceId, tableTool.eventType, 0
    };
    ((MMIClient*)&client)->AutoTestReplyClientPktToServer(autoTestClientTabletToolPkt);
#endif  // OHOS_AUTO_TEST_FRAME

    // 如果是标准化消息，则获取standardTouchEvent
    AnalysisStandardTabletToolEvent(pkt, curRventType, tableTool, windowId);
}
void OHOS::MMI::ClientMsgHandler::AnalysisGestureEvent(const UDSClient& client, NetPacket& pkt) const
{
    EventGesture gesture = {};
    int32_t abilityId = 0;
    int32_t windowId = 0;
    int32_t fd = 0;
    uint64_t serverStartTime = 0;
    EventJoyStickAxis eventJoyStickAxis = {};
    MultimodalEventPtr mousePtr = EventFactory::CreateEvent(EVENT_MOUSE);
    fingerInfos fingersInfos[FINGER_NUM] = {};
    CHK(mousePtr, NULL_POINTER);
    pkt >> gesture >> abilityId >> windowId >> fd >> serverStartTime;
    MMI_LOGT("\nevent dispatcher of client: event Gesture :time=%{public}" PRId64 ";deviceId=%{public}u;"
             "deviceType=%{public}u;deviceName=%{public}s;devNode=%{public}s;eventType=%{public}d;"
             "fingerCount=%{public}d;cancelled=%{public}d;delta.x=%{public}lf;delta.y=%{public}lf;"
             "deltaUnaccel.x=%{public}lf;deltaUnaccel.y=%{public}lf;fd=%{public}d;abilityId=%{public}d;"
             "windowId=%{public}d;preHandlerTime=%{public}" PRId64 ";\n***************************************************\n",
             gesture.time, gesture.deviceId, gesture.deviceType, gesture.deviceName, gesture.devicePhys,
             gesture.eventType, gesture.fingerCount, gesture.cancelled, gesture.delta.x, gesture.delta.y,
             gesture.deltaUnaccel.x, gesture.deltaUnaccel.y, fd, abilityId, windowId, serverStartTime);

    // multimodal ANR
    uint64_t clientEndTime = GetSysClockTime();
    ((MMIClient*)&client)->ReplyMessageToServer(pkt.GetMsgId(), gesture.time, serverStartTime, clientEndTime, fd);

#ifdef OHOS_AUTO_TEST_FRAME
    // Be used by auto-test frame!
    int32_t slot = 0;
    for (auto size = 0; size < MAX_SOLTED_COORDS_NUM; size++) {
        if (gesture.soltTouches.coords[size].isActive) {
            slot = static_cast<int32_t>(size);
        }
    }
    const AutoTestClientPkt autoTestClientGesturePkt = {
        "eventGesture", 0, 0, 0, 0, "", fd, windowId, abilityId, 0, 0,
        gesture.deviceType, gesture.deviceId, gesture.eventType, slot
    };
    ((MMIClient*)&client)->AutoTestReplyClientPktToServer(autoTestClientGesturePkt);
#endif  // OHOS_AUTO_TEST_FRAME

    const MmiPoint mmiPoint(gesture.deltaUnaccel.x, gesture.deltaUnaccel.y);
    auto mouseEvent = reinterpret_cast<MouseEvent*>(mousePtr.GetRefPtr());
    mouseEvent->Initialize(windowId, MOVE, 0, 0, mmiPoint, 0, 0, 0, 0, 0, "", gesture.eventType,
                           static_cast<int32_t>(gesture.time), "", static_cast<int32_t>(gesture.deviceId),
                           false, gesture.deviceType, eventJoyStickAxis);

    int j = 0;
    for (int i = 0; i < FINGER_NUM; i++) {
        if (gesture.soltTouches.coords[i].isActive == true) {
            fingersInfos[j].mPointerId = i;
            fingersInfos[j].mMp.Setxy(gesture.soltTouches.coords[i].x, gesture.soltTouches.coords[i].y);
            j++;
        }
    }
    TouchEvent touchEvent;
    touchEvent.Initialize(windowId, mousePtr, MOUSE_EVENT, POINT_MOVE, 0, 0, 0, 0, 0, 0,
                          gesture.fingerCount, fingersInfos, true);
    EventManager.OnTouch(touchEvent);
}
