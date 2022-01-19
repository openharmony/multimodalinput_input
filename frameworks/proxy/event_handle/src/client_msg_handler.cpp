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
#include <inttypes.h>
#include <iostream>
#include "mmi_func_callback.h"
#include "auto_test_multimodal.h"
#include "bytrace.h"
#include "event_factory.h"
#include "input_device_event.h"
#include "input_event_data_transformation.h"
#include "input_event_monitor_manager.h"
#include "input_filter_manager.h"
#include "input_handler_manager.h"
#include "input_manager_impl.h"
#include "input_monitor_manager.h"
#include "interceptor_manager.h"
#include "keyboard_event.h"
#include "mmi_client.h"
#include "multimodal_event_handler.h"
#include "proto.h"
#include "stylus_event.h"
#include "time_cost_chk.h"
#include "util.h"

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
        {MmiMessageId::ON_KEY, MsgCallbackBind2(&ClientMsgHandler::OnKey, this)},
        {MmiMessageId::ON_KEYEVENT, MsgCallbackBind2(&ClientMsgHandler::OnKeyEvent, this)},
        {MmiMessageId::ON_SUBSCRIBE_KEY, std::bind(&ClientMsgHandler::OnSubscribeKeyEventCallback,
                                                   this, std::placeholders::_1, std::placeholders::_2)},
        {MmiMessageId::ON_KEYMONITOR, MsgCallbackBind2(&ClientMsgHandler::OnKeyMonitor, this)},
        {MmiMessageId::ON_POINTER_EVENT, MsgCallbackBind2(&ClientMsgHandler::OnPointerEvent, this)},
        {MmiMessageId::ON_TOUCH, MsgCallbackBind2(&ClientMsgHandler::OnTouch, this)},
        {MmiMessageId::ON_TOUCHPAD_MONITOR, MsgCallbackBind2(&ClientMsgHandler::OnTouchPadMonitor, this)},
        {MmiMessageId::ON_COPY, MsgCallbackBind2(&ClientMsgHandler::OnCopy, this)},
        {MmiMessageId::ON_SHOW_MENU, MsgCallbackBind2(&ClientMsgHandler::OnShowMenu, this)},
        {MmiMessageId::ON_SEND, MsgCallbackBind2(&ClientMsgHandler::OnSend, this)},
        {MmiMessageId::ON_PASTE, MsgCallbackBind2(&ClientMsgHandler::OnPaste, this)},
        {MmiMessageId::ON_CUT, MsgCallbackBind2(&ClientMsgHandler::OnCut, this)},
        {MmiMessageId::ON_UNDO, MsgCallbackBind2(&ClientMsgHandler::OnUndo, this)},
        {MmiMessageId::ON_REFRESH, MsgCallbackBind2(&ClientMsgHandler::OnRefresh, this)},
        {MmiMessageId::ON_START_DRAG, MsgCallbackBind2(&ClientMsgHandler::OnStartDrag, this)},
        {MmiMessageId::ON_CANCEL, MsgCallbackBind2(&ClientMsgHandler::OnCancel, this)},
        {MmiMessageId::ON_ENTER, MsgCallbackBind2(&ClientMsgHandler::OnEnter, this)},
        {MmiMessageId::ON_PREVIOUS, MsgCallbackBind2(&ClientMsgHandler::OnPrevious, this)},
        {MmiMessageId::ON_NEXT, MsgCallbackBind2(&ClientMsgHandler::OnNext, this)},
        {MmiMessageId::ON_BACK, MsgCallbackBind2(&ClientMsgHandler::OnBack, this)},
        {MmiMessageId::ON_PRINT, MsgCallbackBind2(&ClientMsgHandler::OnPrint, this)},
        {MmiMessageId::ON_PLAY, MsgCallbackBind2(&ClientMsgHandler::OnPlay, this)},
        {MmiMessageId::ON_PAUSE, MsgCallbackBind2(&ClientMsgHandler::OnPause, this)},
        {MmiMessageId::ON_MEDIA_CONTROL, MsgCallbackBind2(&ClientMsgHandler::OnMediaControl, this)},
        {MmiMessageId::ON_SCREEN_SHOT, MsgCallbackBind2(&ClientMsgHandler::OnScreenShot, this)},
        {MmiMessageId::ON_SCREEN_SPLIT, MsgCallbackBind2(&ClientMsgHandler::OnScreenSplit, this)},
        {MmiMessageId::ON_START_SCREEN_RECORD, MsgCallbackBind2(&ClientMsgHandler::OnStartScreenRecord, this)},
        {MmiMessageId::ON_STOP_SCREEN_RECORD, MsgCallbackBind2(&ClientMsgHandler::OnStopScreenRecord, this)},
        {MmiMessageId::ON_GOTO_DESKTOP, MsgCallbackBind2(&ClientMsgHandler::OnGotoDesktop, this)},
        {MmiMessageId::ON_RECENT, MsgCallbackBind2(&ClientMsgHandler::OnRecent, this)},
        {MmiMessageId::ON_SHOW_NOTIFICATION, MsgCallbackBind2(&ClientMsgHandler::OnShowNotification, this)},
        {MmiMessageId::ON_LOCK_SCREEN, MsgCallbackBind2(&ClientMsgHandler::OnLockScreen, this)},
        {MmiMessageId::ON_SEARCH, MsgCallbackBind2(&ClientMsgHandler::OnSearch, this)},
        {MmiMessageId::ON_CLOSE_PAGE, MsgCallbackBind2(&ClientMsgHandler::OnClosePage, this)},
        {MmiMessageId::ON_LAUNCH_VOICE_ASSISTANT, MsgCallbackBind2(&ClientMsgHandler::OnLaunchVoiceAssistant, this)},
        {MmiMessageId::ON_MUTE, MsgCallbackBind2(&ClientMsgHandler::OnMute, this)},
        {MmiMessageId::ON_ANSWER, MsgCallbackBind2(&ClientMsgHandler::OnAnswer, this)},
        {MmiMessageId::ON_REFUSE, MsgCallbackBind2(&ClientMsgHandler::OnRefuse, this)},
        {MmiMessageId::ON_HANG_UP, MsgCallbackBind2(&ClientMsgHandler::OnHangup, this)},
        {MmiMessageId::ON_TELEPHONE_CONTROL, MsgCallbackBind2(&ClientMsgHandler::OnTelephoneControl, this)},
        {MmiMessageId::GET_MMI_INFO_ACK, MsgCallbackBind2(&ClientMsgHandler::GetMultimodeInputInfo, this)},
        {MmiMessageId::ON_DEVICE_ADDED, MsgCallbackBind2(&ClientMsgHandler::DeviceAdd, this)},
        {MmiMessageId::ON_DEVICE_REMOVED, MsgCallbackBind2(&ClientMsgHandler::DeviceRemove, this)},
        {MmiMessageId::KEY_EVENT_INTERCEPTOR, MsgCallbackBind2(&ClientMsgHandler::KeyEventFilter, this)},
        {MmiMessageId::TOUCH_EVENT_INTERCEPTOR, MsgCallbackBind2(&ClientMsgHandler::TouchEventFilter, this)},
        {MmiMessageId::INPUT_DEVICE_INFO, MsgCallbackBind2(&ClientMsgHandler::OnInputDevice, this)},
        {MmiMessageId::INPUT_DEVICE_ID_LIST, MsgCallbackBind2(&ClientMsgHandler::OnInputDeviceIds, this)},
        {MmiMessageId::POINTER_EVENT_INTERCEPTOR, MsgCallbackBind2(&ClientMsgHandler::PointerEventInterceptor, this)},
        {MmiMessageId::REPORT_KEY_EVENT, MsgCallbackBind2(&ClientMsgHandler::ReportKeyEvent, this)},
        {MmiMessageId::REPORT_POINTER_EVENT, MsgCallbackBind2(&ClientMsgHandler::ReportPointerEvent, this)},
        {MmiMessageId::TOUCHPAD_EVENT_INTERCEPTOR, MsgCallbackBind2(&ClientMsgHandler::TouchpadEventInterceptor, this)},
        {MmiMessageId::KEYBOARD_EVENT_INTERCEPTOR, MsgCallbackBind2(&ClientMsgHandler::KeyEventInterceptor, this)}, 
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
    
    uint64_t clientTime = GetSysClockTime();
    auto ret = (*fun)(client, pkt);
    if (ret < 0) {
        MMI_LOGE("CClientMsgHandler::OnMsgHandler Msg handling failed. id[%{public}d] ret[%{public}d]", id, ret);
        return;
    }
    uint64_t endTime = GetSysClockTime();
    ((MMIClient *)&client)->ReplyMessageToServer(pkt.GetMsgId(), clientTime, endTime);
}

int32_t OHOS::MMI::ClientMsgHandler::OnKeyMonitor(const UDSClient& client, NetPacket& pkt)
{
    auto key = OHOS::MMI::KeyEvent::Create();
    int32_t ret = InputEventDataTransformation::NetPacketToKeyEvent(fSkipId, key, pkt);
    if (ret != RET_OK) {
        MMI_LOGE("OnKeyMonitor read netPacket failed");
        return RET_ERR;
    }
    int32_t pid = 0;
    pkt >> pid;
    MMI_LOGD("client receive the msg from server: keyCode = %{public}d, pid = %{public}d", key->GetKeyCode(), pid);
    return IEMManager.OnMonitorInputEvent(key);
}

int32_t OHOS::MMI::ClientMsgHandler::OnKeyEvent(const UDSClient& client, NetPacket& pkt)
{
    int32_t fd = 0;
    uint64_t serverStartTime = 0;
    auto key = OHOS::MMI::KeyEvent::Create();
    int32_t ret = InputEventDataTransformation::NetPacketToKeyEvent(fSkipId, key, pkt);
    if (ret != RET_OK) {
        MMI_LOGE("read netPacket failed");
        return RET_ERR;
    }
    pkt >> fd >> serverStartTime;
    MMI_LOGT("\n4.event dispatcher of clien:\nKeyEvent:KeyCode = %{public}d,"
             "ActionTime = %{public}d,Action = %{public}d,ActionStartTime = %{public}d,"
             "EventType = %{public}d,Flag = %{public}d,"
             "KeyAction = %{public}d,Fd = %{public}d,ServerStartTime = %{public}" PRId64"\n",
             key->GetKeyCode(), key->GetActionTime(), key->GetAction(),
             key->GetActionStartTime(), key->GetEventType(),
             key->GetFlag(), key->GetKeyAction(), fd, serverStartTime);
    int32_t getKeyCode = key->GetKeyCode();
    std::string keyCodestring = std::to_string(getKeyCode);
    MMI_LOGT(" OnKeyEvent client trace keyId = %{public}s\n", keyCodestring.c_str());
    int32_t EVENT_KEY = 1;
    FinishAsyncTrace(BYTRACE_TAG_MULTIMODALINPUT, keyCodestring, EVENT_KEY);
    
    key->SetProcessedCallback([&client, &key]() {
        NetPacket ckt(MmiMessageId::NEW_CHECK_REPLY_MESSAGE);
        auto id = key->GetId();
        ckt << id;
        client.SendMsg(ckt);
    });

    InputManagerImpl::GetInstance()->OnKeyEvent(key);
    return RET_OK;
}

int32_t OHOS::MMI::ClientMsgHandler::OnPointerEvent(const UDSClient& client, NetPacket& pkt)
{
    auto pointerEvent { OHOS::MMI::PointerEvent::Create() };
    if (InputEventDataTransformation::DeserializePointerEvent(false, pointerEvent, pkt) != ERR_OK) {
        MMI_LOGE("Failed to deserialize pointer event.");
        return RET_ERR;
    }

    std::vector<int32_t> pointerIds { pointerEvent->GetPointersIdList() };
    MMI_LOGD("pointer event dispatcher of client:");
    MMI_LOGD("eventType=%{public}d,actionTime=%{public}d,"
             "action=%{public}d,actionStartTime=%{public}d,"
             "flag=%{public}d,pointerAction=%{public}d,sourceType=%{public}d,"
             "VerticalAxisValue=%{public}.2f,HorizontalAxisValue=%{public}.2f,"
             "pointerCount=%{public}d",
             pointerEvent->GetEventType(), pointerEvent->GetActionTime(),
             pointerEvent->GetAction(), pointerEvent->GetActionStartTime(),
             pointerEvent->GetFlag(), pointerEvent->GetPointerAction(),
             pointerEvent->GetSourceType(),
             pointerEvent->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL),
             pointerEvent->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL),
             static_cast<int32_t>(pointerIds.size()));
    std::vector<int32_t> pressedKeys = pointerEvent->GetPressedKeys();
    if (pressedKeys.empty()) {
        MMI_LOGI("Pressed keys is empty");
    } else {
        for (int32_t keyCode : pressedKeys) {
            MMI_LOGI("Pressed keyCode=%{public}d", keyCode);
        }
    }
    for (int32_t pointerId : pointerIds) {
        OHOS::MMI::PointerEvent::PointerItem item;
        CHKR(pointerEvent->GetPointerItem(pointerId, item), PARAM_INPUT_FAIL, RET_ERR);

        MMI_LOGD("downTime=%{public}d,isPressed=%{public}s,"
                "globalX=%{public}d,globalY=%{public}d,localX=%{public}d,localY=%{public}d,"
                "width=%{public}d,height=%{public}d,pressure=%{public}d",
                 item.GetDownTime(), (item.IsPressed() ? "true" : "false"),
                 item.GetGlobalX(), item.GetGlobalY(), item.GetLocalX(), item.GetLocalY(),
                 item.GetWidth(), item.GetHeight(), item.GetPressure());
    }
    if (PointerEvent::POINTER_ACTION_CANCEL == pointerEvent->GetPointerAction()) {
        MMI_LOGD("Operation canceled.");
    }

    pointerEvent->SetProcessedCallback([&client, &pointerEvent]() {
        NetPacket ckt(MmiMessageId::NEW_CHECK_REPLY_MESSAGE);
        auto id = pointerEvent->GetId();
        ckt << id;
        client.SendMsg(ckt);
    });

    InputManagerImpl::GetInstance()->OnPointerEvent(pointerEvent);
    return RET_OK;
}

int32_t OHOS::MMI::ClientMsgHandler::OnSubscribeKeyEventCallback(const UDSClient &client, NetPacket &pkt)
{
    std::shared_ptr<KeyEvent> keyEvent = OHOS::MMI::KeyEvent::Create();
    int32_t ret = InputEventDataTransformation::NetPacketToKeyEvent(fSkipId, keyEvent, pkt);
    if (ret != RET_OK) {
        MMI_LOGE("read net packet failed");
        return RET_ERR;
    }
    int32_t fd = -1;
    int32_t subscribeId = -1;
    pkt >> fd >> subscribeId;
    MMI_LOGD("SubscribeId=%{public}d,Fd=%{public}d,KeyEventId=%{public}d,"
             "KeyCode=%{public}d,ActionTime=%{public}d,ActionStartTime=%{public}d,Action=%{public}d,"
             "KeyAction=%{public}d,EventType=%{public}d,Flag=%{public}d",
        subscribeId, fd, keyEvent->GetId(), keyEvent->GetKeyCode(), keyEvent->GetActionTime(),
        keyEvent->GetActionStartTime(), keyEvent->GetAction(), keyEvent->GetKeyAction(),
        keyEvent->GetEventType(), keyEvent->GetFlag());
    return KeyEventInputSubscribeMgr.OnSubscribeKeyEventCallback(keyEvent, subscribeId);
}

int32_t OHOS::MMI::ClientMsgHandler::OnTouchPadMonitor(const UDSClient& client, NetPacket& pkt)
{
    auto pointer = OHOS::MMI::PointerEvent::Create();
    int32_t ret = InputEventDataTransformation::DeserializePointerEvent(false, pointer, pkt);
    if (ret != RET_OK) {
        MMI_LOGE("OnTouchPadMonitor read netPacket failed");
        return RET_ERR;
    }
    int32_t pid = 0;
    pkt >> pid;
    MMI_LOGD("client receive the msg from server: EventType = %{public}d, pid = %{public}d",
        pointer->GetEventType(), pid);
    return IEMManager.OnTouchpadMonitorInputEvent(pointer);
}

int32_t OHOS::MMI::ClientMsgHandler::OnKey(const UDSClient& client, NetPacket& pkt)
{
    int32_t abilityId = 0;
    int32_t windowId = 0;
    int32_t fd = 0;
    uint64_t serverStartTime = 0;
    EventKeyboard key = {};
    pkt >> key >> abilityId >> windowId >> fd >> serverStartTime;
    MMI_LOGT("Event dispatcher of client:eventKeyboard:time=%{public}" PRId64 ", key=%{public}u, "
             "deviceType=%{public}u, seat_key_count=%{public}u, state=%{public}d, fd=%{public}d",
             key.time, key.key, key.deviceType, key.seat_key_count, key.state, fd);

    /* 根据收到的key，构造keyBoardEvent对象，
    *  其中KeyBoardEvent对象的    handledByIme,unicode,isSingleNonCharacter,isTwoNonCharacters,isThreeNonCharacters五个字段
    *  和KeyEvent对象的keyDownDuration一个字段
    *  和MultimodalEvent对象的highLevelEvent, deviceId, isHighLevelEvent三个字段缺失，暂时填0
    */
    KeyBoardEvent event;
    int32_t deviceEventType = KEY_EVENT;
    event.Initialize(windowId, 0, 0, 0, 0, 0, key.state, key.key, 0, 0, key.uuid, key.eventType,
                     key.time, "", static_cast<int32_t>(key.deviceId), 0, key.deviceType,
                     deviceEventType, key.isIntercepted);
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
                 "Msg=%{public}d,fd=%{public}d,"
                 "occurredTime=%{public}d;\n\n"
                 "************************************************************************\n",
                 idMsg, fd, occurredTime);
        if (type == INPUT_DEVICE_CAP_KNUCKLE) {
            type = HOS_KNUCKLE;
        } else if (type == INPUT_DEVICE_CAP_AISENSOR) {
            type = HOS_AI_SPEECH;
        }
        multEvent.Initialize(windowId, 0, uuid, type, occurredTime, "", deviceId, 0, 0);
    } else {
        pkt >> data >> fd >> windowId >> abilityId >> serverStartTime;
        if (windowId == -1) {
            MMI_LOGT("\nevent dispatcher of client:\n occurredTime=%{public}" PRId64 ";\nsourceType=%{public}d;\n"
                     "\nfd=%{public}d;\n"
                     "\n************************************************************************\n",
                     data.occurredTime, data.eventType, fd);
        } else {
            MMI_LOGT("\nevent dispatcher of client:\n occurredTime=%{public}" PRId64 ";\nsourceType=%{public}d;\n"
                     "\nfd=%{public}d;"
                     "\n**************************************************************\n",
                     data.occurredTime, data.eventType, fd);
        }
        multEvent.Initialize(windowId, 0, data.uuid, data.eventType, data.occurredTime, "", data.deviceId, 0,
            data.deviceType);
    }

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

int32_t OHOS::MMI::ClientMsgHandler::OnInputDeviceIds(const UDSClient& client, NetPacket& pkt)
{
    MMI_LOGT("ClientMsgHandler::OnInputDeviceIds enter");
    int32_t taskId;
    int32_t size = 0;
    std::vector<int32_t> inputDeviceIds;
    CHKR(pkt.Read(taskId), STREAM_BUF_READ_FAIL, RET_ERR);
    CHKR(pkt.Read(size), STREAM_BUF_READ_FAIL, RET_ERR);
    for (int32_t i = 0; i < size; i++) {
        int32_t deviceId = 0;
        CHKR(pkt.Read(deviceId), STREAM_BUF_READ_FAIL, RET_ERR);
        inputDeviceIds.push_back(deviceId);
    }
    auto& instance = InputDeviceEvent::GetInstance();
    instance.OnInputDeviceIds(taskId, inputDeviceIds);
    return RET_OK;
}

int32_t OHOS::MMI::ClientMsgHandler::OnInputDevice(const UDSClient& client, NetPacket& pkt)
{
    MMI_LOGT("ClientMsgHandler::OnInputDevice enter");
    int32_t taskId;
    int32_t id;
    std::string name;
    int32_t deviceType;
    CHKR(pkt.Read(taskId), STREAM_BUF_READ_FAIL, RET_ERR);
    CHKR(pkt.Read(id), STREAM_BUF_READ_FAIL, RET_ERR);
    CHKR(pkt.Read(name), STREAM_BUF_READ_FAIL, RET_ERR);
    CHKR(pkt.Read(deviceType), STREAM_BUF_READ_FAIL, RET_ERR);

    auto& instance = InputDeviceEvent::GetInstance();
    instance.OnInputDevice(taskId, id, name, deviceType);
    return RET_OK;
}

int32_t OHOS::MMI::ClientMsgHandler::KeyEventFilter(const UDSClient& client, NetPacket& pkt)
{
    EventKeyboard key = {};
    int32_t windowId = 0;
    int32_t id = 0;
    pkt >> key >>id;
    MMI_LOGT("\nkey event filter : event dispatcher of client:\neventKeyboard:time=%{public}" PRId64
        ";key=%{public}u;deviceId=%{private}u;"
        "deviceType=%{public}u;seat_key_count=%{public}u;state=%{public}d;\n",
        key.time, key.key, key.deviceId, key.deviceType, key.seat_key_count, key.state);
    TraceKeyEvent(key);
    KeyBoardEvent event;
    int32_t deviceEventType = KEY_EVENT;
    event.Initialize(windowId, 0, 0, 0, 0, 0, key.state, key.key, 0, 0, key.uuid, key.eventType,
                     key.time, "", static_cast<int32_t>(key.deviceId), 0, key.deviceType, deviceEventType);
    return inputFilterManager.OnKeyEvent(event, id);
}

int32_t OHOS::MMI::ClientMsgHandler::TouchEventFilter(const UDSClient& client, NetPacket& pkt)
{
    MMI_LOGD("ClientMsgHandler::TouchEventFilter");
    int32_t id = 0;
    int32_t abilityId = 0;
    int32_t windowId = 0;
    int32_t fd = 0;
    int32_t fingerCount = 0;
    int32_t eventAction = 0;
    uint64_t serverStartTime = 0;
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

    MMI_LOGT("\nevent filter of client:\neventTouch:time=%{public}" PRId64 ";"
             "deviceType=%{public}u;eventType=%{public}d;slot=%{public}d;seat_slot=%{public}d;"
             "fd=%{public}d"
             "\n************************************************************************\n",
        touchData.time, touchData.deviceType, touchData.eventType, touchData.slot,
        touchData.seat_slot, fd);
    TraceTouchEvent(touchData);

    TouchEvent event;
    int32_t deviceEventType = TOUCH_EVENT;
    int32_t fingerIndex = 0;
    if (PRIMARY_POINT_DOWN == eventAction || PRIMARY_POINT_UP == eventAction ||
        OTHER_POINT_DOWN == eventAction || OTHER_POINT_UP == eventAction) {
        fingerIndex = fingersInfos[0].mPointerId;
    }
    event.Initialize(windowId, eventAction, fingerIndex, 0, 0, 0, 0, 0, fingerCount, fingersInfos, 0,
        touchData.uuid, touchData.eventType, static_cast<int32_t>(touchData.time), "",
        static_cast<int32_t>(touchData.deviceId), 0, false, touchData.deviceType, deviceEventType);

    pkt >> id;
    return inputFilterManager.OnTouchEvent(event, id);
}

int32_t OHOS::MMI::ClientMsgHandler::PointerEventInterceptor(const UDSClient& client, NetPacket& pkt)
{
    EventPointer pointData = {};
    EventJoyStickAxis eventJoyStickAxis = {};
    int32_t windowId = 0;
    int32_t id = 0;
    pkt >> pointData >> id;
    int32_t action = pointData.state;
    MmiPoint mmiPoint;
    mmiPoint.Setxy(pointData.delta.x, pointData.delta.y);
    MMI_LOGT("WangYuan\nevent dispatcher of client: mouse_data \neventPointer:time=%{public}" PRId64 ";"
             "eventType=%{public}d;buttonCode=%{public}u;deviceType=%{public}u;"
             "seat_button_count=%{public}u;axes=%{public}u;buttonState=%{public}d;source=%{public}d;"
             "delta.x=%{public}lf;delta.y=%{public}lf;delta_raw.x=%{public}lf;delta_raw.y=%{public}lf;"
             "absolute.x=%{public}lf;absolute.y=%{public}lf;discYe.x=%{public}lf;discrete.y=%{public}lf.\n",
             pointData.time, pointData.eventType, pointData.button, pointData.deviceType,
             pointData.seat_button_count, pointData.axes, pointData.state, pointData.source, pointData.delta.x,
             pointData.delta.y, pointData.delta_raw.x, pointData.delta_raw.y, pointData.absolute.x,
             pointData.absolute.y, pointData.discrete.x, pointData.discrete.y);
    TracePointerEvent(pointData);
    MouseEvent mouse_event;
    mouse_event.Initialize(windowId, action, pointData.button, pointData.state, mmiPoint,
        static_cast<float>(pointData.discrete.x), static_cast<float>(pointData.discrete.y),
        0, 0, 0, pointData.uuid, pointData.eventType, static_cast<int32_t>(pointData.time),
        "", static_cast<int32_t>(pointData.deviceId), 0, pointData.deviceType, eventJoyStickAxis);
    return (inputFilterManager.OnPointerEvent(mouse_event, id));
}

int32_t OHOS::MMI::ClientMsgHandler::ReportKeyEvent(const UDSClient& client, NetPacket& pkt)
{
    int32_t handlerId { };
    InputHandlerType handlerType { };
    pkt >> handlerId >> handlerType;

    auto keyEvent = OHOS::MMI::KeyEvent::Create();
    if (InputEventDataTransformation::NetPacketToKeyEvent(fSkipId, keyEvent, pkt) != ERR_OK) {
        MMI_LOGE("Failed to deserialize key event.");
        return RET_ERR;
    }
    InputHandlerManager::GetInstance().OnInputEvent(handlerId, keyEvent);
    return RET_OK;
}

int32_t OHOS::MMI::ClientMsgHandler::ReportPointerEvent(const UDSClient& client, NetPacket& pkt)
{
    MMI_LOGD("Client ReportPointerEventd in");
    int32_t handlerId { };
    InputHandlerType handlerType { };
    pkt >> handlerId >> handlerType;
    MMI_LOGD("Client handlerId : %{public}d handlerType : %{public}d", handlerId, handlerType); 

    auto pointerEvent { OHOS::MMI::PointerEvent::Create() };
    if (InputEventDataTransformation::DeserializePointerEvent(false, pointerEvent, pkt) != ERR_OK) {
        MMI_LOGE("Failed to deserialize pointer event...");
        return RET_ERR;
    }
    InputHandlerManager::GetInstance().OnInputEvent(handlerId, pointerEvent); 
    return RET_OK;
}

int32_t OHOS::MMI::ClientMsgHandler::TouchpadEventInterceptor(const UDSClient& client, NetPacket& pkt)
{
    auto pointerEvent = OHOS::MMI::PointerEvent::Create();
    int32_t ret = InputEventDataTransformation::DeserializePointerEvent(false, pointerEvent, pkt);
    if (ret != RET_OK) {
        MMI_LOGE("TouchpadEventInterceptor read netPacket failed");
        return RET_ERR;
    }
    int32_t pid = 0;
    int32_t id = 0;
    pkt >> pid >> id;
    MMI_LOGD("client receive the msg from server: pointId = %{public}d, pid = %{public}d\n",
             pointerEvent->GetPointerId(), pid);
    return INTERCEPTORMANAGER.OnPointerEvent(pointerEvent, id);
}

int32_t OHOS::MMI::ClientMsgHandler::KeyEventInterceptor(const UDSClient& client, NetPacket& pkt)
{
    auto keyEvent = OHOS::MMI::KeyEvent::Create();
    int32_t ret = InputEventDataTransformation::NetPacketToKeyEvent(fSkipId, keyEvent, pkt);
    if (ret != RET_OK) {
        MMI_LOGE("TouchpadEventInterceptor read netPacket failed");
        return RET_ERR;
    }
    int32_t pid = 0;
    pkt >> pid;
    MMI_LOGD("client receive the msg from server: keyCode = %{public}d, pid = %{public}d\n",
        keyEvent->GetKeyCode(), pid);
    return INTERCEPTORMANAGER.OnKeyEvent(keyEvent);
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
    MultimodalEventPtr mousePtr = EventFactory::CreateEvent(EventType::EVENT_MOUSE);
    CHK(mousePtr, ERROR_NULL_POINTER);
    pkt >> ret >> pointData >> abilityId >> windowId >> fd >> serverStartTime;
    MMI_LOGT("\nevent dispatcher of client: mouse_data \neventPointer:time=%{public}" PRId64 "; eventType=%{public}d;"
             "buttonCode=%{public}u;deviceType=%{public}u;seat_button_count=%{public}u;"
             "axes=%{public}u;buttonState=%{public}d;source=%{public}d;delta.x=%{public}lf;delta.y=%{public}lf;"
             "delta_raw.x=%{public}lf;delta_raw.y=%{public}lf;absolute.x=%{public}lf;absolute.y=%{public}lf;"
             "discYe.x=%{public}lf;discrete.y=%{public}lf;fd=%{public}d;\n",
             pointData.time, pointData.eventType, pointData.button, pointData.deviceType,
             pointData.seat_button_count, pointData.axes, pointData.state, pointData.source, pointData.delta.x,
             pointData.delta.y, pointData.delta_raw.x, pointData.delta_raw.y, pointData.absolute.x,
             pointData.absolute.y, pointData.discrete.x, pointData.discrete.y, fd);
    TracePointerEvent(pointData);
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
    int32_t seatSlot = 0;
    uint64_t serverStartTime = 0;
    EventTouch touchData = {};
    MmiPoint mmiPoint;
    pkt >> fingerCount >> eventAction >> abilityId >> windowId >> fd >> serverStartTime >> seatSlot;

    fingerInfos fingersInfos[FINGER_NUM] = {};
    /* 根据收到的touchData，构造TouchEvent对象
    *  其中TouchEvent对象的action,index,forcePrecision,maxForce,tapCount五个字段
    *  和ManipulationEvent对象的startTime,operationState,pointerCount,pointerId，  touchArea，touchPressure六个字段，
    *  和MultimodalEvent对象的highLevelEvent, deviceId, isHighLevelEvent三个字段缺失，暂时填0
    */
    for (int i = 0; i < fingerCount; i++) {
        pkt >> touchData;
        fingersInfos[i].mPointerId = touchData.seat_slot;
        fingersInfos[i].mTouchArea = static_cast<float>(touchData.area);
        fingersInfos[i].mTouchPressure = static_cast<float>(touchData.pressure);
        fingersInfos[i].mMp.Setxy(touchData.point.x, touchData.point.y);
        MMI_LOGT("\nevent dispatcher of client:\neventTouch:time=%{public}" PRId64 ";"
                 "deviceType=%{public}u;eventType=%{public}d;slot=%{public}d;seat_slot=%{public}d;"
                 "fd=%{public}d;point.x=%{public}lf;point.y=%{public}lf"
                 "\n************************************************************************\n",
                 touchData.time, touchData.deviceType, touchData.eventType, touchData.slot,
                 touchData.seat_slot, fd, touchData.point.x, touchData.point.y);
    }
    TraceTouchEvent(touchData);
    TouchEvent touchEvent;
    int32_t deviceEventType = TOUCH_EVENT;
    touchEvent.Initialize(windowId, eventAction, seatSlot, 0, 0, 0, 0, 0, fingerCount, fingersInfos, 0,
        touchData.uuid, touchData.eventType, static_cast<int32_t>(touchData.time), "",
        static_cast<int32_t>(touchData.deviceId), 0, false, touchData.deviceType, deviceEventType);

    EventManager.OnTouch(touchEvent);
}

void OHOS::MMI::ClientMsgHandler::AnalysisJoystickEvent(const UDSClient& client, NetPacket& pkt) const
{
    EventJoyStickAxis eventJoyStickData = {};
    int32_t abilityId = 0;
    int32_t windowId = 0;
    int32_t fd = 0;
    int32_t touchAction = 0;
    int32_t deviceEventType = 0;
    std::string nullUUid = "";
    uint64_t serverStartTime = 0;
    MmiPoint mmiPoint;
    MultimodalEventPtr mousePtr = EventFactory::CreateEvent(EventType::EVENT_MOUSE);
    CHK(mousePtr, ERROR_NULL_POINTER);
    pkt >> eventJoyStickData >> abilityId >> windowId >> fd >> serverStartTime;
    MMI_LOGT("\nevent dispatcher of client: "
        "event JoyStick: fd: %{public}d\n", fd);
    PrintEventJoyStickAxisInfo(eventJoyStickData, fd, abilityId, windowId, serverStartTime);

    int32_t mouseAction = static_cast<int32_t>(MouseActionEnum::HOVER_MOVE);
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
    int32_t touchAction = 0;
    int32_t deviceEventType = 0;
    MmiPoint mmiPoint;
    std::string nullUUid = "";
    EventJoyStickAxis eventJoyStickAxis = {};
    MultimodalEventPtr mousePtr = EventFactory::CreateEvent(EventType::EVENT_MOUSE);
    CHK(mousePtr, ERROR_NULL_POINTER);
    pkt >> tabletPad >> abilityId >> windowId >> fd >> serverStartTime;
    MMI_LOGT("\nevent dispatcher of client: event tablet Pad :time=%{public}" PRId64 ";deviceType=%{public}u;"
             "deviceName=%{public}s;eventType=%{public}d;\n"
             "ring.number=%{public}d;ring.position=%{public}lf;ring.source=%{public}d;\n"
             "strip.number=%{public}d;strip.position=%{public}lf;strip.source=%{public}d;\n"
             "fd=%{public}d;preHandlerTime=%{public}" PRId64 ";\n*"
             "***********************************************************************\n",
             tabletPad.time, tabletPad.deviceType, tabletPad.deviceName, tabletPad.eventType,
             tabletPad.ring.number, tabletPad.ring.position, tabletPad.ring.source, tabletPad.strip.number,
             tabletPad.strip.position, tabletPad.strip.source, fd, serverStartTime);

    // multimodal ANR

    int32_t mouseAction = static_cast<int32_t>(MouseActionEnum::HOVER_MOVE);
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
             "deviceName=%{public}s; eventType=%{public}d; type=%{public}u;"
             "serial=%{public}u; button=%{public}d; "
             "state=%{public}d; point.x=%{public}lf; point.y=%{public}lf; tilt.x=%{public}lf;"
             "tilt.y=%{public}lf; distance=%{public}lf; pressure=%{public}lf; "
             "rotation=%{public}lf; slider=%{public}lf; wheel=%{public}lf; wheel_discrete=%{public}d;"
             "size.major=%{public}lf; size.minor=%{public}lf; "
             "proximity_state=%{public}d; tip_state=%{public}d; state=%{public}d; seat_button_count=%{public}d;"
             "fd=%{public}d; preHandlerTime=%{public}" PRId64 ";\n"
             "***********************************************************************\n",
             tableTool.time, tableTool.deviceType, tableTool.deviceName,
             tableTool.eventType, tableTool.tool.type, tableTool.tool.serial,
             tableTool.button, tableTool.state, tableTool.axes.point.x, tableTool.axes.point.y,
             tableTool.axes.tilt.x, tableTool.axes.tilt.y, tableTool.axes.distance, tableTool.axes.pressure,
             tableTool.axes.rotation, tableTool.axes.slider, tableTool.axes.wheel,
             tableTool.axes.wheel_discrete, tableTool.axes.size.major, tableTool.axes.size.minor,
             tableTool.proximity_state, tableTool.tip_state, tableTool.state, tableTool.seat_button_count,
             fd, serverStartTime);
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
            mouseAction = static_cast<int32_t>(MouseActionEnum::HOVER_ENTER);
            touchAction = HOVER_POINTER_ENTER;
        } else if (TABLET_TOOL_PROXIMITY_STATE_OUT == proximityState) {
            mouseAction = static_cast<int32_t>(MouseActionEnum::HOVER_EXIT);
            touchAction = HOVER_POINTER_EXIT;
        } else {
            mouseAction = static_cast<int32_t>(MouseActionEnum::HOVER_MOVE);
            touchAction = HOVER_POINTER_MOVE;
        }
    }
}

void OHOS::MMI::ClientMsgHandler::AnalysisStandardTabletToolEvent(NetPacket& pkt, int32_t curRventType,
                                                                  EventTabletTool tableTool, int32_t windowId) const
{
    const int32_t MOUSE_BTN_LEFT = 0x110;       // left button
    int32_t deviceEventType = 0;
    int32_t touchAction = static_cast<int32_t>(MouseActionEnum::MMNONE);
    EventJoyStickAxis eventJoyStickAxis = {};
    MmiPoint mmiPoint;
    auto mousePtr = EventFactory::CreateEvent(EventType::EVENT_MOUSE);
    CHK(mousePtr, ERROR_NULL_POINTER);
    auto mouseEvent = reinterpret_cast<MouseEvent*>(mousePtr.GetRefPtr());
    auto stylusPtr = EventFactory::CreateEvent(EventType::EVENT_STYLUS);
    CHK(stylusPtr, ERROR_NULL_POINTER);
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
        int32_t mouseAction = static_cast<int32_t>(MouseActionEnum::HOVER_MOVE);
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
    MultimodalEventPtr mousePtr = EventFactory::CreateEvent(EventType::EVENT_MOUSE);
    fingerInfos fingersInfos[FINGER_NUM] = {};
    CHK(mousePtr, ERROR_NULL_POINTER);
    pkt >> gesture >> abilityId >> windowId >> fd >> serverStartTime;
    MMI_LOGT("\nevent dispatcher of client: event Gesture :time=%{public}" PRId64 ";"
             "deviceType=%{public}u;deviceName=%{public}s;devNode=%{public}s;eventType=%{public}d;"
             "fingerCount=%{public}d;cancelled=%{public}d;delta.x=%{public}lf;delta.y=%{public}lf;"
             "deltaUnaccel.x=%{public}lf;deltaUnaccel.y=%{public}lf;fd=%{public}d;"
             "preHandlerTime=%{public}" PRId64 ";\n***************************************************\n",
             gesture.time, gesture.deviceType, gesture.deviceName, gesture.devicePhys,
             gesture.eventType, gesture.fingerCount, gesture.cancelled, gesture.delta.x, gesture.delta.y,
             gesture.deltaUnaccel.x, gesture.deltaUnaccel.y, fd, serverStartTime);

    const MmiPoint mmiPoint(gesture.deltaUnaccel.x, gesture.deltaUnaccel.y);
    auto mouseEvent = reinterpret_cast<MouseEvent*>(mousePtr.GetRefPtr());
    mouseEvent->Initialize(windowId, static_cast<int32_t>(MouseActionEnum::MOVE), 0, 0, mmiPoint, 0, 0, 0, 0, 0, "", gesture.eventType,
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

void OHOS::MMI::ClientMsgHandler::TraceKeyEvent(const EventKeyboard& key) const
{
    int32_t EVENT_KEY = 1;
    char keyUuid[MAX_UUIDSIZE] = {0};
    if (EOK != memcpy_s(keyUuid, sizeof(keyUuid), key.uuid, sizeof(key.uuid))) {
        MMI_LOGT("%{public}s copy data failed", __func__);
        return;
    }
    MMI_LOGT("\n nevent dispatcher of client: keyUuid = %{public}s\n", keyUuid);
    std::string keyEvent = keyUuid;
    FinishAsyncTrace(BYTRACE_TAG_MULTIMODALINPUT, keyEvent, EVENT_KEY);
}

void OHOS::MMI::ClientMsgHandler::TracePointerEvent(const EventPointer& pointData) const
{
    int32_t EVENT_POINTER = 17;
    char pointerUuid[MAX_UUIDSIZE] = {0};
    if (EOK != memcpy_s(pointerUuid, sizeof(pointerUuid), pointData.uuid, sizeof(pointData.uuid))) {
        MMI_LOGT("%{public}s copy data failed", __func__);
        return;
    }
    MMI_LOGT("\n nevent dispatcher of client: pointerUuid = %{public}s\n", pointerUuid);
    std::string pointerEvent = pointerUuid;
    FinishAsyncTrace(BYTRACE_TAG_MULTIMODALINPUT, pointerEvent, EVENT_POINTER);
}

void OHOS::MMI::ClientMsgHandler::TraceTouchEvent(const EventTouch& touchData) const
{
    int32_t EVENT_TOUCH = 9;
    char touchUuid[MAX_UUIDSIZE] = {0};
    if (EOK != memcpy_s(touchUuid, sizeof(touchUuid), touchData.uuid, sizeof(touchData.uuid))) {
        MMI_LOGT("%{public}s copy data failed", __func__);
        return;
    }
    MMI_LOGT("\n nevent dispatcher of client: touchUuid = %{public}s\n", touchUuid);
    std::string touchEventString = touchUuid;
    FinishAsyncTrace(BYTRACE_TAG_MULTIMODALINPUT, touchEventString, EVENT_TOUCH);
}
