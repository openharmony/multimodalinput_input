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
#include "mmi_func_callback.h"
#include "bytrace.h"
#include "input_device_impl.h"
#include "input_event_data_transformation.h"
#include "input_event_monitor_manager.h"
#include "input_filter_manager.h"
#include "input_handler_manager.h"
#include "input_manager_impl.h"
#include "input_monitor_manager.h"
#include "interceptor_manager.h"
#include "mmi_client.h"
#include "multimodal_event_handler.h"
#include "proto.h"
#include "time_cost_chk.h"
#include "util.h"

namespace OHOS {
namespace MMI {
namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "ClientMsgHandler"};
}

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
        {MmiMessageId::GET_MMI_INFO_ACK, MsgCallbackBind2(&ClientMsgHandler::GetMultimodeInputInfo, this)},
        {MmiMessageId::KEY_EVENT_INTERCEPTOR, MsgCallbackBind2(&ClientMsgHandler::KeyEventFilter, this)},
        {MmiMessageId::TOUCH_EVENT_INTERCEPTOR, MsgCallbackBind2(&ClientMsgHandler::TouchEventFilter, this)},
        {MmiMessageId::INPUT_DEVICE, MsgCallbackBind2(&ClientMsgHandler::OnInputDevice, this)},
        {MmiMessageId::INPUT_DEVICE_IDS, MsgCallbackBind2(&ClientMsgHandler::OnInputDeviceIds, this)},
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

void ClientMsgHandler::OnMsgHandler(const UDSClient& client, NetPacket& pkt)
{
    auto id = pkt.GetMsgId();
    TimeCostChk chk("ClientMsgHandler::OnMsgHandler", "overtime 300(us)", MAX_OVER_TIME, id);
    auto callback = GetMsgCallback(id);
    if (callback == nullptr) {
        MMI_LOGE("CClientMsgHandler::OnMsgHandler Unknown msg id:%{public}d", id);
        return;
    }
    auto ret = (*callback)(client, pkt);
    if (ret < 0) {
        MMI_LOGE("CClientMsgHandler::OnMsgHandler Msg handling failed. id:%{public}d,ret:%{public}d", id, ret);
        return;
    }
}

int32_t ClientMsgHandler::OnKeyMonitor(const UDSClient& client, NetPacket& pkt)
{
    auto key = KeyEvent::Create();
    CHKPR(key, ERROR_NULL_POINTER);
    int32_t ret = InputEventDataTransformation::NetPacketToKeyEvent(pkt, key);
    if (ret != RET_OK) {
        MMI_LOGE("OnKeyMonitor read netPacket failed");
        return RET_ERR;
    }
    int32_t pid;
    pkt >> pid;
    CHKR(!pkt.ChkError(), PACKET_READ_FAIL, PACKET_READ_FAIL);
    MMI_LOGD("Client receive the msg from server, keyCode:%{public}d,pid:%{public}d", key->GetKeyCode(), pid);
    return InputMonitorMgr.OnMonitorInputEvent(key);
}

int32_t ClientMsgHandler::OnKeyEvent(const UDSClient& client, NetPacket& pkt)
{
    int32_t fd = 0;
    uint64_t serverStartTime = 0;
    auto key = KeyEvent::Create();
    int32_t ret = InputEventDataTransformation::NetPacketToKeyEvent(pkt, key);
    if (ret != RET_OK) {
        MMI_LOGE("read netPacket failed");
        return RET_ERR;
    }
    pkt >> fd >> serverStartTime;
    CHKR(!pkt.ChkError(), PACKET_READ_FAIL, PACKET_READ_FAIL);
    MMI_LOGD("key event dispatcher of client, KeyCode:%{public}d,"
             "ActionTime:%{public}" PRId64 ",Action:%{public}d,ActionStartTime:%{public}" PRId64 ","
             "EventType:%{public}d,Flag:%{public}u,"
             "KeyAction:%{public}d,eventNumber:%{public}d,Fd:%{public}d,"
             "ServerStartTime:%{public}" PRId64"",
             key->GetKeyCode(), key->GetActionTime(), key->GetAction(),
             key->GetActionStartTime(), key->GetEventType(),
             key->GetFlag(), key->GetKeyAction(), key->GetId(), fd, serverStartTime);
    int32_t keyId = key->GetId();
    std::string keyCodestring = "KeyEventDispatch";
    StartAsyncTrace(BYTRACE_TAG_MULTIMODALINPUT, keyCodestring, keyId);
    int32_t getKeyCode = key->GetKeyCode();
    keyCodestring = "client dispatchKeyCode=" + std::to_string(getKeyCode);
    BYTRACE_NAME(BYTRACE_TAG_MULTIMODALINPUT, keyCodestring);
    key->SetProcessedCallback(eventProcessedCallback_);
    InputManagerImpl::GetInstance()->OnKeyEvent(key);
    return RET_OK;
}

int32_t ClientMsgHandler::OnPointerEvent(const UDSClient& client, NetPacket& pkt)
{
    auto pointerEvent { PointerEvent::Create() };
    if (InputEventDataTransformation::Unmarshalling(pkt, pointerEvent) != ERR_OK) {
        MMI_LOGE("Failed to deserialize pointer event.");
        return RET_ERR;
    }

    std::vector<int32_t> pointerIds { pointerEvent->GetPointersIdList() };
    MMI_LOGD("Pointer event dispatcher of client, eventType:%{public}s, actionTime:%{public}" PRId64 ", "
             "action:%{public}d, actionStartTime:%{public}" PRId64 ", flag:%{public}u, pointerAction:%{public}s, "
             "sourceType:%{public}s, VerticalAxisValue:%{public}.2f, HorizontalAxisValue:%{public}.2f, "
             "PinchAxisValue:%{public}.2f, pointerCount:%{public}zu, eventNumber:%{public}d",
             pointerEvent->DumpEventType(), pointerEvent->GetActionTime(), pointerEvent->GetAction(),
             pointerEvent->GetActionStartTime(), pointerEvent->GetFlag(), pointerEvent->DumpPointerAction(),
             pointerEvent->DumpSourceType(), pointerEvent->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL),
             pointerEvent->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL),
             pointerEvent->GetAxisValue(PointerEvent::AXIS_TYPE_PINCH),
             pointerIds.size(), pointerEvent->GetId());
    std::vector<int32_t> pressedKeys = pointerEvent->GetPressedKeys();
    for (auto &item : pressedKeys) {
        MMI_LOGI("Pressed keyCode:%{public}d", item);
    }
    for (auto &pointerId : pointerIds) {
        PointerEvent::PointerItem item;
        CHKR(pointerEvent->GetPointerItem(pointerId, item), PARAM_INPUT_FAIL, RET_ERR);

        MMI_LOGD("DownTime:%{public}" PRId64 ",isPressed:%{public}s,"
                "globalX:%{public}d,globalY:%{public}d,localX:%{public}d,localY:%{public}d,"
                "width:%{public}d,height:%{public}d,pressure:%{public}d",
                 item.GetDownTime(), (item.IsPressed() ? "true" : "false"),
                 item.GetGlobalX(), item.GetGlobalY(), item.GetLocalX(), item.GetLocalY(),
                 item.GetWidth(), item.GetHeight(), item.GetPressure());
    }
    if (PointerEvent::POINTER_ACTION_CANCEL == pointerEvent->GetPointerAction()) {
        MMI_LOGD("Operation canceled.");
    }
    pointerEvent->SetProcessedCallback(eventProcessedCallback_);
    if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_MOUSE) {
        int32_t pointerId = pointerEvent->GetId();
        std::string pointerEventstring = "PointerEventDispatch";
        StartAsyncTrace(BYTRACE_TAG_MULTIMODALINPUT, pointerEventstring, pointerId);
    }
    if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_TOUCHSCREEN) {
        int32_t touchId = pointerEvent->GetId();
        std::string touchEvent = "touchEventDispatch";
        StartAsyncTrace(BYTRACE_TAG_MULTIMODALINPUT, touchEvent, touchId);
    }
    InputManagerImpl::GetInstance()->OnPointerEvent(pointerEvent);
    return RET_OK;
}

int32_t ClientMsgHandler::OnSubscribeKeyEventCallback(const UDSClient &client, NetPacket &pkt)
{
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    int32_t ret = InputEventDataTransformation::NetPacketToKeyEvent(pkt, keyEvent);
    if (ret != RET_OK) {
        MMI_LOGE("read net packet failed");
        return RET_ERR;
    }
    int32_t fd = -1;
    int32_t subscribeId = -1;
    pkt >> fd >> subscribeId;
    CHKR(!pkt.ChkError(), PACKET_READ_FAIL, PACKET_READ_FAIL);
    MMI_LOGD("Subscribe:%{public}d,Fd:%{public}d,KeyEvent:%{public}d,"
             "KeyCode:%{public}d,ActionTime:%{public}" PRId64 ",ActionStartTime:%{public}" PRId64 ","
             "Action:%{public}d,KeyAction:%{public}d,EventType:%{public}d,Flag:%{public}u",
        subscribeId, fd, keyEvent->GetId(), keyEvent->GetKeyCode(), keyEvent->GetActionTime(),
        keyEvent->GetActionStartTime(), keyEvent->GetAction(), keyEvent->GetKeyAction(),
        keyEvent->GetEventType(), keyEvent->GetFlag());
    int32_t keyId = keyEvent->GetId();
    std::string keyEventString = "keyEventSubscribe";
    StartAsyncTrace(BYTRACE_TAG_MULTIMODALINPUT, keyEventString, keyId);
    int32_t keyCode = keyEvent->GetKeyCode();
    keyEventString = "client subscribe keyCode=" + std::to_string(keyCode);
    BYTRACE_NAME(BYTRACE_TAG_MULTIMODALINPUT, keyEventString);
    return KeyEventInputSubscribeMgr.OnSubscribeKeyEventCallback(keyEvent, subscribeId);
}

int32_t ClientMsgHandler::OnTouchPadMonitor(const UDSClient& client, NetPacket& pkt)
{
    auto pointer = PointerEvent::Create();
    int32_t ret = InputEventDataTransformation::Unmarshalling(pkt, pointer);
    if (ret != RET_OK) {
        MMI_LOGE("OnTouchPadMonitor read netPacket failed");
        return RET_ERR;
    }
    int32_t pid = 0;
    pkt >> pid;
    CHKR(!pkt.ChkError(), PACKET_READ_FAIL, PACKET_READ_FAIL);
    MMI_LOGD("client receive the msg from server: EventType:%{public}d,pid:%{public}d",
        pointer->GetEventType(), pid);
    return InputMonitorMgr.OnTouchpadMonitorInputEvent(pointer);
}

int32_t ClientMsgHandler::OnKey(const UDSClient& client, NetPacket& pkt)
{
    int32_t abilityId = 0;
    int32_t windowId = 0;
    int32_t fd = 0;
    uint64_t serverStartTime = 0;
    EventKeyboard key = {};
    pkt >> key >> abilityId >> windowId >> fd >> serverStartTime;
    CHKR(!pkt.ChkError(), PACKET_READ_FAIL, PACKET_READ_FAIL);
    MMI_LOGD("Event dispatcher of client:eventKeyboard:time:%{public}" PRId64 ",key:%{public}u,"
             "deviceType:%{public}u,seat_key_count:%{public}u,state:%{public}d,fd:%{public}d",
             key.time, key.key, key.deviceType, key.seat_key_count, key.state, fd);

    /* 根据收到的key，构造keyBoardEvent对象，
    *  其中KeyBoardEvent对象的    handledByIme,unicode,isSingleNonCharacter,isTwoNonCharacters,isThreeNonCharacters五个字段
    *  和KeyEvent对象的keyDownDuration一个字段
    *  和MultimodalEvent对象的highLevelEvent, deviceId, isHighLevelEvent三个字段缺失，暂时填0
    */
    KeyBoardEvent event;
    int32_t deviceEventType = KEY_EVENT;
    event.Initialize(windowId, 0, 0, 0, 0, 0, key.state, key.key, 0, 0, key.uuid, key.eventType,
                     key.time, "", key.deviceId, 0, key.deviceType,
                     deviceEventType, key.isIntercepted);
    return EventManager.OnKey(event);
}

int32_t ClientMsgHandler::OnTouch(const UDSClient& client, NetPacket& pkt)
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
            MMI_LOGE("ClientMsgHandler::OnTouch unknow type:%{public}d,errCode:%{public}d", type, UNKNOW_TOUCH_TYPE);
            return RET_ERR;
        }
    }
    return RET_OK;
}

int32_t ClientMsgHandler::GetMultimodeInputInfo(const UDSClient& client, NetPacket& pkt)
{
    TagPackHead tagPackHeadAck;
    pkt >> tagPackHeadAck;
    CHKR(!pkt.ChkError(), PACKET_READ_FAIL, PACKET_READ_FAIL);
    std::cout << "GetMultimodeInputInfo: The client fd is " << tagPackHeadAck.sizeEvent[0] << std::endl;
    return RET_OK;
}

int32_t ClientMsgHandler::OnInputDeviceIds(const UDSClient& client, NetPacket& pkt)
{
    MMI_LOGD("enter");
    int32_t userData;
    int32_t size;
    std::vector<int32_t> inputDeviceIds;
    CHKR(pkt.Read(userData), STREAM_BUF_READ_FAIL, RET_ERR);
    CHKR(pkt.Read(size), STREAM_BUF_READ_FAIL, RET_ERR);
    for (int32_t i = 0; i < size; i++) {
        int32_t deviceId = 0;
        CHKR(pkt.Read(deviceId), STREAM_BUF_READ_FAIL, RET_ERR);
        inputDeviceIds.push_back(deviceId);
    }
    InputDeviceImpl::GetInstance().OnInputDeviceIds(userData, inputDeviceIds);
    return RET_OK;
}

int32_t ClientMsgHandler::OnInputDevice(const UDSClient& client, NetPacket& pkt)
{
    MMI_LOGD("enter");
    int32_t userData;
    int32_t id;
    std::string name;
    int32_t deviceType;
    CHKR(pkt.Read(userData), STREAM_BUF_READ_FAIL, RET_ERR);
    CHKR(pkt.Read(id), STREAM_BUF_READ_FAIL, RET_ERR);
    CHKR(pkt.Read(name), STREAM_BUF_READ_FAIL, RET_ERR);
    CHKR(pkt.Read(deviceType), STREAM_BUF_READ_FAIL, RET_ERR);

    InputDeviceImpl::GetInstance().OnInputDevice(userData, id, name, deviceType);
    return RET_OK;
}

int32_t ClientMsgHandler::KeyEventFilter(const UDSClient& client, NetPacket& pkt)
{
#if 0
    EventKeyboard key = {};
    int32_t id = 0;
    pkt >> key >>id;
    CHKR(!pkt.ChkError(), PACKET_READ_FAIL, PACKET_READ_FAIL);
    MMI_LOGD("key event filter : event dispatcher of client:eventKeyboard:time:%{public}" PRId64
        ",key:%{public}u,deviceId=%{private}u,"
        "deviceType:%{public}u,seat_key_count:%{public}u,state:%{public}d",
        key.time, key.key, key.deviceId, key.deviceType, key.seat_key_count, key.state);
    KeyBoardEvent event;
    int32_t windowId = 0;
    int32_t deviceEventType = KEY_EVENT;
    event.Initialize(windowId, 0, 0, 0, 0, 0, key.state, key.key, 0, 0, key.uuid, key.eventType,
                     key.time, "", key.deviceId, 0, key.deviceType, deviceEventType);
    return InputFilterMgr.OnKeyEvent(event, id);
#endif
    MMI_LOGE("chengmai_todo");
    return RET_ERR;
}

int32_t ClientMsgHandler::TouchEventFilter(const UDSClient& client, NetPacket& pkt)
{
#if 0
    MMI_LOGD("enter");
    int32_t abilityId = 0;
    int32_t windowId = 0;
    int32_t fd = 0;
    int32_t fingerCount = 0;
    int32_t eventAction = 0;
    uint64_t serverStartTime = 0;
    pkt >> fingerCount >> eventAction >> abilityId >> windowId >> fd >> serverStartTime;
    CHKR(!pkt.ChkError(), PACKET_READ_FAIL, PACKET_READ_FAIL);

    EventTouch touchData = {};
    fingerInfos fingersInfos[FINGER_NUM] = {};
    /* 根据收到的touchData，构造TouchEvent对象
    *  其中TouchEvent对象的action,index,forcePrecision,maxForce,tapCount五个字段
    *  和ManipulationEvent对象的startTime,operationState,pointerCount,pointerId，  touchArea，touchPressure六个字段，
    *  和MultimodalEvent对象的highLevelEvent, deviceId, isHighLevelEvent三个字段缺失，暂时填0
    */
    for (int32_t i = 0; i < fingerCount; i++) {
        pkt >> touchData;
        CHKR(!pkt.ChkError(), PACKET_READ_FAIL, PACKET_READ_FAIL);
        fingersInfos[i].mPointerId = i;
        fingersInfos[i].mTouchArea = static_cast<float>(touchData.area);
        fingersInfos[i].mTouchPressure = static_cast<float>(touchData.pressure);
        fingersInfos[i].mMp.Setxy(touchData.point.x, touchData.point.y);
    }

    MMI_LOGD("Event filter of client:eventTouch:time:%{public}" PRId64 ","
             "deviceType:%{public}u,eventType:%{public}d,slot:%{public}d,seatSlot:%{public}d,fd:%{public}d",
             touchData.time, touchData.deviceType, touchData.eventType, touchData.slot, touchData.seatSlot, fd);

    int32_t fingerIndex = 0;
    if (PRIMARY_POINT_DOWN == eventAction || PRIMARY_POINT_UP == eventAction ||
        OTHER_POINT_DOWN == eventAction || OTHER_POINT_UP == eventAction) {
        fingerIndex = fingersInfos[0].mPointerId;
    }
    TouchEvent event;
    int32_t deviceEventType = TOUCH_EVENT;
    event.Initialize(windowId, eventAction, fingerIndex, 0, 0, 0, 0, 0, fingerCount, fingersInfos, 0,
        touchData.uuid, touchData.eventType, static_cast<int32_t>(touchData.time), "",
        touchData.deviceId, 0, false, touchData.deviceType, deviceEventType);

    int32_t id = 0;
    pkt >> id;
    CHKR(!pkt.ChkError(), PACKET_READ_FAIL, PACKET_READ_FAIL);
    return InputFilterMgr.OnTouchEvent(event, id);
#endif
    MMI_LOGE("chengmai_todo");
    return RET_ERR;
}

int32_t ClientMsgHandler::PointerEventInterceptor(const UDSClient& client, NetPacket& pkt)
{
#if 0
    EventPointer pointData = {};
    int32_t id = 0;
    pkt >> pointData >> id;
    CHKR(!pkt.ChkError(), PACKET_READ_FAIL, PACKET_READ_FAIL);
    MmiPoint mmiPoint;
    mmiPoint.Setxy(pointData.delta.x, pointData.delta.y);
    MMI_LOGD("WangYuanevent dispatcher of client: mouse_data eventPointer:time:%{public}" PRId64 ","
             "eventType:%{public}d,buttonCode:%{public}u,deviceType:%{public}u,"
             "seat_button_count:%{public}u,axis:%{public}u,buttonState:%{public}d,source:%{public}d,"
             "delta.x:%{public}lf,delta.y:%{public}lf,delta_raw.x:%{public}lf,delta_raw.y:%{public}lf,"
             "absolute.x:%{public}lf,absolute.y:%{public}lf,discYe.x:%{public}lf,discrete.y:%{public}lf",
             pointData.time, pointData.eventType, pointData.button, pointData.deviceType,
             pointData.seat_button_count, pointData.axis, pointData.state, pointData.source, pointData.delta.x,
             pointData.delta.y, pointData.delta_raw.x, pointData.delta_raw.y, pointData.absolute.x,
             pointData.absolute.y, pointData.discrete.x, pointData.discrete.y);
    int32_t action = pointData.state;
    EventJoyStickAxis eventJoyStickAxis = {};
    int32_t windowId = 0;
    MouseEvent mouse_event;
    mouse_event.Initialize(windowId, action, pointData.button, pointData.state, mmiPoint,
        static_cast<float>(pointData.discrete.x), static_cast<float>(pointData.discrete.y),
        0, 0, 0, pointData.uuid, pointData.eventType, static_cast<int32_t>(pointData.time),
        "", pointData.deviceId, 0, pointData.deviceType, eventJoyStickAxis);
    return (InputFilterMgr.OnPointerEvent(mouse_event, id));
#endif
    MMI_LOGE("chengmai_todo");
    return RET_ERR;
}

int32_t ClientMsgHandler::ReportKeyEvent(const UDSClient& client, NetPacket& pkt)
{
    int32_t handlerId;
    CHKR(pkt.Read(handlerId), STREAM_BUF_READ_FAIL, RET_ERR);
    auto keyEvent = KeyEvent::Create();
    if (InputEventDataTransformation::NetPacketToKeyEvent(pkt, keyEvent) != ERR_OK) {
        MMI_LOGE("Failed to deserialize key event.");
        return RET_ERR;
    }
    InputHandlerManager::GetInstance().OnInputEvent(handlerId, keyEvent);
    return RET_OK;
}

int32_t ClientMsgHandler::ReportPointerEvent(const UDSClient& client, NetPacket& pkt)
{
    MMI_LOGD("enter");
    int32_t handlerId;
    InputHandlerType handlerType;
    CHKR(pkt.Read(handlerId), STREAM_BUF_READ_FAIL, RET_ERR);
    CHKR(pkt.Read(handlerType), STREAM_BUF_READ_FAIL, RET_ERR);
    MMI_LOGD("Client handlerId:%{public}d,handlerType:%{public}d", handlerId, handlerType);
    auto pointerEvent { PointerEvent::Create() };
    if (InputEventDataTransformation::Unmarshalling(pkt, pointerEvent) != ERR_OK) {
        MMI_LOGE("Failed to deserialize pointer event");
        return RET_ERR;
    }
    if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_MOUSE) {
        int32_t pointerId = pointerEvent->GetId();
        std::string pointerEventString = "pointerEventFilter";
        StartAsyncTrace(BYTRACE_TAG_MULTIMODALINPUT, pointerEventString, pointerId);
    }
    if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_TOUCHSCREEN) {
        int32_t touchId = pointerEvent->GetId();
        std::string touchEventString = "touchEventFilter";
        StartAsyncTrace(BYTRACE_TAG_MULTIMODALINPUT, touchEventString, touchId);
    }
    InputHandlerManager::GetInstance().OnInputEvent(handlerId, pointerEvent);
    return RET_OK;
}

int32_t ClientMsgHandler::TouchpadEventInterceptor(const UDSClient& client, NetPacket& pkt)
{
    auto pointerEvent = PointerEvent::Create();
    int32_t ret = InputEventDataTransformation::Unmarshalling(pkt, pointerEvent);
    if (ret != RET_OK) {
        MMI_LOGE("TouchpadEventInterceptor read netPacket failed");
        return RET_ERR;
    }
    int32_t pid = 0;
    int32_t id = 0;
    pkt >> pid >> id;
    CHKR(!pkt.ChkError(), PACKET_READ_FAIL, PACKET_READ_FAIL);
    MMI_LOGD("client receive the msg from server: pointId:%{public}d,pid:%{public}d",
             pointerEvent->GetPointerId(), pid);
    return InterceptorMgr.OnPointerEvent(pointerEvent, id);
}

int32_t ClientMsgHandler::KeyEventInterceptor(const UDSClient& client, NetPacket& pkt)
{
    auto keyEvent = KeyEvent::Create();
    int32_t ret = InputEventDataTransformation::NetPacketToKeyEvent(pkt, keyEvent);
    if (ret != RET_OK) {
        MMI_LOGE("TouchpadEventInterceptor read netPacket failed");
        return RET_ERR;
    }
    int32_t pid = 0;
    pkt >> pid;
    CHKR(!pkt.ChkError(), PACKET_READ_FAIL, PACKET_READ_FAIL);

    int32_t keyId = keyEvent->GetId();
    std::string keyEventString = "keyEventFilter";
    StartAsyncTrace(BYTRACE_TAG_MULTIMODALINPUT, keyEventString, keyId);
    int32_t keyCode = keyEvent->GetKeyCode();
    keyEventString = "client filter keyCode=" + std::to_string(keyCode);
    BYTRACE_NAME(BYTRACE_TAG_MULTIMODALINPUT, keyEventString);
    MMI_LOGD("client receive the msg from server: keyCode:%{public}d,pid:%{public}d",
        keyEvent->GetKeyCode(), pid);
    return InterceptorMgr.OnKeyEvent(keyEvent);
}

void ClientMsgHandler::AnalysisPointEvent(const UDSClient& client, NetPacket& pkt) const
{
    int32_t abilityId = 0;
    int32_t windowId = 0;
    int32_t fd = 0;
    uint64_t serverStartTime = 0;
    int32_t ret = RET_ERR;
    EventPointer pointData = {};
    pkt >> ret >> pointData >> abilityId >> windowId >> fd >> serverStartTime;
    CHK(!pkt.ChkError(), PACKET_READ_FAIL);
    MMI_LOGD("event dispatcher of client: mouse_data eventPointer:time:%{public}" PRId64 ",eventType:%{public}d,"
             "buttonCode:%{public}u,deviceType:%{public}u,seat_button_count:%{public}u,"
             "axis:%{public}u,buttonState:%{public}d,source:%{public}d,delta.x:%{public}lf,delta.y:%{public}lf, "
             "delta_raw.x:%{public}lf,delta_raw.y:%{public}lf,absolute.x:%{public}lf,absolute.y:%{public}lf,"
             "discYe.x:%{public}lf,discrete.y:%{public}lf,fd:%{public}d",
             pointData.time, pointData.eventType, pointData.button, pointData.deviceType,
             pointData.seat_button_count, pointData.axis, pointData.state, pointData.source, pointData.delta.x,
             pointData.delta.y, pointData.delta_raw.x, pointData.delta_raw.y, pointData.absolute.x,
             pointData.absolute.y, pointData.discrete.x, pointData.discrete.y, fd);
    int32_t action = pointData.state;
    /* 根据收到的point，构造MouseEvent对象，
    *  其中MouseEvent对象的action,actionButton,cursorDelta,scrollingDelta四个字段
    *  和MultimodalEvent对象的highLevelEvent, deviceId, isHighLevelEvent三个字段缺失，暂时填0
    */
    MmiPoint mmiPoint;
    mmiPoint.Setxy(pointData.delta.x, pointData.delta.y);
    MultimodalEventPtr mousePtr = EventFactory::CreateEvent(EventType::EVENT_MOUSE);
    CHKPV(mousePtr);
    EventJoyStickAxis eventJoyStickAxis = {};
    (reinterpret_cast<MouseEvent*> (mousePtr.GetRefPtr()))->Initialize(windowId, action,
        pointData.button, pointData.state, mmiPoint, static_cast<float>(pointData.discrete.x),
        static_cast<float>(pointData.discrete.y), 0, 0, 0, pointData.uuid, pointData.eventType,
        static_cast<int32_t>(pointData.time), "", pointData.deviceId, 0,
        pointData.deviceType, eventJoyStickAxis);

    // 如果是标准化消息，则获取standardTouch
    TouchEvent touchEvent;
    int32_t deviceEventType = 0;
    deviceEventType = MOUSE_EVENT;
    fingerInfos fingersInfos[FINGER_NUM] = {};
    StandardTouchStruct standardTouch = {};
    if (ret > 0) {
        pkt >> standardTouch;
        CHK(!pkt.ChkError(), PACKET_READ_FAIL);

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

void ClientMsgHandler::AnalysisTouchEvent(const UDSClient& client, NetPacket& pkt) const
{
    int32_t abilityId = 0;
    int32_t windowId = 0;
    int32_t fd = 0;
    int32_t fingerCount = 0;
    int32_t eventAction = 0;
    int32_t seatSlot = 0;
    uint64_t serverStartTime = 0;
    pkt >> fingerCount >> eventAction >> abilityId >> windowId >> fd >> serverStartTime >> seatSlot;
    CHK(!pkt.ChkError(), PACKET_READ_FAIL);

    EventTouch touchData = {};
    fingerInfos fingersInfos[FINGER_NUM] = {};
    /* 根据收到的touchData，构造TouchEvent对象
    *  其中TouchEvent对象的action,index,forcePrecision,maxForce,tapCount五个字段
    *  和ManipulationEvent对象的startTime,operationState,pointerCount,pointerId，  touchArea，touchPressure六个字段，
    *  和MultimodalEvent对象的highLevelEvent, deviceId, isHighLevelEvent三个字段缺失，暂时填0
    */
    for (int32_t i = 0; i < fingerCount; i++) {
        pkt >> touchData;
        CHK(!pkt.ChkError(), PACKET_READ_FAIL);
        fingersInfos[i].mPointerId = touchData.seatSlot;
        fingersInfos[i].mTouchArea = static_cast<float>(touchData.area);
        fingersInfos[i].mTouchPressure = static_cast<float>(touchData.pressure);
        fingersInfos[i].mMp.Setxy(touchData.point.x, touchData.point.y);
        MMI_LOGD("Event dispatcher of client:eventTouch:time:%{public}" PRId64
                 ",deviceType:%{public}u,eventType:%{public}d,slot:%{public}d,seatSlot:%{public}d,"
                 "fd:%{public}d,point.x:%{public}lf,point.y:%{public}lf",
                 touchData.time, touchData.deviceType, touchData.eventType, touchData.slot,
                 touchData.seatSlot, fd, touchData.point.x, touchData.point.y);
    }
    TouchEvent touchEvent;
    int32_t deviceEventType = TOUCH_EVENT;
    touchEvent.Initialize(windowId, eventAction, seatSlot, 0, 0, 0, 0, 0, fingerCount, fingersInfos, 0,
        touchData.uuid, touchData.eventType, static_cast<int32_t>(touchData.time), "",
        touchData.deviceId, 0, false, touchData.deviceType, deviceEventType);

    EventManager.OnTouch(touchEvent);
}

void ClientMsgHandler::AnalysisJoystickEvent(const UDSClient& client, NetPacket& pkt) const
{
    EventJoyStickAxis eventJoyStickData = {};
    int32_t abilityId = 0;
    int32_t windowId = 0;
    int32_t fd = 0;
    uint64_t serverStartTime = 0;
    pkt >> eventJoyStickData >> abilityId >> windowId >> fd >> serverStartTime;
    CHK(!pkt.ChkError(), PACKET_READ_FAIL);
    MMI_LOGD("event dispatcher of client: "
        "event JoyStick: fd:%{public}d", fd);
    PrintEventJoyStickAxisInfo(eventJoyStickData, fd, abilityId, windowId, serverStartTime);

    std::string nullUUid = "";
    MmiPoint mmiPoint;
    MultimodalEventPtr mousePtr = EventFactory::CreateEvent(EventType::EVENT_MOUSE);
    CHKPV(mousePtr);
    int32_t mouseAction = static_cast<int32_t>(MouseActionEnum::HOVER_MOVE);
    (reinterpret_cast<MouseEvent*>(mousePtr.GetRefPtr()))->Initialize(windowId, mouseAction, 0, 0, mmiPoint,
        0, 0, 0, 0, 0, nullUUid, eventJoyStickData.eventType, static_cast<int32_t>(eventJoyStickData.time), "",
        eventJoyStickData.deviceId, false, eventJoyStickData.deviceType, eventJoyStickData);

    int32_t deviceEventType = 0;
    deviceEventType = MOUSE_EVENT;
    int32_t touchAction = 0;
    touchAction = HOVER_POINTER_MOVE;
    TouchEvent touchEvent;
    touchEvent.Initialize(windowId, mousePtr, deviceEventType, touchAction, 0, 0, 0, 0, 0, 0, 1,
        nullptr, false);
    EventManager.OnTouch(touchEvent);
}

void ClientMsgHandler::AnalysisTouchPadEvent(const UDSClient& client, NetPacket& pkt) const
{
    EventTabletPad tabletPad = {};
    int32_t abilityId = 0;
    int32_t windowId = 0;
    int32_t fd = 0;
    uint64_t serverStartTime = 0;
    pkt >> tabletPad >> abilityId >> windowId >> fd >> serverStartTime;
    CHK(!pkt.ChkError(), PACKET_READ_FAIL);
    MMI_LOGD("event dispatcher of client: event tablet Pad :time:%{public}" PRId64 ",deviceType:%{public}u,"
             "deviceName:%{public}s,eventType:%{public}d,"
             "ring.number:%{public}d,ring.position:%{public}lf,ring.source:%{public}d,"
             "strip.number:%{public}d,strip.position:%{public}lf,strip.source:%{public}d,"
             "fd:%{public}d,preHandlerTime:%{public}" PRId64,
             tabletPad.time, tabletPad.deviceType, tabletPad.deviceName, tabletPad.eventType,
             tabletPad.ring.number, tabletPad.ring.position, tabletPad.ring.source, tabletPad.strip.number,
             tabletPad.strip.position, tabletPad.strip.source, fd, serverStartTime);
    // Multimodal ANR
    MmiPoint mmiPoint;
    MultimodalEventPtr mousePtr = EventFactory::CreateEvent(EventType::EVENT_MOUSE);
    CHKPV(mousePtr);
    std::string nullUUid = "";
    int32_t mouseAction = static_cast<int32_t>(MouseActionEnum::HOVER_MOVE);
    EventJoyStickAxis eventJoyStickAxis = {};
    eventJoyStickAxis.abs_wheel.standardValue = static_cast<float>(tabletPad.ring.position);
    auto mouseEvent = reinterpret_cast<MouseEvent*>(mousePtr.GetRefPtr());
    mouseEvent->Initialize(windowId, mouseAction, 0, 0, mmiPoint, 0, 0, 0, 0, 0, nullUUid, tabletPad.eventType,
                           static_cast<int32_t>(tabletPad.time), "", tabletPad.deviceId,
                           false, tabletPad.deviceType, eventJoyStickAxis);

    int32_t deviceEventType = 0;
    deviceEventType = MOUSE_EVENT;
    int32_t touchAction = 0;
    touchAction = HOVER_POINTER_MOVE;
    TouchEvent touchEvent;
    touchEvent.Initialize(windowId, mousePtr, deviceEventType, touchAction, 0, 0, 0, 0, 0, 0, 1, nullptr, false);
    EventManager.OnTouch(touchEvent);
}

void ClientMsgHandler::PrintEventTabletToolInfo(EventTabletTool tableTool, uint64_t serverStartTime,
                                                int32_t abilityId, int32_t windowId, int32_t fd) const
{
    MMI_LOGD("event dispatcher of client: event tablet Tool :time:%{public}" PRId64 ", deviceType:%{public}u,"
             "deviceName:%{public}s, eventType:%{public}d,type:%{public}u,"
             "serial:%{public}u,button:%{public}d,"
             "state:%{public}d,point.x:%{public}lf,point.y:%{public}lf,tilt.x:%{public}lf,"
             "tilt.y:%{public}lf,distance:%{public}lf, pressure:%{public}lf,"
             "rotation:%{public}lf,slider:%{public}lf,wheel:%{public}lf,wheel_discrete:%{public}d,"
             "size.major:%{public}lf,size.minor:%{public}lf, "
             "proximity_state:%{public}d,tip_state:%{public}d,state:%{public}d,seat_button_count:%{public}d,"
             "fd:%{public}d,preHandlerTime:%{public}" PRId64,
             tableTool.time, tableTool.deviceType, tableTool.deviceName,
             tableTool.eventType, tableTool.tool.type, tableTool.tool.serial,
             tableTool.button, tableTool.state, tableTool.axes.point.x, tableTool.axes.point.y,
             tableTool.axes.tilt.x, tableTool.axes.tilt.y, tableTool.axes.distance, tableTool.axes.pressure,
             tableTool.axes.rotation, tableTool.axes.slider, tableTool.axes.wheel,
             tableTool.axes.wheel_discrete, tableTool.axes.size.major, tableTool.axes.size.minor,
             tableTool.proximity_state, tableTool.tip_state, tableTool.state, tableTool.seat_button_count,
             fd, serverStartTime);
}

void ClientMsgHandler::GetStandardStylusActionType(int32_t curRventType, int32_t &stylusAction,
                                                   int32_t &touchAction) const
{
    constexpr int32_t EVENT_TOUCH_DOWN = 500;               // LIBINPUT_EVENT_TOUCH_DOWN
    constexpr int32_t EVENT_TOUCH_UP = 501;                 // LIBINPUT_EVENT_TOUCH_UP
    constexpr int32_t EVENT_TOUCH_MOTION = 502;             // LIBINPUT_EVENT_TOUCH_MOTION

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

int32_t ClientMsgHandler::GetNonStandardStylusActionType(int32_t tableToolState) const
{
    int32_t stylusAction = tableToolState;
    if (stylusAction == BUTTON_STATE_PRESSED) {
        stylusAction = BUTTON_PRESS;
    } else {
        stylusAction = BUTTON_RELEASE;
    }
    return stylusAction;
}

void ClientMsgHandler::GetMouseActionType(int32_t eventType, int32_t proximityState,
                                          int32_t &mouseAction, int32_t &touchAction) const
{
    constexpr int32_t EVENT_TABLET_TOOL_PROXIMITY = 601;    // LIBINPUT_EVENT_TABLET_TOOL_PROXIMITY
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

void ClientMsgHandler::AnalysisStandardTabletToolEvent(NetPacket& pkt, int32_t curRventType,
                                                       EventTabletTool tableTool, int32_t windowId) const
{
    constexpr int32_t MOUSE_BTN_LEFT = 0x110;       // left button
    int32_t deviceEventType = 0;
    int32_t touchAction = static_cast<int32_t>(MouseActionEnum::MMNONE);
    EventJoyStickAxis eventJoyStickAxis = {};
    MmiPoint mmiPoint;
    auto mousePtr = EventFactory::CreateEvent(EventType::EVENT_MOUSE);
    CHKPV(mousePtr);
    auto mouseEvent = reinterpret_cast<MouseEvent*>(mousePtr.GetRefPtr());
    auto stylusPtr = EventFactory::CreateEvent(EventType::EVENT_STYLUS);
    CHKPV(stylusPtr);
    auto stylusEvent = reinterpret_cast<StylusEvent*>(stylusPtr.GetRefPtr());

    StandardTouchStruct standardTouchEvent = {};
    TouchEvent touchEvent;
    fingerInfos fingersInfos[FINGER_NUM] = {};
    if (curRventType > 0) {
        pkt >> standardTouchEvent;
        CHK(!pkt.ChkError(), PACKET_READ_FAIL);
        fingersInfos[0].mMp.Setxy(standardTouchEvent.x, standardTouchEvent.y);
        int32_t stylusAction = POINT_MOVE;
        deviceEventType = STYLUS_EVENT;

        GetStandardStylusActionType(curRventType, stylusAction, touchAction);
        stylusEvent->Initialize(windowId, stylusAction, tableTool.button, static_cast<int32_t>(standardTouchEvent.time),
            tableTool.state, 1, fingersInfos, 0, "", tableTool.eventType, static_cast<int32_t>(tableTool.time),
            "", tableTool.deviceId,  0, tableTool.deviceType);

        touchEvent.Initialize(windowId, stylusPtr, deviceEventType, touchAction, tableTool.tool.type, 0, 0, 0,
            static_cast<int32_t>(standardTouchEvent.time), standardTouchEvent.buttonState, 1, fingersInfos, true);
    } else if (tableTool.button > 0 && tableTool.button != MOUSE_BTN_LEFT) {
        int32_t stylusAction = GetNonStandardStylusActionType(static_cast<int32_t>(tableTool.state));
        stylusEvent->Initialize(windowId, stylusAction, tableTool.button, static_cast<int32_t>(tableTool.time),
            tableTool.state, 1, fingersInfos, 0, "", tableTool.eventType, static_cast<int32_t>(tableTool.time),
            "", tableTool.deviceId,  0, tableTool.deviceType);

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
            tableTool.deviceId, 0, tableTool.deviceType, eventJoyStickAxis);

        deviceEventType = MOUSE_EVENT;
        touchEvent.Initialize(windowId, mousePtr, deviceEventType, touchAction,
            tableTool.tool.type, 0, 0, 0, 0, 0, 1, fingersInfos, false);
    }
    EventManager.OnTouch(touchEvent);
}

void ClientMsgHandler::AnalysisTabletToolEvent(const UDSClient& client, NetPacket& pkt) const
{
    EventTabletTool tableTool = {};
    int32_t curRventType = 0;
    int32_t abilityId = 0;
    int32_t windowId = 0;
    int32_t fd = 0;
    uint64_t serverStartTime = 0;

    pkt >> curRventType >> tableTool >> abilityId >> windowId >> fd >> serverStartTime;
    CHK(!pkt.ChkError(), PACKET_READ_FAIL);
    PrintEventTabletToolInfo(tableTool, serverStartTime, abilityId, windowId, fd);
    // 如果是标准化消息，则获取standardTouchEvent
    AnalysisStandardTabletToolEvent(pkt, curRventType, tableTool, windowId);
}

void ClientMsgHandler::AnalysisGestureEvent(const UDSClient& client, NetPacket& pkt) const
{
    EventGesture gesture = {};
    int32_t abilityId = 0;
    int32_t windowId = 0;
    int32_t fd = 0;
    uint64_t serverStartTime = 0;
    pkt >> gesture >> abilityId >> windowId >> fd >> serverStartTime;
    CHK(!pkt.ChkError(), PACKET_READ_FAIL);
    MMI_LOGD("event dispatcher of client: event Gesture :time:%{public}" PRId64 ","
             "deviceType:%{public}u,deviceName:%{public}s, devNode:%{public}s,eventType:%{public}d,"
             "fingerCount:%{public}d,cancelled:%{public}d,delta.x:%{public}lf,delta.y:%{public}lf, "
             "deltaUnaccel.x:%{public}lf,deltaUnaccel.y:%{public}lf,fd:%{public}d,"
             "preHandlerTime:%{public}" PRId64,
             gesture.time, gesture.deviceType, gesture.deviceName, gesture.physical,
             gesture.eventType, gesture.fingerCount, gesture.cancelled, gesture.delta.x, gesture.delta.y,
             gesture.deltaUnaccel.x, gesture.deltaUnaccel.y, fd, serverStartTime);

    EventJoyStickAxis eventJoyStickAxis = {};
    MultimodalEventPtr mousePtr = EventFactory::CreateEvent(EventType::EVENT_MOUSE);
    CHKPV(mousePtr);
    const MmiPoint mmiPoint(gesture.deltaUnaccel.x, gesture.deltaUnaccel.y);
    auto mouseEvent = reinterpret_cast<MouseEvent*>(mousePtr.GetRefPtr());
    mouseEvent->Initialize(windowId, static_cast<int32_t>(MouseActionEnum::MOVE), 0, 0,
                           mmiPoint, 0, 0, 0, 0, 0, "", gesture.eventType, static_cast<int32_t>(gesture.time), "",
                           gesture.deviceId, false, gesture.deviceType, eventJoyStickAxis);

    int32_t j = 0;
    fingerInfos fingersInfos[FINGER_NUM] = {};
    for (int32_t i = 0; i < FINGER_NUM; i++) {
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

void ClientMsgHandler::OnEventProcessed(int32_t eventId)
{
    MMIClientPtr client = MMIEventHdl.GetMMIClient();
    CHKPV(client);
    NetPacket pkt(MmiMessageId::NEW_CHECK_REPLY_MESSAGE);
    pkt << eventId;
    CHK(client->SendMessage(pkt), MSG_SEND_FAIL);
}
} // namespace MMI
} // namespace OHOS
