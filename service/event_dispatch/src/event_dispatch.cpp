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

#include "event_dispatch.h"
#include <cinttypes>
#include "input-event-codes.h"
#include "ability_launch_manager.h"
#include "ability_manager_client.h"
#include "bytrace.h"
#include "event_filter_wrap.h"
#include "hisysevent.h"
#include "input_event_data_transformation.h"
#include "input_event_monitor_manager.h"
#include "input_handler_manager_global.h"
#include "interceptor_manager_global.h"
#include "key_event_subscriber.h"
#include "mmi_server.h"
#include "outer_interface.h"
#include "system_event_handler.h"
#include "util.h"

namespace OHOS {
namespace MMI {
constexpr int64_t INPUT_UI_TIMEOUT_TIME = 5 * 1000000;
constexpr int64_t INPUT_UI_TIMEOUT_TIME_MAX = 20 * 1000000;

    namespace {
        constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "EventDispatch" };
    }

static void PrintEventSlotedCoordsInfo(const SlotedCoordsInfo& r)
{
    using namespace OHOS::MMI;
    for (int32_t i = 0; i < MAX_SOLTED_COORDS_NUMS; i++) {
        MMI_LOGD("[%{public}d] isActive:%{public}d,x:%{public}f,y:%{public}f",
            i, r.coords[i].isActive, r.coords[i].x, r.coords[i].y);
    }
}

EventDispatch::EventDispatch()
{
}

EventDispatch::~EventDispatch()
{
}

void EventDispatch::OnEventTouchGetPointEventType(const EventTouch& touch,
                                                  const int32_t fingerCount,
                                                  POINT_EVENT_TYPE& pointEventType)
{
    CHK(fingerCount > 0, PARAM_INPUT_INVALID);
    CHK(touch.time > 0, PARAM_INPUT_INVALID);
    CHK(touch.seatSlot >= 0, PARAM_INPUT_INVALID);
    CHK(touch.eventType >= 0, PARAM_INPUT_INVALID);
    if (fingerCount == 1) {
        switch (touch.eventType) {
            case LIBINPUT_EVENT_TOUCH_DOWN: {
                pointEventType = PRIMARY_POINT_DOWN;
                break;
            }
            case LIBINPUT_EVENT_TOUCH_UP: {
                pointEventType = PRIMARY_POINT_UP;
                break;
            }
            case LIBINPUT_EVENT_TOUCH_MOTION: {
                pointEventType = POINT_MOVE;
                break;
            }
            default: {
                break;
            }
        }
    } else {
        switch (touch.eventType) {
            case LIBINPUT_EVENT_TOUCH_DOWN: {
                pointEventType = OTHER_POINT_DOWN;
                break;
            }
            case LIBINPUT_EVENT_TOUCH_UP: {
                pointEventType = OTHER_POINT_UP;
                break;
            }
            case LIBINPUT_EVENT_TOUCH_MOTION: {
                pointEventType = POINT_MOVE;
                break;
            }
            default: {
                break;
            }
        }
    }
}

int32_t EventDispatch::GestureRegisteredEventDispatch(const MmiMessageId& idMsg,
                                                      UDSServer& udsServer,
                                                      RegisteredEvent& registeredEvent,
                                                      int64_t preHandlerTime)
{
    auto ret = RET_OK;
    if (idMsg == MmiMessageId::ON_PREVIOUS) {
        ret = DispatchRegEvent(MmiMessageId::ON_PREVIOUS, udsServer, registeredEvent,
            INPUT_DEVICE_CAP_GESTURE, preHandlerTime);
        if (ret != RET_OK) {
            return ret;
        }
        ret = DispatchRegEvent(MmiMessageId::ON_SHOW_NOTIFICATION, udsServer, registeredEvent,
            INPUT_DEVICE_CAP_GESTURE, preHandlerTime);
    } else if (idMsg == MmiMessageId::ON_NEXT) {
        ret = DispatchRegEvent(MmiMessageId::ON_NEXT, udsServer, registeredEvent,
            INPUT_DEVICE_CAP_GESTURE, preHandlerTime);
        if (ret != RET_OK) {
            return ret;
        }
        ret = DispatchRegEvent(MmiMessageId::ON_BACK, udsServer, registeredEvent,
            INPUT_DEVICE_CAP_GESTURE, preHandlerTime);
    } else {
        ret = DispatchRegEvent(idMsg, udsServer, registeredEvent,
            INPUT_DEVICE_CAP_GESTURE, preHandlerTime);
    }
    return ret;
}

int32_t EventDispatch::DispatchRegEvent(const MmiMessageId& idMsg, UDSServer& udsServer,
    const RegisteredEvent& registeredEvent, int32_t inputDeviceType, int64_t preHandlerTime)
{
    CHKR(idMsg > MmiMessageId::INVALID, PARAM_INPUT_INVALID, PARAM_INPUT_INVALID);
    std::vector<int32_t> fds;
    RegEventHM->FindSocketFds(idMsg, fds);
    if (fds.empty()) {
        MMI_LOGW("Yet none of socketFds is found");
        return RET_OK;
    }

    for (const auto& fd : fds) {
        auto appInfo = AppRegs->FindSocketFd(fd);
        MMI_LOGD("Event dispatcher of server, RegisteredEvent:physical:%{public}s,"
                 "deviceType:%{public}u,eventType:%{public}u,occurredTime:%{public}" PRId64 ","
                 "conbinecode:%{public}d,fd:%{public}d",
                 registeredEvent.physical, registeredEvent.deviceType,
                 registeredEvent.eventType, registeredEvent.occurredTime,
                 idMsg, fd);

        if (AppRegs->IsMultimodeInputReady(idMsg, fd, registeredEvent.occurredTime, preHandlerTime)) {
            NetPacket pkt(idMsg);
            int32_t type = inputDeviceType;
            pkt << type << registeredEvent << fd << appInfo.windowId << appInfo.abilityId << preHandlerTime;
            CHKR(udsServer.SendMsg(fd, pkt), MSG_SEND_FAIL, MSG_SEND_FAIL);
        }
    }
    return RET_OK;
}

int32_t EventDispatch::KeyBoardRegEveHandler(const EventKeyboard& key, UDSServer& udsServer,
    struct libinput_event *event, int32_t inputDeviceType, int64_t preHandlerTime)
{
    CHKPR(event, ERROR_NULL_POINTER);
    RegisteredEvent eve = {};
    auto result = eventPackage_.PackageRegisteredEvent<EventKeyboard>(key, eve);
    if (result != RET_OK) {
        MMI_LOGE("Registered event package failed, ret:%{public}d,errCode:%{public}d", result, REG_EVENT_PKG_FAIL);
        return RET_ERR;
    }
    auto ret1 = RET_OK;
    auto ret2 = RET_OK;
    if ((key.key == KEY_ENTER || key.key == KEY_KPENTER) && (key.state == KEY_STATE_PRESSED)) {
        ret1 = DispatchRegEvent(MmiMessageId::ON_SEND, udsServer, eve, INPUT_DEVICE_CAP_KEYBOARD, preHandlerTime);
        if (ret1 != RET_OK) {
            MMI_LOGW("Dispatching ON_SEND event has failed, ret:%{public}d,errCode:%{public}d", ret1,
                SPCL_REG_EVENT_DISP_FAIL);
        }
        ret2 = DispatchRegEvent(MmiMessageId::ON_ENTER, udsServer, eve, INPUT_DEVICE_CAP_KEYBOARD, preHandlerTime);
        if (ret2 != RET_OK) {
            MMI_LOGW("Dispatching ON_ENTER event has failed, ret:%{public}d,errCode:%{public}d", ret2,
                SPCL_REG_EVENT_DISP_FAIL);
        }
    } else if ((key.key == KEY_ESC) && (key.state == KEY_STATE_PRESSED)) {
        ret1 = DispatchRegEvent(MmiMessageId::ON_CANCEL, udsServer, eve, INPUT_DEVICE_CAP_KEYBOARD, preHandlerTime);
        if (ret1 != RET_OK) {
            MMI_LOGW("Dispatching ON_CANCEL event has failed, ret:%{public}d,errCode:%{public}d", ret1,
                SPCL_REG_EVENT_DISP_FAIL);
        }
        ret2 = DispatchRegEvent(MmiMessageId::ON_BACK, udsServer, eve, INPUT_DEVICE_CAP_KEYBOARD, preHandlerTime);
        if (ret2 != RET_OK) {
            MMI_LOGW("Dispatching ON_BACK event has failed, ret:%{public}d,errCode:%{public}d", ret2,
                SPCL_REG_EVENT_DISP_FAIL);
        }
    } else if ((key.key == KEY_BACK) && (key.state == KEY_STATE_PRESSED)) {
        ret1 = DispatchRegEvent(MmiMessageId::ON_CLOSE_PAGE, udsServer,
                                eve, INPUT_DEVICE_CAP_KEYBOARD, preHandlerTime);
        if (ret1 != RET_OK) {
            MMI_LOGW("Dispatching ON_CLOSE_PAGE event has failed, ret:%{public}d,errCode:%{public}d", ret1,
                SPCL_REG_EVENT_DISP_FAIL);
        }
        ret2 = DispatchRegEvent(MmiMessageId::ON_BACK, udsServer, eve, INPUT_DEVICE_CAP_KEYBOARD, preHandlerTime);
        if (ret2 != RET_OK) {
            MMI_LOGW("Dispatching ON_BACK event has failed, ret:%{public}d,errCode:%{public}d", ret2,
                SPCL_REG_EVENT_DISP_FAIL);
        }
    }
    if ((ret1 != RET_OK) || (ret2 != RET_OK)) {
        MMI_LOGE("dispatching special registered event has failed");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t EventDispatch::DispatchTabletPadEvent(UDSServer& udsServer, struct libinput_event *event,
    const EventTabletPad& tabletPad, const int64_t preHandlerTime)
{
    CHKPR(event, ERROR_NULL_POINTER);
    auto device = libinput_event_get_device(event);
    CHKPR(device, ERROR_NULL_POINTER);
    auto focusId = WinMgr->GetFocusSurfaceId();
    if (focusId < 0) {
        MMI_LOGW("Failed to get the focus window");
        return RET_OK;
    }
    auto appInfo = AppRegs->FindWinId(focusId); // obtain application information for focusId
    if (appInfo.fd == RET_ERR) {
        MMI_LOGE("Failed to find fd, errCode:%{public}d", FOCUS_ID_OBTAIN_FAIL);
        return FOCUS_ID_OBTAIN_FAIL;
    }
    MMI_LOGD("4.event dispatcher of server, EventTabletPad:time:%{public}" PRId64 ",deviceType:%{public}u,"
             "deviceName:%{public}s,physical:%{public}s,eventType:%{public}d,"
             "ring.number:%{public}d,ring.position:%{public}lf,ring.source:%{public}d,"
             "strip.number:%{public}d,strip.position:%{public}lf,strip.source:%{public}d,"
             "fd:%{public}d,preHandlerTime:%{public}" PRId64,
             tabletPad.time, tabletPad.deviceType, tabletPad.deviceName,
             tabletPad.physical, tabletPad.eventType, tabletPad.ring.number, tabletPad.ring.position,
             tabletPad.ring.source, tabletPad.strip.number, tabletPad.strip.position, tabletPad.strip.source,
             appInfo.fd, preHandlerTime);

    if (AppRegs->IsMultimodeInputReady(MmiMessageId::ON_TOUCH, appInfo.fd, tabletPad.time, preHandlerTime)) {
        NetPacket pkt(MmiMessageId::ON_TOUCH);
        int32_t inputType = INPUT_DEVICE_CAP_TOUCH_PAD;
        pkt << inputType << tabletPad << appInfo.abilityId << focusId << appInfo.fd << preHandlerTime;
        if (!udsServer.SendMsg(appInfo.fd, pkt)) {
            MMI_LOGE("Sending structure of EventTabletPad failed! errCode:%{public}d", MSG_SEND_FAIL);
            return MSG_SEND_FAIL;
        }
    }
    return RET_OK;
}

int32_t EventDispatch::DispatchJoyStickEvent(UDSServer &udsServer, struct libinput_event *event,
    const EventJoyStickAxis& eventJoyStickAxis, const int64_t preHandlerTime)
{
    CHKPR(event, ERROR_NULL_POINTER);
    auto device = libinput_event_get_device(event);
    CHKPR(device, ERROR_NULL_POINTER);
    auto focusId = WinMgr->GetFocusSurfaceId();
    if (focusId < 0) {
        MMI_LOGW("Failed to get the focus window");
        return RET_OK;
    }
    auto appInfo = AppRegs->FindWinId(focusId); // obtain application information for focusId
    if (appInfo.fd == RET_ERR) {
        MMI_LOGE("Failed to find fd, errCode:%{public}d", FOCUS_ID_OBTAIN_FAIL);
        return FOCUS_ID_OBTAIN_FAIL;
    }
    PrintEventJoyStickAxisInfo(eventJoyStickAxis, appInfo.fd, appInfo.abilityId, focusId, preHandlerTime);

    if (AppRegs->IsMultimodeInputReady(MmiMessageId::ON_TOUCH, appInfo.fd, eventJoyStickAxis.time, preHandlerTime)) {
        NetPacket pkt(MmiMessageId::ON_TOUCH);
        int32_t inputType = INPUT_DEVICE_CAP_JOYSTICK;
        pkt << inputType << eventJoyStickAxis << appInfo.abilityId << focusId << appInfo.fd << preHandlerTime;
        if (!udsServer.SendMsg(appInfo.fd, pkt)) {
            MMI_LOGE("Sending structure of EventJoyStickAxis failed! errCode:%{public}d", MSG_SEND_FAIL);
            return MSG_SEND_FAIL;
        }
    }
    return RET_OK;
}

int32_t EventDispatch::DispatchTabletToolEvent(UDSServer& udsServer, struct libinput_event *event,
    const EventTabletTool& tableTool, const int64_t preHandlerTime)
{
    CHKPR(event, ERROR_NULL_POINTER);
    int32_t focusId = WinMgr->GetFocusSurfaceId(); // obtaining focusId
    if (focusId < 0) {
        MMI_LOGW("Failed to get the focus window");
        return RET_OK;
    }
    // obtain application information for focusId
    auto appInfo = AppRegs->FindWinId(focusId);
    if (appInfo.fd == RET_ERR) {
        MMI_LOGE("Failed to obtain AppInfo, desWindow:%{public}d,errCode:%{public}d", focusId, FOCUS_ID_OBTAIN_FAIL);
        return FOCUS_ID_OBTAIN_FAIL;
    }
    StandardTouchStruct inputEvent = {}; // Standardization handler of struct EventPointer
    standardEvent_.StandardTouchEvent(event, inputEvent);

    if (AppRegs->IsMultimodeInputReady(MmiMessageId::ON_TOUCH, appInfo.fd, tableTool.time, preHandlerTime)) {
        NetPacket pkt(MmiMessageId::ON_TOUCH);
        int32_t inputType = INPUT_DEVICE_CAP_TABLET_TOOL;
        pkt << inputType << inputEvent.curRventType << tableTool << appInfo.abilityId
            << focusId << appInfo.fd << preHandlerTime;
        if (inputEvent.curRventType > 0) {
            pkt << inputEvent;
        }
        MMI_LOGD("4.event dispatcher of server, TabletTool:time:%{public}" PRId64 ","
                 "deviceType:%{public}u,deviceName:%{public}s,physical:%{public}s,eventType:%{public}d,"
                 "type:%{public}u,serial:%{public}u, button:%{public}d,state:%{public}d,"
                 "point.x:%{public}lf,point.y:%{public}lf,tilt.x:%{public}lf,tilt.y:%{public}lf,"
                 "distance:%{public}lf,pressure:%{public}lf,rotation:%{public}lf,slider:%{public}lf,"
                 "wheel:%{public}lf,wheel_discrete:%{public}d,size.major:%{public}lf,size.minor:%{public}lf,"
                 "proximity_state:%{public}d,tip_state:%{public}d,state:%{public}d,seat_button_count:%{public}d,"
                 "preHandlerTime:%{public}" PRId64 ",fd:%{public}d",
                 tableTool.time, tableTool.deviceType, tableTool.deviceName,
                 tableTool.physical, tableTool.eventType, tableTool.tool.type,
                 tableTool.tool.serial, tableTool.button, tableTool.state, tableTool.axes.point.x,
                 tableTool.axes.point.y, tableTool.axes.tilt.x, tableTool.axes.tilt.y, tableTool.axes.distance,
                 tableTool.axes.pressure, tableTool.axes.rotation, tableTool.axes.slider, tableTool.axes.wheel,
                 tableTool.axes.wheel_discrete, tableTool.axes.size.major, tableTool.axes.size.minor,
                 tableTool.proximity_state, tableTool.tip_state, tableTool.state, tableTool.seat_button_count,
                 preHandlerTime, appInfo.fd);
        if (!udsServer.SendMsg(appInfo.fd, pkt)) {
            MMI_LOGE("Sending structure of EventTabletTool failed! errCode:%{public}d", MSG_SEND_FAIL);
            return MSG_SEND_FAIL;
        }
    }
    return RET_OK;
}

bool EventDispatch::HandlePointerEventFilter(std::shared_ptr<PointerEvent> point)
{
    return EventFilterWrap::GetInstance().HandlePointerEventFilter(point);
}

void EventDispatch::HandlePointerEventTrace(const std::shared_ptr<PointerEvent> &point)
{
    if (point->GetSourceType() == PointerEvent::SOURCE_TYPE_MOUSE) {
        int32_t pointerId = point->GetId();
        std::string pointerEvent = "OnEventPointer";
        FinishAsyncTrace(BYTRACE_TAG_MULTIMODALINPUT, pointerEvent, pointerId);
    }
    if (point->GetSourceType() == PointerEvent::SOURCE_TYPE_TOUCHSCREEN) {
        int32_t touchId = point->GetId();
        std::string touchEvent = "OnEventTouch";
        FinishAsyncTrace(BYTRACE_TAG_MULTIMODALINPUT, touchEvent, touchId);
    }
}

int32_t EventDispatch::HandlePointerEvent(std::shared_ptr<PointerEvent> point)
{
    CHKPR(point, ERROR_NULL_POINTER);
    auto fd = WinMgr->UpdateTargetPointer(point);
    if (HandlePointerEventFilter(point)) {
        MMI_LOGI("Pointer event interception succeeded");
        return RET_OK;
    }
    if (InputHandlerManagerGlobal::GetInstance().HandleEvent(point)) {
        HandlePointerEventTrace(point);
        return RET_OK;
    }
    NetPacket pkt(MmiMessageId::ON_POINTER_EVENT);
    InputEventDataTransformation::Marshalling(point, pkt);
    HandlePointerEventTrace(point);
    auto udsServer = InputHandler->GetUDSServer();
    if (udsServer == nullptr) {
        MMI_LOGE("UdsServer is a nullptr");
        return RET_ERR;
    }
    if (fd < 0) {
        MMI_LOGE("The fd less than 0");
        return RET_ERR;
    }

    if (!udsServer->SendMsg(fd, pkt)) {
        MMI_LOGE("Sending structure of EventTouch failed! errCode:%{public}d", MSG_SEND_FAIL);
        return RET_ERR;
    }
    return RET_OK;
}

int32_t EventDispatch::DispatchTouchTransformPointEvent(UDSServer& udsServer,
    std::shared_ptr<PointerEvent> point)
{
    MMI_LOGD("enter");
    CHKPR(point, ERROR_NULL_POINTER);
    InputHandlerManagerGlobal::GetInstance().HandleEvent(point);
    auto appInfo = AppRegs->FindWinId(point->GetAgentWindowId()); // obtain application information
    if (appInfo.fd == RET_ERR) {
        MMI_LOGE("Failed to find fd, errCode:%{public}d", FOCUS_ID_OBTAIN_FAIL);
        return FOCUS_ID_OBTAIN_FAIL;
    }
    NetPacket pkt(MmiMessageId::ON_POINTER_EVENT);
    InputEventDataTransformation::Marshalling(point, pkt);
    if (!udsServer.SendMsg(appInfo.fd, pkt)) {
        MMI_LOGE("Sending structure of EventTouch failed! errCode:%{public}d", MSG_SEND_FAIL);
        return MSG_SEND_FAIL;
    }
    MMI_LOGD("call  DispatchTouchTransformPointEvent leave");
    return RET_OK;
}

int32_t EventDispatch::DispatchPointerEvent(UDSServer &udsServer, struct libinput_event *event,
    EventPointer &point, const int64_t preHandlerTime)
{
    CHKPR(event, ERROR_NULL_POINTER);
    auto device = libinput_event_get_device(event);
    CHKPR(device, ERROR_NULL_POINTER);
    int32_t desWindowId = WinMgr->GetFocusSurfaceId(); // obtaining focusId
    if (desWindowId < 0) {
        MMI_LOGW("Failed to get focus surface, desWindow:%{public}d", desWindowId);
        return RET_OK;
    }
    // obtain application information for focusId
    auto appInfo = AppRegs->FindWinId(desWindowId);
    if (appInfo.fd == RET_ERR) {
        MMI_LOGE("Failed to find focus");
        return FOCUS_ID_OBTAIN_FAIL;
    }
    StandardTouchStruct inputEvent = {}; // Standardization handler of struct EventPointer
    standardEvent_.StandardTouchEvent(event, inputEvent);

    if (AppRegs->IsMultimodeInputReady(MmiMessageId::ON_TOUCH, appInfo.fd, point.time, preHandlerTime)) {
        KeyEventValueTransformations KeyEventValue = {};
        KeyEventValue = KeyValueTransformationInput(point.button);
        point.button = KeyEventValue.keyValueOfSys;
        NetPacket pkt(MmiMessageId::ON_TOUCH);
        int32_t inputType = INPUT_DEVICE_CAP_POINTER;
        pkt << inputType << inputEvent.curRventType << point << appInfo.abilityId
            << desWindowId << appInfo.fd << preHandlerTime;
        if (inputEvent.curRventType > 0) {
            pkt << inputEvent;
        }
        MMI_LOGD("4.event dispatcher of server, eventPointer:time:%{public}" PRId64 ",deviceType:%{public}u,"
                 "deviceName:%{public}s,physical:%{public}s,eventType:%{public}d,"
                 "buttonCode:%{public}u,seat_button_count:%{public}u,axis:%{public}u,buttonState:%{public}d,"
                 "source:%{public}d,delta.x:%{public}lf,delta.y:%{public}lf,delta_raw.x:%{public}lf,"
                 "delta_raw.y:%{public}lf,absolute.x:%{public}lf,absolute.y:%{public}lf,discrete.x:%{public}lf,"
                 "discrete.y:%{public}lf,fd:%{public}d,preHandlerTime:%{public}" PRId64,
                 point.time, point.deviceType, point.deviceName,
                 point.physical, point.eventType, point.button, point.seat_button_count, point.axis,
                 point.state, point.source, point.delta.x, point.delta.y, point.delta_raw.x,
                 point.delta_raw.y, point.absolute.x, point.absolute.y, point.discrete.x,
                 point.discrete.y, appInfo.fd, preHandlerTime);
        if (!udsServer.SendMsg(appInfo.fd, pkt)) {
            MMI_LOGE("Sending structure of EventPointer failed! errCode:%{public}d", MSG_SEND_FAIL);
            return MSG_SEND_FAIL;
        }
    }
    return RET_OK;
}

int32_t EventDispatch::DispatchGestureEvent(UDSServer& udsServer, struct libinput_event *event,
    const EventGesture& gesture, const int64_t preHandlerTime)
{
    CHKPR(event, ERROR_NULL_POINTER);
    auto device = libinput_event_get_device(event);
    CHKPR(device, ERROR_NULL_POINTER);

    MmiMessageId idMsg = MmiMessageId::INVALID;
    MMIRegEvent->OnEventGestureGetSign(gesture, idMsg);
    if (idMsg != MmiMessageId::INVALID) {
        RegisteredEvent registeredEvent = {};
        auto packageResult = eventPackage_.PackageRegisteredEvent<EventGesture>(gesture, registeredEvent);
        if (packageResult != RET_OK) {
            MMI_LOGE("Registered event package failed, ret:%{public}d,errCode:%{public}d",
                packageResult, REG_EVENT_PKG_FAIL);
        }
        auto ret = GestureRegisteredEventDispatch(idMsg, udsServer, registeredEvent, preHandlerTime);
        if (ret != RET_OK) {
            MMI_LOGE("Gesture Swipe dispatch failed return:%{public}d,errCode:%{public}d",
                ret, REG_EVENT_DISP_FAIL);
        }
    }

    auto focusId = WinMgr->GetFocusSurfaceId();
    if (focusId < 0) {
        MMI_LOGE("Focus Id is invalid! errCode:%{public}d", FOCUS_ID_OBTAIN_FAIL);
        return RET_OK;
    }
    auto appInfo = AppRegs->FindWinId(focusId); // obtain application information
    if (appInfo.fd == RET_ERR) {
        MMI_LOGD("Failed to find fd, errCode:%{public}d", FOCUS_ID_OBTAIN_FAIL);
        return FOCUS_ID_OBTAIN_FAIL;
    }

    MMI_LOGD("4.event dispatcher of server, EventGesture:time:%{public}" PRId64 ",deviceType:%{public}u,"
             "deviceName:%{public}s,physical:%{public}s,eventType:%{public}d,"
             "fingerCount:%{public}d,cancelled:%{public}d,delta.x:%{public}lf,delta.y:%{public}lf,"
             "deltaUnaccel.x:%{public}lf,deltaUnaccel.y:%{public}lf,fd:%{public}d,"
             "preHandlerTime:%{public}" PRId64,
             gesture.time, gesture.deviceType, gesture.deviceName, gesture.physical,
             gesture.eventType, gesture.fingerCount, gesture.cancelled, gesture.delta.x, gesture.delta.y,
             gesture.deltaUnaccel.x, gesture.deltaUnaccel.y, appInfo.fd, preHandlerTime);
    PrintEventSlotedCoordsInfo(gesture.soltTouches);

    if (AppRegs->IsMultimodeInputReady(MmiMessageId::ON_TOUCH, appInfo.fd, gesture.time, preHandlerTime)) {
        NetPacket pkt(MmiMessageId::ON_TOUCH);
        int32_t inputType = INPUT_DEVICE_CAP_GESTURE;
        pkt << inputType << gesture << appInfo.abilityId << focusId << appInfo.fd << preHandlerTime;
        if (!udsServer.SendMsg(appInfo.fd, pkt)) {
            MMI_LOGE("Sending structure of EventGesture failed! errCode:%{public}d", MSG_SEND_FAIL);
            return MSG_SEND_FAIL;
        }
    }
    return RET_OK;
}

int32_t EventDispatch::DispatchTouchEvent(const EventTouch& touch, const int fd,
    const int64_t preHandlerTime, UDSServer& udsServer, NetPacket &newPacket) const
{
    std::vector<std::pair<uint32_t, int32_t>> touchIds;
    MMIRegEvent->GetTouchIds(touch.deviceId, touchIds);
    if (!touchIds.empty()) {
        for (auto &touchId : touchIds) {
            EventTouch touchTemp = {};
            errno_t retErr = memcpy_s(&touchTemp, sizeof(touchTemp), &touch, sizeof(touch));
            CHKR(retErr == EOK, MEMCPY_SEC_FUN_FAIL, RET_ERR);
            MMIRegEvent->GetTouchInfo(touchId, touchTemp);
            MMI_LOGT("4.event dispatcher of server, eventTouch:time:%{public}" PRId64 ",deviceType:%{public}u,"
                        "deviceName:%{public}s,physical:%{public}s,eventType:%{public}d,"
                        "slot:%{public}d,seatSlot:%{public}d,pressure:%{public}lf,point.x:%{public}lf,"
                        "point.y:%{public}lf,fd:%{public}d,preHandlerTime:%{public}" PRId64,
                        touchTemp.time, touchTemp.deviceType, touchTemp.deviceName,
                        touchTemp.physical, touchTemp.eventType, touchTemp.slot, touchTemp.seatSlot,
                        touchTemp.pressure, touchTemp.point.x, touchTemp.point.y, fd,
                        preHandlerTime);
            newPacket << touchTemp;
        }
    }
    if (touch.eventType == LIBINPUT_EVENT_TOUCH_UP) {
        newPacket << touch;
        MMI_LOGT("4.event dispatcher of server, eventTouch:time:%{public}" PRId64 ",deviceType:%{public}u,"
                    "deviceName:%{public}s,physical:%{public}s,eventType:%{public}d,"
                    "slot:%{public}d,seatSlot:%{public}d,pressure:%{public}lf,point.x:%{public}lf,"
                    "point.y:%{public}lf,fd:%{public}d,preHandlerTime:%{public}" PRId64,
                    touch.time, touch.deviceType, touch.deviceName,
                    touch.physical, touch.eventType, touch.slot, touch.seatSlot, touch.pressure,
                    touch.point.x, touch.point.y, fd, preHandlerTime);
    }
    if (!udsServer.SendMsg(fd, newPacket)) {
        MMI_LOGE("Sending structure of EventTouch failed! errCode:%{public}d", MSG_SEND_FAIL);
        return MSG_SEND_FAIL;
    }
    return RET_OK;
}

int32_t EventDispatch::DispatchTouchEvent(UDSServer& udsServer, struct libinput_event *event,
    const EventTouch& touch, const int64_t preHandlerTime)
{
    CHKPR(event, ERROR_NULL_POINTER);
    auto device = libinput_event_get_device(event);
    CHKPR(device, ERROR_NULL_POINTER);
    int32_t ret = RET_OK;
    MmiMessageId idMsg = MmiMessageId::INVALID;
    MMIRegEvent->OnEventTouchGetSign(touch, idMsg);
    if (idMsg != MmiMessageId::INVALID) {
        RegisteredEvent registeredEvent = {};
        auto packageResult = eventPackage_.PackageRegisteredEvent<EventTouch>(touch, registeredEvent);
        if (packageResult != RET_OK) {
            MMI_LOGE("Registered event package failed, ret:%{public}d,errCode:%{public}d",
                packageResult, REG_EVENT_PKG_FAIL);
        }
        ret = DispatchRegEvent(idMsg, udsServer, registeredEvent, INPUT_DEVICE_CAP_TOUCH, preHandlerTime);
        if (ret != RET_OK) {
            MMI_LOGE("Touch comb dispatch failed return:%{public}d,errCode:%{public}d",
                ret, REG_EVENT_DISP_FAIL);
        }
    }
    int32_t touchFocusId = WinMgr->GetTouchFocusSurfaceId();
    auto appInfo = AppRegs->FindWinId(touchFocusId); // obtain application information
    if (appInfo.fd == RET_ERR) {
        MMI_LOGE("Failed to find fd:%{public}d,errCode:%{public}d", touchFocusId, FOCUS_ID_OBTAIN_FAIL);
        return FOCUS_ID_OBTAIN_FAIL;
    }
    MMI_LOGD("DispatchTouchEvent focusId:%{public}d,fd:%{public}d", touchFocusId, appInfo.fd);
    if (AppRegs->IsMultimodeInputReady(MmiMessageId::ON_TOUCH, appInfo.fd, touch.time, preHandlerTime)) {
        NetPacket pkt(MmiMessageId::ON_TOUCH);
        int32_t fingerCount = MMIRegEvent->GetTouchInfoSizeDeviceId(touch.deviceId);
        if (touch.eventType == LIBINPUT_EVENT_TOUCH_UP) {
            fingerCount++;
        }
        int32_t inputType = INPUT_DEVICE_CAP_TOUCH;
        pkt << inputType << fingerCount;
        POINT_EVENT_TYPE pointEventType = EVENT_TYPE_INVALID;
        OnEventTouchGetPointEventType(touch, fingerCount, pointEventType);
        int32_t eventType = pointEventType;
        pkt << eventType << appInfo.abilityId << touchFocusId << appInfo.fd << preHandlerTime << touch.seatSlot;
        ret = DispatchTouchEvent(touch, appInfo.fd, preHandlerTime, udsServer, pkt);
    }
    return ret;
}

int32_t EventDispatch::DispatchCommonPointEvent(UDSServer& udsServer, struct libinput_event *event,
    const EventPointer& point, const int64_t preHandlerTime)
{
    CHKPR(event, ERROR_NULL_POINTER);
    auto device = libinput_event_get_device(event);
    auto type = libinput_event_get_type(event);
    CHKPR(device, ERROR_NULL_POINTER);

    int32_t ret = RET_OK;
    MmiMessageId idMsg = MmiMessageId::INVALID;
    if (type == LIBINPUT_EVENT_POINTER_BUTTON) {
        MMIRegEvent->OnEventPointButton(point.button, point.time, point.state, idMsg);
    }
    if (type == LIBINPUT_EVENT_POINTER_AXIS) {
        MMIRegEvent->OnEventPointAxis(point, idMsg);
    }
    if (idMsg != MmiMessageId::INVALID) {
        RegisteredEvent registeredEvent = {};
        auto packageResult = eventPackage_.PackageRegisteredEvent<EventPointer>(point, registeredEvent);
        if (packageResult != RET_OK) {
            MMI_LOGE("Registered event package failed, ret:%{public}d,errCode:%{public}d",
                packageResult, REG_EVENT_PKG_FAIL);
        }
        SysEveHdl->OnSystemEventHandler(idMsg);
        ret = DispatchRegEvent(idMsg, udsServer, registeredEvent, INPUT_DEVICE_CAP_POINTER, preHandlerTime);
        if (ret != RET_OK) {
            MMI_LOGE("key comb dispatch failed return:%{public}d,errCode:%{public}d",
                ret, REG_EVENT_DISP_FAIL);
        }
    }
    return ret;
}

void EventDispatch::OnKeyboardEventTrace(const std::shared_ptr<KeyEvent> &key, IsEventHandler isEventHandler)
{
    MMI_LOGD("enter");
    int32_t keyCode = key->GetKeyCode();
    std::string checkKeyCode;
    if (isEventHandler == KEY_FILTER_EVENT) {
        checkKeyCode = "key intercept service GetKeyCode=" + std::to_string(keyCode);
        MMI_LOGD("key intercept service trace GetKeyCode:%{public}d", keyCode);
    } else if (isEventHandler == KEY_CHECKLAUNABILITY_EVENT) {
        checkKeyCode = "CheckLaunchAbility service GetKeyCode=" + std::to_string(keyCode);
        MMI_LOGD("CheckLaunchAbility service trace GetKeyCode:%{public}d", keyCode);
    } else if (isEventHandler == KEY_SUBSCRIBE_EVENT) {
        checkKeyCode = "SubscribeKeyEvent service GetKeyCode=" + std::to_string(keyCode);
        MMI_LOGD("SubscribeKeyEvent service trace GetKeyCode:%{public}d", keyCode);
    } else {
        checkKeyCode = "DispatchKeyEvent service GetKeyCode=" + std::to_string(keyCode);
        MMI_LOGD("DispatchKeyEvent service trace GetKeyCode:%{public}d", keyCode);
    }
    BYTRACE_NAME(BYTRACE_TAG_MULTIMODALINPUT, checkKeyCode);
    int32_t keyId = key->GetId();
    const std::string keyEventString = "OnKeyEvent";
    FinishAsyncTrace(BYTRACE_TAG_MULTIMODALINPUT, keyEventString, keyId);
}

int32_t EventDispatch::DispatchKeyEventPid(UDSServer& udsServer,
    std::shared_ptr<KeyEvent> key, const int64_t preHandlerTime)
{
    MMI_LOGD("begin");
    CHKPR(key, PARAM_INPUT_INVALID);
    if (!key->HasFlag(InputEvent::EVENT_FLAG_NO_INTERCEPT)) {
        if (InterceptorMgrGbl.OnKeyEvent(key)) {
            MMI_LOGD("keyEvent filter find a keyEvent from Original event keyCode: %{puiblic}d",
                key->GetKeyCode());
            OnKeyboardEventTrace(key, KEY_FILTER_EVENT);
            return RET_OK;
        }
    }
    if (AbilityMgr->CheckLaunchAbility(key)) {
        MMI_LOGD("The keyEvent start launch an ability, keyCode:%{public}d", key->GetKeyCode());
        OnKeyboardEventTrace(key, KEY_CHECKLAUNABILITY_EVENT);
        return RET_OK;
    }
    if (KeyEventSubscriber_.SubscribeKeyEvent(key)) {
        MMI_LOGD("Subscribe keyEvent filter success. keyCode:%{public}d", key->GetKeyCode());
        OnKeyboardEventTrace(key, KEY_SUBSCRIBE_EVENT);
        return RET_OK;
    }
    auto fd = WinMgr->UpdateTarget(key);
    CHKR(fd >= 0, FD_OBTAIN_FAIL, RET_ERR);

    MMI_LOGD("4.event dispatcher of server:KeyEvent:KeyCode:%{public}d,"
             "ActionTime:%{public}" PRId64 ",Action:%{public}d,ActionStartTime:%{public}" PRId64 ","
             "EventType:%{public}d,Flag:%{public}u,"
             "KeyAction:%{public}d,Fd:%{public}d,PreHandlerTime:%{public}" PRId64 "",
             key->GetKeyCode(), key->GetActionTime(), key->GetAction(),
             key->GetActionStartTime(),
             key->GetEventType(),
             key->GetFlag(), key->GetKeyAction(), fd, preHandlerTime);

    InputHandlerManagerGlobal::GetInstance().HandleEvent(key);
    NetPacket pkt(MmiMessageId::ON_KEYEVENT);
    InputEventDataTransformation::KeyEventToNetPacket(key, pkt);
    OnKeyboardEventTrace(key, KEY_DISPATCH_EVENT);
    pkt << fd << preHandlerTime;
    if (!udsServer.SendMsg(fd, pkt)) {
        MMI_LOGE("Sending structure of EventKeyboard failed! errCode:%{public}d", MSG_SEND_FAIL);
        return MSG_SEND_FAIL;
    }
    MMI_LOGD("end");
    return RET_OK;
}

int32_t EventDispatch::DispatchKeyEvent(UDSServer& udsServer, struct libinput_event *event,
    const KeyEventValueTransformations& trs, EventKeyboard& key, const int64_t preHandlerTime)
{
    CHKPR(event, ERROR_NULL_POINTER);
    auto device = libinput_event_get_device(event);
    CHKPR(device, ERROR_NULL_POINTER);

    int32_t ret = RET_OK;
    ret = KeyBoardRegEveHandler(key, udsServer, event, INPUT_DEVICE_CAP_KEYBOARD, preHandlerTime);
    if (ret != RET_OK) {
        MMI_LOGE("Special Registered Event dispatch failed, ret:%{public}d,errCode:%{public}d", ret,
            SPCL_REG_EVENT_DISP_FAIL);
    }
    MmiMessageId idMsg = MmiMessageId::INVALID;
    EventKeyboard prevKey = {};
    MMIRegEvent->OnEventKeyGetSign(key, idMsg, prevKey);
    if (MmiMessageId::INVALID != idMsg) {
        RegisteredEvent registeredEvent = {};
        auto result = eventPackage_.PackageRegisteredEvent<EventKeyboard>(prevKey, registeredEvent);
        if (result != RET_OK) {
            MMI_LOGE("Registered event package failed. ret:%{public}d,errCode:%{public}d", result, REG_EVENT_PKG_FAIL);
        }
        ret = DispatchRegEvent(idMsg, udsServer, registeredEvent, INPUT_DEVICE_CAP_KEYBOARD, preHandlerTime);
        if (ret != RET_OK) {
            MMI_LOGE("Registered Event dispatch failed. ret:%{public}d,errCode:%{public}d", ret, REG_EVENT_DISP_FAIL);
        }
    }
    auto focusId = WinMgr->GetFocusSurfaceId();
    if (focusId < 0) {
        MMI_LOGE("Don't find focus window, so the event will be discarded. errCode:%{public}d", FOCUS_ID_OBTAIN_FAIL);
        return RET_OK;
    }
    auto appInfo = AppRegs->FindWinId(focusId); // obtain application information for focusId
    if (appInfo.fd == RET_ERR) {
        MMI_LOGE("Failed to find, fd:%{public}d,errCode:%{public}d", focusId, FOCUS_ID_OBTAIN_FAIL);
        return FOCUS_ID_OBTAIN_FAIL;
    }
    key.key = trs.keyValueOfSys; // struct EventKeyboard tranformed into L3

    MMI_LOGD("4.event dispatcher of server, eventKeyboard:time:%{public}" PRId64 ",deviceType:%{public}u,"
             "deviceName:%{public}s,physical:%{public}s,eventType:%{public}d,unicode:%{public}d,key:%{public}u,"
             "key_detail:%{public}s,seat_key_count:%{public}u,state:%{public}d,fd:%{public}d,"
             "preHandlerTime:%{public}" PRId64, key.time, key.deviceType, key.deviceName, key.physical,
             key.eventType, key.unicode, key.key, trs.keyEvent.c_str(), key.seat_key_count, key.state, appInfo.fd,
             preHandlerTime);
    if (AppRegs->IsMultimodeInputReady(MmiMessageId::ON_KEY, appInfo.fd, key.time, preHandlerTime)) {
        NetPacket pkt(MmiMessageId::ON_KEY);
        pkt << key << appInfo.abilityId << focusId << appInfo.fd << preHandlerTime;
        if (!udsServer.SendMsg(appInfo.fd, pkt)) {
            MMI_LOGE("Sending structure of EventKeyboard failed! errCode:%{public}d", MSG_SEND_FAIL);
            return MSG_SEND_FAIL;
        }
    }
    return ret;
}

int32_t EventDispatch::AddInputEventFilter(sptr<IEventFilter> filter)
{
    return EventFilterWrap::GetInstance().AddInputEventFilter(filter);
}

int32_t EventDispatch::DispatchGestureNewEvent(UDSServer& udsServer, struct libinput_event *event,
    std::shared_ptr<PointerEvent> pointerEvent, const int64_t preHandlerTime)
{
    CHKPR(event, ERROR_NULL_POINTER);
    auto device = libinput_event_get_device(event);
    CHKPR(device, ERROR_NULL_POINTER);

    auto focusId = WinMgr->GetFocusSurfaceId();
    if (focusId < 0) {
        MMI_LOGW("Failed to get focus surface, focus:%{public}d", focusId);
        return RET_OK;
    }
    auto appInfo = AppRegs->FindWinId(focusId); // obtain application information
    if (appInfo.fd == RET_ERR) {
        MMI_LOGE("Failed to find fd, errCode:%{public}d", FOCUS_ID_OBTAIN_FAIL);
        return FOCUS_ID_OBTAIN_FAIL;
    }

    pointerEvent->SetTargetWindowId(focusId);

    std::vector<int32_t> pointerIds { pointerEvent->GetPointersIdList() };
    MMI_LOGD("Pointer event dispatcher of server:eventType:%{public}d,actionTime:%{public}" PRId64 ","
             "action:%{public}d,actionStartTime:%{public}" PRId64 ","
             "flag:%{public}u,pointerAction:%{public}d,sourceType:%{public}d,"
             "VerticalAxisValue:%{public}.02f, HorizontalAxisValue:%{public}.02f,"
             "pointerCount:%{public}zu",
             pointerEvent->GetEventType(), pointerEvent->GetActionTime(),
             pointerEvent->GetAction(), pointerEvent->GetActionStartTime(),
             pointerEvent->GetFlag(), pointerEvent->GetPointerAction(),
             pointerEvent->GetSourceType(),
             pointerEvent->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL),
             pointerEvent->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL),
             pointerIds.size());

    for (const auto &pointerId : pointerIds) {
        OHOS::MMI::PointerEvent::PointerItem item;
        CHKR(pointerEvent->GetPointerItem(pointerId, item), PARAM_INPUT_FAIL, RET_ERR);

        MMI_LOGD("\tdownTime:%{public}" PRId64 ",isPressed:%{public}s,"
                 "globalX:%{public}d,globalY:%{public}d,localX:%{public}d,localY:%{public}d,"
                 "width:%{public}d,height:%{public}d,pressure:%{public}d",
                 item.GetDownTime(), (item.IsPressed() ? "true" : "false"),
                 item.GetGlobalX(), item.GetGlobalY(), item.GetLocalX(), item.GetLocalY(),
                 item.GetWidth(), item.GetHeight(), item.GetPressure());
    }

    NetPacket pkt(MmiMessageId::ON_POINTER_EVENT);
    InputEventDataTransformation::Marshalling(pointerEvent, pkt);
    pkt << appInfo.fd << preHandlerTime;
    if (!udsServer.SendMsg(appInfo.fd, pkt)) {
        MMI_LOGE("Sending structure of PointerEvent failed! errCode:%{public}d", MSG_SEND_FAIL);
        return MSG_SEND_FAIL;
    }
    return RET_OK;
}

bool EventDispatch::IsANRProcess(int64_t time, SessionPtr ss)
{
    int64_t firstTime;
    if (ss->EventsIsEmpty()) {
        firstTime = time;
    } else {
        firstTime = ss->GetFirstEventTime();
    }

    if (time < (firstTime + INPUT_UI_TIMEOUT_TIME)) {
        ss->isANRProcess_ = false;
        MMI_LOGI("the event reports normally");
        return false;
    }

    int32_t ret = OHOS::HiviewDFX::HiSysEvent::Write(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "APPLICATION_BLOCK_INPUT",
        OHOS::HiviewDFX::HiSysEvent::EventType::FAULT,
        "PID", ss->GetPid(),
        "UID", ss->GetUid(),
        "PACKAGE_NAME", "",
        "PROCESS_NAME", "",
        "MSG", "failed to dispatch pointer or key events of multimodalinput");
    if (ret != 0) {
        MMI_LOGE("HiviewDFX Write failed, HiviewDFX errCode: %{public}d", ret);
    }

    ret = OHOS::AAFwk::AbilityManagerClient::GetInstance()->SendANRProcessID(ss->GetPid());
    if (ret != 0) {
        MMI_LOGE("AAFwk SendANRProcessID failed, AAFwk errCode: %{public}d", ret);
    }
    return true;
}
} // namespace MMI
} // namespace OHOS