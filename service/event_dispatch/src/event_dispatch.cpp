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

#include "event_dispatch.h"
#include <inttypes.h>
#include "input-event-codes.h"
#include "ability_launch_manager.h"
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
constexpr int32_t INPUT_UI_TIMEOUT_TIME = 5 * 1000000;
constexpr int32_t INPUT_UI_TIMEOUT_TIME_MAX = 20 * 1000000;
constexpr int32_t TRIGGER_ANR = 0;
constexpr int32_t NOT_TRIGGER_ANR = 1;
    namespace {
        constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "EventDispatch" };
    }

static void PrintEventSlotedCoordsInfo(const SlotedCoordsInfo& r)
{
    using namespace OHOS::MMI;
    for (int32_t i = 0; i < MAX_SOLTED_COORDS_NUMS; i++) {
        MMI_LOGT("[%{public}d] isActive:%{public}d,x:%{public}f,y:%{public}f",
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
                                                      uint64_t preHandlerTime)
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
    const RegisteredEvent& registeredEvent, int32_t inputDeviceType, uint64_t preHandlerTime)
{
    CHKR(idMsg > MmiMessageId::INVALID, PARAM_INPUT_INVALID, PARAM_INPUT_INVALID);
    std::vector<int32_t> fds;
    RegEventHM->FindSocketFds(idMsg, fds);
    if (fds.empty()) {
        MMI_LOGW("Yet none of socketFds is found");
        return RET_OK;
    }

    for (const auto& fd : fds) {
        auto appInfo = AppRegs->FindBySocketFd(fd);
        MMI_LOGT("Event dispatcher of server, RegisteredEvent:physical:%{public}s,"
                 "deviceType:%{public}u,eventType:%{public}u,occurredTime:%{public}" PRId64 ","
                 "conbinecode:%{public}d,fd:%{public}d",
                 registeredEvent.physical, registeredEvent.deviceType,
                 registeredEvent.eventType, registeredEvent.occurredTime,
                 idMsg, fd);

        if (AppRegs->IsMultimodeInputReady(idMsg, fd, registeredEvent.occurredTime, preHandlerTime)) {
            NetPacket newPacket(idMsg);
            int32_t type = inputDeviceType;
            newPacket << type << registeredEvent << fd << appInfo.windowId << appInfo.abilityId << preHandlerTime;
            CHKR(udsServer.SendMsg(fd, newPacket), MSG_SEND_FAIL, MSG_SEND_FAIL);
        }
    }
    return RET_OK;
}

int32_t EventDispatch::KeyBoardRegEveHandler(const EventKeyboard& key, UDSServer& udsServer,
    libinput_event *event, int32_t inputDeviceType, uint64_t preHandlerTime)
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
    if ((ret1 == RET_OK) && (ret2 == RET_OK)) {
        return RET_OK;
    } else {
        MMI_LOGE("dispatching special registered event has failed");
        return RET_ERR;
    }
}

int32_t EventDispatch::DispatchTabletPadEvent(UDSServer& udsServer, libinput_event *event,
    const EventTabletPad& tabletPad, const uint64_t preHandlerTime)
{
    CHKPR(event, ERROR_NULL_POINTER);
    auto device = libinput_event_get_device(event);
    CHKPR(device, ERROR_NULL_POINTER);
#ifdef DEBUG_CODE_TEST
    std::string str = WinMgr->GetSurfaceIdListString();
#endif

    auto focusId = WinMgr->GetFocusSurfaceId();
    if (focusId < 0) {
        return RET_OK;
    }
    auto appInfo = AppRegs->FindByWinId(focusId); // obtain application information for focusId
    if (appInfo.fd == RET_ERR) {
        MMI_LOGE("Failed to find fd, errCode:%{public}d", FOCUS_ID_OBTAIN_FAIL);
        return FOCUS_ID_OBTAIN_FAIL;
    }
#ifdef DEBUG_CODE_TEST
    MMI_LOGT("MMIWMS:windowId:%{public}s", str.c_str());
    if (focusId == -1) {
        MMI_LOGT("WMS:windowId = ''");
    } else {
        MMI_LOGT("WMS:windowId:%{public}d", focusId);
    }
    MMI_LOGT("CALL_AMS, MMIAPPM:fd :%{public}d,abilityID:%{public}d", appInfo.fd, appInfo.abilityId);
#endif

    MMI_LOGT("4.event dispatcher of server, EventTabletPad:time:%{public}" PRId64 ",deviceType:%{public}u,"
             "deviceName:%{public}s,physical:%{public}s,eventType:%{public}d,"
             "ring.number:%{public}d,ring.position:%{public}lf,ring.source:%{public}d,"
             "strip.number:%{public}d,strip.position:%{public}lf,strip.source:%{public}d,"
             "fd:%{public}d,preHandlerTime:%{public}" PRId64,
             tabletPad.time, tabletPad.deviceType, tabletPad.deviceName,
             tabletPad.physical, tabletPad.eventType, tabletPad.ring.number, tabletPad.ring.position,
             tabletPad.ring.source, tabletPad.strip.number, tabletPad.strip.position, tabletPad.strip.source,
             appInfo.fd, preHandlerTime);

    if (AppRegs->IsMultimodeInputReady(MmiMessageId::ON_TOUCH, appInfo.fd, tabletPad.time, preHandlerTime)) {
        NetPacket newPacket(MmiMessageId::ON_TOUCH);
        int32_t inputType = INPUT_DEVICE_CAP_TOUCH_PAD;
        newPacket << inputType << tabletPad << appInfo.abilityId << focusId << appInfo.fd << preHandlerTime;
        if (!udsServer.SendMsg(appInfo.fd, newPacket)) {
            MMI_LOGE("Sending structure of EventTabletPad failed! errCode:%{public}d", MSG_SEND_FAIL);
            return MSG_SEND_FAIL;
        }
    }
    return RET_OK;
}

int32_t EventDispatch::DispatchJoyStickEvent(UDSServer &udsServer, libinput_event *event,
    const EventJoyStickAxis& eventJoyStickAxis, const uint64_t preHandlerTime)
{
    CHKPR(event, ERROR_NULL_POINTER);
    auto device = libinput_event_get_device(event);
    CHKPR(device, ERROR_NULL_POINTER);
    auto focusId = WinMgr->GetFocusSurfaceId();
    if (focusId < 0) {
        return RET_OK;
    }
    auto appInfo = AppRegs->FindByWinId(focusId); // obtain application information for focusId
    if (appInfo.fd == RET_ERR) {
        MMI_LOGE("Failed to find fd, errCode:%{public}d", FOCUS_ID_OBTAIN_FAIL);
        return FOCUS_ID_OBTAIN_FAIL;
    }
#ifdef DEBUG_CODE_TEST
    std::string str = WinMgr->GetSurfaceIdListString();
    PrintWMSInfo(str, appInfo.fd, appInfo.abilityId, focusId);
#endif
    PrintEventJoyStickAxisInfo(eventJoyStickAxis, appInfo.fd, appInfo.abilityId, focusId, preHandlerTime);

    if (AppRegs->IsMultimodeInputReady(MmiMessageId::ON_TOUCH, appInfo.fd, eventJoyStickAxis.time, preHandlerTime)) {
        NetPacket newPacket(MmiMessageId::ON_TOUCH);
        int32_t inputType = INPUT_DEVICE_CAP_JOYSTICK;
        newPacket << inputType << eventJoyStickAxis << appInfo.abilityId << focusId << appInfo.fd << preHandlerTime;
        if (!udsServer.SendMsg(appInfo.fd, newPacket)) {
            MMI_LOGE("Sending structure of EventJoyStickAxis failed! errCode:%{public}d", MSG_SEND_FAIL);
            return MSG_SEND_FAIL;
        }
    }
    return RET_OK;
}

int32_t EventDispatch::DispatchTabletToolEvent(UDSServer& udsServer, libinput_event *event,
    const EventTabletTool& tableTool, const uint64_t preHandlerTime)
{
    CHKPR(event, ERROR_NULL_POINTER);
    int32_t focusId = WinMgr->GetFocusSurfaceId(); // obtaining focusId
    if (focusId < 0) {
        return RET_OK;
    }
    // obtain application information for focusId
    auto appInfo = AppRegs->FindByWinId(focusId);
    if (appInfo.fd == RET_ERR) {
        return FOCUS_ID_OBTAIN_FAIL;
    }
    StandardTouchStruct inputEvent = {}; // Standardization handler of struct EventPointer
    standardEvent_.StandardTouchEvent(event, inputEvent);

    if (AppRegs->IsMultimodeInputReady(MmiMessageId::ON_TOUCH, appInfo.fd, tableTool.time, preHandlerTime)) {
        NetPacket newPacket(MmiMessageId::ON_TOUCH);
        int32_t inputType = INPUT_DEVICE_CAP_TABLET_TOOL;
        newPacket << inputType << inputEvent.curRventType << tableTool << appInfo.abilityId
            << focusId << appInfo.fd << preHandlerTime;
        if (inputEvent.curRventType > 0) {
            newPacket << inputEvent;
        }

#ifdef DEBUG_CODE_TEST
        std::string strIds = WinMgr->GetSurfaceIdListString();
        PrintWMSInfo(strIds, appInfo.fd, appInfo.abilityId, focusId);
#endif
        MMI_LOGT("4.event dispatcher of server, TabletTool:time:%{public}" PRId64 ","
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
        if (!udsServer.SendMsg(appInfo.fd, newPacket)) {
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

int32_t EventDispatch::HandlePointerEvent(std::shared_ptr<PointerEvent> point)
{
    MMI_LOGD("Enter");
    CHKPR(point, ERROR_NULL_POINTER);
    auto fd = WinMgr->UpdateTargetPointer(point);
    if (HandlePointerEventFilter(point)) {
        MMI_LOGI("Pointer event interception succeeded");
        return RET_OK;
    }
    if (!point->NeedSkipInspection() &&
        InputHandlerManagerGlobal::GetInstance().HandleEvent(point)) {
        int32_t pointerFilter = 1;
        int32_t touchFilter = 2;
        if (pointerFilter == point->GetSourceType()) {
            int32_t pointerId = point->GetId();
            std::string pointerEvent = "OnEventPointer";
            FinishAsyncTrace(BYTRACE_TAG_MULTIMODALINPUT, pointerEvent, pointerId);
        }
        if (touchFilter == point->GetSourceType()) {
            int32_t touchId = point->GetId();
            std::string touchEvent = "OnEventTouch";
            FinishAsyncTrace(BYTRACE_TAG_MULTIMODALINPUT, touchEvent, touchId);
        }
        return RET_OK;
    }
    NetPacket newPacket(MmiMessageId::ON_POINTER_EVENT);
    InputEventDataTransformation::Marshalling(point, newPacket);
    auto udsServer = InputHandler->GetUDSServer();
    if (udsServer == nullptr) {
        MMI_LOGE("UdsServer is a nullptr");
        return RET_ERR;
    }
    if (fd < 0) {
        MMI_LOGE("The fd less than 0");
        return RET_ERR;
    }

    if (IsANRProcess(udsServer, fd, point->GetId()) == TRIGGER_ANR) {
        MMI_LOGE("the pointer event does not report normally, triggering ANR");
    }

    if (!udsServer->SendMsg(fd, newPacket)) {
        MMI_LOGE("Sending structure of EventTouch failed! errCode:%{public}d", MSG_SEND_FAIL);
        return RET_ERR;
    }
    MMI_LOGD("Leave");
    return RET_OK;
}

int32_t EventDispatch::DispatchTouchTransformPointEvent(UDSServer& udsServer,
    std::shared_ptr<PointerEvent> point)
{
    CHKPR(point, ERROR_NULL_POINTER);
    InputHandlerManagerGlobal::GetInstance().HandleEvent(point);
    MMI_LOGD("call  DispatchTouchTransformPointEvent begin");
    auto appInfo = AppRegs->FindByWinId(point->GetAgentWindowId()); // obtain application information
    if (appInfo.fd == RET_ERR) {
        MMI_LOGE("Failed to find fd, errCode:%{public}d", FOCUS_ID_OBTAIN_FAIL);
        return FOCUS_ID_OBTAIN_FAIL;
    }
    NetPacket newPacket(MmiMessageId::ON_POINTER_EVENT);
    InputEventDataTransformation::Marshalling(point, newPacket);
    if (!udsServer.SendMsg(appInfo.fd, newPacket)) {
        MMI_LOGE("Sending structure of EventTouch failed! errCode:%{public}d", MSG_SEND_FAIL);
        return MSG_SEND_FAIL;
    }
    MMI_LOGD("call  DispatchTouchTransformPointEvent end");
    return RET_OK;
}

int32_t EventDispatch::DispatchPointerEvent(UDSServer &udsServer, libinput_event *event,
    EventPointer &point, const uint64_t preHandlerTime)
{
    CHKPR(event, ERROR_NULL_POINTER);
    auto device = libinput_event_get_device(event);
    CHKPR(device, ERROR_NULL_POINTER);

#ifdef DEBUG_CODE_TEST
    std::string strIds = WinMgr->GetSurfaceIdListString();
    size_t size = 0;
#endif
    int32_t desWindowId = WinMgr->GetFocusSurfaceId(); // obtaining focusId
    if (desWindowId < 0) {
        MMI_LOGW("Failed to get focus surface, desWindow:%{public}d", desWindowId);
        return RET_OK;
    }
    // obtain application information for focusId
    auto appInfo = AppRegs->FindByWinId(desWindowId);
    if (appInfo.fd == RET_ERR) {
        MMI_LOGE("Failed to find focus");
        return FOCUS_ID_OBTAIN_FAIL;
    }
    StandardTouchStruct inputEvent = {}; // Standardization handler of struct EventPointer
    standardEvent_.StandardTouchEvent(event, inputEvent);

    if (AppRegs->IsMultimodeInputReady(MmiMessageId::ON_TOUCH, appInfo.fd, point.time, preHandlerTime)) {
        KeyEventValueTransformations KeyEventValue = {};
        KeyEventValue = KeyValueTransformationByInput(point.button);
        point.button = KeyEventValue.keyValueOfHos;
        NetPacket newPacket(MmiMessageId::ON_TOUCH);
        int32_t inputType = INPUT_DEVICE_CAP_POINTER;
        newPacket << inputType << inputEvent.curRventType << point << appInfo.abilityId
            << desWindowId << appInfo.fd << preHandlerTime;
        if (inputEvent.curRventType > 0) {
            newPacket << inputEvent;
        }
#ifdef DEBUG_CODE_TEST
        auto type = libinput_event_get_type(event);
        if (type != LIBINPUT_EVENT_POINTER_BUTTON) {
            MMI_LOGT("MMIWMS:windowId:%{public}s", strIds.c_str());
            if (desWindowId == -1) {
                MMI_LOGT("WMS:windowId = ''");
            } else {
                MMI_LOGT("WMS:windowId:%{public}d", desWindowId);
            }
            MMI_LOGT("CALL_AMS MMIAPPM:fd:%{public}d,abilityID:%{public}d", appInfo.fd, appInfo.abilityId);
        } else {
            if (size == windowCount_) {
                MMI_LOGT("MMIWMS:windowId:%{public}s,WMS:windowId:%{public}d,CALL_AMS:windowId:%{public}d"
                    "MMIAPPM:fd:%{public}d,abilityID:%{public}d", strIds.c_str(), desWindowId, desWindowId,
                    appInfo.fd, appInfo.abilityId);
            } else {
                MMI_LOGT("MMIWMS:windowId:%{public}s,WMS:windowId:%{public}d,CALL_AMS:windowId: ''"
                    "MMIAPPM:fd:%{public}d,abilityID:%{public}d", strIds.c_str(), desWindowId,
                    appInfo.fd, appInfo.abilityId);
            }
        }
#endif

        MMI_LOGT("4.event dispatcher of server, eventPointer:time:%{public}" PRId64 ",deviceType:%{public}u,"
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
        if (!udsServer.SendMsg(appInfo.fd, newPacket)) {
            MMI_LOGE("Sending structure of EventPointer failed! errCode:%{public}d", MSG_SEND_FAIL);
            return MSG_SEND_FAIL;
        }
    }
    return RET_OK;
}

int32_t EventDispatch::DispatchGestureEvent(UDSServer& udsServer, libinput_event *event,
    const EventGesture& gesture, const uint64_t preHandlerTime)
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
    auto appInfo = AppRegs->FindByWinId(focusId); // obtain application information
    if (appInfo.fd == RET_ERR) {
        MMI_LOGT("Failed to find fd, errCode:%{public}d", FOCUS_ID_OBTAIN_FAIL);
        return FOCUS_ID_OBTAIN_FAIL;
    }

    MMI_LOGT("4.event dispatcher of server, EventGesture:time:%{public}" PRId64 ",deviceType:%{public}u,"
             "deviceName:%{public}s,physical:%{public}s,eventType:%{public}d,"
             "fingerCount:%{public}d,cancelled:%{public}d,delta.x:%{public}lf,delta.y:%{public}lf,"
             "deltaUnaccel.x:%{public}lf,deltaUnaccel.y:%{public}lf,fd:%{public}d,"
             "preHandlerTime:%{public}" PRId64,
             gesture.time, gesture.deviceType, gesture.deviceName, gesture.physical,
             gesture.eventType, gesture.fingerCount, gesture.cancelled, gesture.delta.x, gesture.delta.y,
             gesture.deltaUnaccel.x, gesture.deltaUnaccel.y, appInfo.fd, preHandlerTime);
    PrintEventSlotedCoordsInfo(gesture.soltTouches);

    if (AppRegs->IsMultimodeInputReady(MmiMessageId::ON_TOUCH, appInfo.fd, gesture.time, preHandlerTime)) {
        NetPacket newPacket(MmiMessageId::ON_TOUCH);
        int32_t inputType = INPUT_DEVICE_CAP_GESTURE;
        newPacket << inputType << gesture << appInfo.abilityId << focusId << appInfo.fd << preHandlerTime;
        if (!udsServer.SendMsg(appInfo.fd, newPacket)) {
            MMI_LOGE("Sending structure of EventGesture failed! errCode:%{public}d", MSG_SEND_FAIL);
            return MSG_SEND_FAIL;
        }
    }
    return RET_OK;
}

int32_t EventDispatch::DispatchTouchEvent(UDSServer& udsServer, libinput_event *event,
    const EventTouch& touch, const uint64_t preHandlerTime)
{
    CHKPR(event, ERROR_NULL_POINTER);
    auto device = libinput_event_get_device(event);
    CHKPR(device, ERROR_NULL_POINTER);
#ifdef DEBUG_CODE_TEST
    std::string str = WinMgr->GetSurfaceIdListString();
#endif
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
    auto appInfo = AppRegs->FindByWinId(touchFocusId); // obtain application information
    if (appInfo.fd == RET_ERR) {
        MMI_LOGE("Failed to find fd:%{public}d,errCode:%{public}d", touchFocusId, FOCUS_ID_OBTAIN_FAIL);
        return FOCUS_ID_OBTAIN_FAIL;
    }
    MMI_LOGD("DispatchTouchEvent focusId:%{public}d,fd:%{public}d", touchFocusId, appInfo.fd);
#ifdef DEBUG_CODE_TEST
    MMI_LOGT("MMIWMS:windowId:%{public}s", str.c_str());
    if (touchFocusId == -1) {
        MMI_LOGT("WMS:windowId = ''");
    } else {
        MMI_LOGT("WMS:windowId:%{public}d", touchFocusId);
    }
    MMI_LOGT("CALL_AMS:windowId:'' MMIAPPM:fd: %{public}d,abilityID:%{public}d", appInfo.fd, appInfo.abilityId);
#endif

    if (AppRegs->IsMultimodeInputReady(MmiMessageId::ON_TOUCH, appInfo.fd, touch.time, preHandlerTime)) {
        NetPacket newPacket(MmiMessageId::ON_TOUCH);
        int32_t fingerCount = MMIRegEvent->GetTouchInfoSizeByDeviceId(touch.deviceId);
        if (touch.eventType == LIBINPUT_EVENT_TOUCH_UP) {
            fingerCount++;
        }
        int32_t inputType = INPUT_DEVICE_CAP_TOUCH;
        newPacket << inputType << fingerCount;
        POINT_EVENT_TYPE pointEventType = EVENT_TYPE_INVALID;
        OnEventTouchGetPointEventType(touch, fingerCount, pointEventType);
        int32_t eventType = pointEventType;
        newPacket << eventType << appInfo.abilityId << touchFocusId << appInfo.fd << preHandlerTime << touch.seatSlot;
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
                         touchTemp.pressure, touchTemp.point.x, touchTemp.point.y, appInfo.fd,
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
                     touch.point.x, touch.point.y, appInfo.fd, preHandlerTime);
        }
        if (!udsServer.SendMsg(appInfo.fd, newPacket)) {
            MMI_LOGE("Sending structure of EventTouch failed! errCode:%{public}d", MSG_SEND_FAIL);
            return MSG_SEND_FAIL;
        }
    }
    return ret;
}
int32_t EventDispatch::DispatchCommonPointEvent(UDSServer& udsServer, libinput_event *event,
    const EventPointer& point, const uint64_t preHandlerTime)
{
    CHKPR(event, ERROR_NULL_POINTER);
    auto device = libinput_event_get_device(event);
    auto type = libinput_event_get_type(event);
    CHKPR(device, ERROR_NULL_POINTER);

#ifdef DEBUG_CODE_TEST
    std::string str = WinMgr->GetSurfaceIdListString();
#endif
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

void EventDispatch::OnKeyboardEventTrace(const std::shared_ptr<KeyEvent> &key, int32_t number)
{
    int32_t checkLaunchAbility = 1;
    int32_t keyCode = key->GetKeyCode();
    std::string checkKeyCode;
    if (checkLaunchAbility == number) {
        checkKeyCode = "CheckLaunchAbility service GetKeyCode = " + std::to_string(keyCode);
        MMI_LOGT("CheckLaunchAbility service trace GetKeyCode:%{public}d", keyCode);
    } else {
        checkKeyCode = "FilterSubscribeKeyEvent service GetKeyCode = " + std::to_string(keyCode);
        MMI_LOGT("FilterSubscribeKeyEvent service trace GetKeyCode:%{public}d", keyCode);
    }
    BYTRACE_NAME(BYTRACE_TAG_MULTIMODALINPUT, checkKeyCode);
    int32_t keyId = key->GetId();
    std::string keyEventString = "OnKeyEvent";
    FinishAsyncTrace(BYTRACE_TAG_MULTIMODALINPUT, keyEventString, keyId);
}

int32_t EventDispatch::DispatchKeyEventByPid(UDSServer& udsServer,
    std::shared_ptr<KeyEvent> key, const uint64_t preHandlerTime)
{
    CHKPR(key, PARAM_INPUT_INVALID);
    MMI_LOGD("DispatchKeyEventByPid begin");
    if (key->HasFlag(InputEvent::EVENT_FLAG_NO_INTERCEPT)) {
        if (InterceptorMgrGbl.OnKeyEvent(key)) {
            MMI_LOGD("keyEvent filter find a keyEvent from Original event keyCode: %{puiblic}d",
                key->GetKeyCode());
            return RET_OK;
        }
    }
    if (AbilityMgr->CheckLaunchAbility(key)) {
        MMI_LOGD("The keyEvent start launch an ability, keyCode:%{public}d", key->GetKeyCode());
        int32_t checkLaunchAbility = 1;
        OnKeyboardEventTrace(key, checkLaunchAbility);
        return RET_OK;
    }
    if (KeyEventSubscriber_.FilterSubscribeKeyEvent(key)) {
        MMI_LOGD("Subscribe keyEvent filter success. keyCode:%{public}d", key->GetKeyCode());
        int32_t filterSubscribeKeyEvent = 2;
        OnKeyboardEventTrace(key, filterSubscribeKeyEvent);
        return RET_OK;
    }
    auto fd = WinMgr->UpdateTarget(key);
    CHKR(fd > 0, FD_OBTAIN_FAIL, RET_ERR);
#ifdef DEBUG_CODE_TEST
    std::string str = WinMgr->GetSurfaceIdListString();
    PrintWMSInfo(str, fd, 0, key->GetTargetWindowId());
#endif

    MMI_LOGT("4.event dispatcher of server:KeyEvent:KeyCode:%{public}d,"
             "ActionTime:%{public}d,Action:%{public}d,ActionStartTime:%{public}d,"
             "EventType:%{public}d,Flag:%{public}d,"
             "KeyAction:%{public}d,Fd:%{public}d,PreHandlerTime:%{public}" PRId64 "",
             key->GetKeyCode(), key->GetActionTime(), key->GetAction(),
             key->GetActionStartTime(),
             key->GetEventType(),
             key->GetFlag(), key->GetKeyAction(), fd, preHandlerTime);

    if (IsANRProcess(&udsServer, fd, key->GetId()) == TRIGGER_ANR) {
        MMI_LOGE("the key event does not report normally, triggering ANR");
    }

    InputMonitorServiceMgr.OnMonitorInputEvent(key);
    NetPacket newPkt(MmiMessageId::ON_KEYEVENT);
    InputEventDataTransformation::KeyEventToNetPacket(key, newPkt);
    newPkt << fd << preHandlerTime;
    if (!udsServer.SendMsg(fd, newPkt)) {
        MMI_LOGE("Sending structure of EventKeyboard failed! errCode:%{public}d", MSG_SEND_FAIL);
        return MSG_SEND_FAIL;
    }
    MMI_LOGD("DispatchKeyEventByPid end");
    return RET_OK;
}

int32_t EventDispatch::DispatchKeyEvent(UDSServer& udsServer, libinput_event *event,
    const KeyEventValueTransformations& trs, EventKeyboard& key, const uint64_t preHandlerTime)
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
    auto appInfo = AppRegs->FindByWinId(focusId); // obtain application information for focusId
    if (appInfo.fd == RET_ERR) {
        MMI_LOGE("Failed to find, fd:%{public}d,errCode:%{public}d", focusId, FOCUS_ID_OBTAIN_FAIL);
        return FOCUS_ID_OBTAIN_FAIL;
    }
    key.key = trs.keyValueOfHos; // struct EventKeyboard tranformed into HOS_L3

    MMI_LOGT("4.event dispatcher of server, eventKeyboard:time:%{public}" PRId64 ",deviceType:%{public}u,"
             "deviceName:%{public}s,physical:%{public}s,eventType:%{public}d,unicode:%{public}d,key:%{public}u,"
             "key_detail:%{public}s,seat_key_count:%{public}u,state:%{public}d,fd:%{public}d,"
             "preHandlerTime:%{public}" PRId64, key.time, key.deviceType, key.deviceName, key.physical,
             key.eventType, key.unicode, key.key, trs.keyEvent.c_str(), key.seat_key_count, key.state, appInfo.fd,
             preHandlerTime);
    if (AppRegs->IsMultimodeInputReady(MmiMessageId::ON_KEY, appInfo.fd, key.time, preHandlerTime)) {
        NetPacket newPkt(MmiMessageId::ON_KEY);
        newPkt << key << appInfo.abilityId << focusId << appInfo.fd << preHandlerTime;
        if (!udsServer.SendMsg(appInfo.fd, newPkt)) {
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

int32_t EventDispatch::DispatchGestureNewEvent(UDSServer& udsServer, libinput_event *event,
    std::shared_ptr<PointerEvent> pointerEvent, const uint64_t preHandlerTime)
{
    CHKPR(event, ERROR_NULL_POINTER);
    auto device = libinput_event_get_device(event);
    CHKPR(device, ERROR_NULL_POINTER);

    auto focusId = WinMgr->GetFocusSurfaceId();
    if (focusId < 0) {
        MMI_LOGW("Failed to get focus surface, focus:%{public}d", focusId);
        return RET_OK;
    }
    auto appInfo = AppRegs->FindByWinId(focusId); // obtain application information
    if (appInfo.fd == RET_ERR) {
        MMI_LOGE("Failed to find fd, errCode:%{public}d", FOCUS_ID_OBTAIN_FAIL);
        return FOCUS_ID_OBTAIN_FAIL;
    }

    pointerEvent->SetTargetWindowId(focusId);

    std::vector<int32_t> pointerIds { pointerEvent->GetPointersIdList() };
    MMI_LOGT("pointer event dispatcher of server:eventType:%{public}d,actionTime:%{public}d,"
             "action:%{public}d,actionStartTime:%{public}d,"
             "flag:%{public}d,pointerAction:%{public}d,sourceType:%{public}d,"
             "VerticalAxisValue:%{public}.02f, HorizontalAxisValue:%{public}.02f,"
             "pointerCount:%{public}d",
             pointerEvent->GetEventType(), pointerEvent->GetActionTime(),
             pointerEvent->GetAction(), pointerEvent->GetActionStartTime(),
             pointerEvent->GetFlag(), pointerEvent->GetPointerAction(),
             pointerEvent->GetSourceType(),
             pointerEvent->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL),
             pointerEvent->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL),
             static_cast<int32_t>(pointerIds.size()));

    for (const auto &pointerId : pointerIds) {
        OHOS::MMI::PointerEvent::PointerItem item;
        CHKR(pointerEvent->GetPointerItem(pointerId, item), PARAM_INPUT_FAIL, RET_ERR);

        MMI_LOGT("\tdownTime:%{public}d,isPressed:%{public}s,"
                 "globalX:%{public}d,globalY:%{public}d,localX:%{public}d,localY:%{public}d,"
                 "width:%{public}d,height:%{public}d,pressure:%{public}d",
                 item.GetDownTime(), (item.IsPressed() ? "true" : "false"),
                 item.GetGlobalX(), item.GetGlobalY(), item.GetLocalX(), item.GetLocalY(),
                 item.GetWidth(), item.GetHeight(), item.GetPressure());
    }

    NetPacket newPkt(MmiMessageId::ON_POINTER_EVENT);
    InputEventDataTransformation::Marshalling(pointerEvent, newPkt);
    newPkt << appInfo.fd << preHandlerTime;
    if (!udsServer.SendMsg(appInfo.fd, newPkt)) {
        MMI_LOGE("Sending structure of PointerEvent failed! errCode:%{public}d", MSG_SEND_FAIL);
        return MSG_SEND_FAIL;
    }
    return RET_OK;
}

int32_t EventDispatch::IsANRProcess(UDSServer* udsServer, int32_t fd, int32_t id)
{
    MMI_LOGD("begin");
    auto session = udsServer->GetSession(fd);
    CHKPR(session, SESSION_NOT_FOUND);
    auto currentTime = GetSysClockTime();
    session->AddEvent(id, currentTime);

    auto firstTime = session->GetFirstEventTime();
    if (currentTime < (firstTime + INPUT_UI_TIMEOUT_TIME)) {
        MMI_LOGI("the event reports normally");
        return NOT_TRIGGER_ANR;
    }
    if (currentTime >= (firstTime + INPUT_UI_TIMEOUT_TIME_MAX)) {
        session->ClearEventsVct();
        MMI_LOGI("event is cleared");
    }

    int32_t ret = OHOS::HiviewDFX::HiSysEvent::Write(OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "APPLICATION_BLOCK_INPUT",
        OHOS::HiviewDFX::HiSysEvent::EventType::FAULT);
    if (ret < 0) {
        MMI_LOGE("failed to notify HiSysEvent");
        return TRIGGER_ANR;
    }

    MMI_LOGD("end");
    return TRIGGER_ANR;
}
} // namespace MMI
} // namespace OHOS