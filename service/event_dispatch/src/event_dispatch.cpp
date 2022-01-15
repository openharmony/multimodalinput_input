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
#include "ability_launch_manager.h"
#include "input_event_data_transformation.h"
#include "input_event_monitor_manager.h"
#include "input_handler_manager_global.h"
#include "interceptor_manager_global.h"
#include "mmi_server.h"
#include "outer_interface.h"
#include "system_event_handler.h"
#include "util.h"
#include "event_filter_death_recipient.h"


namespace OHOS::MMI {
    namespace {
        static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "EventDispatch" };
    }
}

static void PrintEventSlotedCoordsInfo(const SlotedCoordsInfo& r)
{
    using namespace OHOS::MMI;
    for (int32_t i = 0; i < MAX_SOLTED_COORDS_NUM; i++) {
        MMI_LOGT("[%{public}d] isActive: %{public}d, x = %{public}f, y = %{public}f\n",
            i, r.coords[i].isActive, r.coords[i].x, r.coords[i].y);
    }
}

OHOS::MMI::EventDispatch::EventDispatch()
{
}

OHOS::MMI::EventDispatch::~EventDispatch()
{
}

void OHOS::MMI::EventDispatch::OnEventTouchGetPointEventType(const EventTouch& touch,
    POINT_EVENT_TYPE& pointEventType, const int32_t fingerCount)
{
    CHK(fingerCount > 0, PARAM_INPUT_INVALID);
    CHK(touch.time > 0, PARAM_INPUT_INVALID);
    CHK(touch.seat_slot >= 0, PARAM_INPUT_INVALID);
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

int32_t OHOS::MMI::EventDispatch::GestureRegisteredEventDispatch(const MmiMessageId& idMsg,
                                                                 OHOS::MMI::UDSServer& udsServer,
                                                                 RegisteredEvent& registeredEvent,
                                                                 uint64_t preHandlerTime)
{
    auto ret = RET_OK;
    if (idMsg == MmiMessageId::ON_PREVIOUS) {
        ret = RegisteredEventDispatch(MmiMessageId::ON_PREVIOUS, udsServer, registeredEvent,
            INPUT_DEVICE_CAP_GESTURE, preHandlerTime);
        if (ret != RET_OK) {
            return ret;
        }
        ret = RegisteredEventDispatch(MmiMessageId::ON_SHOW_NOTIFICATION, udsServer, registeredEvent,
            INPUT_DEVICE_CAP_GESTURE, preHandlerTime);
    } else if (idMsg == MmiMessageId::ON_NEXT) {
        ret = RegisteredEventDispatch(MmiMessageId::ON_NEXT, udsServer, registeredEvent,
            INPUT_DEVICE_CAP_GESTURE, preHandlerTime);
        if (ret != RET_OK) {
            return ret;
        }
        ret = RegisteredEventDispatch(MmiMessageId::ON_BACK, udsServer, registeredEvent,
            INPUT_DEVICE_CAP_GESTURE, preHandlerTime);
    } else {
        ret = RegisteredEventDispatch(idMsg, udsServer, registeredEvent,
            INPUT_DEVICE_CAP_GESTURE, preHandlerTime);
    }
    return ret;
}

int32_t OHOS::MMI::EventDispatch::RegisteredEventDispatch(const MmiMessageId& idMsg, OHOS::MMI::UDSServer& udsServer,
    RegisteredEvent& registeredEvent, int32_t inputDeviceType, uint64_t preHandlerTime)
{
    CHKR(idMsg > MmiMessageId::INVALID, PARAM_INPUT_INVALID, PARAM_INPUT_INVALID);
    std::vector<int32_t> fds;
    RegEventHM->FindSocketFdsByEventHandle(idMsg, fds);
    if (fds.empty()) {
        return RET_OK;
    }

    for (auto fd : fds) {
        auto appInfo = AppRegs->FindBySocketFd(fd);
        MMI_LOGT("\nevent dispatcher of server:\n RegisteredEvent:devicePhys=%{public}s;"
                 "deviceType=%{public}u;eventType=%{public}u;occurredTime=%{public}" PRId64 ";"
                 "conbinecode=%{public}d;fd=%{public}d;\n*****************\n",
                 registeredEvent.devicePhys, registeredEvent.deviceType,
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

int32_t OHOS::MMI::EventDispatch::KeyBoardRegisteredEventHandler(EventKeyboard& key, UDSServer& udsServer,
    libinput_event& event, int32_t inputDeviceType, uint64_t preHandlerTime)
{
    auto ret = RET_OK;
    RegisteredEvent registeredEvent = {};
    auto packageResult = eventPackage_.PackageRegisteredEvent<EventKeyboard>(registeredEvent, key);
    if (packageResult != RET_OK) {
        MMI_LOGE("Registered event package failed... ret:%{public}d errCode:%{public}d",
            packageResult, REG_EVENT_PKG_FAIL);
    }
    if ((key.key == KEY_ENTER || key.key == KEY_KPENTER) && key.state == KEY_STATE_PRESSED) {
        ret = RegisteredEventDispatch(MmiMessageId::ON_SEND, udsServer, registeredEvent,
            INPUT_DEVICE_CAP_KEYBOARD, preHandlerTime);
        if (ret != RET_OK) {
            MMI_LOGE("Registered special Event dispatch failed return:%{public}d errCode:%{public}d", ret,
                SPCL_REG_EVENT_DISP_FAIL);
        }
        ret = RegisteredEventDispatch(MmiMessageId::ON_ENTER, udsServer, registeredEvent,
            INPUT_DEVICE_CAP_KEYBOARD, preHandlerTime);
        if (ret != RET_OK) {
            MMI_LOGE("Registered special Event dispatch failed return:%{public}d errCode:%{public}d", ret,
                SPCL_REG_EVENT_DISP_FAIL);
        }
    } else if (key.key == KEY_ESC && key.state == KEY_STATE_PRESSED) {
        ret = RegisteredEventDispatch(MmiMessageId::ON_CANCEL, udsServer, registeredEvent,
            INPUT_DEVICE_CAP_KEYBOARD, preHandlerTime);
        if (ret != RET_OK) {
            MMI_LOGE("Registered special Event dispatch failed return:%{public}d errCode:%{public}d", ret,
                SPCL_REG_EVENT_DISP_FAIL);
        }
        ret = RegisteredEventDispatch(MmiMessageId::ON_BACK, udsServer, registeredEvent,
            INPUT_DEVICE_CAP_KEYBOARD, preHandlerTime);
        if (ret != RET_OK) {
            MMI_LOGE("Registered special Event dispatch failed return:%{public}d errCode:%{public}d", ret,
                SPCL_REG_EVENT_DISP_FAIL);
        }
    } else if (key.key == KEY_BACK && key.state == KEY_STATE_PRESSED) {
        ret = RegisteredEventDispatch(MmiMessageId::ON_CLOSE_PAGE, udsServer, registeredEvent,
            INPUT_DEVICE_CAP_KEYBOARD, preHandlerTime);
        if (ret != RET_OK) {
            MMI_LOGE("Registered special Event dispatch failed return:%{public}d errCode:%{public}d", ret,
                SPCL_REG_EVENT_DISP_FAIL);
        }
        ret = RegisteredEventDispatch(MmiMessageId::ON_BACK, udsServer, registeredEvent,
            INPUT_DEVICE_CAP_KEYBOARD, preHandlerTime);
        if (ret != RET_OK) {
            MMI_LOGE("Registered special Event dispatch failed return:%{public}d errCode:%{public}d", ret,
                SPCL_REG_EVENT_DISP_FAIL);
        }
    }
    return ret;
}

int32_t OHOS::MMI::EventDispatch::DispatchTabletPadEvent(UDSServer& udsServer, libinput_event& event,
    EventTabletPad& tabletPad, const uint64_t preHandlerTime)
{
    auto device = libinput_event_get_device(&event);
    CHKR(device, NULL_POINTER, LIBINPUT_DEV_EMPTY);
#ifdef DEBUG_CODE_TEST
    std::string str = WinMgr->GetSurfaceIdListString();
#endif

    auto focusId = WinMgr->GetFocusSurfaceId();
    if (focusId < 0) {
        return RET_OK;
    }
    auto appInfo = AppRegs->FindByWinId(focusId); // obtain application information for focusId
    if (appInfo.fd == RET_ERR) {
        MMI_LOGE("Failed to find fd... errCode:%{public}d", FOCUS_ID_OBTAIN_FAIL);
        return FOCUS_ID_OBTAIN_FAIL;
    }
#ifdef DEBUG_CODE_TEST
    MMI_LOGT("\nMMIWMS:windowId=[%{public}s]\n", str.c_str());
    if (focusId == -1) {
        MMI_LOGT("\nWMS:windowId = ''\n");
    } else {
        MMI_LOGT("\nWMS:windowId = %{public}d\n", focusId);
    }
    MMI_LOGT("\nCALL_AMS:windowId = ''\n");
    MMI_LOGT("\nMMIAPPM:fd =%{public}d,abilityID = %{public}d\n", appInfo.fd, appInfo.abilityId);
#endif

    MMI_LOGT("\n4.event dispatcher of server:\nEventTabletPad:time=%{public}" PRId64 ";deviceType=%{public}u;"
             "deviceName=%{public}s;devicePhys=%{public}s;eventType=%{public}d;\n"
             "ring.number=%{public}d;ring.position=%{public}lf;ring.source=%{public}d;\n"
             "strip.number=%{public}d;strip.position=%{public}lf;strip.source=%{public}d;\n"
             "fd=%{public}d;preHandlerTime=%{public}" PRId64 ";\n*"
             "***********************************************************************\n",
             tabletPad.time, tabletPad.deviceType, tabletPad.deviceName,
             tabletPad.devicePhys, tabletPad.eventType, tabletPad.ring.number, tabletPad.ring.position,
             tabletPad.ring.source, tabletPad.strip.number, tabletPad.strip.position, tabletPad.strip.source,
             appInfo.fd, preHandlerTime);

    if (AppRegs->IsMultimodeInputReady(MmiMessageId::ON_TOUCH, appInfo.fd, tabletPad.time, preHandlerTime)) {
        NetPacket newPacket(MmiMessageId::ON_TOUCH);
        int32_t inputType = INPUT_DEVICE_CAP_TOUCH_PAD;
        newPacket << inputType << tabletPad << appInfo.abilityId << focusId << appInfo.fd << preHandlerTime;
        if (!udsServer.SendMsg(appInfo.fd, newPacket)) {
            MMI_LOGE("Sending structure of EventTabletPad failed! errCode:%{public}d\n", MSG_SEND_FAIL);
            return MSG_SEND_FAIL;
        }
    }
    return RET_OK;
}

int32_t OHOS::MMI::EventDispatch::DispatchJoyStickEvent(UDSServer &udsServer, libinput_event& event,
    EventJoyStickAxis& eventJoyStickAxis, const uint64_t preHandlerTime)
{
    auto device = libinput_event_get_device(&event);
    CHKR(device, NULL_POINTER, LIBINPUT_DEV_EMPTY);
    auto focusId = WinMgr->GetFocusSurfaceId();
    if (focusId < 0) {
        return RET_OK;
    }
    auto appInfo = AppRegs->FindByWinId(focusId); // obtain application information for focusId
    if (appInfo.fd == RET_ERR) {
        MMI_LOGE("Failed to find fd... errCode:%{public}d", FOCUS_ID_OBTAIN_FAIL);
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
            MMI_LOGE("Sending structure of EventJoyStickAxis failed! errCode:%{public}d\n", MSG_SEND_FAIL);
            return MSG_SEND_FAIL;
        }
    }
    return RET_OK;
}

int32_t OHOS::MMI::EventDispatch::DispatchTabletToolEvent(UDSServer& udsServer, libinput_event& event,
    EventTabletTool& tableTool, const uint64_t preHandlerTime, WindowSwitch& windowSwitch)
{
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
        MMI_LOGT("\n4.event dispatcher of server:TabletTool:time=%{public}" PRId64 ";"
                 "deviceType=%{public}u; deviceName=%{public}s; devicePhys=%{public}s; eventType=%{public}d; "
                 "type=%{public}u; serial=%{public}u; button=%{public}d; state=%{public}d; "
                 "point.x=%{public}lf; point.y=%{public}lf; tilt.x=%{public}lf; tilt.y=%{public}lf; "
                 "distance=%{public}lf; pressure=%{public}lf; rotation=%{public}lf; slider=%{public}lf; "
                 "wheel=%{public}lf; wheel_discrete=%{public}d; size.major=%{public}lf; size.minor=%{public}lf; "
                 "proximity_state=%{public}d; tip_state=%{public}d; state=%{public}d; seat_button_count=%{public}d; "
                 "preHandlerTime=%{public}" PRId64 "; fd=%{public}d;"
                 "\n**************************************************\n",
                 tableTool.time, tableTool.deviceType, tableTool.deviceName,
                 tableTool.devicePhys, tableTool.eventType, tableTool.tool.type,
                 tableTool.tool.serial, tableTool.button, tableTool.state, tableTool.axes.point.x,
                 tableTool.axes.point.y, tableTool.axes.tilt.x, tableTool.axes.tilt.y, tableTool.axes.distance,
                 tableTool.axes.pressure, tableTool.axes.rotation, tableTool.axes.slider, tableTool.axes.wheel,
                 tableTool.axes.wheel_discrete, tableTool.axes.size.major, tableTool.axes.size.minor,
                 tableTool.proximity_state, tableTool.tip_state, tableTool.state, tableTool.seat_button_count,
                 preHandlerTime, appInfo.fd);
        if (!udsServer.SendMsg(appInfo.fd, newPacket)) {
            MMI_LOGE("Sending structure of EventTabletTool failed! errCode:%{public}d\n", MSG_SEND_FAIL);
            return MSG_SEND_FAIL;
        }
    }
    return RET_OK;
}

bool OHOS::MMI::EventDispatch::HandlePointerEventFilter(std::shared_ptr<PointerEvent> point)
{
    std::lock_guard<std::mutex> guard(lockInputEventFilter_);
    if (filter_ != nullptr && filter_->HandlePointerEvent(point)) {
        return true;
    }
    return false;
}

int32_t OHOS::MMI::EventDispatch::handlePointerEvent(std::shared_ptr<PointerEvent> point) 
{
    MMI_LOGE("handlePointerEvent begin .....");

    auto source = point->GetSourceType();
    auto fd = WinMgr->UpdateTargetPointer(point);
    if (HandlePointerEventFilter(point)) {
        return RET_OK;
    }
    switch (source) {
        case PointerEvent::SOURCE_TYPE_MOUSE: {
            if (HandleMouseEvent(point)) {
                return RET_OK;
            }
            break;
        }
        case PointerEvent::SOURCE_TYPE_TOUCHSCREEN: {
            if (HandleTouchScreenEvent(point)) {
                MMI_LOGD("PointerEvent consumed,will not send to client.");
                return RET_OK;
            }
            break;
        }
        case PointerEvent::SOURCE_TYPE_TOUCHPAD: {
            if (HandleTouchPadEvent(point)) {
                return RET_OK;
            }
            break;
        }
        default: {
            MMI_LOGD("Unknown source type!");
            break;
        }
    }
    NetPacket newPacket(MmiMessageId::ON_POINTER_EVENT);
    InputEventDataTransformation::SerializePointerEvent(point, newPacket);
    auto udsServer = InputHandler->GetUDSServer();
    if (udsServer == nullptr) {
        MMI_LOGE("udsServer is a nullptr");
        return RET_ERR;
    }
    if (fd <= 0) {
        MMI_LOGE("the fd less than 0");
        return RET_ERR;
    }
    if (!udsServer->SendMsg(fd, newPacket)) {
        MMI_LOGE("Sending structure of EventTouch failed! errCode:%{public}d\n", MSG_SEND_FAIL);
        return RET_ERR;
    }
    MMI_LOGE("handlePointerEvent end .....");
    return RET_OK;
}

bool OHOS::MMI::EventDispatch::HandleTouchScreenEvent(std::shared_ptr<PointerEvent> point)
{
    return InputHandlerManagerGlobal::GetInstance().HandleEvent(point);
}

bool OHOS::MMI::EventDispatch::HandleMouseEvent(std::shared_ptr<PointerEvent> point)
{
    return false;
}

bool OHOS::MMI::EventDispatch::HandleTouchPadEvent(std::shared_ptr<PointerEvent> point)
{
    if (INTERCEPTORMANAGERGLOBAL.OnPointerEvent(point)) {
        return true;
    }
    if (InputHandlerManagerGlobal::GetInstance().HandleEvent(point)) {
        return true;
    }
    return false;
}

int32_t OHOS::MMI::EventDispatch::DispatchTouchTransformPointEvent(UDSServer& udsServer,
    std::shared_ptr<PointerEvent> point)
{
    InputHandlerManagerGlobal::GetInstance().HandleEvent(point);
    MMI_LOGD("call  DispatchTouchTransformPointEvent begin"); 
    auto appInfo = AppRegs->FindByWinId(point->GetAgentWindowId()); // obtain application information
    if (appInfo.fd == RET_ERR) {
        MMI_LOGE("Failed to find fd... errCode:%{public}d", FOCUS_ID_OBTAIN_FAIL);
        return FOCUS_ID_OBTAIN_FAIL;
    }
    NetPacket newPacket(MmiMessageId::ON_POINTER_EVENT);
    InputEventDataTransformation::SerializePointerEvent(point, newPacket);
    if (!udsServer.SendMsg(appInfo.fd, newPacket)) {
        MMI_LOGE("Sending structure of EventTouch failed! errCode:%{public}d\n", MSG_SEND_FAIL);
        return MSG_SEND_FAIL;
    }
    MMI_LOGD("call  DispatchTouchTransformPointEvent end"); 
    return RET_OK;
}

int32_t OHOS::MMI::EventDispatch::DispatchPointerEvent(UDSServer &udsServer, libinput_event &event,
    EventPointer &point, const uint64_t preHandlerTime, WindowSwitch& windowSwitch)
{
    auto device = libinput_event_get_device(&event);
    CHKR(device, NULL_POINTER, LIBINPUT_DEV_EMPTY);

#ifdef DEBUG_CODE_TEST
    std::string strIds = WinMgr->GetSurfaceIdListString();
    size_t size = 0;
#endif
    int32_t desWindowId = WinMgr->GetFocusSurfaceId(); // obtaining focusId
    if (desWindowId < 0) {
        return RET_OK;
    }
    auto temp = windowSwitch.GetEventPointer();
    // obtain application information for focusId
    auto appInfo = AppRegs->FindByWinId(desWindowId);
    if (appInfo.fd == RET_ERR) {
        return FOCUS_ID_OBTAIN_FAIL;
    }
    StandardTouchStruct inputEvent = {}; // Standardization handler of struct EventPointer
    standardEvent_.StandardTouchEvent(event, inputEvent);
    if (inputEvent.curRventType > 0 && (point.eventType == LIBINPUT_EVENT_POINTER_MOTION ||
        point.eventType == LIBINPUT_EVENT_POINTER_MOTION_ABSOLUTE)) {
        point.deviceType = temp.deviceType;
        point.deviceId = temp.deviceId;
        CHKR(EOK == memcpy_s(point.deviceName, sizeof(point.deviceName),
            temp.deviceName, sizeof(temp.deviceName)), MEMCPY_SEC_FUN_FAIL, RET_ERR);
        CHKR(EOK == memcpy_s(point.devicePhys, sizeof(point.devicePhys),
            temp.devicePhys, sizeof(temp.devicePhys)), MEMCPY_SEC_FUN_FAIL, RET_ERR);
    }

    if (AppRegs->IsMultimodeInputReady(MmiMessageId::ON_TOUCH, appInfo.fd, point.time, preHandlerTime)) {
        struct KeyEventValueTransformations KeyEventValue = {};
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
        auto type = libinput_event_get_type(&event);
        if (type != LIBINPUT_EVENT_POINTER_BUTTON) {
            MMI_LOGT("\nMMIWMS:windowId=[%{public}s]\n", strIds.c_str());
            if (desWindowId == -1) {
                MMI_LOGT("\nWMS:windowId = ''\n");
            } else {
                MMI_LOGT("\nWMS:windowId = %{public}d\n", desWindowId);
            }
            MMI_LOGT("\nCALL_AMS:windowId = ''\n");
            MMI_LOGT("\nMMIAPPM:fd =%{public}d,abilityID = %{public}d\n", appInfo.fd, appInfo.abilityId);
        } else {
            if (size == windowCount_) {
                MMI_LOGT("\nMMIWMS:windowId = [%{public}s]\n", strIds.c_str());
                MMI_LOGT("\nWMS:windowId = %{public}d\n", desWindowId);
                MMI_LOGT("\nCALL_AMS:windowId = %{public}d\n", desWindowId);
                MMI_LOGT("\nMMIAPPM:fd =%{public}d,abilityID = %{public}d\n", appInfo.fd, appInfo.abilityId);
            } else {
                MMI_LOGT("\nMMIWMS:windowId=[%{public}s]\n", strIds.c_str());
                MMI_LOGT("\nWMS:windowId = %{public}d\n", desWindowId);
                MMI_LOGT("\nCALL_AMS:windowId = ''\n");
                MMI_LOGT("\nMMIAPPM:fd =%{public}d,abilityID = %{public}d\n", appInfo.fd, appInfo.abilityId);
            }
        }
#endif

        MMI_LOGT("\n4.event dispatcher of server:\neventPointer:time=%{public}" PRId64 ";deviceType=%{public}u;"
                    "deviceName=%{public}s;devicePhys=%{public}s;eventType=%{public}d;"
                    "buttonCode=%{public}u;seat_button_count=%{public}u;axes=%{public}u;buttonState=%{public}d;"
                    "source=%{public}d;delta.x=%{public}lf;delta.y=%{public}lf;delta_raw.x=%{public}lf;"
                    "delta_raw.y=%{public}lf;absolute.x=%{public}lf;absolute.y=%{public}lf;discrete.x=%{public}lf;"
                    "discrete.y=%{public}lf;fd=%{public}d;"
                    "preHandlerTime=%{public}" PRId64 ";\n**************************************************************\n",
                    point.time, point.deviceType, point.deviceName,
                    point.devicePhys, point.eventType, point.button, point.seat_button_count, point.axes,
                    point.state, point.source, point.delta.x, point.delta.y, point.delta_raw.x,
                    point.delta_raw.y, point.absolute.x, point.absolute.y, point.discrete.x,
                    point.discrete.y, appInfo.fd, preHandlerTime);
        if (!udsServer.SendMsg(appInfo.fd, newPacket)) {
            MMI_LOGE("Sending structure of EventPointer failed! errCode:%{public}d\n", MSG_SEND_FAIL);
            return MSG_SEND_FAIL;
        }
    }
    return RET_OK;
}

int32_t OHOS::MMI::EventDispatch::DispatchGestureEvent(UDSServer& udsServer, libinput_event& event,
    EventGesture& gesture, const uint64_t preHandlerTime)
{
    auto device = libinput_event_get_device(&event);
    CHKR(device, NULL_POINTER, LIBINPUT_DEV_EMPTY);

    MmiMessageId idMsg = MmiMessageId::INVALID;
    MMIRegEvent->OnEventGestureGetSign(gesture, idMsg);
    if (idMsg != MmiMessageId::INVALID) {
        RegisteredEvent registeredEvent = {};
        auto packageResult = eventPackage_.PackageRegisteredEvent<EventGesture>(registeredEvent, gesture);
        if (packageResult != RET_OK) {
            MMI_LOGE("Registered event package failed... ret:%{public}d errCode:%{public}d",
                packageResult, REG_EVENT_PKG_FAIL);
        }
        auto ret = GestureRegisteredEventDispatch(idMsg, udsServer, registeredEvent, preHandlerTime);
        if (ret != RET_OK) {
            MMI_LOGE("Gesture Swipe dispatch failed return:%{public}d errCode:%{public}d",
                ret, REG_EVENT_DISP_FAIL);
        }
    }

    auto focusId = WinMgr->GetFocusSurfaceId();
    if (focusId < 0) {
        return RET_OK;
    }
    auto appInfo = AppRegs->FindByWinId(focusId); // obtain application information
    if (appInfo.fd == RET_ERR) {
        MMI_LOGT("Failed to find fd... errCode:%{public}d", FOCUS_ID_OBTAIN_FAIL);
        return FOCUS_ID_OBTAIN_FAIL;
    }

    MMI_LOGT("\n4.event dispatcher of server:\nEventGesture:time=%{public}" PRId64 ";deviceType=%{public}u;"
             "deviceName=%{public}s;devicePhys=%{public}s;eventType=%{public}d;"
             "fingerCount=%{public}d;cancelled=%{public}d;delta.x=%{public}lf;delta.y=%{public}lf;"
             "deltaUnaccel.x=%{public}lf;deltaUnaccel.y=%{public}lf;fd=%{public}d;"
             "preHandlerTime=%{public}" PRId64 ";\n***************************************************\n",
             gesture.time, gesture.deviceType, gesture.deviceName, gesture.devicePhys,
             gesture.eventType, gesture.fingerCount, gesture.cancelled, gesture.delta.x, gesture.delta.y,
             gesture.deltaUnaccel.x, gesture.deltaUnaccel.y, appInfo.fd, preHandlerTime);
    PrintEventSlotedCoordsInfo(gesture.soltTouches);

    if (AppRegs->IsMultimodeInputReady(MmiMessageId::ON_TOUCH, appInfo.fd, gesture.time, preHandlerTime)) {
        NetPacket newPacket(MmiMessageId::ON_TOUCH);
        int32_t inputType = INPUT_DEVICE_CAP_GESTURE;
        newPacket << inputType << gesture << appInfo.abilityId << focusId << appInfo.fd << preHandlerTime;
        if (!udsServer.SendMsg(appInfo.fd, newPacket)) {
            MMI_LOGE("Sending structure of EventGesture failed! errCode:%{public}d\n", MSG_SEND_FAIL);
            return MSG_SEND_FAIL;
        }
    }
    return RET_OK;
}

int32_t OHOS::MMI::EventDispatch::DispatchTouchEvent(UDSServer& udsServer, libinput_event& event,
    EventTouch& touch, const uint64_t preHandlerTime, WindowSwitch& windowSwitch)
{
    auto device = libinput_event_get_device(&event);
    CHKR(device, NULL_POINTER, LIBINPUT_DEV_EMPTY);

#ifdef DEBUG_CODE_TEST
    std::string str = WinMgr->GetSurfaceIdListString();
#endif
    int32_t ret = RET_OK;
    MmiMessageId idMsg = MmiMessageId::INVALID;
    MMIRegEvent->OnEventTouchGetSign(touch, idMsg);
    if (idMsg != MmiMessageId::INVALID) {
        RegisteredEvent registeredEvent = {};
        auto packageResult = eventPackage_.PackageRegisteredEvent<EventTouch>(registeredEvent, touch);
        if (packageResult != RET_OK) {
            MMI_LOGE("Registered event package failed... ret:%{public}d errCode:%{public}d",
                packageResult, REG_EVENT_PKG_FAIL);
        }
        ret = RegisteredEventDispatch(idMsg, udsServer, registeredEvent, INPUT_DEVICE_CAP_TOUCH, preHandlerTime);
        if (ret != RET_OK) {
            MMI_LOGE("Touch comb dispatch failed return:%{public}d errCode:%{public}d",
                ret, REG_EVENT_DISP_FAIL);
        }
    }
    int32_t touchFocusId = WinMgr->GetTouchFocusSurfaceId();
    auto appInfo = AppRegs->FindByWinId(touchFocusId); // obtain application information
    if (appInfo.fd == RET_ERR) {
        MMI_LOGE("Failed to find fd:%{public}d... errCode:%{public}d", touchFocusId, FOCUS_ID_OBTAIN_FAIL);
        return FOCUS_ID_OBTAIN_FAIL;
    }
    MMI_LOGD("DispatchTouchEvent focusId:%{public}d fd:%{public}d", touchFocusId, appInfo.fd);
#ifdef DEBUG_CODE_TEST
    MMI_LOGT("\nMMIWMS:windowId=[%{public}s]\n", str.c_str());
    if (touchFocusId == -1) {
        MMI_LOGT("\nWMS:windowId = ''\n");
    } else {
        MMI_LOGT("\nWMS:windowId = %{public}d\n", touchFocusId);
    }
    MMI_LOGT("\nCALL_AMS:windowId = ''\n");
    MMI_LOGT("\nMMIAPPM:fd =%{public}d,abilityID = %{public}d\n", appInfo.fd, appInfo.abilityId);
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
        OnEventTouchGetPointEventType(touch, pointEventType, fingerCount);
        int32_t eventType = pointEventType;
        newPacket << eventType << appInfo.abilityId << touchFocusId << appInfo.fd << preHandlerTime << touch.seat_slot;
        std::vector<PAIR<uint32_t, int32_t>> touchIds;
        MMIRegEvent->GetTouchIds(touchIds, touch.deviceId);
        if (!touchIds.empty()) {
            for (PAIR<uint32_t, int32_t> touchId : touchIds) {
                struct EventTouch touchTemp = {};
                CHKR(EOK == memcpy_s(&touchTemp, sizeof(touchTemp), &touch, sizeof(touch)),
                     MEMCPY_SEC_FUN_FAIL, RET_ERR);
                MMIRegEvent->GetTouchInfoByTouchId(touchTemp, touchId);
                MMI_LOGT("\n4.event dispatcher of server:\neventTouch:time=%{public}" PRId64 ";deviceType=%{public}u;"
                         "deviceName=%{public}s;devicePhys=%{public}s;eventType=%{public}d;"
                         "slot=%{public}d;seat_slot=%{public}d;pressure=%{public}lf;point.x=%{public}lf;"
                         "point.y=%{public}lf;fd=%{public}d;"
                         "preHandlerTime=%{public}" PRId64 ";\n*********************************************************\n",
                         touchTemp.time, touchTemp.deviceType, touchTemp.deviceName,
                         touchTemp.devicePhys, touchTemp.eventType, touchTemp.slot, touchTemp.seat_slot,
                         touchTemp.pressure, touchTemp.point.x, touchTemp.point.y, appInfo.fd,
                         preHandlerTime);
                newPacket << touchTemp;

            }
        }
        if (touch.eventType == LIBINPUT_EVENT_TOUCH_UP) {
            newPacket << touch;
            MMI_LOGT("\n4.event dispatcher of server:\neventTouch:time=%{public}" PRId64 ";deviceType=%{public}u;"
                     "deviceName=%{public}s;devicePhys=%{public}s;eventType=%{public}d;"
                     "slot=%{public}d;seat_slot=%{public}d;pressure=%{public}lf;point.x=%{public}lf;"
                     "point.y=%{public}lf;fd=%{public}d;"
                     "preHandlerTime=%{public}" PRId64 ";\n****************************************************************\n",
                     touch.time, touch.deviceType, touch.deviceName,
                     touch.devicePhys, touch.eventType, touch.slot, touch.seat_slot, touch.pressure,
                     touch.point.x, touch.point.y, appInfo.fd, preHandlerTime);
        }
        if (!udsServer.SendMsg(appInfo.fd, newPacket)) {
            MMI_LOGE("Sending structure of EventTouch failed! errCode:%{public}d\n", MSG_SEND_FAIL);
            return MSG_SEND_FAIL;
        }
    }
    return ret;
}
int32_t OHOS::MMI::EventDispatch::DispatchCommonPointEvent(UDSServer& udsServer, libinput_event& event,
    EventPointer& point, const uint64_t preHandlerTime)
{
    auto device = libinput_event_get_device(&event);
    auto type = libinput_event_get_type(&event);
    CHKR(device, NULL_POINTER, LIBINPUT_DEV_EMPTY);

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
        auto packageResult = eventPackage_.PackageRegisteredEvent<EventPointer>(registeredEvent, point);
        if (packageResult != RET_OK) {
            MMI_LOGE("Registered event package failed... ret:%{public}d errCode:%{public}d",
                packageResult, REG_EVENT_PKG_FAIL);
        }
        SysEveHdl->OnSystemEventHandler(idMsg);
        ret = RegisteredEventDispatch(idMsg, udsServer, registeredEvent, INPUT_DEVICE_CAP_POINTER, preHandlerTime);
        if (ret != RET_OK) {
            MMI_LOGE("key comb dispatch failed return:%{public}d errCode:%{public}d",
                ret, REG_EVENT_DISP_FAIL);
        }
    }
    return ret;
}

int32_t OHOS::MMI::EventDispatch::DispatchKeyEventByPid(UDSServer& udsServer,
    std::shared_ptr<OHOS::MMI::KeyEvent> key, const uint64_t preHandlerTime)
{
    MMI_LOGD("DispatchKeyEventByPid begin");
    if (AbilityMgr->CheckLaunchAbility(key)) {
        MMI_LOGD("keyEvent start launch an ability, keyCode : %{puiblic}d", key->GetKeyCode());
        return RET_OK;
    }
    if (KeyEventInputSubscribeFlt.FilterSubscribeKeyEvent(udsServer, key)) {
        MMI_LOGD("subscribe keyEvent filter success. keyCode=%{puiblic}d", key->GetKeyCode());
        return RET_OK;
    }
    int32_t ret = RET_OK;
    // int32_t ret = RET_OK;
    // ret = KeyBoardRegisteredEventHandler(key, udsServer, event, INPUT_DEVICE_CAP_KEYBOARD, preHandlerTime);
    // if (ret != RET_OK) {
    //     MMI_LOGE("Special Registered Event dispatch failed return:%{public}d errCode:%{public}d", ret,
    //         SPCL_REG_EVENT_DISP_FAIL);
    // }
    // MmiMessageId idMsg = MmiMessageId::INVALID;
    // EventKeyboard prevKey = {};
    // MMIRegEvent->OnEventKeyGetSign(key, idMsg, prevKey);

    auto fd = WinMgr->UpdateTarget(key);
    CHKR(fd > 0, FD_OBTAIN_FAIL, RET_ERR);
#ifdef DEBUG_CODE_TEST
    std::string str = WinMgr->GetSurfaceIdListString();
    PrintWMSInfo(str, fd, 0, key->GetTargetWindowId());
#endif

    MMI_LOGT("\n4.event dispatcher of server:\nKeyEvent:,KeyCode = %{public}d,"
             "ActionTime = %{public}d,Action = %{public}d,ActionStartTime = %{public}d,"
             "EventType = %{public}d,Flag = %{public}d,"
             "KeyAction = %{public}d,Fd = %{public}d,PreHandlerTime = %{public}" PRId64"\n",
             key->GetKeyCode(), key->GetActionTime(), key->GetAction(),
             key->GetActionStartTime(),
             key->GetEventType(),
             key->GetFlag(), key->GetKeyAction(), fd, preHandlerTime);
    /*
    if (AppRegs->IsMultimodeInputReady(MmiMessageId::ON_KEY, fd, 0)) {
        NetPacket newPkt(MmiMessageId::ON_KEY);
        newPkt << key << appInfo.abilityId << focusId << appInfo.fd << preHandlerTime;
        if (!udsServer.SendMsg(appInfo.fd, newPkt)) {
            MMI_LOGE("Sending structure of EventKeyboard failed! errCode:%{public}d\n", MSG_SEND_FAIL);
            return MSG_SEND_FAIL;
        }
    }
    */
    IEMServiceManager.ReportKeyEvent(key);
    NetPacket newPkt(MmiMessageId::ON_KEYEVENT);
    InputEventDataTransformation::KeyEventToNetPacket(key, newPkt);
    newPkt << fd << preHandlerTime;
    if (!udsServer.SendMsg(fd, newPkt)) {
        MMI_LOGE("Sending structure of EventKeyboard failed! errCode:%{public}d\n", MSG_SEND_FAIL);
        return MSG_SEND_FAIL;
    }
    MMI_LOGD("DispatchKeyEventByPid end");
    return ret;
}

int32_t OHOS::MMI::EventDispatch::DispatchKeyEvent(UDSServer& udsServer, libinput_event& event,
    const KeyEventValueTransformations& trs, EventKeyboard& key, const uint64_t preHandlerTime)
{
    auto device = libinput_event_get_device(&event);
    CHKR(device, NULL_POINTER, LIBINPUT_DEV_EMPTY);

    int32_t ret = RET_OK;
    ret = KeyBoardRegisteredEventHandler(key, udsServer, event, INPUT_DEVICE_CAP_KEYBOARD, preHandlerTime);
    if (ret != RET_OK) {
        MMI_LOGE("Special Registered Event dispatch failed return:%{public}d errCode:%{public}d", ret,
            SPCL_REG_EVENT_DISP_FAIL);
    }
    MmiMessageId idMsg = MmiMessageId::INVALID;
    EventKeyboard prevKey = {};
    MMIRegEvent->OnEventKeyGetSign(key, idMsg, prevKey);
    if (MmiMessageId::INVALID != idMsg) {
        RegisteredEvent registeredEvent = {};
        auto packageResult = eventPackage_.PackageRegisteredEvent<EventKeyboard>(registeredEvent, prevKey);
        if (packageResult != RET_OK) {
            MMI_LOGE("Registered event package failed... ret:%{public}d errCode:%{public}d",
                packageResult, REG_EVENT_PKG_FAIL);
        }
        ret = RegisteredEventDispatch(idMsg, udsServer, registeredEvent, INPUT_DEVICE_CAP_KEYBOARD, preHandlerTime);
        if (ret != RET_OK) {
            MMI_LOGE("Registered Event dispatch failed return:%{public}d errCode:%{public}d",
                ret, REG_EVENT_DISP_FAIL);
        }
    }
    auto focusId = WinMgr->GetFocusSurfaceId();
    if (focusId < 0) {
        return RET_OK;
    }
    auto appInfo = AppRegs->FindByWinId(focusId); // obtain application information for focusId
    if (appInfo.fd == RET_ERR) {
        MMI_LOGT("Failed to find fd:%{public}d... errCode:%{public}d", focusId, FOCUS_ID_OBTAIN_FAIL);
        return FOCUS_ID_OBTAIN_FAIL;
    }
    key.key = trs.keyValueOfHos; // struct EventKeyboard tranformed into HOS_L3
#ifdef DEBUG_CODE_TEST
    std::string str = WinMgr->GetSurfaceIdListString();
    PrintWMSInfo(str, appInfo.fd, appInfo.abilityId, focusId);
#endif

    MMI_LOGT("\n4.event dispatcher of server:\neventKeyboard:time=%{public}" PRId64 ";deviceType=%{public}u;"
             "deviceName=%{public}s;devicePhys=%{public}s;eventType=%{public}d;"
             "unicode=%{public}d;key=%{public}u;key_detail=%{public}s;seat_key_count=%{public}u;"
             "state=%{public}d;fd=%{public}d;"
             "preHandlerTime=%{public}" PRId64 ";\n***********************************************************************\n",
             key.time, key.deviceType, key.deviceName, key.devicePhys, key.eventType,
             key.unicode, key.key, trs.keyEvent.c_str(), key.seat_key_count, key.state, appInfo.fd,
             preHandlerTime);

    if (AppRegs->IsMultimodeInputReady(MmiMessageId::ON_KEY, appInfo.fd, key.time, preHandlerTime)) {
        NetPacket newPkt(MmiMessageId::ON_KEY);
        newPkt << key << appInfo.abilityId << focusId << appInfo.fd << preHandlerTime;
        if (!udsServer.SendMsg(appInfo.fd, newPkt)) {
            MMI_LOGE("Sending structure of EventKeyboard failed! errCode:%{public}d\n", MSG_SEND_FAIL);
            return MSG_SEND_FAIL;
        }
    }
    return ret;
}

int32_t OHOS::MMI::EventDispatch::SetInputEventFilter(sptr<IEventFilter> filter)
{
    std::lock_guard<std::mutex> guard(lockInputEventFilter_);
    filter_ = filter;

    if (filter_ != nullptr) {
        std::weak_ptr<EventDispatch> weakPtr = shared_from_this();
        auto deathCallback = [weakPtr](const wptr<IRemoteObject> &object) {
            auto sharedPtr = weakPtr.lock();
            if (sharedPtr) {
                sharedPtr->SetInputEventFilter(nullptr);
            }
        };

        eventFilterRecipient_ = new EventFilterDeathRecipient(deathCallback);

        auto client = filter->AsObject().GetRefPtr();
        client->AddDeathRecipient(eventFilterRecipient_);
    }

    return RET_OK;
}

int32_t OHOS::MMI::EventDispatch::DispatchGestureNewEvent(UDSServer& udsServer, libinput_event& event,
    std::shared_ptr<PointerEvent> pointerEvent, const uint64_t preHandlerTime)
{
    auto device = libinput_event_get_device(&event);
    CHKR(device, NULL_POINTER, LIBINPUT_DEV_EMPTY);

    auto focusId = WinMgr->GetFocusSurfaceId();
    if (focusId < 0) {
        return RET_OK;
    }
    auto appInfo = AppRegs->FindByWinId(focusId); // obtain application information
    if (appInfo.fd == RET_ERR) {
        MMI_LOGT("Failed to find fd... errCode:%{public}d", FOCUS_ID_OBTAIN_FAIL);
        return FOCUS_ID_OBTAIN_FAIL;
    }

    pointerEvent->SetTargetWindowId(focusId);

    std::vector<int32_t> pointerIds { pointerEvent->GetPointersIdList() };
    MMI_LOGT("\npointer event dispatcher of server:\neventType=%{public}d,actionTime=%{public}d,"
             "action=%{public}d,actionStartTime=%{public}d,"
             "flag=%{public}d,pointerAction=%{public}d,sourceType=%{public}d,"
             "VerticalAxisValue=%{public}.02f,HorizontalAxisValue=%{public}.02f,"
             "pointerCount=%{public}d",
             pointerEvent->GetEventType(), pointerEvent->GetActionTime(),
             pointerEvent->GetAction(), pointerEvent->GetActionStartTime(),
             pointerEvent->GetFlag(), pointerEvent->GetPointerAction(),
             pointerEvent->GetSourceType(),
             pointerEvent->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL),
             pointerEvent->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL),
             static_cast<int32_t>(pointerIds.size()));

    for (int32_t pointerId : pointerIds) {
        OHOS::MMI::PointerEvent::PointerItem item;
        CHKR(pointerEvent->GetPointerItem(pointerId, item), PARAM_INPUT_FAIL, RET_ERR);

        MMI_LOGT("\n\tdownTime=%{public}d,isPressed=%{public}s,"
                 "globalX=%{public}d,globalY=%{public}d,localX=%{public}d,localY=%{public}d,"
                 "width=%{public}d,height=%{public}d,pressure=%{public}d",
                 item.GetDownTime(), (item.IsPressed() ? "true" : "false"),
                 item.GetGlobalX(), item.GetGlobalY(), item.GetLocalX(), item.GetLocalY(),
                 item.GetWidth(), item.GetHeight(), item.GetPressure());
    }

    NetPacket newPkt(MmiMessageId::ON_POINTER_EVENT);
    InputEventDataTransformation::SerializePointerEvent(pointerEvent, newPkt);
    newPkt << appInfo.fd << preHandlerTime;
    if (!udsServer.SendMsg(appInfo.fd, newPkt)) {
        MMI_LOGE("Sending structure of PointerEvent failed! errCode:%{public}d\n", MSG_SEND_FAIL);
        return MSG_SEND_FAIL;
    }
    return RET_OK;
}
