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
#include "util.h"
#include "mmi_server.h"
#include "system_event_handler.h"
#include "outer_interface.h"

namespace OHOS::MMI {
    namespace {
        static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "EventDispatch" };
    }
}

#ifdef OHOS_AUTO_TEST_FRAME
static float AutoTestStandardValue[JOYSTICK_AXIS_END] = {};
#endif

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

#ifdef OHOS_AUTO_TEST_FRAME    // Send event to auto-test frame
    AutoTestCoordinate coordinate = { static_cast<double>(0), static_cast<double>(0), static_cast<double>(0),
        static_cast<double>(0) };
    auto retAutoTestMag = SendManagePktToAutoTest(udsServer, {}, WinMgr->GetFocusSurfaceId(), fds, coordinate);
    if (retAutoTestMag != RET_OK) {
        MMI_LOGE("Send event to auto-test failed! errCode:%{public}d", KEY_EVENT_DISP_FAIL);
    }
#endif  // OHOS_AUTO_TEST_FRAME
    for (auto fd : fds) {
        auto appInfo = AppRegs->FindBySocketFd(fd);
        MMI_LOGT("\nevent dispatcher of server:\n RegisteredEvent:deviceId=%{public}u;devicePhys=%{public}s;"
                 "deviceType=%{public}u;eventType=%{public}u;occurredTime=%{public}" PRId64 ";uuid=%{public}s;"
                 "conbinecode=%{public}d;fd=%{public}d;windowId=%{public}d;abilityId=%{public}d;\n*****************\n",
                 registeredEvent.deviceId, registeredEvent.devicePhys, registeredEvent.deviceType,
                 registeredEvent.eventType, registeredEvent.occurredTime, registeredEvent.uuid,
                 idMsg, fd, appInfo.windowId, appInfo.abilityId);
#ifdef OHOS_AUTO_TEST_FRAME    // Send event to auto-test frame
        const AutoTestDispatcherPkt autoTestDispatcherPkt = {
            "MixedKey", registeredEvent.eventType, 0, 0, 0, 0, idMsg, fd, appInfo.windowId, appInfo.abilityId,
            0, 0, static_cast<uint16_t>(registeredEvent.deviceType), 0, 0, 0
        };
        auto retAutoTestDpc = SendDispatcherPktToAutoTest(udsServer, autoTestDispatcherPkt);
        if (retAutoTestDpc != RET_OK) {
            MMI_LOGE("Send event to auto-test failed! errCode:%{public}d", KEY_EVENT_DISP_FAIL);
        }
#endif  // OHOS_AUTO_TEST_FRAME

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
#ifdef OHOS_AUTO_TEST_FRAME    // Send event to auto-test frame
    AutoTestCoordinate coordinate = { static_cast<double>(0), static_cast<double>(0), static_cast<double>(0),
        static_cast<double>(0) };
    auto retAutoTestMag = SendManagePktToAutoTest(udsServer, appInfo, WinMgr->GetFocusSurfaceId(), {}, coordinate);
    if (retAutoTestMag != RET_OK) {
        MMI_LOGE("Send event to auto-test failed! errCode:%{public}d", KEY_EVENT_DISP_FAIL);
    }

    const AutoTestDispatcherPkt autoTestDispatcherPkt = {
        "eventTabletPad", tabletPad.eventType, 0, 0, 0, 0, MmiMessageId::INVALID,
        appInfo.fd, focusId, appInfo.abilityId, 0, 0, static_cast<uint16_t>(tabletPad.deviceType),
        tabletPad.deviceId, 0, 0
    };
    auto retAutoTestDpc = SendDispatcherPktToAutoTest(udsServer, autoTestDispatcherPkt);
    if (retAutoTestDpc != RET_OK) {
        MMI_LOGE("Send event to auto-test failed! errCode:%{public}d", KEY_EVENT_DISP_FAIL);
    }

#endif  // OHOS_AUTO_TEST_FRAME
    MMI_LOGT("\n4.event dispatcher of server:\nEventTabletPad:time=%{public}" PRId64 ";deviceType=%{public}u;"
             "deviceId=%{public}u;deviceName=%{public}s;devicePhys=%{public}s;eventType=%{public}d;\n"
             "ring.number=%{public}d;ring.position=%{public}lf;ring.source=%{public}d;\n"
             "strip.number=%{public}d;strip.position=%{public}lf;strip.source=%{public}d;\n"
             "fd=%{public}d;abilityId=%{public}d;windowId=%{public}d;preHandlerTime=%{public}" PRId64 ";\n*"
             "***********************************************************************\n",
             tabletPad.time, tabletPad.deviceType, tabletPad.deviceId, tabletPad.deviceName,
             tabletPad.devicePhys, tabletPad.eventType, tabletPad.ring.number, tabletPad.ring.position,
             tabletPad.ring.source, tabletPad.strip.number, tabletPad.strip.position, tabletPad.strip.source,
             appInfo.fd, appInfo.abilityId, focusId, preHandlerTime);

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
#ifdef OHOS_AUTO_TEST_FRAME    // Send event to auto-test frame
    AutoTestCoordinate coordinate = { static_cast<double>(0), static_cast<double>(0), static_cast<double>(0),
        static_cast<double>(0) };
    auto retAutoTestMag = SendManagePktToAutoTest(udsServer, appInfo, WinMgr->GetFocusSurfaceId(), {}, coordinate);
    if (retAutoTestMag != RET_OK) {
        MMI_LOGE("Send event to auto-test failed! errCode:%{public}d", KEY_EVENT_DISP_FAIL);
    }
    AutoTestDispatcherPkt autoTestDispatcherPkt = {
        "eventJoyStickAxis", eventJoyStickAxis.eventType, 0, 0, 0, 0, MmiMessageId::INVALID, appInfo.fd, focusId,
        appInfo.abilityId, 0, 0, static_cast<uint16_t>(eventJoyStickAxis.deviceType),
        eventJoyStickAxis.deviceId, 0, 0
    };
    for (auto i = 0; i < JOYSTICK_AXIS_END; i++) {
        AutoTestStandardValue[i] = 0;
    }
    autoTestDispatcherPkt.sizeOfstandardValue = JOYSTICK_AXIS_END;
    AutoTestSetStandardValue(eventJoyStickAxis);
    auto retAutoTestDpc = SendDispatcherPktToAutoTest(udsServer, autoTestDispatcherPkt);
    if (retAutoTestDpc != RET_OK) {
        MMI_LOGE("Send event to auto-test failed! errCode:%{public}d", KEY_EVENT_DISP_FAIL);
    }
#endif  // OHOS_AUTO_TEST_FRAME

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
#ifdef OHOS_AUTO_TEST_FRAME    // Send event to auto-test frame
    const AutoTestStandardPkt autoTestStandardPkt = {
        inputEvent.reRventType, inputEvent.curRventType, static_cast<uint32_t>(inputEvent.buttonType),
        inputEvent.buttonState, inputEvent.x, inputEvent.y, 0, 0
    };
    auto retAutoTestStd = SendStandardPktToAutoTest(udsServer, autoTestStandardPkt);
    if (retAutoTestStd != RET_OK) {
        MMI_LOGE("Send event to auto-test failed! errCode:%{public}d", KEY_EVENT_DISP_FAIL);
    }
#endif  // OHOS_AUTO_TEST_FRAME
    
    if (AppRegs->IsMultimodeInputReady(MmiMessageId::ON_TOUCH, appInfo.fd, tableTool.time, preHandlerTime)) {
        NetPacket newPacket(MmiMessageId::ON_TOUCH);
        int32_t inputType = INPUT_DEVICE_CAP_TABLET_TOOL;
        newPacket << inputType << inputEvent.curRventType << tableTool << appInfo.abilityId
            << focusId << appInfo.fd << preHandlerTime;
        if (inputEvent.curRventType > 0) {
            newPacket << inputEvent;
        }

#ifdef OHOS_AUTO_TEST_FRAME    // Send event to auto-test frame
        AutoTestCoordinate coordinate = { static_cast<double>(0), static_cast<double>(0), static_cast<double>(0),
            static_cast<double>(0) };
        auto retAutoTestMag = SendManagePktToAutoTest(udsServer, appInfo, WinMgr->GetFocusSurfaceId(), {}, coordinate);
        if (retAutoTestMag != RET_OK) {
            MMI_LOGE("Send event to auto-test failed! errCode:%{public}d", KEY_EVENT_DISP_FAIL);
        }

        const AutoTestDispatcherPkt autoTestDispatcherPkt = {
            "eventTableTool", inputEvent.curRventType, tableTool.button, inputEvent.buttonState,
            inputEvent.x, inputEvent.y, MmiMessageId::INVALID, appInfo.fd, focusId, appInfo.abilityId,
            0, 0, static_cast<uint16_t>(tableTool.deviceType), tableTool.deviceId, 0, 0
        };
        auto retAutoTestDpc = SendDispatcherPktToAutoTest(udsServer, autoTestDispatcherPkt);
        if (retAutoTestDpc != RET_OK) {
            MMI_LOGE("Send event to auto-test failed! errCode:%{public}d", KEY_EVENT_DISP_FAIL);
        }
#endif  // OHOS_AUTO_TEST_FRAME
#ifdef DEBUG_CODE_TEST
        std::string strIds = WinMgr->GetSurfaceIdListString();
        PrintWMSInfo(strIds, appInfo.fd, appInfo.abilityId, focusId);
#endif
        MMI_LOGT("\n4.event dispatcher of server:TabletTool:time=%{public}" PRId64 "; deviceId=%{public}u; "
                 "deviceType=%{public}u; deviceName=%{public}s; devicePhys=%{public}s; eventType=%{public}d; "
                 "type=%{public}u; tool_id=%{public}u; serial=%{public}u; button=%{public}d; state=%{public}d; "
                 "point.x=%{public}lf; point.y=%{public}lf; tilt.x=%{public}lf; tilt.y=%{public}lf; "
                 "distance=%{public}lf; pressure=%{public}lf; rotation=%{public}lf; slider=%{public}lf; "
                 "wheel=%{public}lf; wheel_discrete=%{public}d; size.major=%{public}lf; size.minor=%{public}lf; "
                 "proximity_state=%{public}d; tip_state=%{public}d; state=%{public}d; seat_button_count=%{public}d; "
                 "preHandlerTime=%{public}" PRId64 "; fd=%{public}d;windowId=%{public}d; "
                 "abilityId=%{public}d;\n**************************************************\n",
                 tableTool.time, tableTool.deviceId, tableTool.deviceType, tableTool.deviceName,
                 tableTool.devicePhys, tableTool.eventType, tableTool.tool.type, tableTool.tool.tool_id,
                 tableTool.tool.serial, tableTool.button, tableTool.state, tableTool.axes.point.x,
                 tableTool.axes.point.y, tableTool.axes.tilt.x, tableTool.axes.tilt.y, tableTool.axes.distance,
                 tableTool.axes.pressure, tableTool.axes.rotation, tableTool.axes.slider, tableTool.axes.wheel,
                 tableTool.axes.wheel_discrete, tableTool.axes.size.major, tableTool.axes.size.minor,
                 tableTool.proximity_state, tableTool.tip_state, tableTool.state, tableTool.seat_button_count,
                 preHandlerTime, appInfo.fd, focusId, appInfo.abilityId);
        if (!udsServer.SendMsg(appInfo.fd, newPacket)) {
            MMI_LOGE("Sending structure of EventTabletTool failed! errCode:%{public}d\n", MSG_SEND_FAIL);
            return MSG_SEND_FAIL;
        }
    }
    return RET_OK;
}

int32_t OHOS::MMI::EventDispatch::DispatchPointerEvent(UDSServer &udsServer, libinput_event &event,
    EventPointer &point, const uint64_t preHandlerTime, WindowSwitch& windowSwitch)
{
    auto type = libinput_event_get_type(&event);
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
#ifdef OHOS_AUTO_TEST_FRAME    // Send event to auto-test frame
    const AutoTestStandardPkt autoTestStandardPkt = {
        inputEvent.reRventType, inputEvent.curRventType, static_cast<uint32_t>(inputEvent.buttonType),
        inputEvent.buttonState, point.delta_raw.x, point.delta_raw.y, point.delta.x, point.delta.y
    };
    auto retAutoTestStd = SendStandardPktToAutoTest(udsServer, autoTestStandardPkt);
    if (retAutoTestStd != RET_OK) {
        MMI_LOGE("Send event to auto-test failed! errCode:%{public}d", KEY_EVENT_DISP_FAIL);
    }
#endif  // OHOS_AUTO_TEST_FRAME

    if (AppRegs->IsMultimodeInputReady(MmiMessageId::ON_TOUCH, appInfo.fd, point.time, preHandlerTime)) {
        struct KeyEventValueTransformations temp = {};
        temp = KeyValueTransformationByInput(point.button);
        point.button = temp.keyValueOfHos;
        NetPacket newPacket(MmiMessageId::ON_TOUCH);
        int32_t inputType = INPUT_DEVICE_CAP_POINTER;
        newPacket << inputType << inputEvent.curRventType << point << appInfo.abilityId
            << desWindowId << appInfo.fd << preHandlerTime;
        if (inputEvent.curRventType > 0) {
            newPacket << inputEvent;
        }
        if (type != LIBINPUT_EVENT_POINTER_BUTTON) {
#ifdef DEBUG_CODE_TEST
            MMI_LOGT("\nMMIWMS:windowId=[%{public}s]\n", strIds.c_str());
            if (desWindowId == -1) {
                MMI_LOGT("\nWMS:windowId = ''\n");
            } else {
                MMI_LOGT("\nWMS:windowId = %{public}d\n", desWindowId);
            }
            MMI_LOGT("\nCALL_AMS:windowId = ''\n");
            MMI_LOGT("\nMMIAPPM:fd =%{public}d,abilityID = %{public}d\n", appInfo.fd, appInfo.abilityId);
#endif
        } else {
            if (size == windowCount_) {
#ifdef DEBUG_CODE_TEST
                MMI_LOGT("\nMMIWMS:windowId = [%{public}s]\n", strIds.c_str());
                MMI_LOGT("\nWMS:windowId = %{public}d\n", desWindowId);
                MMI_LOGT("\nCALL_AMS:windowId = %{public}d\n", desWindowId);
                MMI_LOGT("\nMMIAPPM:fd =%{public}d,abilityID = %{public}d\n", appInfo.fd, appInfo.abilityId);
#endif
            } else {
#ifdef DEBUG_CODE_TEST
                MMI_LOGT("\nMMIWMS:windowId=[%{public}s]\n", strIds.c_str());
                MMI_LOGT("\nWMS:windowId = %{public}d\n", desWindowId);
                MMI_LOGT("\nCALL_AMS:windowId = ''\n");
                MMI_LOGT("\nMMIAPPM:fd =%{public}d,abilityID = %{public}d\n", appInfo.fd, appInfo.abilityId);
#endif
            }
        }

#ifdef OHOS_AUTO_TEST_FRAME    // Send event to auto-test frame
        AutoTestCoordinate coordinate = { static_cast<double>(0), static_cast<double>(0), static_cast<double>(0),
            static_cast<double>(0) };
        auto retAutoTestMag = SendManagePktToAutoTest(udsServer, appInfo, WinMgr->GetFocusSurfaceId(), {}, coordinate);
        if (retAutoTestMag != RET_OK) {
            MMI_LOGE("Send event to auto-test failed! errCode:%{public}d", KEY_EVENT_DISP_FAIL);
        }

        const AutoTestDispatcherPkt autoTestDispatcherPkt = {
            "eventPointer", point.eventType, point.button, point.state, point.delta_raw.x, point.delta_raw.y,
            MmiMessageId::INVALID, appInfo.fd, desWindowId, appInfo.abilityId, point.delta.x, point.delta.y,
            static_cast<uint16_t>(point.deviceType), point.deviceId, 0, 0
        };
        auto retAutoTestDpc = SendDispatcherPktToAutoTest(udsServer, autoTestDispatcherPkt);
        if (retAutoTestDpc != RET_OK) {
            MMI_LOGE("Send event to auto-test failed! errCode:%{public}d", KEY_EVENT_DISP_FAIL);
        }
#endif  // OHOS_AUTO_TEST_FRAME
        MMI_LOGT("\n4.event dispatcher of server:\neventPointer:time=%{public}" PRId64 ";deviceType=%{public}u;"
                 "deviceId=%{public}u;deviceName=%{public}s;devicePhys=%{public}s;eventType=%{public}d;"
                 "buttonCode=%{public}u;seat_button_count=%{public}u;axes=%{public}u;buttonState=%{public}d;"
                 "source=%{public}d;delta.x=%{public}lf;delta.y=%{public}lf;delta_raw.x=%{public}lf;"
                 "delta_raw.y=%{public}lf;absolute.x=%{public}lf;absolute.y=%{public}lf;discrete.x=%{public}lf;"
                 "discrete.y=%{public}lf;fd=%{public}d;abilityId=%{public}d;windowId=%{public}d;"
                 "preHandlerTime=%{public}" PRId64 ";\n**************************************************************\n",
                 point.time, point.deviceType, point.deviceId, point.deviceName,
                 point.devicePhys, point.eventType, point.button, point.seat_button_count, point.axes,
                 point.state, point.source, point.delta.x, point.delta.y, point.delta_raw.x,
                 point.delta_raw.y, point.absolute.x, point.absolute.y, point.discrete.x,
                 point.discrete.y, appInfo.fd, appInfo.abilityId, desWindowId, preHandlerTime);
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
    int32_t focusId = WinMgr->GetFocusSurfaceId();
    if (focusId < 0) {
        return RET_OK;
    }
    auto appInfo = AppRegs->FindByWinId(focusId); // obtain application information
    if (appInfo.fd == RET_ERR) {
        MMI_LOGT("Failed to find fd... errCode:%{public}d", FOCUS_ID_OBTAIN_FAIL);
        return FOCUS_ID_OBTAIN_FAIL;
    }
#ifdef OHOS_AUTO_TEST_FRAME    // Send event to auto-test frame
    AutoTestCoordinate coordinate = { static_cast<double>(0), static_cast<double>(0), static_cast<double>(0),
        static_cast<double>(0) };
    auto retAutoTestMag = SendManagePktToAutoTest(udsServer, appInfo, WinMgr->GetFocusSurfaceId(), {}, coordinate);
    if (retAutoTestMag != RET_OK) {
        MMI_LOGE("Send event to auto-test failed! errCode:%{public}d", KEY_EVENT_DISP_FAIL);
    }
    int32_t slot = 0;
    for (auto size = 0; size < MAX_SOLTED_COORDS_NUM; size++) {
        if (gesture.soltTouches.coords[size].isActive) {
            slot = static_cast<int32_t>(size);
        }
    }
    const AutoTestDispatcherPkt autoTestDispatcherPkt = {
        "eventGesture", gesture.eventType, 0, 0,
        gesture.delta.x, gesture.delta.y, MmiMessageId::INVALID, appInfo.fd, focusId, appInfo.abilityId,
        0, 0, static_cast<uint16_t>(gesture.deviceType), gesture.deviceId, 0, slot
    };
    auto retAutoTestDpc = SendDispatcherPktToAutoTest(udsServer, autoTestDispatcherPkt);
    if (retAutoTestDpc != RET_OK) {
        MMI_LOGE("Send event to auto-test failed! errCode:%{public}d", KEY_EVENT_DISP_FAIL);
    }

#endif  // OHOS_AUTO_TEST_FRAME
    MMI_LOGT("\n4.event dispatcher of server:\nEventGesture:time=%{public}" PRId64 ";deviceType=%{public}u;"
             "deviceId=%{public}u;deviceName=%{public}s;devicePhys=%{public}s;eventType=%{public}d;"
             "fingerCount=%{public}d;cancelled=%{public}d;delta.x=%{public}lf;delta.y=%{public}lf;"
             "deltaUnaccel.x=%{public}lf;deltaUnaccel.y=%{public}lf;fd=%{public}d;abilityId=%{public}d;"
             "windowId=%{public}d;preHandlerTime=%{public}" PRId64 ";\n***************************************************\n",
             gesture.time, gesture.deviceType, gesture.deviceId, gesture.deviceName, gesture.devicePhys,
             gesture.eventType, gesture.fingerCount, gesture.cancelled, gesture.delta.x, gesture.delta.y,
             gesture.deltaUnaccel.x, gesture.deltaUnaccel.y, appInfo.fd, appInfo.abilityId, focusId, preHandlerTime);
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
        MMI_LOGT("Failed to find fd:%{public}d... errCode:%{public}d", touchFocusId, FOCUS_ID_OBTAIN_FAIL);
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
#ifdef OHOS_AUTO_TEST_FRAME    // Send event to auto-test frame
        AutoTestCoordinate coordinate = { static_cast<double>(0), static_cast<double>(0), static_cast<double>(0),
            static_cast<double>(0) };
        auto type = libinput_event_get_type(&event);
        auto data = libinput_event_get_touch_event(&event);
        switch (type) {
            case LIBINPUT_EVENT_TOUCH_DOWN: {
                coordinate.windowRawX = libinput_event_touch_get_x(data);
                coordinate.windowRawY = libinput_event_touch_get_y(data);
                auto touchSurfaceInfo = WinMgr->GetTouchSurfaceInfo(coordinate.windowRawX, coordinate.windowRawY);
                CHKR(touchSurfaceInfo, NULL_POINTER, RET_ERR);
                coordinate.focusWindowRawX = coordinate.windowRawX - touchSurfaceInfo->dstX;
                coordinate.focusWindowRawY = coordinate.windowRawX - touchSurfaceInfo->dstX;
                break;
            }
            case LIBINPUT_EVENT_TOUCH_UP: {
                coordinate.windowRawX = 0;
                coordinate.windowRawY = 0;
                coordinate.focusWindowRawX = 0;
                coordinate.focusWindowRawY = 0;
                break;
            }
            case LIBINPUT_EVENT_TOUCH_MOTION: {
                coordinate.windowRawX = libinput_event_touch_get_x(data);
                coordinate.windowRawY = libinput_event_touch_get_y(data);
                auto touchSurfaceId = WinMgr->GetTouchFocusSurfaceId();
                auto touchSurfaceInfo = WinMgr->GetSurfaceInfo(touchSurfaceId);
                CHKR(touchSurfaceInfo, NULL_POINTER, RET_ERR);
                coordinate.focusWindowRawX = coordinate.windowRawX - touchSurfaceInfo->dstX;
                coordinate.focusWindowRawY = coordinate.windowRawX - touchSurfaceInfo->dstX;
                break;
            }
            default: {
                break;
            }
        }
        auto retAutoTestMag = SendManagePktToAutoTest(udsServer, appInfo, WinMgr->GetTouchFocusSurfaceId(), {}, 
            coordinate);
        if (retAutoTestMag != RET_OK) {
            MMI_LOGE("Send event to auto-test failed! errCode:%{public}d", KEY_EVENT_DISP_FAIL);
        }
#endif  // OHOS_AUTO_TEST_FRAME
        std::vector<PAIR<uint32_t, int32_t>> touchIds;
        MMIRegEvent->GetTouchIds(touchIds, touch.deviceId);
        if (!touchIds.empty()) {
            for (PAIR<uint32_t, int32_t> touchId : touchIds) {
                struct EventTouch touchTemp = {};
                CHKR(EOK == memcpy_s(&touchTemp, sizeof(touchTemp), &touch, sizeof(touch)),
                     MEMCPY_SEC_FUN_FAIL, RET_ERR);
                MMIRegEvent->GetTouchInfoByTouchId(touchTemp, touchId);
                MMI_LOGT("\n4.event dispatcher of server:\neventTouch:time=%{public}" PRId64 ";deviceType=%{public}u;"
                         "deviceId=%{public}u;deviceName=%{public}s;devicePhys=%{public}s;eventType=%{public}d;"
                         "slot=%{public}d;seat_slot=%{public}d;pressure=%{public}lf;point.x=%{public}lf;"
                         "point.y=%{public}lf;fd=%{public}d;abilityId=%{public}d,windowId=%{public}d;"
                         "preHandlerTime=%{public}" PRId64 ";\n*********************************************************\n",
                         touchTemp.time, touchTemp.deviceType, touchTemp.deviceId, touchTemp.deviceName,
                         touchTemp.devicePhys, touchTemp.eventType, touchTemp.slot, touchTemp.seat_slot,
                         touchTemp.pressure, touchTemp.point.x, touchTemp.point.y, appInfo.fd,
                         appInfo.abilityId, touchFocusId, preHandlerTime);
                newPacket << touchTemp;

#ifdef OHOS_AUTO_TEST_FRAME    // Send event to auto-test frame
                const AutoTestDispatcherPkt autoTestDispatcherPkt = {
                    "eventTouch", touchTemp.eventType, 0, 0, touchTemp.point.x, touchTemp.point.y,
                    MmiMessageId::INVALID, appInfo.fd, touchFocusId, appInfo.abilityId, 0, 0,
                    static_cast<uint16_t>(touchTemp.deviceType), touchTemp.deviceId, 0, touchTemp.slot
                };
                auto retAutoTestDpc = SendDispatcherPktToAutoTest(udsServer, autoTestDispatcherPkt);
                if (retAutoTestDpc != RET_OK) {
                    MMI_LOGE("Send event to auto-test failed! errCode:%{public}d", KEY_EVENT_DISP_FAIL);
                }
#endif  // OHOS_AUTO_TEST_FRAME
            }
        }
        if (touch.eventType == LIBINPUT_EVENT_TOUCH_UP) {
            newPacket << touch;
            MMI_LOGT("\n4.event dispatcher of server:\neventTouch:time=%{public}" PRId64 ";deviceType=%{public}u;"
                     "deviceId=%{public}u;deviceName=%{public}s;devicePhys=%{public}s;eventType=%{public}d;"
                     "slot=%{public}d;seat_slot=%{public}d;pressure=%{public}lf;point.x=%{public}lf;"
                     "point.y=%{public}lf;fd=%{public}d;abilityId=%{public}d;windowId=%{public}d;"
                     "preHandlerTime=%{public}" PRId64 ";\n****************************************************************\n",
                     touch.time, touch.deviceType, touch.deviceId, touch.deviceName,
                     touch.devicePhys, touch.eventType, touch.slot, touch.seat_slot, touch.pressure,
                     touch.point.x, touch.point.y, appInfo.fd, appInfo.abilityId, touchFocusId, preHandlerTime);

#ifdef OHOS_AUTO_TEST_FRAME    // Send event to auto-test frame
            const AutoTestDispatcherPkt autoTestDispatcherPkt = {
                "eventTouch", touch.eventType, 0, 0,
                touch.point.x, touch.point.y, MmiMessageId::INVALID, appInfo.fd, touchFocusId, appInfo.abilityId,
                0, 0, static_cast<uint16_t>(touch.deviceType), touch.deviceId, 0, touch.slot
            };
            auto retAutoTestDpc = SendDispatcherPktToAutoTest(udsServer, autoTestDispatcherPkt);
            if (retAutoTestDpc != RET_OK) {
                MMI_LOGE("Send event to auto-test failed! errCode:%{public}d", KEY_EVENT_DISP_FAIL);
            }
#endif  // OHOS_AUTO_TEST_FRAME
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
             "deviceId=%{public}u;deviceName=%{public}s;devicePhys=%{public}s;eventType=%{public}d;"
             "mUnicode=%{public}d;key=%{public}u;key_detail=%{public}s;seat_key_count=%{public}u;"
             "state=%{public}d;fd=%{public}d;abilityId=%{public}d;windowId=%{public}d;"
             "preHandlerTime=%{public}" PRId64 ";\n***********************************************************************\n",
             key.time, key.deviceType, key.deviceId, key.deviceName, key.devicePhys, key.eventType,
             key.mUnicode, key.key, trs.keyEvent.c_str(), key.seat_key_count, key.state, appInfo.fd,
             appInfo.abilityId, focusId, preHandlerTime);
#ifdef OHOS_AUTO_TEST_FRAME    // Send event to auto-test frame
    AutoTestCoordinate coordinate = { static_cast<double>(0), static_cast<double>(0), static_cast<double>(0),
        static_cast<double>(0) };
    auto retAutoTestMag = SendManagePktToAutoTest(udsServer, appInfo, WinMgr->GetFocusSurfaceId(), {}, coordinate);
    if (retAutoTestMag != RET_OK) {
        MMI_LOGE("Send event to auto-test failed! errCode:%{public}d", KEY_EVENT_DISP_FAIL);
    }

    AutoTestDispatcherPkt autoTestDispatcherPkt = {
        "eventKeyboard", key.eventType, key.key, key.state, 0, 0, MmiMessageId::INVALID, appInfo.fd, focusId,
        appInfo.abilityId, 0, 0, static_cast<uint16_t>(key.deviceType), key.deviceId, 0, 0
    };
    auto retAutoTestDpc = SendDispatcherPktToAutoTest(udsServer, autoTestDispatcherPkt);
    if (retAutoTestDpc != RET_OK) {
        MMI_LOGE("Send event to auto-test failed! errCode:%{public}d", KEY_EVENT_DISP_FAIL);
    }
#endif  // OHOS_AUTO_TEST_FRAME

    if (AppRegs->IsMultimodeInputReady(MmiMessageId::ON_KEY, appInfo.fd, key.time, preHandlerTime)) {
        NetPacket newPkt(MmiMessageId::ON_KEY);
        newPkt << key << appInfo.abilityId << focusId << preHandlerTime;
        if (!udsServer.SendMsg(appInfo.fd, newPkt)) {
            MMI_LOGE("Sending structure of EventKeyboard failed! errCode:%{public}d\n", MSG_SEND_FAIL);
            return MSG_SEND_FAIL;
        }
    }
    return ret;
}

// Auto-test frame code
#ifdef OHOS_AUTO_TEST_FRAME
int32_t OHOS::MMI::EventDispatch::SendLibPktToAutoTest(UDSServer& udsServer,
    const AutoTestLibinputPkt& autoTestLibinputPkt)
{
    if (!AppRegs->AutoTestGetAutoTestFd()) {
        return RET_OK;
    }

    NetPacket pktAutoTest(MmiMessageId::ST_MESSAGE_LIBPKT);
    pktAutoTest << autoTestLibinputPkt;
    if (!udsServer.SendMsg(AppRegs->AutoTestGetAutoTestFd(), pktAutoTest)) {
        MMI_LOGE("Send LibinputPkt massage failed to auto-test frame ! \n");
        return MSG_SEND_FAIL;
    }
    return RET_OK;
}

int32_t OHOS::MMI::EventDispatch::SendMappingPktToAutoTest(UDSServer& udsServer, int32_t sourceType)
{
    if (!AppRegs->AutoTestGetAutoTestFd()) {
        return RET_OK;
    }

    NetPacket pktAutoTest(MmiMessageId::ST_MESSAGE_MAPPKT);
    pktAutoTest << sourceType;
    if (!udsServer.SendMsg(AppRegs->AutoTestGetAutoTestFd(), pktAutoTest)) {
        MMI_LOGE("Send MappingPkt massage failed to auto-test frame ! \n");
        return MSG_SEND_FAIL;
    }
    return RET_OK;
}

int32_t OHOS::MMI::EventDispatch::SendStandardPktToAutoTest(UDSServer& udsServer,
    const AutoTestStandardPkt& autoTestStandardPkt)
{
    if (!AppRegs->AutoTestGetAutoTestFd()) {
        return RET_OK;
    }

    NetPacket pktAutoTest(MmiMessageId::ST_MESSAGE_STDPKT);
    pktAutoTest << autoTestStandardPkt;
    if (!udsServer.SendMsg(AppRegs->AutoTestGetAutoTestFd(), pktAutoTest)) {
        MMI_LOGE("Send StandardPkt massage failed to auto-test frame ! \n");
        return MSG_SEND_FAIL;
    }
    return RET_OK;
}

int32_t OHOS::MMI::EventDispatch::SendDispatcherPktToAutoTest(UDSServer& udsServer,
    const AutoTestDispatcherPkt& autoTestDispatcherPkt) const
{
    if (!AppRegs->AutoTestGetAutoTestFd()) {
        return RET_OK;
    }

    std::vector<float> autoTestJoystic;
    float tempstandardValue = 0;
    for (auto i = 0; i < autoTestDispatcherPkt.sizeOfstandardValue; i++) {
        tempstandardValue = AutoTestStandardValue[i];
        autoTestJoystic.push_back(tempstandardValue);
    }
    uint16_t joysticAxisNum = autoTestJoystic.size();
    NetPacket pktAutoTest(MmiMessageId::ST_MESSAGE_DPCPKT);

    pktAutoTest << joysticAxisNum << autoTestDispatcherPkt;
    for (auto it = autoTestJoystic.begin(); it != autoTestJoystic.end(); it++) {
        pktAutoTest << *it;
    }
    if (!udsServer.SendMsg(AppRegs->AutoTestGetAutoTestFd(), pktAutoTest)) {
        MMI_LOGE("Send DispatcherPkt massage failed to auto-test frame ! \n");
        return MSG_SEND_FAIL;
    }
    return RET_OK;
}

int32_t OHOS::MMI::EventDispatch::SendManagePktToAutoTest(UDSServer& udsServer, const OHOS::MMI::AppInfo& appInfo,
    const int32_t focusId, const std::vector<int32_t>& fds, AutoTestCoordinate coordinate) const
{
    if (!AppRegs->AutoTestGetAutoTestFd()) {
        return RET_OK;
    }

    std::vector<int32_t> windowList;
    std::vector<AutoTestClientListPkt> clientList;
    WinMgr->GetSurfaceIdList(windowList);
    if (fds.empty()) {
        AutoTestClientListPkt tempInfo = {appInfo.fd, focusId, appInfo.abilityId};
        clientList.push_back(tempInfo);
    } else {
        for (auto fd : fds) {
            auto tempAppInfo = AppRegs->FindBySocketFd(fd);
            AutoTestClientListPkt tempInfo = {tempAppInfo.fd, tempAppInfo.windowId, tempAppInfo.abilityId};
            clientList.push_back(tempInfo);
        }
    }
    AutoTestManagePkt autoTestManagePkt = {};
    autoTestManagePkt.sizeOfWindowList = static_cast<int32_t>(windowList.size());
    autoTestManagePkt.sizeOfAppManager = static_cast<int32_t>(clientList.size());
    autoTestManagePkt.focusId = focusId;
    autoTestManagePkt.windowId = appInfo.windowId;

    NetPacket pktAutoTest(MmiMessageId::ST_MESSAGE_MAGPKT);
    pktAutoTest << autoTestManagePkt;
    for (auto it = windowList.begin(); it != windowList.end(); it++) {
        pktAutoTest << *it;
    }
    for (auto it = clientList.begin(); it != clientList.end(); it++) {
        pktAutoTest << *it;
    }
    pktAutoTest << coordinate;
    if (!udsServer.SendMsg(AppRegs->AutoTestGetAutoTestFd(), pktAutoTest)) {
        MMI_LOGE("Send ManagePkt massage failed to auto-test frame ! \n");
        return MSG_SEND_FAIL;
    }
    return RET_OK;
}

int32_t OHOS::MMI::EventDispatch::SendKeyTypePktToAutoTest(UDSServer& udsServer,
    const AutoTestKeyTypePkt& autoTestKeyTypePkt)
{
    if (!AppRegs->AutoTestGetAutoTestFd()) {
        return RET_OK;
    }

    NetPacket pktAutoTest(MmiMessageId::ST_MESSAGE_KEYTYPEPKT);
    pktAutoTest << autoTestKeyTypePkt;
    if (!udsServer.SendMsg(AppRegs->AutoTestGetAutoTestFd(), pktAutoTest)) {
        MMI_LOGE("Send KeyTypePkt massage failed to auto-test frame ! \n");
        return MSG_SEND_FAIL;
    }
    return RET_OK;
}
void OHOS::MMI::EventDispatch::AutoTestSetStandardValue(EventJoyStickAxis& eventJoyStickAxis)
{
    if (eventJoyStickAxis.abs_throttle.isChanged) {
        AutoTestStandardValue[JOYSTICK_AXIS_THROTTLE] = eventJoyStickAxis.abs_throttle.standardValue;
    }
    if (eventJoyStickAxis.abs_hat0x.isChanged) {
        AutoTestStandardValue[JOYSTICK_AXIS_HAT0X] = eventJoyStickAxis.abs_hat0x.standardValue;
    }
    if (eventJoyStickAxis.abs_hat0y.isChanged) {
        AutoTestStandardValue[JOYSTICK_AXIS_HAT0Y] = eventJoyStickAxis.abs_hat0y.standardValue;
    }
    if (eventJoyStickAxis.abs_x.isChanged) {
        AutoTestStandardValue[JOYSTICK_AXIS_X] = eventJoyStickAxis.abs_x.standardValue;
    }
    if (eventJoyStickAxis.abs_y.isChanged) {
        AutoTestStandardValue[JOYSTICK_AXIS_Y] = eventJoyStickAxis.abs_y.standardValue;
    }
    if (eventJoyStickAxis.abs_z.isChanged) {
        AutoTestStandardValue[JOYSTICK_AXIS_Z] = eventJoyStickAxis.abs_z.standardValue;
    }
    if (eventJoyStickAxis.abs_rx.isChanged) {
        AutoTestStandardValue[JOYSTICK_AXIS_RX] = eventJoyStickAxis.abs_rx.standardValue;
    }
    if (eventJoyStickAxis.abs_ry.isChanged) {
        AutoTestStandardValue[JOYSTICK_AXIS_RY] = eventJoyStickAxis.abs_ry.standardValue;
    }
    if (eventJoyStickAxis.abs_rz.isChanged) {
        AutoTestStandardValue[JOYSTICK_AXIS_RZ] = eventJoyStickAxis.abs_rz.standardValue;
    }
}
#endif  // OHOS_AUTO_TEST_FRAME