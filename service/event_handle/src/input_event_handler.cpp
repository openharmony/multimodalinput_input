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

#include "input_event_handler.h"
#include <sys/stat.h>
#include <vector>
#include <cstring>
#include <unistd.h>
#include <functional>
#include <cstdio>
#include <inttypes.h>
#include "util.h"
#include "mmi_server.h"
#include "outer_interface.h"
#include "time_cost_chk.h"

namespace OHOS::MMI {
    namespace {
        static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "InputEventHandler" };
    }
}

OHOS::MMI::InputEventHandler::InputEventHandler()
{
    udsServer_ = nullptr;
    notifyDeviceChange_ = nullptr;
}

OHOS::MMI::InputEventHandler::~InputEventHandler()
{
}

bool OHOS::MMI::InputEventHandler::Init(UDSServer& udsServer)
{
    udsServer_ = &udsServer;
    MsgCallback funs[] = {
        {
            MmiMessageId::LIBINPUT_EVENT_DEVICE_ADDED,
            std::bind(&InputEventHandler::OnEventDeviceAdded, this, std::placeholders::_1)
        },
        {
            MmiMessageId::LIBINPUT_EVENT_DEVICE_REMOVED,
            std::bind(&InputEventHandler::OnEventDeviceRemoved, this, std::placeholders::_1)
        },
        {
            MmiMessageId::LIBINPUT_EVENT_KEYBOARD_KEY,
            std::bind(&InputEventHandler::OnEventKeyboard, this, std::placeholders::_1)
        },
        {
            MmiMessageId::LIBINPUT_EVENT_POINTER_MOTION,
            std::bind(&InputEventHandler::OnEventPointer, this, std::placeholders::_1)
        },
        {
            MmiMessageId::LIBINPUT_EVENT_POINTER_MOTION_ABSOLUTE,
            std::bind(&InputEventHandler::OnEventPointer, this, std::placeholders::_1)
        },
        {
            MmiMessageId::LIBINPUT_EVENT_POINTER_BUTTON,
            std::bind(&InputEventHandler::OnEventPointer, this, std::placeholders::_1)
        },
        {
            MmiMessageId::LIBINPUT_EVENT_POINTER_AXIS,
            std::bind(&InputEventHandler::OnEventPointer, this, std::placeholders::_1)
        },
        {
            MmiMessageId::LIBINPUT_EVENT_TOUCH_DOWN,
            std::bind(&InputEventHandler::OnEventTouch, this, std::placeholders::_1)
        },
        {
            MmiMessageId::LIBINPUT_EVENT_TOUCH_UP,
            std::bind(&InputEventHandler::OnEventTouch, this, std::placeholders::_1)
        },
        {
            MmiMessageId::LIBINPUT_EVENT_TOUCH_MOTION,
            std::bind(&InputEventHandler::OnEventTouch, this, std::placeholders::_1)
        },
        {
            MmiMessageId::LIBINPUT_EVENT_TOUCH_CANCEL,
            std::bind(&InputEventHandler::OnEventTouch, this, std::placeholders::_1)
        },
        {
            MmiMessageId::LIBINPUT_EVENT_TOUCH_FRAME,
            std::bind(&InputEventHandler::OnEventTouch, this, std::placeholders::_1)
        },
        {
            MmiMessageId::LIBINPUT_EVENT_TABLET_TOOL_AXIS,
            std::bind(&InputEventHandler::OnEventTabletTool, this, std::placeholders::_1)
        },
        {
            MmiMessageId::LIBINPUT_EVENT_TABLET_TOOL_PROXIMITY,
            std::bind(&InputEventHandler::OnEventTabletTool, this, std::placeholders::_1)
        },
        {
            MmiMessageId::LIBINPUT_EVENT_TABLET_TOOL_TIP,
            std::bind(&InputEventHandler::OnEventTabletTool, this, std::placeholders::_1)
        },
        {
            MmiMessageId::LIBINPUT_EVENT_TABLET_TOOL_BUTTON,
            std::bind(&InputEventHandler::OnEventTabletTool, this, std::placeholders::_1)
        },
        {
            MmiMessageId::LIBINPUT_EVENT_TABLET_PAD_BUTTON,
            std::bind(&InputEventHandler::OnEventTabletPadKey, this, std::placeholders::_1)
        },
        {
            MmiMessageId::LIBINPUT_EVENT_TABLET_PAD_RING,
            std::bind(&InputEventHandler::OnEventTabletPad, this, std::placeholders::_1)
        },
        {
            MmiMessageId::LIBINPUT_EVENT_TABLET_PAD_STRIP,
            std::bind(&InputEventHandler::OnEventTabletPad, this, std::placeholders::_1)
        },
        {
            MmiMessageId::LIBINPUT_EVENT_TABLET_PAD_KEY,
            std::bind(&InputEventHandler::OnEventTabletPadKey, this, std::placeholders::_1)
        },
        {
            MmiMessageId::LIBINPUT_EVENT_GESTURE_SWIPE_BEGIN,
            std::bind(&InputEventHandler::OnEventGesture, this, std::placeholders::_1)
        },
        {
            MmiMessageId::LIBINPUT_EVENT_GESTURE_SWIPE_UPDATE,
            std::bind(&InputEventHandler::OnEventGesture, this, std::placeholders::_1)
        },
        {
            MmiMessageId::LIBINPUT_EVENT_GESTURE_SWIPE_END,
            std::bind(&InputEventHandler::OnEventGesture, this, std::placeholders::_1)
        },
        {
            MmiMessageId::LIBINPUT_EVENT_GESTURE_PINCH_BEGIN,
            std::bind(&InputEventHandler::OnEventGesture, this, std::placeholders::_1)
        },
        {
            MmiMessageId::LIBINPUT_EVENT_GESTURE_PINCH_UPDATE,
            std::bind(&InputEventHandler::OnEventGesture, this, std::placeholders::_1)
        },
        {
            MmiMessageId::LIBINPUT_EVENT_GESTURE_PINCH_END,
            std::bind(&InputEventHandler::OnEventGesture, this, std::placeholders::_1)
        },
        {
            MmiMessageId::LIBINPUT_EVENT_SWITCH_TOGGLE,
            std::bind(&InputEventHandler::OnEventSwitchToggle, this, std::placeholders::_1)
        },
    };
    for (auto& it : funs) {
        CHKC(RegistrationEvent(it), EVENT_REG_FAIL);
    }
    return true;
}

void OHOS::MMI::InputEventHandler::OnEvent(void *event)
{
    CHK(event, NULL_POINTER);
    std::lock_guard<std::mutex> lock(mu_);
    auto *lpMmiEvent = static_cast<multimodal_libinput_event *>(event);
    CHK(lpMmiEvent, NULL_POINTER);
    auto *lpEvent = lpMmiEvent->event;
    CHK(lpEvent, NULL_POINTER);
    if (initSysClock_ != 0 && lastSysClock_ == 0) {
        MMI_LOGE("Event not handled... id:%{public}" PRId64 " eventType:%{public}d initSysClock:%{public}" PRId64 "",
                 idSeed_, eventType_, initSysClock_);
    }

    eventType_ = libinput_event_get_type(lpEvent);
    auto tid = GetThisThreadIdOfLL();
    const uint64_t maxUInt64 = (std::numeric_limits<uint64_t>::max)() - 1;
    initSysClock_ = GetSysClockTime();
    lastSysClock_ = 0;
    idSeed_ += 1;
    if (idSeed_ >= maxUInt64) {
        idSeed_ = 1;
    }
    MMI_LOGT("Event reporting... id:%{public}" PRId64 " tid:%{public}" PRId64 " eventType:%{public}d initSysClock:%{public}" PRId64 "",
             idSeed_, tid, eventType_, initSysClock_);

    OnEventHandler(*lpMmiEvent);
    lastSysClock_ = GetSysClockTime();
    uint64_t lostTime = lastSysClock_ - initSysClock_;
    MMI_LOGT("Event handling completed... id:%{public}" PRId64 " lastSynClock:%{public}" PRId64 " lostTime:%{public}" PRId64 "",
             idSeed_, lastSysClock_, lostTime);
}

int32_t OHOS::MMI::InputEventHandler::OnEventHandler(multimodal_libinput_event &ev)
{
    CHKR(ev.event, NULL_POINTER, NULL_POINTER);
    auto type = libinput_event_get_type(ev.event);
    OHOS::MMI::TimeCostChk chk("InputEventHandler::OnEventHandler", "overtime 1000(us)", MAX_INPUT_EVENT_TIME, type);
    auto fun = GetFun(static_cast<MmiMessageId>(type));
    if (!fun) {
        MMI_LOGE("Unknown event type[%{public}d].errCode:%{public}d", type, UNKNOWN_EVENT);
        return UNKNOWN_EVENT;
    }
    auto ret = (*fun)(ev);
    if (ret != 0) {
        MMI_LOGE("Event handling failed. type[%{public}d] ret[%{public}d] errCode:%{public}d",
                 type, ret, EVENT_CONSUM_FAIL);
    }
    return ret;
}

void OHOS::MMI::InputEventHandler::OnCheckEventReport()
{
    std::lock_guard<std::mutex> lock(mu_);
    if (initSysClock_ == 0) {
        return;
    }
    if (lastSysClock_ != 0) {
        return;
    }

    const uint64_t MAX_DID_TIME = 1000 * 1000 * 3;
    auto curSysClock = GetSysClockTime();
    auto lostTime = curSysClock - initSysClock_;
    if (lostTime < MAX_DID_TIME) {
        return;
    }
    MMI_LOGE("Event not responding... id:%{public}" PRId64 " eventType:%{public}d initSysClock:%{public}" PRId64 " "
             "lostTime:%{public}" PRId64 "", idSeed_, eventType_, initSysClock_, lostTime);
}

void OHOS::MMI::InputEventHandler::RegistnotifyDeviceChange(NotifyDeviceChange cb)
{
    notifyDeviceChange_ = cb;
}

int32_t OHOS::MMI::InputEventHandler::OnEventDeviceAdded(multimodal_libinput_event &ev)
{
    CHKR(ev.event, NULL_POINTER, NULL_POINTER);
    uint64_t preHandlerTime = GetSysClockTime();
    DeviceManage deviceManage = {};

    CHKR(udsServer_, NULL_POINTER, RET_ERR);
    auto packageResult = eventPackage_.PackageDeviceManageEvent(*ev.event, deviceManage, *udsServer_);
    if (packageResult != RET_OK) {
        MMI_LOGE("Deviceadded event package failed... ret:%{public}d errCode:%{public}d",
                 packageResult, DEV_ADD_EVENT_PKG_FAIL);
        return DEV_ADD_EVENT_PKG_FAIL;
    }
    MMI_LOGT("\n4.event dispatcher of server:DeviceManage:deviceId=%{public}u;devicePhys=%{public}s;"
             "deviceName=%{public}s;deviceType=%{public}u;\n**************************************\n",
             deviceManage.deviceId, deviceManage.devicePhys, deviceManage.deviceName, deviceManage.deviceType);

    int32_t focusId = WinMgr->GetFocusSurfaceId();
    if (focusId < 0) {
        return RET_OK; // DeviceAdded event will be discarded if focusId < 0
    }
    auto appInfo = AppRegs->FindByWinId(focusId);
    if (appInfo.fd == RET_ERR) {
        return RET_OK; // DeviceAdded event will be discarded if appInfo.fd == RET_ERR
    }
    NetPacket newPacket(MmiMessageId::ON_DEVICE_ADDED);
    newPacket << deviceManage << appInfo.abilityId << focusId << appInfo.fd << preHandlerTime;
    if (!SendMsg(appInfo.fd, newPacket)) {
        MMI_LOGE("Sending structure of DeviceManage failed! errCode:%{public}d\n", MSG_SEND_FAIL);
        return MSG_SEND_FAIL;
    }
    return RET_OK;
}

int32_t OHOS::MMI::InputEventHandler::OnEventDeviceRemoved(multimodal_libinput_event &ev)
{
    CHKR(ev.event, NULL_POINTER, NULL_POINTER);
    uint64_t preHandlerTime = GetSysClockTime();
    CHKR(udsServer_, NULL_POINTER, RET_ERR);
    DeviceManage deviceManage = {};
    auto packageResult = eventPackage_.PackageDeviceManageEvent(*ev.event, deviceManage, *udsServer_);
    if (packageResult != RET_OK) {
        MMI_LOGE("Deviceremoved event package failed... ret:%{public}d errCode:%{public}d",
                 packageResult, DEV_REMOVE_EVENT_PKG_FAIL);
        return DEV_REMOVE_EVENT_PKG_FAIL;
    }
    MMI_LOGT("\n4.event dispatcher of server:DeviceManage:deviceId=%{public}u;devicePhys=%{public}s;"
             "deviceName=%{public}s;deviceType=%{public}u;\n**************************************\n",
             deviceManage.deviceId, deviceManage.devicePhys, deviceManage.deviceName, deviceManage.deviceType);

    int32_t focusId = WinMgr->GetFocusSurfaceId();
    if (focusId < 0) {
        return RET_OK; // DeviceRemoved event will be discarded if focusId < 0
    }
    auto appInfo = AppRegs->FindByWinId(focusId);
    if (appInfo.fd == RET_ERR) {
        return RET_OK; // DeviceRemoved event will be discarded if appInfo.fd == RET_ERR
    }
    NetPacket newPacket(MmiMessageId::ON_DEVICE_REMOVED);
    newPacket << deviceManage << appInfo.abilityId << focusId << appInfo.fd << preHandlerTime;
    if (!SendMsg(appInfo.fd, newPacket)) {
        MMI_LOGE("Sending structure of DeviceManage failed! errCode:%{public}d\n", MSG_SEND_FAIL);
        return MSG_SEND_FAIL;
    }
    return RET_OK;
}

int32_t OHOS::MMI::InputEventHandler::OnEventKeyboard(multimodal_libinput_event &ev)
{
    CHKR(ev.event, NULL_POINTER, NULL_POINTER);
    uint64_t preHandlerTime = GetSysClockTime();
    EventKeyboard key = {};
    CHKR(udsServer_, NULL_POINTER, RET_ERR);
    auto packageResult = eventPackage_.PackageKeyEvent(*ev.event, key, *udsServer_);
    if (packageResult == MULTIDEVICE_SAME_EVENT_FAIL) { // The multi_device_same_event should be discarded
        return RET_OK;
    }
    if (packageResult != RET_OK) {
        MMI_LOGE("Key event package failed... ret:%{public}d errCode:%{public}d", packageResult, KEY_EVENT_PKG_FAIL);
        return KEY_EVENT_PKG_FAIL;
    }
#ifdef OHOS_AUTO_TEST_FRAME // Send event to auto-test frame
    const AutoTestLibinputPkt autoTestLibinputPkt = {"eventKeyboard", key.key, key.state, 0, 0, 0, 0};
    auto retAutoTestLibPkt = eventDispatch_.SendLibPktToAutoTest(*udsServer_, autoTestLibinputPkt);
    if (retAutoTestLibPkt != RET_OK) {
        MMI_LOGE("Send event to auto-test failed! errCode:%{public}d", KEY_EVENT_DISP_FAIL);
    }
    auto retAutoTestMapPkt = eventDispatch_.SendMappingPktToAutoTest(*udsServer_, key.eventType);
    if (retAutoTestMapPkt != RET_OK) {
        MMI_LOGE("Send event to auto-test failed! errCode:%{public}d", KEY_EVENT_DISP_FAIL);
    }
#endif  // OHOS_AUTO_TEST_FRAME

    auto hosKey = KeyValueTransformationByInput(key.key); // libinput key transformed into HOS key
    key.mUnicode = 0;
#ifndef OHOS_AUTO_TEST_FRAME
    if (hosKey.isSystemKey && OnSystemEvent(hosKey, key.state)) { // Judging whether key is system key.
        return RET_OK;
    }
#else
    AutoTestKeyTypePkt autoTestKeyTypePkt = {};
    bool retSystemEvent = OnSystemEvent(hosKey, key.state, autoTestKeyTypePkt);
    auto retAutoTestTypePktPkt = eventDispatch_.SendKeyTypePktToAutoTest(*udsServer_, autoTestKeyTypePkt);
    if (retAutoTestTypePktPkt != RET_OK) {
        MMI_LOGE("Send event to auto-test failed! errCode:%{public}d", KEY_EVENT_DISP_FAIL);
    }
    if (hosKey.isSystemKey && retSystemEvent) {
        return RET_OK;
    }
#endif  // OHOS_AUTO_TEST_FRAME
    auto eventDispatchResult = eventDispatch_.DispatchKeyEvent(*udsServer_, *ev.event, hosKey, key, preHandlerTime);
    if (eventDispatchResult != RET_OK) {
        MMI_LOGE("Key event dispatch failed... ret:%{public}d errCode:%{public}d",
                 eventDispatchResult, KEY_EVENT_DISP_FAIL);
        return KEY_EVENT_DISP_FAIL;
    }
    return RET_OK;
}

int32_t OHOS::MMI::InputEventHandler::OnEventPointer(multimodal_libinput_event &ev)
{
    CHKR(ev.event, NULL_POINTER, NULL_POINTER);
    uint64_t preHandlerTime = GetSysClockTime();
    auto device = libinput_event_get_device(ev.event);
    auto type = libinput_event_get_type(ev.event);
    CHKR(device, NULL_POINTER, LIBINPUT_DEV_EMPTY);
    CHKR(udsServer_, NULL_POINTER, RET_ERR);
    int32_t devicType = static_cast<int32_t>(libinput_device_get_tags(device));
    if (devicType & EVDEV_UDEV_TAG_JOYSTICK) {
        if (type == LIBINPUT_EVENT_POINTER_BUTTON) {
            return OnEventJoyStickKey(ev, preHandlerTime);
        } else if (type == LIBINPUT_EVENT_POINTER_AXIS) {
            return OnEventJoyStickAxis(ev, preHandlerTime);
        }
    }
    EventPointer point = {};
    auto packageResult = eventPackage_.PackagePointerEvent(ev, point, winSwitch_, *udsServer_);
    if (packageResult == MULTIDEVICE_SAME_EVENT_FAIL) { // The multi_device_same_event should be discarded
        return RET_OK;
    }
    if (packageResult != RET_OK) {
        MMI_LOGE("Pointer event package failed... ret:%{public}d errCode:%{public}d",
                 packageResult, POINT_EVENT_PKG_FAIL);
        return POINT_EVENT_PKG_FAIL;
    }
#ifdef OHOS_AUTO_TEST_FRAME // Send event to auto-test frame
    const AutoTestLibinputPkt autoTestLibinputPkt = {
        "eventPointer", point.button, point.state,
        point.delta_raw.x, point.delta_raw.y, point.delta.x, point.delta.y
    };
    auto retAutoTestLibPkt = eventDispatch_.SendLibPktToAutoTest(*udsServer_, autoTestLibinputPkt);
    if (retAutoTestLibPkt != RET_OK) {
        MMI_LOGE("Send event to auto-test failed! errCode:%{public}d", KEY_EVENT_DISP_FAIL);
    }
    auto retAutoTestMapPkt = eventDispatch_.SendMappingPktToAutoTest(*udsServer_, point.eventType);
    if (retAutoTestMapPkt != RET_OK) {
        MMI_LOGE("Send event to auto-test failed! errCode:%{public}d", KEY_EVENT_DISP_FAIL);
    }
#endif  // OHOS_AUTO_TEST_FRAME
    MMI_LOGT("\n2.mapping event:\nEvent:eventType=%{public}d;", point.eventType);
    auto retEvent = eventDispatch_.DispatchCommonPointEvent(*udsServer_, *ev.event, point, preHandlerTime);
    if (retEvent != RET_OK) {
        MMI_LOGE("common_point event dispatch failed... ret:%{public}d errCode:%{public}d",
            retEvent, POINT_REG_EVENT_DISP_FAIL);
        return POINT_REG_EVENT_DISP_FAIL;
    }
    retEvent = eventDispatch_.DispatchPointerEvent(*udsServer_, *ev.event, point, preHandlerTime, winSwitch_);
    if (retEvent != RET_OK) {
        MMI_LOGE("Pointer event dispatch failed... ret:%{public}d errCode:%{public}d",
            retEvent, POINT_EVENT_DISP_FAIL);
        return POINT_EVENT_DISP_FAIL;
    }
    return RET_OK;
}

int32_t OHOS::MMI::InputEventHandler::OnEventTouch(multimodal_libinput_event &ev)
{
    CHKR(ev.event, NULL_POINTER, NULL_POINTER);
    uint64_t preHandlerTime = GetSysClockTime();
    struct EventTouch touch = {};
    CHKR(udsServer_, NULL_POINTER, RET_ERR);
    auto packageResult = eventPackage_.PackageTouchEvent(ev, touch, winSwitch_, *udsServer_);
    if (packageResult == UNKNOWN_EVENT_PKG_FAIL) {
        return RET_OK;
    }
    if (packageResult != RET_OK) {
        MMI_LOGE("Touch event package failed... ret:%{public}d errCode:%{public}d",
                 packageResult, TOUCH_EVENT_PKG_FAIL);
        return TOUCH_EVENT_PKG_FAIL;
    }

#ifdef OHOS_AUTO_TEST_FRAME
    // Send event to auto-test frame
    const AutoTestLibinputPkt autoTestLibinputPkt = {
        "eventTouch", 0, 0, touch.point.x, touch.point.y, 0, 0
    };
    auto retAutoTestLibPkt = eventDispatch_.SendLibPktToAutoTest(*udsServer_, autoTestLibinputPkt);
    if (retAutoTestLibPkt != RET_OK) {
        MMI_LOGE("Send event to auto-test failed! errCode:%{public}d", KEY_EVENT_DISP_FAIL);
    }
    auto retAutoTestMapPkt = eventDispatch_.SendMappingPktToAutoTest(*udsServer_, touch.eventType);
    if (retAutoTestMapPkt != RET_OK) {
        MMI_LOGE("Send event to auto-test failed! errCode:%{public}d", KEY_EVENT_DISP_FAIL);
    }
#endif  // OHOS_AUTO_TEST_FRAME

    auto ret = eventDispatch_.DispatchTouchEvent(*udsServer_, *ev.event, touch, preHandlerTime, winSwitch_);
    if (ret != RET_OK) {
        MMI_LOGE("Touch event dispatch failed... ret:%{public}d errCode:%{public}d", ret, TOUCH_EVENT_DISP_FAIL);
        return TOUCH_EVENT_DISP_FAIL;
    }
    return RET_OK;
}

int32_t OHOS::MMI::InputEventHandler::OnEventGesture(multimodal_libinput_event &ev)
{
    CHKR(ev.event, NULL_POINTER, NULL_POINTER);
    uint64_t preHandlerTime = GetSysClockTime();
    EventGesture gesture = {};
    CHKR(udsServer_, NULL_POINTER, RET_ERR);
    auto packageResult = eventPackage_.PackageGestureEvent(*ev.event, gesture, *udsServer_);
    if (packageResult != RET_OK) {
        MMI_LOGE("Gesture swipe event package failed... ret:%{public}d errCode:%{public}d",
            packageResult, GESTURE_EVENT_PKG_FAIL);
        return GESTURE_EVENT_PKG_FAIL;
    }
#ifdef OHOS_AUTO_TEST_FRAME // Send event to auto-test frame
    const AutoTestLibinputPkt autoTestLibinputPkt = { "eventGesture", 0, 0, gesture.delta.x, gesture.delta.y, 0, 0 };
    auto retAutoTestLibPkt = eventDispatch_.SendLibPktToAutoTest(*udsServer_, autoTestLibinputPkt);
    if (retAutoTestLibPkt != RET_OK) {
        MMI_LOGE("Send event to auto-test failed! errCode:%{public}d", KEY_EVENT_DISP_FAIL);
    }
    auto retAutoTestMapPkt = eventDispatch_.SendMappingPktToAutoTest(*udsServer_, gesture.eventType);
    if (retAutoTestMapPkt != RET_OK) {
        MMI_LOGE("Send event to auto-test failed! errCode:%{public}d", KEY_EVENT_DISP_FAIL);
    }
#endif  // OHOS_AUTO_TEST_FRAME
    auto eventDispatchResult = eventDispatch_.DispatchGestureEvent(*udsServer_, *ev.event, gesture, preHandlerTime);
    if (eventDispatchResult != RET_OK) {
        MMI_LOGE("Gesture event dispatch failed... ret:%{public}d errCode:%{public}d",
            eventDispatchResult, GESTURE_EVENT_DISP_FAIL);
        return GESTURE_EVENT_DISP_FAIL;
    }
    return RET_OK;
}

int32_t OHOS::MMI::InputEventHandler::OnEventTabletTool(multimodal_libinput_event &ev)
{
    CHKR(ev.event, NULL_POINTER, NULL_POINTER);
    uint64_t preHandlerTime = GetSysClockTime();
    EventTabletTool tableTool = {};
    CHKR(udsServer_, NULL_POINTER, RET_ERR);
    auto packageResult = eventPackage_.PackageTabletToolEvent(*ev.event, tableTool, *udsServer_);
    if (packageResult == MULTIDEVICE_SAME_EVENT_FAIL) { // The multi_device_same_event should be discarded
        return RET_OK;
    }
    if (packageResult != RET_OK) {
        MMI_LOGE("Tablettool event package failed... ret:%{public}d errCode:%{public}d",
            packageResult, TABLETTOOL_EVENT_PKG_FAIL);
        return TABLETTOOL_EVENT_PKG_FAIL;
    }
#ifdef OHOS_AUTO_TEST_FRAME
    // Send event to auto-test frame
    const AutoTestLibinputPkt autoTestLibinputPkt = {
        "eventTabletTool", tableTool.button, tableTool.state, 0, 0, tableTool.axes.point.x, tableTool.axes.point.y
    };
    auto retAutoTestLibPkt = eventDispatch_.SendLibPktToAutoTest(*udsServer_, autoTestLibinputPkt);
    if (retAutoTestLibPkt != RET_OK) {
        MMI_LOGE("Send event to auto-test failed! errCode:%{public}d", KEY_EVENT_DISP_FAIL);
    }
    auto retAutoTestMapPkt = eventDispatch_.SendMappingPktToAutoTest(*udsServer_, tableTool.eventType);
    if (retAutoTestMapPkt != RET_OK) {
        MMI_LOGE("Send event to auto-test failed! errCode:%{public}d", KEY_EVENT_DISP_FAIL);
    }
#endif  // OHOS_AUTO_TEST_FRAME
    MMI_LOGT("\n2.mapping event:\nEvent:eventType=%{public}d;", tableTool.eventType);
    auto retEvent = eventDispatch_.DispatchTabletToolEvent(*udsServer_, *ev.event, tableTool, preHandlerTime, winSwitch_);
    if (retEvent != RET_OK) {
        MMI_LOGE("Tabletool event dispatch failed... ret:%{public}d errCode:%{public}d",
            retEvent, TABLETTOOL_EVENT_DISP_FAIL);
        return TABLETTOOL_EVENT_DISP_FAIL;
    }
    return RET_OK;
}

int32_t OHOS::MMI::InputEventHandler::OnEventTabletPad(multimodal_libinput_event &ev)
{
    CHKR(ev.event, NULL_POINTER, NULL_POINTER);
    uint64_t preHandlerTime = GetSysClockTime();
    CHKR(udsServer_, NULL_POINTER, RET_ERR);
    EventTabletPad tabletPad = {};
    auto packageResult = eventPackage_.PackageTabletPadEvent(*ev.event, tabletPad, *udsServer_);
    if (packageResult != RET_OK) {
        MMI_LOGE("Tabletpad event package failed... ret:%{public}d errCode:%{public}d",
            packageResult, TABLETPAD_EVENT_PKG_FAIL);
        return TABLETPAD_EVENT_PKG_FAIL;
    }
#ifdef OHOS_AUTO_TEST_FRAME
    // Send event to auto-test frame
    const AutoTestLibinputPkt autoTestLibinputPkt = {
        "eventTabletPad", 0, 0, 0, 0, 0, 0,
    };
    auto retAutoTestLibPkt = eventDispatch_.SendLibPktToAutoTest(*udsServer_, autoTestLibinputPkt);
    if (retAutoTestLibPkt != RET_OK) {
        MMI_LOGE("Send event to auto-test failed! errCode:%{public}d", KEY_EVENT_DISP_FAIL);
    }
    auto retAutoTestMapPkt = eventDispatch_.SendMappingPktToAutoTest(*udsServer_, tabletPad.eventType);
    if (retAutoTestMapPkt != RET_OK) {
        MMI_LOGE("Send event to auto-test failed! errCode:%{public}d", KEY_EVENT_DISP_FAIL);
    }
#endif  // OHOS_AUTO_TEST_FRAME
    auto ret = eventDispatch_.DispatchTabletPadEvent(*udsServer_, *ev.event, tabletPad, preHandlerTime);
    if (ret != RET_OK) {
        MMI_LOGE("Tabletpad event dispatch failed... ret:%{public}d errCode:%{public}d",
                 ret, TABLETPAD_EVENT_DISP_FAIL);
        return TABLETPAD_EVENT_DISP_FAIL;
    }
    return RET_OK;
}

int32_t OHOS::MMI::InputEventHandler::OnEventSwitchToggle(multimodal_libinput_event &ev)
{
    CHKR(ev.event, NULL_POINTER, NULL_POINTER);
    auto type = libinput_event_get_type(ev.event);
    MMI_LOGT("\nfunction is _OnEventSwitchToggle,sourceType is LIBINPUT_EVENT_SWITCH_TOGGLE %{public}d", type);

#ifdef OHOS_AUTO_TEST_FRAME
    // Send event to auto-test frame
    const AutoTestLibinputPkt autoTestLibinputPkt = {
        "eventSwitchToggle", 0, 0, 0, 0, 0, 0
    };
    auto retAutoTestLibPkt = eventDispatch_.SendLibPktToAutoTest(*udsServer_, autoTestLibinputPkt);
    if (retAutoTestLibPkt != RET_OK) {
        MMI_LOGE("Send event to auto-test failed! errCode:%{public}d", KEY_EVENT_DISP_FAIL);
    }
    auto retAutoTestMapPkt = eventDispatch_.SendMappingPktToAutoTest(*udsServer_, type);
    if (retAutoTestMapPkt != RET_OK) {
        MMI_LOGE("Send event to auto-test failed! errCode:%{public}d", KEY_EVENT_DISP_FAIL);
    }
#endif  // OHOS_AUTO_TEST_FRAME
    return RET_OK;
}

int32_t OHOS::MMI::InputEventHandler::OnEventTabletPadKey(multimodal_libinput_event &ev)
{
    CHKR(ev.event, NULL_POINTER, NULL_POINTER);
    uint64_t preHandlerTime = GetSysClockTime();
    CHKR(udsServer_, NULL_POINTER, RET_ERR);
    EventKeyboard key = {};
    auto packageResult = eventPackage_.PackageTabletPadKeyEvent(*ev.event, key, *udsServer_);
    if (packageResult == MULTIDEVICE_SAME_EVENT_FAIL) { // The multi_device_same_event should be discarded
        return RET_OK;
    }
    if (packageResult != RET_OK) {
        MMI_LOGE("Tabletpadkey event package failed... ret:%{public}d errCode:%{public}d",
            packageResult, TABLETPAD_KEY_EVENT_PKG_FAIL);
        return TABLETPAD_KEY_EVENT_PKG_FAIL;
    }
#ifdef OHOS_AUTO_TEST_FRAME // Send event to auto-test frame
    const AutoTestLibinputPkt autoTestLibinputPkt = { "eventTabletPadKey", key.key, key.state, 0, 0, 0, 0 };
    auto retAutoTestLibPkt = eventDispatch_.SendLibPktToAutoTest(*udsServer_, autoTestLibinputPkt);
    if (retAutoTestLibPkt != RET_OK) {
        MMI_LOGE("Send event to auto-test failed! errCode:%{public}d", KEY_EVENT_DISP_FAIL);
    }
    auto retAutoTestMapPkt = eventDispatch_.SendMappingPktToAutoTest(*udsServer_, key.eventType);
    if (retAutoTestMapPkt != RET_OK) {
        MMI_LOGE("Send event to auto-test failed! errCode:%{public}d", KEY_EVENT_DISP_FAIL);
    }
#endif  // OHOS_AUTO_TEST_FRAME
    auto hosKey = KeyValueTransformationByInput(key.key);           // libinput key transformed into HOS key
#ifndef OHOS_AUTO_TEST_FRAME // Send event to auto-test frame
    if (hosKey.isSystemKey && OnSystemEvent(hosKey, key.state)) {   // Judging whether key is system key.
        return RET_OK;
    }
#else
    AutoTestKeyTypePkt autoTestKeyTypePkt = {};
    bool retSystemEvent = OnSystemEvent(hosKey, key.state, autoTestKeyTypePkt);
    auto retAutoTestTypePktPkt = eventDispatch_.SendKeyTypePktToAutoTest(*udsServer_, autoTestKeyTypePkt);
    if (retAutoTestTypePktPkt != RET_OK) {
        MMI_LOGE("Send event to auto-test failed! errCode:%{public}d", KEY_EVENT_DISP_FAIL);
    }
    if (hosKey.isSystemKey && retSystemEvent) {
        return RET_OK;
    }
#endif  // OHOS_AUTO_TEST_FRAME

    auto eventDispatchResult = eventDispatch_.DispatchKeyEvent(*udsServer_, *ev.event, hosKey, key, preHandlerTime);
    if (eventDispatchResult != RET_OK) {
        MMI_LOGE("Key event dispatch failed... ret:%{public}d errCode:%{public}d",
                 eventDispatchResult, TABLETPAD_KEY_EVENT_DISP_FAIL);
        return TABLETPAD_KEY_EVENT_DISP_FAIL;
    }
    return RET_OK;
}

int32_t OHOS::MMI::InputEventHandler::OnEventJoyStickKey(multimodal_libinput_event &ev, const uint64_t time)
{
    CHKR(ev.event, NULL_POINTER, NULL_POINTER);
    CHKR(udsServer_, NULL_POINTER, RET_ERR);
    EventKeyboard key = {};
    auto packageResult = eventPackage_.PackageJoyStickKeyEvent(*ev.event, key, *udsServer_);
    if (packageResult != RET_OK) {
        MMI_LOGE("Joystickkey event package failed... ret:%{public}d errCode:%{public}d",
            packageResult, JOYSTICK_KEY_EVENT_PKG_FAIL);
        return JOYSTICK_KEY_EVENT_PKG_FAIL;
    }
#ifdef OHOS_AUTO_TEST_FRAME
    // Send event to auto-test frame
    const AutoTestLibinputPkt autoTestLibinputPkt = { "eventJoyStickKey", key.key, key.state, 0, 0, 0, 0 };
    auto retAutoTestLibPkt = eventDispatch_.SendLibPktToAutoTest(*udsServer_, autoTestLibinputPkt);
    if (retAutoTestLibPkt != RET_OK) {
        MMI_LOGE("Send event to auto-test failed! errCode:%{public}d", KEY_EVENT_DISP_FAIL);
    }
    auto retAutoTestMapPkt = eventDispatch_.SendMappingPktToAutoTest(*udsServer_, key.eventType);
    if (retAutoTestMapPkt != RET_OK) {
        MMI_LOGE("Send event to auto-test failed! errCode:%{public}d", KEY_EVENT_DISP_FAIL);
    }
#endif  // OHOS_AUTO_TEST_FRAME
    // libinput key transformed into HOS key
    auto hosKey = KeyValueTransformationByInput(key.key);
    key.mUnicode = 0;
    // Judging whether key is system key.
#ifndef OHOS_AUTO_TEST_FRAME
    if (hosKey.isSystemKey && OnSystemEvent(hosKey, key.state)) {
        return RET_OK;
    }
#else
    AutoTestKeyTypePkt autoTestKeyTypePkt = {};
    bool retSystemEvent = OnSystemEvent(hosKey, key.state, autoTestKeyTypePkt);
    auto retAutoTestTypePktPkt = eventDispatch_.SendKeyTypePktToAutoTest(*udsServer_, autoTestKeyTypePkt);
    if (retAutoTestTypePktPkt != RET_OK) {
        MMI_LOGE("Send event to auto-test failed! errCode:%{public}d", KEY_EVENT_DISP_FAIL);
    }
    if (hosKey.isSystemKey && retSystemEvent) {
        return RET_OK;
    }
#endif  // OHOS_AUTO_TEST_FRAME
    auto eventDispatchResult = eventDispatch_.DispatchKeyEvent(*udsServer_, *ev.event, hosKey, key, time);
    if (eventDispatchResult != RET_OK) {
        MMI_LOGE("JoyStick event dispatch failed... ret:%{public}d errCode:%{public}d",
                 eventDispatchResult, JOYSTICK_EVENT_DISP_FAIL);
        return JOYSTICK_EVENT_DISP_FAIL;
    }
    return RET_OK;
}

int32_t OHOS::MMI::InputEventHandler::OnEventJoyStickAxis(multimodal_libinput_event &ev, const uint64_t time)
{
    CHKR(ev.event, NULL_POINTER, NULL_POINTER);
    CHKR(udsServer_, NULL_POINTER, RET_ERR);
    EventJoyStickAxis eventJoyStickAxis = {};
    auto packageResult = eventPackage_.PackageJoyStickAxisEvent(*ev.event, eventJoyStickAxis, *udsServer_);
    if (packageResult != RET_OK) {
        MMI_LOGE("Joystickaxis event package failed... ret:%{public}d errCode:%{public}d",
            packageResult, JOYSTICK_AXIS_EVENT_PKG_FAIL);
        return JOYSTICK_AXIS_EVENT_PKG_FAIL;
    }
#ifdef OHOS_AUTO_TEST_FRAME
    auto retAutoTestMapPkt = eventDispatch_.SendMappingPktToAutoTest(*udsServer_, eventJoyStickAxis.eventType);
    if (retAutoTestMapPkt != RET_OK) {
        MMI_LOGE("Send event to auto-test failed! errCode:%{public}d", KEY_EVENT_DISP_FAIL);
    }
#endif // OHOS_AUTO_TEST_FRAME
    auto ret = eventDispatch_.DispatchJoyStickEvent(*udsServer_, *ev.event, eventJoyStickAxis, time);
    if (ret != RET_OK) {
        MMI_LOGE("Joystick event dispatch failed... ret:%{public}d errCode:%{public}d", ret, JOYSTICK_EVENT_DISP_FAIL);
        return JOYSTICK_EVENT_DISP_FAIL;
    }
    return RET_OK;
}

bool OHOS::MMI::InputEventHandler::SendMsg(const int32_t fd, NetPacket& pkt) const
{
    CHKF(udsServer_, OHOS::NULL_POINTER);
    return udsServer_->SendMsg(fd, pkt);
}

#ifndef OHOS_AUTO_TEST_FRAME
bool OHOS::MMI::InputEventHandler::OnSystemEvent(const KeyEventValueTransformations& temp,
    const enum KEY_STATE state) const
#else
bool OHOS::MMI::InputEventHandler::OnSystemEvent(const KeyEventValueTransformations& temp,
    const enum KEY_STATE state, struct AutoTestKeyTypePkt& autoTestKeyTypePkt)
#endif  // OHOS_AUTO_TEST_FRAME
{
    const int32_t systemEventAttr = OuterInterface::GetSystemEventAttrByHosKeyValue(temp.keyValueOfHos);
    uint16_t retCode = 0;
    switch (systemEventAttr) {
        case MMI_SYSTEM_SERVICE: {
            (void)OuterInterface::SystemEventHandler(temp, state, systemEventAttr);
            (void)OuterInterface::DistributedEventHandler(temp, state, systemEventAttr);
            retCode = 1;
#ifdef OHOS_AUTO_TEST_FRAME
            autoTestKeyTypePkt.disSystem = 1;
#endif  // OHOS_AUTO_TEST_FRAME
            break;
        }
        case MMI_SYSTEM_SERVICE_AND_APP: {
            if (OuterInterface::SystemEventHandler(temp, state, systemEventAttr) ||
                OuterInterface::DistributedEventHandler(temp, state, systemEventAttr)) {
                retCode = 1;
#ifdef OHOS_AUTO_TEST_FRAME
                autoTestKeyTypePkt.disSystem = 1;
#endif  // OHOS_AUTO_TEST_FRAME
            }
#ifdef OHOS_AUTO_TEST_FRAME
            if (!retCode) {
                autoTestKeyTypePkt.disClient = 1;
            }
#endif  // OHOS_AUTO_TEST_FRAME
            break;
        }
        case MMI_CAMERA_APP: {
            (void)OuterInterface::SystemEventHandler(temp, state, systemEventAttr);
            (void)OuterInterface::DistributedEventHandler(temp, state, systemEventAttr);
            retCode = 1;
#ifdef OHOS_AUTO_TEST_FRAME
            autoTestKeyTypePkt.disCamrea = 1;
#endif  // OHOS_AUTO_TEST_FRAME
            break;
        }
        default: {
            break;
        }
    }
    return retCode;
}
