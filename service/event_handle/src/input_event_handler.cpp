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
#include <cstdio>
#include <cstring>
#include <functional>
#include <vector>
#include <inttypes.h>
#include <sys/stat.h>
#include <unistd.h>
#include "input_device_manager.h"
#include "interceptor_manager_global.h"
#include "mmi_server.h"
#include "mouse_event_handler.h"
#include "outer_interface.h"
#include "s_input.h"
#include "server_input_filter_manager.h"
#include "time_cost_chk.h"
#include "touch_transform_point_manager.h"
#include "ability_launch_manager.h"
#include "util.h"

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
            MmiMessageId::LIBINPUT_KEY_EVENT,
            std::bind(&InputEventHandler::OnKeyEventDispatch, this, std::placeholders::_1)
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
            MmiMessageId::LIBINPUT_EVENT_TOUCHPAD_DOWN,
            std::bind(&InputEventHandler::OnEventTouchpad, this, std::placeholders::_1)
        },
        {
            MmiMessageId::LIBINPUT_EVENT_TOUCHPAD_UP,
            std::bind(&InputEventHandler::OnEventTouchpad, this, std::placeholders::_1)
        },
        {
            MmiMessageId::LIBINPUT_EVENT_TOUCHPAD_MOTION,
            std::bind(&InputEventHandler::OnEventTouchpad, this, std::placeholders::_1)
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

OHOS::MMI::UDSServer* OHOS::MMI::InputEventHandler::GetUDSServer()
{
    return udsServer_;
}

int32_t OHOS::MMI::InputEventHandler::AddInputEventFilter(sptr<IEventFilter> filter)
{
    return eventDispatch_.AddInputEventFilter(filter);
}

int32_t OHOS::MMI::InputEventHandler::OnEventDeviceAdded(multimodal_libinput_event &ev)
{
    CHKR(ev.event, NULL_POINTER, NULL_POINTER);
    auto device = libinput_event_get_device(ev.event);
    INPUTDEVMGR->OnInputDeviceAdded(device);

    uint64_t preHandlerTime = GetSysClockTime();
    DeviceManage deviceManage = {};

    CHKR(udsServer_, NULL_POINTER, RET_ERR);
    auto packageResult = eventPackage_.PackageDeviceManageEvent(*ev.event, deviceManage, *udsServer_);
    if (packageResult != RET_OK) {
        MMI_LOGE("Deviceadded event package failed... ret:%{public}d errCode:%{public}d",
                 packageResult, DEV_ADD_EVENT_PKG_FAIL);
        return DEV_ADD_EVENT_PKG_FAIL;
    }
    MMI_LOGT("\n4.event dispatcher of server:DeviceManage:devicePhys=%{public}s;"
             "deviceName=%{public}s;deviceType=%{public}u;\n**************************************\n",
             deviceManage.devicePhys, deviceManage.deviceName, deviceManage.deviceType);

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
    auto device = libinput_event_get_device(ev.event);
    INPUTDEVMGR->OnInputDeviceRemoved(device);

    uint64_t preHandlerTime = GetSysClockTime();
    CHKR(udsServer_, NULL_POINTER, RET_ERR);
    DeviceManage deviceManage = {};
    auto packageResult = eventPackage_.PackageDeviceManageEvent(*ev.event, deviceManage, *udsServer_);
    if (packageResult != RET_OK) {
        MMI_LOGE("Deviceremoved event package failed... ret:%{public}d errCode:%{public}d",
                 packageResult, DEV_REMOVE_EVENT_PKG_FAIL);
        return DEV_REMOVE_EVENT_PKG_FAIL;
    }
    MMI_LOGT("\n4.event dispatcher of server:DeviceManage:devicePhys=%{public}s;"
             "deviceName=%{public}s;deviceType=%{public}u;\n**************************************\n",
             deviceManage.devicePhys, deviceManage.deviceName, deviceManage.deviceType);

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

int32_t OHOS::MMI::InputEventHandler::OnEventKey(libinput_event& event)
{
    uint64_t preHandlerTime = GetSysClockTime();
    if (keyEvent == nullptr) {
        keyEvent = OHOS::MMI::KeyEvent::Create();
    }
    CHKR(udsServer_, NULL_POINTER, RET_ERR);
    auto packageResult = eventPackage_.PackageKeyEvent(event, keyEvent, *udsServer_);
    if (packageResult == MULTIDEVICE_SAME_EVENT_FAIL) { // The multi_device_same_event should be discarded
        return RET_OK;
    }
    if (packageResult != RET_OK) {
        MMI_LOGE("KeyEvent package failed... ret:%{public}d errCode:%{public}d", packageResult, KEY_EVENT_PKG_FAIL);
        return KEY_EVENT_PKG_FAIL;
    }

    int32_t kac = keyEvent->GetKeyAction();
    KEY_STATE kacState = (kac == OHOS::MMI::KeyEvent::KEY_ACTION_DOWN) ? KEY_STATE_PRESSED : KEY_STATE_RELEASED;
    int16_t lowKeyCode = static_cast<int16_t>(keyEvent->GetKeyCode());
    auto hosKey = KeyValueTransformationByInput(lowKeyCode);
    if (hosKey.isSystemKey) {
        OnSystemEvent(hosKey, kacState);
    }

    auto device = libinput_event_get_device(&event);
    CHKR(device, NULL_POINTER, LIBINPUT_DEV_EMPTY);

    auto eventDispatchResult = eventDispatch_.DispatchKeyEventByPid(*udsServer_, keyEvent, preHandlerTime);
    if (eventDispatchResult != RET_OK) {
        MMI_LOGE("KeyEvent dispatch failed... ret:%{public}d errCode:%{public}d",
                 eventDispatchResult, KEY_EVENT_DISP_FAIL);
        return KEY_EVENT_DISP_FAIL;
    }
    MMI_LOGD("Inject keyCode = %{public}d,action = %{public}d", keyEvent->GetKeyCode(), keyEvent->GetKeyAction());
    return RET_OK;
}

int32_t OHOS::MMI::InputEventHandler::OnKeyEventDispatch(multimodal_libinput_event& ev)
{
#ifdef OHOS_WESTEN_MODEL
    uint64_t preHandlerTime = GetSysClockTime();
#endif
    if (keyEvent == nullptr) {
        keyEvent = OHOS::MMI::KeyEvent::Create();
    }
    CHKR(udsServer_, NULL_POINTER, RET_ERR);
    auto packageResult = eventPackage_.PackageKeyEvent(*ev.event, keyEvent, *udsServer_);
    if (packageResult == MULTIDEVICE_SAME_EVENT_FAIL) { // The multi_device_same_event should be discarded
        return RET_OK;
    }
    if (packageResult != RET_OK) {
        MMI_LOGE("KeyEvent package failed... ret:%{public}d errCode:%{public}d", packageResult, KEY_EVENT_PKG_FAIL);
        return KEY_EVENT_PKG_FAIL;
    }
#ifndef OHOS_WESTEN_MODEL
    if (INTERCEPTORMANAGERGLOBAL.OnKeyEvent(keyEvent)) {
        MMI_LOGD("key event filter find a key event from Original event keyCode : %{puiblic}d",
            keyEvent->GetKeyCode());
        return RET_OK;
    }
    (void)OnEventKey(*ev.event);
#else

    int32_t kac = keyEvent->GetKeyAction();
    KEY_STATE kacState = (kac == OHOS::MMI::KeyEvent::KEY_ACTION_DOWN) ? KEY_STATE_PRESSED : KEY_STATE_RELEASED;
    int16_t lowKeyCode = static_cast<int16_t>(keyEvent->GetKeyCode());
    auto hosKey = KeyValueTransformationByInput(lowKeyCode);
    if (hosKey.isSystemKey) { // Judging whether key is system key.
        OnSystemEvent(hosKey, kacState);
    }

    auto device = libinput_event_get_device(ev.event);
    CHKR(device, NULL_POINTER, LIBINPUT_DEV_EMPTY);

    auto eventDispatchResult = eventDispatch_.DispatchKeyEventByPid(*udsServer_, keyEvent, preHandlerTime);
    if (eventDispatchResult != RET_OK) {
        MMI_LOGE("KeyEvent dispatch failed... ret:%{public}d errCode:%{public}d", 
            eventDispatchResult, KEY_EVENT_DISP_FAIL);
        return KEY_EVENT_DISP_FAIL;
    }
#endif
    return RET_OK;
}

int32_t OHOS::MMI::InputEventHandler::OnKeyboardEvent(libinput_event& event)
{
    uint64_t preHandlerTime = GetSysClockTime();
    EventKeyboard keyBoard = {};
    CHKR(udsServer_, NULL_POINTER, RET_ERR);
    auto packageResult = eventPackage_.PackageKeyEvent(event, keyBoard, *udsServer_);
    if (packageResult == MULTIDEVICE_SAME_EVENT_FAIL) { // The multi_device_same_event should be discarded
        return RET_OK;
    }
    if (packageResult != RET_OK) {
        MMI_LOGE("Key event package failed... ret:%{public}d errCode:%{public}d", packageResult, KEY_EVENT_PKG_FAIL);
        return KEY_EVENT_PKG_FAIL;
    }

    auto hosKey = KeyValueTransformationByInput(keyBoard.key); // libinput key transformed into HOS key
    keyBoard.unicode = 0;

    if (hosKey.isSystemKey) { // Judging whether key is system key.
        OnSystemEvent(hosKey, keyBoard.state);
    }

    if (keyEvent == nullptr) {
        keyEvent = OHOS::MMI::KeyEvent::Create();
    }
    keyBoard.key = static_cast<uint32_t>(hosKey.keyValueOfHos);
    if (EventPackage::KeyboardToKeyEvent(keyBoard, keyEvent, *udsServer_) == RET_ERR) {
        MMI_LOGE("on OnKeyboardEvent translate key event error!\n");
        return RET_ERR;
    }
    if (AbilityMgr->CheckLaunchAbility(keyEvent)) {
        MMI_LOGD("key event start launch an ability, keyCode : %{puiblic}d", keyBoard.key);
        return RET_OK;
    }
    if (KeyEventInputSubscribeFlt.FilterSubscribeKeyEvent(*udsServer_, keyEvent)) {
        MMI_LOGD("subscribe key event filter success. keyCode=%{puiblic}d", keyBoard.key);
        return RET_OK;
    }
    auto device = libinput_event_get_device(&event);
    CHKR(device, NULL_POINTER, LIBINPUT_DEV_EMPTY);

    auto eventDispatchResult = eventDispatch_.DispatchKeyEventByPid(*udsServer_, keyEvent, preHandlerTime);
    if (eventDispatchResult != RET_OK) {
        MMI_LOGE("Key event dispatch failed... ret:%{public}d errCode:%{public}d",
                 eventDispatchResult, KEY_EVENT_DISP_FAIL);
        return KEY_EVENT_DISP_FAIL;
    }

    return RET_OK;
}

int32_t OHOS::MMI::InputEventHandler::OnEventKeyboard(multimodal_libinput_event &ev)
{
    CHKR(ev.event, NULL_POINTER, NULL_POINTER);
#ifdef OHOS_WESTEN_MODEL
    uint64_t preHandlerTime = GetSysClockTime();
#endif
    EventKeyboard keyBoard = {};
    CHKR(udsServer_, NULL_POINTER, RET_ERR);
    auto packageResult = eventPackage_.PackageKeyEvent(*ev.event, keyBoard, *udsServer_);
    if (packageResult == MULTIDEVICE_SAME_EVENT_FAIL) { // The multi_device_same_event should be discarded
        return RET_OK;
    }
    if (packageResult != RET_OK) {
        MMI_LOGE("Key event package failed... ret:%{public}d errCode:%{public}d", packageResult, KEY_EVENT_PKG_FAIL);
        return KEY_EVENT_PKG_FAIL;
    }
#ifndef OHOS_WESTEN_MODEL
    if (ServerKeyFilter->OnKeyEvent(keyBoard)) {
        MMI_LOGD("key event filter find a  key event from Original event  keyCode : %{puiblic}d", keyBoard.key);
        return RET_OK;
    }
    (void)OnKeyboardEvent(*ev.event);
#else
    auto hosKey = KeyValueTransformationByInput(keyBoard.key); // libinput key transformed into HOS key
    keyBoard.unicode = 0;
    if (hosKey.isSystemKey && OnSystemEvent(hosKey, keyBoard.state)) { // Judging whether key is system key.
        return RET_OK;
    }

    auto eventDispatchResult = eventDispatch_.DispatchKeyEvent(*udsServer_, *ev.event, hosKey, keyBoard,
                                                               preHandlerTime);
    if (eventDispatchResult != RET_OK) {
        MMI_LOGE("Key event dispatch failed... ret:%{public}d errCode:%{public}d",
                 eventDispatchResult, KEY_EVENT_DISP_FAIL);
        return KEY_EVENT_DISP_FAIL;
    }
#endif
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
#ifndef OHOS_WESTEN_MODEL
    if (ServerKeyFilter->OnPointerEvent(point)) {
        MMI_LOGD("pointer event interceptor find a pointer event pointer button: %{puiblic}d", point.button);
        return RET_OK;
    }
    if (type == LIBINPUT_EVENT_POINTER_BUTTON) {
        MouseState->CountState(point.button, point.state);
    }
    MouseState->SetMouseCoords(point.delta.x, point.delta.y);
#else
    MMI_LOGT("\n2.mapping event:\nEvent:eventType=%{public}d;", point.eventType);
    /*
    auto retEvent = eventDispatch_.DispatchCommonPointEvent(*udsServer_, *ev.event, point, preHandlerTime);
    if (retEvent != RET_OK) {
        MMI_LOGE("common_point event dispatch failed... ret:%{public}d errCode:%{public}d",
            retEvent, POINT_REG_EVENT_DISP_FAIL);
        return POINT_REG_EVENT_DISP_FAIL;
    }
    */
#endif
#ifndef OHOS_WESTEN_MODEL
    /* New */
    (void)OnMouseEventHandler(*ev.event, point.deviceId);
#else
    auto retEvent = eventDispatch_.DispatchPointerEvent(*udsServer_, *ev.event, point, preHandlerTime, winSwitch_);
    if (retEvent != RET_OK) {
        MMI_LOGE("Pointer event dispatch failed... ret:%{public}d errCode:%{public}d",
            retEvent, POINT_EVENT_DISP_FAIL);
        return POINT_EVENT_DISP_FAIL;
    }
#endif
    return RET_OK;
}

int32_t OHOS::MMI::InputEventHandler::OnEventTouchSecond(libinput_event& event)
{
    MMI_LOGD("call  OnEventTouchSecond begin"); 
    auto point = touchTransformPointManger->onLibinputTouchEvent(event);
    if (point == nullptr) {
        return RET_OK;
    }
    eventDispatch_.handlePointerEvent(point);
    auto type = libinput_event_get_type(&event);
    if (type == LIBINPUT_EVENT_TOUCH_UP) {
        point->RemovePointerItem(point->GetPointerId());
        MMI_LOGD("this touch event is up  remove this finger"); 
        if (point->GetPointersIdList().empty()) {
            MMI_LOGD("this touch event is final finger up  remove this finger");
            point->Init();
        }
        return RET_OK;
    }
    MMI_LOGD("call  OnEventTouchSecond end"); 
    return RET_OK;
}

int32_t OHOS::MMI::InputEventHandler::OnEventTouchPadSecond(libinput_event& event)
{
    MMI_LOGD("call  OnEventTouchPadSecond begin");

    auto point = touchTransformPointManger->onLibinputTouchPadEvent(event);    
    if (point == nullptr) {
        return RET_OK;
    }
    eventDispatch_.handlePointerEvent(point);
    auto type = libinput_event_get_type(&event);
    if (type == LIBINPUT_EVENT_TOUCHPAD_UP) {
        point->RemovePointerItem(point->GetPointerId());
        MMI_LOGD("this touch pad event is up  remove this finger");
        if (point->GetPointersIdList().empty()) {
            MMI_LOGD("this touch pad event is final finger up  remove this finger");
            point->Init();
        }
        return RET_OK;
    }
    MMI_LOGD("call  OnEventTouchPadSecond end");
    return RET_OK;
}
int32_t OHOS::MMI::InputEventHandler::OnEventTouch(multimodal_libinput_event &ev)
{
    CHKR(ev.event, NULL_POINTER, NULL_POINTER);
    SInput::Loginfo_packaging_tool(*ev.event);
#ifndef OHOS_WESTEN_MODEL
    OnEventTouchSecond(*ev.event);
#endif
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
#ifndef OHOS_WESTEN_MODEL
    if (ServerKeyFilter->OnTouchEvent(*udsServer_, *ev.event, touch, preHandlerTime, winSwitch_)) {
        return RET_OK;
    }
#endif
#ifdef OHOS_WESTEN_MODEL

    auto ret = eventDispatch_.DispatchTouchEvent(*udsServer_, *ev.event, touch, preHandlerTime, winSwitch_);
    if (ret != RET_OK) {
        MMI_LOGE("Touch event dispatch failed... ret:%{public}d errCode:%{public}d", ret, TOUCH_EVENT_DISP_FAIL);
        return TOUCH_EVENT_DISP_FAIL;
    }
#endif
    return RET_OK;
}

int32_t OHOS::MMI::InputEventHandler::OnEventTouchpad(multimodal_libinput_event& ev)
{
#ifndef OHOS_WESTEN_MODEL
    OnEventTouchPadSecond(*ev.event);
#endif

    return RET_OK;
}

int32_t OHOS::MMI::InputEventHandler::OnGestureEvent(libinput_event& event)
{
    MMI_LOGT("InputEventHandler::OnGestureEvent\n");
    uint64_t preHandlerTime = GetSysClockTime();
    EventGesture gesture = {};
    CHKR(udsServer_, NULL_POINTER, RET_ERR);
    auto packageResult = eventPackage_.PackageGestureEvent(event, gesture, *udsServer_);
    if (packageResult != RET_OK) {
        MMI_LOGE("Gesture swipe event package failed... ret:%{public}d errCode:%{public}d",
            packageResult, GESTURE_EVENT_PKG_FAIL);
        return GESTURE_EVENT_PKG_FAIL;
    }
    auto pointerEvent = EventPackage::GestureToPointerEvent(gesture, *udsServer_);
    if (RET_OK == eventDispatch_.handlePointerEvent(pointerEvent)) {
        MMI_LOGD("interceptor of OnGestureEvent end .....");
        return RET_OK;
    }
    auto eventDispatchResult = eventDispatch_.DispatchGestureNewEvent(*udsServer_, event, pointerEvent, preHandlerTime);
    if (eventDispatchResult != RET_OK) {
        MMI_LOGE("Gesture New event dispatch failed... ret:%{public}d errCode:%{public}d",
            eventDispatchResult, GESTURE_EVENT_DISP_FAIL);
        return GESTURE_EVENT_DISP_FAIL;
    }
    return RET_OK;
}

int32_t OHOS::MMI::InputEventHandler::OnEventGesture(multimodal_libinput_event &ev)
{
    CHKR(ev.event, NULL_POINTER, NULL_POINTER);
    OnGestureEvent(*ev.event);
    uint64_t preHandlerTime = GetSysClockTime();
    EventGesture gesture = {};
    CHKR(udsServer_, NULL_POINTER, RET_ERR);
    auto packageResult = eventPackage_.PackageGestureEvent(*ev.event, gesture, *udsServer_);
    if (packageResult != RET_OK) {
        MMI_LOGE("Gesture swipe event package failed... ret:%{public}d errCode:%{public}d",
            packageResult, GESTURE_EVENT_PKG_FAIL);
        return GESTURE_EVENT_PKG_FAIL;
    }

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
    auto hosKey = KeyValueTransformationByInput(key.key);           // libinput key transformed into HOS key
    if (hosKey.isSystemKey && OnSystemEvent(hosKey, key.state)) {   // Judging whether key is system key.
        return RET_OK;
    }

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
    // libinput key transformed into HOS key
    auto hosKey = KeyValueTransformationByInput(key.key);
    key.unicode = 0;
    // Judging whether key is system key.
    if (hosKey.isSystemKey && OnSystemEvent(hosKey, key.state)) {
        return RET_OK;
    }
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
    auto ret = eventDispatch_.DispatchJoyStickEvent(*udsServer_, *ev.event, eventJoyStickAxis, time);
    if (ret != RET_OK) {
        MMI_LOGE("Joystick event dispatch failed... ret:%{public}d errCode:%{public}d", ret, JOYSTICK_EVENT_DISP_FAIL);
        return JOYSTICK_EVENT_DISP_FAIL;
    }
    return RET_OK;
}

int32_t OHOS::MMI::InputEventHandler::OnMouseEventHandler(libinput_event& event, const int32_t deviceId)
{
    auto mouseEvent = MouseEventHandler::Create();
    if (mouseEvent == nullptr) {
        return RET_ERR;
    }
    if (keyEvent == nullptr) {
        keyEvent = OHOS::MMI::KeyEvent::Create();
    }
    if (keyEvent != nullptr) {
        std::vector<int32_t> pressedKeys = keyEvent->GetPressedKeys();
        if (pressedKeys.empty()) {
            MMI_LOGI("Pressed keys is empty");
        } else {
            for (int32_t keyCode : pressedKeys) {
                MMI_LOGI("Pressed keyCode=%{public}d", keyCode);
            }
        }
        mouseEvent->SetPressedKeys(pressedKeys);
    }
    mouseEvent->SetMouseData(event, deviceId);
    // MouseEvent Normalization Results
    MMI_LOGI("MouseEvent Normalization Results : PointerAction = %{public}d, PointerId = %{public}d,"
        "SourceType = %{public}d, ButtonId = %{public}d,"
        "VerticalAxisValue = %{public}lf, HorizontalAxisValue = %{public}lf",
        mouseEvent->GetPointerAction(), mouseEvent->GetPointerId(), mouseEvent->GetSourceType(),
        mouseEvent->GetButtonId(), mouseEvent->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL),
        mouseEvent->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL));
    std::vector<int32_t> pointerIds { mouseEvent->GetPointersIdList() };
    for (int32_t pointerId : pointerIds) {
        PointerEvent::PointerItem item;
        mouseEvent->GetPointerItem(pointerId, item);
        MMI_LOGI("MouseEvent Item Normalization Results : DownTime = %{public}d, IsPressed = %{public}d,"
            "GlobalX = %{public}d, GlobalY = %{public}d, LocalX = %{public}d, LocalY = %{public}d, Width = %{public}d,"
            "Height = %{public}d, Pressure = %{public}d, DeviceId = %{public}d",
            item.GetDownTime(), static_cast<int32_t>(item.IsPressed()), item.GetGlobalX(), item.GetGlobalY(),
            item.GetLocalX(), item.GetLocalY(), item.GetWidth(), item.GetHeight(), item.GetPressure(),
            item.GetDeviceId());
    }

    eventDispatch_.handlePointerEvent(mouseEvent);
    return RET_OK;
}

int32_t OHOS::MMI::InputEventHandler::OnMouseEventTimerHanler(std::shared_ptr<OHOS::MMI::PointerEvent> mouse_event)
{
    if (mouse_event == nullptr) {
        return RET_ERR;
    }
    eventDispatch_.handlePointerEvent(mouse_event);
    return RET_OK;
}

bool OHOS::MMI::InputEventHandler::SendMsg(const int32_t fd, NetPacket& pkt) const
{
    CHKF(udsServer_, OHOS::NULL_POINTER);
    return udsServer_->SendMsg(fd, pkt);
}

bool OHOS::MMI::InputEventHandler::OnSystemEvent(const KeyEventValueTransformations& temp,
    const enum KEY_STATE state) const
{
    const int32_t systemEventAttr = OuterInterface::GetSystemEventAttrByHosKeyValue(temp.keyValueOfHos);
    uint16_t retCode = 0;
    switch (systemEventAttr) {
        case MMI_SYSTEM_SERVICE: {
            (void)OuterInterface::SystemEventHandler(temp, state, systemEventAttr);
            (void)OuterInterface::DistributedEventHandler(temp, state, systemEventAttr);
            retCode = 1;
            break;
        }
        case MMI_SYSTEM_SERVICE_AND_APP: {
            if (OuterInterface::SystemEventHandler(temp, state, systemEventAttr) ||
                OuterInterface::DistributedEventHandler(temp, state, systemEventAttr)) {
                retCode = 1;
            }
            break;
        }
        case MMI_CAMERA_APP: {
            (void)OuterInterface::SystemEventHandler(temp, state, systemEventAttr);
            (void)OuterInterface::DistributedEventHandler(temp, state, systemEventAttr);
            retCode = 1;
            break;
        }
        default: {
            break;
        }
    }
    return retCode;
}
