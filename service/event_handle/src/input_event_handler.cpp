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
#include "bytrace.h"
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

namespace OHOS {
namespace MMI {
    namespace {
        constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "InputEventHandler" };
    }

InputEventHandler::InputEventHandler()
{
    udsServer_ = nullptr;
    notifyDeviceChange_ = nullptr;
}

InputEventHandler::~InputEventHandler()
{
}

bool InputEventHandler::Init(UDSServer& udsServer)
{
    MMI_LOGD("enter");
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
    for (auto &item : funs) {
        CHKC(RegistrationEvent(item), EVENT_REG_FAIL);
    }
    MMI_LOGD("leave");
    return true;
}

void InputEventHandler::OnEvent(void *event)
{
    MMI_LOGD("enter");
    CHKPV(event);
    std::lock_guard<std::mutex> lock(mu_);
    auto *lpMmiEvent = static_cast<multimodal_libinput_event *>(event);
    CHKPV(lpMmiEvent);
    auto *lpEvent = lpMmiEvent->event;
    CHKPV(lpEvent);
    if (initSysClock_ != 0 && lastSysClock_ == 0) {
        MMI_LOGE("Event not handled. id:%{public}" PRId64 ",eventType:%{public}d,initSysClock:%{public}" PRId64,
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
    MMI_LOGT("Event reporting. id:%{public}" PRId64 ",tid:%{public}" PRId64 ",eventType:%{public}d,"
             "initSysClock:%{public}" PRId64, idSeed_, tid, eventType_, initSysClock_);

    OnEventHandler(*lpMmiEvent);
    lastSysClock_ = GetSysClockTime();
    uint64_t lostTime = lastSysClock_ - initSysClock_;
    MMI_LOGT("Event handling completed. id:%{public}" PRId64 ",lastSynClock:%{public}" PRId64
             ",lostTime:%{public}" PRId64, idSeed_, lastSysClock_, lostTime);
    MMI_LOGD("leave");
}

int32_t InputEventHandler::OnEventHandler(const multimodal_libinput_event& ev)
{
    MMI_LOGD("enter");
    CHKPR(ev.event, ERROR_NULL_POINTER);
    auto type = libinput_event_get_type(ev.event);
    TimeCostChk chk("InputEventHandler::OnEventHandler", "overtime 1000(us)", MAX_INPUT_EVENT_TIME, type);
    auto fun = GetFun(static_cast<MmiMessageId>(type));
    if (!fun) {
        MMI_LOGE("Unknown event type:%{public}d,errCode:%{public}d", type, UNKNOWN_EVENT);
        return UNKNOWN_EVENT;
    }
    auto ret = (*fun)(ev);
    if (ret != 0) {
        MMI_LOGE("Event handling failed. type:%{public}d,ret:%{public}d,errCode:%{public}d",
                 type, ret, EVENT_CONSUM_FAIL);
    }
    MMI_LOGD("leave");
    return ret;
}

void InputEventHandler::OnCheckEventReport()
{
    MMI_LOGD("enter");
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
    MMI_LOGE("Event not responding. id:%{public}" PRId64 ",eventType:%{public}d,initSysClock:%{public}" PRId64 ","
             "lostTime:%{public}" PRId64, idSeed_, eventType_, initSysClock_, lostTime);
    MMI_LOGD("leave");
}

void InputEventHandler::RegistnotifyDeviceChange(NotifyDeviceChange cb)
{
    MMI_LOGD("enter");
    notifyDeviceChange_ = cb;
    MMI_LOGD("leave");
}

UDSServer* InputEventHandler::GetUDSServer()
{
    MMI_LOGD("enter");
    MMI_LOGD("leave");
    return udsServer_;
}

int32_t InputEventHandler::AddInputEventFilter(sptr<IEventFilter> filter)
{
    MMI_LOGD("enter");
    MMI_LOGD("leave");
    return eventDispatch_.AddInputEventFilter(filter);
}

int32_t InputEventHandler::OnEventDeviceAdded(const multimodal_libinput_event& ev)
{
    MMI_LOGD("enter");
    CHKPR(ev.event, ERROR_NULL_POINTER);
#ifndef OHOS_WESTEN_MODEL
    auto device = libinput_event_get_device(ev.event);
    InputDevMgr->OnInputDeviceAdded(device);
#else
    uint64_t sysStartProcessTime = GetSysClockTime();
    DeviceManage deviceManage = {};

    CHKPR(udsServer_, ERROR_NULL_POINTER);
    auto packageResult = eventPackage_.PackageDeviceManageEvent(ev.event, deviceManage);
    if (packageResult != RET_OK) {
        MMI_LOGE("Deviceadded event package failed. ret:%{public}d,errCode:%{public}d",
                 packageResult, DEV_ADD_EVENT_PKG_FAIL);
        return DEV_ADD_EVENT_PKG_FAIL;
    }
    MMI_LOGT("4.event dispatcher of server, DeviceManage:physical:%{public}s,"
             "deviceName:%{public}s,deviceType:%{public}u",
             deviceManage.physical, deviceManage.deviceName, deviceManage.deviceType);

    int32_t focusId = WinMgr->GetFocusSurfaceId();
    if (focusId < 0) {
        return RET_OK; // DeviceAdded event will be discarded if focusId < 0
    }
    auto appInfo = AppRegs->FindByWinId(focusId);
    if (appInfo.fd == RET_ERR) {
        return RET_OK; // DeviceAdded event will be discarded if appInfo.fd == RET_ERR
    }
    NetPacket newPacket(MmiMessageId::ON_DEVICE_ADDED);
    newPacket << deviceManage << appInfo.abilityId << focusId << appInfo.fd << sysStartProcessTime;
    if (!SendMsg(appInfo.fd, newPacket)) {
        MMI_LOGE("Sending structure of DeviceManage failed! errCode:%{public}d", MSG_SEND_FAIL);
        return MSG_SEND_FAIL;
    }
#endif
    MMI_LOGD("leave");
    return RET_OK;
}

int32_t InputEventHandler::OnEventDeviceRemoved(const multimodal_libinput_event& ev)
{
    MMI_LOGD("enter");
    CHKPR(ev.event, ERROR_NULL_POINTER);
#ifndef OHOS_WESTEN_MODEL
    auto device = libinput_event_get_device(ev.event);
    InputDevMgr->OnInputDeviceRemoved(device);
#else
    uint64_t sysStartProcessTime = GetSysClockTime();
    CHKPR(udsServer_, ERROR_NULL_POINTER);
    DeviceManage deviceManage = {};
    auto packageResult = eventPackage_.PackageDeviceManageEvent(ev.event, deviceManage);
    if (packageResult != RET_OK) {
        MMI_LOGE("Deviceremoved event package failed. ret:%{public}d,errCode:%{public}d",
                 packageResult, DEV_REMOVE_EVENT_PKG_FAIL);
        return DEV_REMOVE_EVENT_PKG_FAIL;
    }
    MMI_LOGT("4.event dispatcher of server, DeviceManage:physical:%{public}s,"
             "deviceName:%{public}s,deviceType:%{public}u",
             deviceManage.physical, deviceManage.deviceName, deviceManage.deviceType);

    int32_t focusId = WinMgr->GetFocusSurfaceId();
    if (focusId < 0) {
        return RET_OK; // DeviceRemoved event will be discarded if focusId < 0
    }
    auto appInfo = AppRegs->FindByWinId(focusId);
    if (appInfo.fd == RET_ERR) {
        return RET_OK; // DeviceRemoved event will be discarded if appInfo.fd == RET_ERR
    }
    NetPacket newPacket(MmiMessageId::ON_DEVICE_REMOVED);
    newPacket << deviceManage << appInfo.abilityId << focusId << appInfo.fd << sysStartProcessTime;
    if (!SendMsg(appInfo.fd, newPacket)) {
        MMI_LOGE("Sending structure of DeviceManage failed, errCode:%{public}d", MSG_SEND_FAIL);
        return MSG_SEND_FAIL;
    }
#endif
    MMI_LOGD("leave");
    return RET_OK;
}

int32_t InputEventHandler::OnEventKey(libinput_event *event)
{
    MMI_LOGD("enter");
    CHKPR(event, PARAM_INPUT_INVALID);
    CHKPR(udsServer_, ERROR_NULL_POINTER);
    uint64_t sysStartProcessTime = GetSysClockTime();
    if (keyEvent_ == nullptr) {
        keyEvent_ = KeyEvent::Create();
    }
    auto packageResult = eventPackage_.PackageKeyEvent(event, keyEvent_);
    if (packageResult == MULTIDEVICE_SAME_EVENT_MARK) {
        MMI_LOGD("The same event reported by multi_device should be discarded");
        return RET_OK;
    }
    if (packageResult != RET_OK) {
        MMI_LOGE("KeyEvent package failed. ret:%{public}d,errCode:%{public}d", packageResult, KEY_EVENT_PKG_FAIL);
        return KEY_EVENT_PKG_FAIL;
    }

    int32_t action = keyEvent_->GetKeyAction();
    KEY_STATE kacState = (action == KeyEvent::KEY_ACTION_DOWN) ? KEY_STATE_PRESSED : KEY_STATE_RELEASED;

#ifdef OHOS_WESTEN_MODEL
    int16_t lowKeyCode = static_cast<int16_t>(keyEvent_->GetKeyCode());
    auto oKey = KeyValueTransformationByInput(lowKeyCode);
    if (oKey.isSystemKey) {
        OnSystemEvent(oKey, kacState);
    }
#endif

    auto device = libinput_event_get_device(event);
    CHKPR(device, ERROR_NULL_POINTER);

    auto eventDispatchResult = eventDispatch_.DispatchKeyEventByPid(*udsServer_, keyEvent_, sysStartProcessTime);
    if (eventDispatchResult != RET_OK) {
        MMI_LOGE("KeyEvent dispatch failed. ret:%{public}d,errCode:%{public}d",
                 eventDispatchResult, KEY_EVENT_DISP_FAIL);
        return KEY_EVENT_DISP_FAIL;
    }
    int32_t keyCode = keyEvent_->GetKeyCode();
    std::string keyEventString = "service dispatch keyCode=" + std::to_string(keyCode);
    BYTRACE_NAME(BYTRACE_TAG_MULTIMODALINPUT, keyEventString);
    int32_t keyId = keyEvent_->GetId();
    keyEventString = "OnKeyEvent";
    FinishAsyncTrace(BYTRACE_TAG_MULTIMODALINPUT, keyEventString, keyId);
    MMI_LOGD("Inject keyCode=%{public}d, action=%{public}d", keyEvent_->GetKeyCode(), keyEvent_->GetKeyAction());
    MMI_LOGD("leave");
    return RET_OK;
}

int32_t InputEventHandler::OnKeyEventDispatch(const multimodal_libinput_event& ev)
{
    MMI_LOGD("enter");
#ifdef OHOS_WESTEN_MODEL
    uint64_t sysStartProcessTime = GetSysClockTime();
#endif
    if (keyEvent_ == nullptr) {
        keyEvent_ = KeyEvent::Create();
    }
    CHKPR(udsServer_, ERROR_NULL_POINTER);
    auto packageResult = eventPackage_.PackageKeyEvent(ev.event, keyEvent_);
    if (packageResult == MULTIDEVICE_SAME_EVENT_MARK) {
        MMI_LOGD("The same event reported by multi_device should be discarded");
        return RET_OK;
    }
    if (packageResult != RET_OK) {
        MMI_LOGE("KeyEvent package failed. ret:%{public}d,errCode:%{public}d", packageResult, KEY_EVENT_PKG_FAIL);
        return KEY_EVENT_PKG_FAIL;
    }
    int32_t keyId = keyEvent_->GetId();
    std::string keyEventString = "OnKeyEvent";
    StartAsyncTrace(BYTRACE_TAG_MULTIMODALINPUT, keyEventString, keyId);
    keyEventString = "service report keyId=" + std::to_string(keyId);
    BYTRACE_NAME(BYTRACE_TAG_MULTIMODALINPUT, keyEventString);
#ifndef OHOS_WESTEN_MODEL
    if (InterceptorMgrGbl.OnKeyEvent(keyEvent_)) {
        MMI_LOGD("key event filter find a key event from Original event keyCode:%{puiblic}d",
                 keyEvent_->GetKeyCode());
        int32_t keyCode = keyEvent_->GetKeyCode();
        keyEventString = "service filter keyCode=" + std::to_string(keyCode);
        BYTRACE_NAME(BYTRACE_TAG_MULTIMODALINPUT, keyEventString);
        FinishAsyncTrace(BYTRACE_TAG_MULTIMODALINPUT, keyEventString, keyId);
        return RET_OK;
    }
    MMI_LOGD("leave");
    return OnEventKey(ev.event);
#else

    int32_t action = keyEvent_->GetKeyAction();
    KEY_STATE kacState = (action == KeyEvent::KEY_ACTION_DOWN) ? KEY_STATE_PRESSED : KEY_STATE_RELEASED;
    int16_t lowKeyCode = static_cast<int16_t>(keyEvent_->GetKeyCode());
    auto oKey = KeyValueTransformationByInput(lowKeyCode);
    if (oKey.isSystemKey) {
        OnSystemEvent(oKey, kacState);
    }

    auto device = libinput_event_get_device(ev.event);
    CHKPR(device, ERROR_NULL_POINTER);

    auto eventDispatchResult = eventDispatch_.DispatchKeyEventByPid(*udsServer_, keyEvent_, sysStartProcessTime);
    if (eventDispatchResult != RET_OK) {
        MMI_LOGE("KeyEvent dispatch failed. ret:%{public}d,errCode:%{public}d", 
            eventDispatchResult, KEY_EVENT_DISP_FAIL);
        return KEY_EVENT_DISP_FAIL;
    }
    return RET_OK;
#endif
}

int32_t InputEventHandler::OnKeyboardEvent(libinput_event *event)
{
    MMI_LOGD("enter");
    CHKPR(event, ERROR_NULL_POINTER);
    uint64_t sysStartProcessTime = GetSysClockTime();
    CHKPR(udsServer_, ERROR_NULL_POINTER);
    EventKeyboard keyBoard = {};
    auto packageResult = eventPackage_.PackageKeyEvent(event, keyBoard);
    if (packageResult == MULTIDEVICE_SAME_EVENT_MARK) { // The multi_device_same_event should be discarded
        MMI_LOGD("The same event occurs on multiple devices, ret:%{puiblic}d", packageResult);
        return RET_OK;
    }
    if (packageResult != RET_OK) {
        MMI_LOGE("Key event package failed. ret:%{public}d,errCode:%{public}d", packageResult, KEY_EVENT_PKG_FAIL);
        return KEY_EVENT_PKG_FAIL;
    }

    auto oKey = KeyValueTransformationByInput(keyBoard.key); // libinput key transformed into HOS key
    keyBoard.unicode = 0;

#ifdef OHOS_WESTEN_MODEL
    if (oKey.isSystemKey) { // Judging whether key is system key.
        OnSystemEvent(oKey, keyBoard.state);
    }
#endif
    if (keyEvent_ == nullptr) {
        keyEvent_ = KeyEvent::Create();
    }
    keyBoard.key = static_cast<uint32_t>(oKey.keyValueOfHos);
    if (EventPackage::KeyboardToKeyEvent(keyBoard, keyEvent_) == RET_ERR) {
        MMI_LOGE("On the OnKeyboardEvent translate key event error");
        return RET_ERR;
    }
    auto device = libinput_event_get_device(event);
    CHKPR(device, LIBINPUT_DEV_EMPTY);

    auto eventDispatchResult = eventDispatch_.DispatchKeyEventByPid(*udsServer_, keyEvent_, sysStartProcessTime);
    if (eventDispatchResult != RET_OK) {
        MMI_LOGE("Key event dispatch failed. ret:%{public}d,errCode:%{public}d",
                 eventDispatchResult, KEY_EVENT_DISP_FAIL);
        return KEY_EVENT_DISP_FAIL;
    }

    MMI_LOGD("leave");
    return RET_OK;
}

int32_t InputEventHandler::OnEventKeyboard(const multimodal_libinput_event& ev)
{
    MMI_LOGD("enter");
    CHKPR(ev.event, ERROR_NULL_POINTER);
#ifdef OHOS_WESTEN_MODEL
    uint64_t sysStartProcessTime = GetSysClockTime();
#endif

    CHKPR(udsServer_, ERROR_NULL_POINTER);
    EventKeyboard keyBoard = {};
    auto packageResult = eventPackage_.PackageKeyEvent(ev.event, keyBoard);
    if (packageResult == MULTIDEVICE_SAME_EVENT_MARK) { // The multi_device_same_event should be discarded
        MMI_LOGD("The same event occurs on multiple devices, ret:%{puiblic}d", packageResult);
        return RET_OK;
    }
    if (packageResult != RET_OK) {
        MMI_LOGE("Key event package failed. ret:%{public}d,errCode:%{public}d", packageResult, KEY_EVENT_PKG_FAIL);
        return KEY_EVENT_PKG_FAIL;
    }
    
#ifndef OHOS_WESTEN_MODEL
    return OnKeyboardEvent(ev.event);
#else
    if (ServerKeyFilter->OnKeyEvent(keyBoard)) {
        MMI_LOGD("Key event filter find a key event from Original event, keyCode:%{puiblic}d", keyBoard.key);
        return RET_OK;
    }
    auto oKey = KeyValueTransformationByInput(keyBoard.key); // libinput key transformed into HOS key
    keyBoard.unicode = 0;
    if (oKey.isSystemKey && OnSystemEvent(oKey, keyBoard.state)) { // Judging whether key is system key.
        return RET_OK;
    }

    auto eventDispatchResult = eventDispatch_.DispatchKeyEvent(*udsServer_, ev.event, oKey, keyBoard,
                                                               sysStartProcessTime);
    if (eventDispatchResult != RET_OK) {
        MMI_LOGE("Key event dispatch failed. ret:%{public}d,errCode:%{public}d",
                 eventDispatchResult, KEY_EVENT_DISP_FAIL);
        return KEY_EVENT_DISP_FAIL;
    }
    return RET_OK;
#endif
}

int32_t InputEventHandler::OnEventPointer(const multimodal_libinput_event& ev)
{
    MMI_LOGD("enter");
    CHKPR(udsServer_, ERROR_NULL_POINTER);
    CHKPR(ev.event, ERROR_NULL_POINTER);
    uint64_t sysStartProcessTime = GetSysClockTime();
    auto device = libinput_event_get_device(ev.event);
    CHKPR(device, LIBINPUT_DEV_EMPTY);
    int32_t devicType = static_cast<int32_t>(libinput_device_get_tags(device));
    if (devicType & EVDEV_UDEV_TAG_JOYSTICK) {
        auto type = libinput_event_get_type(ev.event);
        if (type == LIBINPUT_EVENT_POINTER_BUTTON) {
            MMI_LOGI("JoyStickKey Process");
            return OnEventJoyStickKey(ev, sysStartProcessTime);
        } else if (type == LIBINPUT_EVENT_POINTER_AXIS) {
            MMI_LOGI("JoyStickAxis Process");
            return OnEventJoyStickAxis(ev, sysStartProcessTime);
        }
    }
    EventPointer point = {};
    auto packageResult = eventPackage_.PackagePointerEvent(ev.event, point);
    if (packageResult == MULTIDEVICE_SAME_EVENT_MARK) { // The multi_device_same_event should be discarded
        MMI_LOGW("The same event reported by multi_device should be discarded");
        return RET_OK;
    }
    if (packageResult != RET_OK) {
        MMI_LOGE("Pointer event package failed. ret:%{public}d,errCode:%{public}d",
                 packageResult, POINT_EVENT_PKG_FAIL);
        return POINT_EVENT_PKG_FAIL;
    }
#ifdef OHOS_WESTEN_MODEL
    if (ServerKeyFilter->OnPointerEvent(point)) {
        MMI_LOGD("Pointer event interceptor find a pointer event pointer button:%{puiblic}d", point.button);
        return RET_OK;
    }
#else
    MMI_LOGT("2.mapping event, Event:eventType:%{public}d", point.eventType);
    /*
    auto retEvent = eventDispatch_.DispatchCommonPointEvent(*udsServer_, *ev.event, point, preHandlerTime);
    if (retEvent != RET_OK) {
        MMI_LOGE("common_point event dispatch failed. ret:%{public}d,errCode:%{public}d",
            retEvent, POINT_REG_EVENT_DISP_FAIL);
        return POINT_REG_EVENT_DISP_FAIL;
    }
    */
#endif
#ifndef OHOS_WESTEN_MODEL
    /* New */
    return OnMouseEventHandler(ev.event);
#else
    auto retEvent = eventDispatch_.DispatchPointerEvent(*udsServer_, ev.event, point, sysStartProcessTime);
    if (retEvent != RET_OK) {
        MMI_LOGE("Pointer event dispatch failed. ret:%{public}d,errCode:%{public}d",
            retEvent, POINT_EVENT_DISP_FAIL);
        return POINT_EVENT_DISP_FAIL;
    }
    return RET_OK;
#endif
}

int32_t InputEventHandler::OnEventTouchSecond(libinput_event *event)
{
    MMI_LOGD("enter");
    CHKPR(event, ERROR_NULL_POINTER);
    auto point = TouchTransformPointManger->OnLibinputTouchEvent(event);
    CHKPR(point, ERROR_NULL_POINTER);
    int32_t pointerId = point->GetId();
    std::string touchEvent = "OnEventTouch";
    StartAsyncTrace(BYTRACE_TAG_MULTIMODALINPUT, touchEvent, pointerId);
    eventDispatch_.HandlePointerEvent(point);
    FinishAsyncTrace(BYTRACE_TAG_MULTIMODALINPUT, touchEvent, pointerId);
    auto type = libinput_event_get_type(event);
    if (type == LIBINPUT_EVENT_TOUCH_UP) {
        point->RemovePointerItem(point->GetPointerId());
        MMI_LOGD("This touch event is up remove this finger"); 
        if (point->GetPointersIdList().empty()) {
            MMI_LOGD("This touch event is final finger up remove this finger");
            point->Reset();
        }
        return RET_OK;
    }
    MMI_LOGD("Leave"); 
    return RET_OK;
}

int32_t InputEventHandler::OnEventTouchPadSecond(libinput_event *event)
{
    MMI_LOGD("enter");
    CHKPR(event, ERROR_NULL_POINTER);

    auto point = TouchTransformPointManger->OnLibinputTouchPadEvent(event);
    if (point == nullptr) {
        return RET_OK;
    }
    eventDispatch_.HandlePointerEvent(point);
    auto type = libinput_event_get_type(event);
    if (type == LIBINPUT_EVENT_TOUCHPAD_UP) {
        point->RemovePointerItem(point->GetPointerId());
        MMI_LOGD("This touch pad event is up remove this finger");
        if (point->GetPointersIdList().empty()) {
            MMI_LOGD("This touch pad event is final finger up remove this finger");
            point->Reset();
        }
        return RET_OK;
    }
    MMI_LOGD("Leave");
    return RET_OK;
}

int32_t InputEventHandler::OnEventTouch(const multimodal_libinput_event& ev)
{
    MMI_LOGD("enter");
    CHKPR(ev.event, ERROR_NULL_POINTER);
    SInput::LoginfoPackagingTool(ev.event);
#ifndef OHOS_WESTEN_MODEL
    return OnEventTouchSecond(ev.event);
#else
    CHKPR(udsServer_, ERROR_NULL_POINTER);
    uint64_t sysStartProcessTime = GetSysClockTime();
    EventTouch touch = {};
    auto packageResult = eventPackage_.PackageTouchEvent(ev.event, touch);
    if (packageResult == UNKNOWN_EVENT_PKG_FAIL) {
        return RET_OK;
    }
    if (packageResult != RET_OK) {
        MMI_LOGE("Touch event package failed, ret:%{public}d,errCode:%{public}d",
                 packageResult, TOUCH_EVENT_PKG_FAIL);
        return TOUCH_EVENT_PKG_FAIL;
    }
    if (ServerKeyFilter->OnTouchEvent(ev.event, touch, sysStartProcessTime)) {
        return RET_OK;
    }
    auto ret = eventDispatch_.DispatchTouchEvent(*udsServer_, ev.event, touch, sysStartProcessTime);
    if (ret != RET_OK) {
        MMI_LOGE("Touch event dispatch failed. ret:%{public}d,errCode:%{public}d", ret, TOUCH_EVENT_DISP_FAIL);
        return TOUCH_EVENT_DISP_FAIL;
    }
#endif
    MMI_LOGD("leave");
    return RET_OK;
}

int32_t InputEventHandler::OnEventTouchpad(const multimodal_libinput_event& ev)
{
    MMI_LOGD("enter");
#ifndef OHOS_WESTEN_MODEL
    OnEventTouchPadSecond(ev.event);
#endif
    MMI_LOGD("leave");
    return RET_OK;
}

int32_t InputEventHandler::OnGestureEvent(libinput_event *event)
{
    MMI_LOGD("enter");
    CHKPR(event, ERROR_NULL_POINTER);
    MMI_LOGD("InputEventHandler::OnGestureEvent");
    auto pointer = TouchTransformPointManger->OnTouchPadGestrueEvent(event);
    if (pointer == nullptr) {
        MMI_LOGE("Gesture event package failed, errCode:%{public}d", GESTURE_EVENT_PKG_FAIL);
        return GESTURE_EVENT_PKG_FAIL;
    }
    MMI_LOGT("GestrueEvent package, eventType:%{public}d,actionTime:%{public}d,"
             "action:%{public}d,actionStartTime:%{public}d,"
             "pointerAction:%{public}d,sourceType:%{public}d,"
             "PinchAxisValue:%{public}.2f",
             pointer->GetEventType(), pointer->GetActionTime(),
             pointer->GetAction(), pointer->GetActionStartTime(),
             pointer->GetPointerAction(), pointer->GetSourceType(),
             pointer->GetAxisValue(PointerEvent::AXIS_TYPE_PINCH));

    PointerEvent::PointerItem item;
    pointer->GetPointerItem(pointer->GetPointerId(), item);
    MMI_LOGT("item:DownTime:%{public}d,IsPressed:%{public}s,"
             "GlobalX:%{public}d,GlobalY:%{public}d,LocalX:%{public}d,LocalY:%{public}d,"
             "Width:%{public}d,Height:%{public}d,DeviceId:%{public}d",
             item.GetDownTime(), (item.IsPressed() ? "true" : "false"),
             item.GetGlobalX(), item.GetGlobalY(), item.GetLocalX(), item.GetLocalY(),
             item.GetWidth(), item.GetHeight(), item.GetDeviceId());

    int32_t ret = eventDispatch_.HandlePointerEvent(pointer);
    if (ret != RET_OK) {
        MMI_LOGE("Gesture event dispatch failed, errCode:%{public}d", GESTURE_EVENT_DISP_FAIL);
        return GESTURE_EVENT_DISP_FAIL;
    }
    MMI_LOGD("leave");
    return RET_OK;
}

int32_t InputEventHandler::OnEventGesture(const multimodal_libinput_event& ev)
{
    MMI_LOGD("enter");
    CHKPR(ev.event, ERROR_NULL_POINTER);
#ifndef OHOS_WESTEN_MODEL
    OnGestureEvent(ev.event);
#else
    uint64_t sysStartProcessTime = GetSysClockTime();
    EventGesture gesture = {};
    CHKPR(udsServer_, ERROR_NULL_POINTER);
    auto packageResult = eventPackage_.PackageGestureEvent(ev.event, gesture);
    if (packageResult != RET_OK) {
        MMI_LOGE("Gesture swipe event package failed, ret:%{public}d,errCode:%{public}d",
                 packageResult, GESTURE_EVENT_PKG_FAIL);
        return GESTURE_EVENT_PKG_FAIL;
    }

    auto eventDispatchResult = eventDispatch_.DispatchGestureEvent(*udsServer_, ev.event, gesture,
                                                                   sysStartProcessTime);
    if (eventDispatchResult != RET_OK) {
        MMI_LOGE("Gesture event dispatch failed, ret:%{public}d,errCode:%{public}d",
                 eventDispatchResult, GESTURE_EVENT_DISP_FAIL);
        return GESTURE_EVENT_DISP_FAIL;
    }
#endif
MMI_LOGD("leave");
    return RET_OK;
}

int32_t InputEventHandler::OnEventTabletTool(const multimodal_libinput_event& ev)
{
    MMI_LOGD("enter");
    CHKPR(ev.event, ERROR_NULL_POINTER);
    uint64_t sysStartProcessTime = GetSysClockTime();
    EventTabletTool tableTool = {};
    CHKPR(udsServer_, ERROR_NULL_POINTER);
    auto packageResult = eventPackage_.PackageTabletToolEvent(ev.event, tableTool);
    if (packageResult == MULTIDEVICE_SAME_EVENT_MARK) { // The multi_device_same_event should be discarded
        MMI_LOGD("The same event reported by multi_device should be discarded");
        return RET_OK;
    }
    if (packageResult != RET_OK) {
        MMI_LOGE("Tablettool event package failed. ret:%{public}d,errCode:%{public}d",
                 packageResult, TABLETTOOL_EVENT_PKG_FAIL);
        return TABLETTOOL_EVENT_PKG_FAIL;
    }
    MMI_LOGT("2.mapping event, Event:eventType:%{public}d;", tableTool.eventType);
    auto retEvent = eventDispatch_.DispatchTabletToolEvent(*udsServer_, ev.event, tableTool, sysStartProcessTime);
    if (retEvent != RET_OK) {
        MMI_LOGE("Tabletool event dispatch failed. ret:%{public}d,errCode:%{public}d",
                 retEvent, TABLETTOOL_EVENT_DISP_FAIL);
        return TABLETTOOL_EVENT_DISP_FAIL;
    }
    MMI_LOGD("leave");
    return RET_OK;
}

int32_t InputEventHandler::OnEventTabletPad(const multimodal_libinput_event& ev)
{
    MMI_LOGD("enter");
    CHKPR(ev.event, ERROR_NULL_POINTER);
    uint64_t sysStartProcessTime = GetSysClockTime();
    CHKPR(udsServer_, ERROR_NULL_POINTER);
    EventTabletPad tabletPad = {};
    auto packageResult = eventPackage_.PackageTabletPadEvent(ev.event, tabletPad);
    if (packageResult != RET_OK) {
        MMI_LOGE("Tabletpad event package failed. ret:%{public}d,errCode:%{public}d",
                 packageResult, TABLETPAD_EVENT_PKG_FAIL);
        return TABLETPAD_EVENT_PKG_FAIL;
    }
    auto ret = eventDispatch_.DispatchTabletPadEvent(*udsServer_, ev.event, tabletPad, sysStartProcessTime);
    if (ret != RET_OK) {
        MMI_LOGE("Tabletpad event dispatch failed. ret:%{public}d,errCode:%{public}d",
                 ret, TABLETPAD_EVENT_DISP_FAIL);
        return TABLETPAD_EVENT_DISP_FAIL;
    }
    MMI_LOGD("leave");
    return RET_OK;
}

int32_t InputEventHandler::OnEventSwitchToggle(const multimodal_libinput_event& ev)
{
    MMI_LOGD("enter");
    CHKPR(ev.event, ERROR_NULL_POINTER);
    auto type = libinput_event_get_type(ev.event);
    MMI_LOGT("Function is OnEventSwitchToggle, sourceType is LIBINPUT_EVENT_SWITCH_TOGGLE:%{public}d", type);
    MMI_LOGD("leave");
    return RET_OK;
}

int32_t InputEventHandler::OnEventTabletPadKey(const multimodal_libinput_event& ev)
{
    MMI_LOGD("enter");
    CHKPR(ev.event, ERROR_NULL_POINTER);
    uint64_t sysStartProcessTime = GetSysClockTime();
    CHKPR(udsServer_, ERROR_NULL_POINTER);
    EventKeyboard key = {};
    auto packageResult = eventPackage_.PackageTabletPadKeyEvent(ev.event, key);
    if (packageResult == MULTIDEVICE_SAME_EVENT_MARK) { // The multi_device_same_event should be discarded
        MMI_LOGD("The same event reported by multi_device should be discarded");
        return RET_OK;
    }
    if (packageResult != RET_OK) {
        MMI_LOGE("Tabletpadkey event package failed. ret:%{public}d,errCode:%{public}d",
                 packageResult, TABLETPAD_KEY_EVENT_PKG_FAIL);
        return TABLETPAD_KEY_EVENT_PKG_FAIL;
    }
    auto oKey = KeyValueTransformationByInput(key.key);           // libinput key transformed into HOS key
#ifdef OHOS_WESTEN_MODEL
    if (oKey.isSystemKey && OnSystemEvent(oKey, key.state)) {   // Judging whether key is system key.
        return RET_OK;
    }
#endif
    auto eventDispatchResult = eventDispatch_.DispatchKeyEvent(*udsServer_, ev.event, oKey, key, sysStartProcessTime);
    if (eventDispatchResult != RET_OK) {
        MMI_LOGE("Key event dispatch failed. ret:%{public}d,errCode:%{public}d",
                 eventDispatchResult, TABLETPAD_KEY_EVENT_DISP_FAIL);
        return TABLETPAD_KEY_EVENT_DISP_FAIL;
    }
    MMI_LOGD("leave");
    return RET_OK;
}

int32_t InputEventHandler::OnEventJoyStickKey(const multimodal_libinput_event& ev, const uint64_t time)
{
    MMI_LOGD("enter");
    CHKPR(ev.event, ERROR_NULL_POINTER);
    CHKPR(udsServer_, ERROR_NULL_POINTER);
    EventKeyboard key = {};
    auto packageResult = eventPackage_.PackageJoyStickKeyEvent(ev.event, key);
    if (packageResult != RET_OK) {
        MMI_LOGE("Joystickkey event package failed. ret:%{public}d,errCode:%{public}d",
                 packageResult, JOYSTICK_KEY_EVENT_PKG_FAIL);
        return JOYSTICK_KEY_EVENT_PKG_FAIL;
    }
    // libinput key transformed into HOS key
    auto oKey = KeyValueTransformationByInput(key.key);
    key.unicode = 0;
#ifdef OHOS_WESTEN_MODEL
    // Judging whether key is system key.
    if (oKey.isSystemKey && OnSystemEvent(oKey, key.state)) {
        return RET_OK;
    }
#endif
    auto eventDispatchResult = eventDispatch_.DispatchKeyEvent(*udsServer_, ev.event, oKey, key, time);
    if (eventDispatchResult != RET_OK) {
        MMI_LOGE("JoyStick event dispatch failed. ret:%{public}d,errCode:%{public}d",
                 eventDispatchResult, JOYSTICK_EVENT_DISP_FAIL);
        return JOYSTICK_EVENT_DISP_FAIL;
    }
    MMI_LOGD("leave");
    return RET_OK;
}

int32_t InputEventHandler::OnEventJoyStickAxis(const multimodal_libinput_event& ev, const uint64_t time)
{
    MMI_LOGD("enter");
    CHKPR(ev.event, ERROR_NULL_POINTER);
    CHKPR(udsServer_, ERROR_NULL_POINTER);
    EventJoyStickAxis eventJoyStickAxis = {};
    auto packageResult = eventPackage_.PackageJoyStickAxisEvent(ev.event, eventJoyStickAxis);
    if (packageResult != RET_OK) {
        MMI_LOGE("Joystickaxis event package failed. ret:%{public}d,errCode:%{public}d",
                 packageResult, JOYSTICK_AXIS_EVENT_PKG_FAIL);
        return JOYSTICK_AXIS_EVENT_PKG_FAIL;
    }
    auto ret = eventDispatch_.DispatchJoyStickEvent(*udsServer_, ev.event, eventJoyStickAxis, time);
    if (ret != RET_OK) {
        MMI_LOGE("Joystick event dispatch failed. ret:%{public}d,errCode:%{public}d", ret, JOYSTICK_EVENT_DISP_FAIL);
        return JOYSTICK_EVENT_DISP_FAIL;
    }
    MMI_LOGD("leave");
    return RET_OK;
}

int32_t InputEventHandler::OnMouseEventHandler(libinput_event *event)
{
    MMI_LOGD("enter");
    CHKPR(event, ERROR_NULL_POINTER);
    MMI_LOGD("Libinput Events reported");

    // 更新 全局 鼠标事件 数据
    MouseEventHdr->Normalize(event);

    auto pointerEvent = MouseEventHdr->GetPointerEvent();
    if (pointerEvent == nullptr) {
        MMI_LOGE("MouseEvent is NULL");
        return RET_ERR;
    }

    // 处理 按键 + 鼠标
    if (keyEvent_ == nullptr) {
        keyEvent_ = KeyEvent::Create();
    }
    if (keyEvent_ != nullptr) {
        std::vector<int32_t> pressedKeys = keyEvent_->GetPressedKeys();
        if (pressedKeys.empty()) {
            MMI_LOGI("Pressed keys is empty");
        } else {
            for (int32_t keyCode : pressedKeys) {
                MMI_LOGI("Pressed keyCode:%{public}d", keyCode);
            }
        }
        pointerEvent->SetPressedKeys(pressedKeys);
    }
    int32_t pointerId = keyEvent_->GetId();
    std::string pointerEventstring = "OnEventPointer";
    StartAsyncTrace(BYTRACE_TAG_MULTIMODALINPUT, pointerEventstring, pointerId);
    // 派发
    eventDispatch_.HandlePointerEvent(pointerEvent);
    FinishAsyncTrace(BYTRACE_TAG_MULTIMODALINPUT, pointerEventstring, pointerId);
    // 返回值 代表是 鼠标事件有没有处理过， 不关心成功与失败
    MMI_LOGD("leave");
    return RET_OK;
}

int32_t InputEventHandler::OnMouseEventEndTimerHandler(std::shared_ptr<PointerEvent> pointerEvent)
{
    MMI_LOGD("enter");
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    // Mouse Axis Data
    MMI_LOGI("MouseEvent Normalization Results, PointerAction:%{public}d,PointerId:%{public}d,"
             "SourceType:%{public}d,ButtonId:%{public}d,"
             "VerticalAxisValue:%{public}lf,HorizontalAxisValue:%{public}lf",
             pointerEvent->GetPointerAction(), pointerEvent->GetPointerId(), pointerEvent->GetSourceType(),
             pointerEvent->GetButtonId(), pointerEvent->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL),
             pointerEvent->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL));
    PointerEvent::PointerItem item;
    CHKR(pointerEvent->GetPointerItem(pointerEvent->GetPointerId(), item), PARAM_INPUT_FAIL, RET_ERR);
    MMI_LOGI("MouseEvent Item Normalization Results, DownTime:%{public}d,IsPressed:%{public}d,"
             "GlobalX:%{public}d,GlobalY:%{public}d,LocalX:%{public}d,LocalY:%{public}d,"
             "Width:%{public}d,Height:%{public}d,Pressure:%{public}d,DeviceId:%{public}d",
             item.GetDownTime(), static_cast<int32_t>(item.IsPressed()), item.GetGlobalX(), item.GetGlobalY(),
             item.GetLocalX(), item.GetLocalY(), item.GetWidth(), item.GetHeight(), item.GetPressure(),
             item.GetDeviceId());

    eventDispatch_.HandlePointerEvent(pointerEvent);
    MMI_LOGD("leave");
    return RET_OK;
}

bool InputEventHandler::SendMsg(const int32_t fd, NetPacket& pkt) const
{
    MMI_LOGD("enter");
    CHKPF(udsServer_, OHOS::ERROR_NULL_POINTER);
    MMI_LOGD("leave");
    return udsServer_->SendMsg(fd, pkt);
}
#ifdef OHOS_WESTEN_MODEL
bool InputEventHandler::OnSystemEvent(const KeyEventValueTransformations& temp,
    const enum KEY_STATE state) const
{
    MMI_LOGD("enter");
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
    MMI_LOGD("leave");
    return retCode;
}
#endif
} // namespace MMI
} // namespace OHOS
