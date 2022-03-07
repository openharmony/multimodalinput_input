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

#include "input_event_handler.h"
#include <cstdio>
#include <cstring>
#include <functional>
#include <vector>
#include <cinttypes>
#include <sys/stat.h>
#include <unistd.h>
#include "bytrace.h"
#include "input_device_manager.h"
#include "interceptor_manager_global.h"
#include "libinput.h"
#include "mmi_func_callback.h"
#include "mouse_event_handler.h"
#include "s_input.h"
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

InputEventHandler::~InputEventHandler() {}

void InputEventHandler::Init(UDSServer& udsServer)
{
    udsServer_ = &udsServer;
    MsgCallback funs[] = {
        {
            static_cast<MmiMessageId>(LIBINPUT_EVENT_DEVICE_ADDED),
            MsgCallbackBind1(&InputEventHandler::OnEventDeviceAdded, this)
        },
        {
            static_cast<MmiMessageId>(LIBINPUT_EVENT_DEVICE_REMOVED),
            MsgCallbackBind1(&InputEventHandler::OnEventDeviceRemoved, this)
        },
        {
            static_cast<MmiMessageId>(LIBINPUT_EVENT_KEYBOARD_KEY),
            std::bind(&InputEventHandler::OnKeyboardEvent, this, std::placeholders::_1)
        },
        {
            static_cast<MmiMessageId>(LIBINPUT_EVENT_POINTER_MOTION),
            MsgCallbackBind1(&InputEventHandler::OnEventPointer, this)
        },
        {
            static_cast<MmiMessageId>(LIBINPUT_EVENT_POINTER_MOTION_ABSOLUTE),
            MsgCallbackBind1(&InputEventHandler::OnEventPointer, this)
        },
        {
            static_cast<MmiMessageId>(LIBINPUT_EVENT_POINTER_BUTTON),
            MsgCallbackBind1(&InputEventHandler::OnEventPointer, this)
        },
        {
            static_cast<MmiMessageId>(LIBINPUT_EVENT_POINTER_AXIS),
            MsgCallbackBind1(&InputEventHandler::OnEventPointer, this)
        },
        {
            static_cast<MmiMessageId>(LIBINPUT_EVENT_TOUCH_DOWN),
            MsgCallbackBind1(&InputEventHandler::OnEventTouch, this)
        },
        {
            static_cast<MmiMessageId>(LIBINPUT_EVENT_TOUCH_UP),
            MsgCallbackBind1(&InputEventHandler::OnEventTouch, this)
        },
        {
            static_cast<MmiMessageId>(LIBINPUT_EVENT_TOUCH_MOTION),
            MsgCallbackBind1(&InputEventHandler::OnEventTouch, this)
        },
        {
            static_cast<MmiMessageId>(LIBINPUT_EVENT_TOUCH_CANCEL),
            MsgCallbackBind1(&InputEventHandler::OnEventTouch, this)
        },
        {
            static_cast<MmiMessageId>(LIBINPUT_EVENT_TOUCH_FRAME),
            MsgCallbackBind1(&InputEventHandler::OnEventTouch, this)
        },
        {
            static_cast<MmiMessageId>(LIBINPUT_EVENT_TOUCHPAD_DOWN),
            MsgCallbackBind1(&InputEventHandler::OnEventTouchpad, this)
        },
        {
            static_cast<MmiMessageId>(LIBINPUT_EVENT_TOUCHPAD_UP),
            MsgCallbackBind1(&InputEventHandler::OnEventTouchpad, this)
        },
        {
            static_cast<MmiMessageId>(LIBINPUT_EVENT_TOUCHPAD_MOTION),
            MsgCallbackBind1(&InputEventHandler::OnEventTouchpad, this)
        },
        {
            static_cast<MmiMessageId>(LIBINPUT_EVENT_GESTURE_SWIPE_BEGIN),
            MsgCallbackBind1(&InputEventHandler::OnEventGesture, this)
        },
        {
            static_cast<MmiMessageId>(LIBINPUT_EVENT_GESTURE_SWIPE_UPDATE),
            MsgCallbackBind1(&InputEventHandler::OnEventGesture, this)
        },
        {
            static_cast<MmiMessageId>(LIBINPUT_EVENT_GESTURE_SWIPE_END),
            MsgCallbackBind1(&InputEventHandler::OnEventGesture, this)
        },
        {
            static_cast<MmiMessageId>(LIBINPUT_EVENT_GESTURE_PINCH_BEGIN),
            MsgCallbackBind1(&InputEventHandler::OnEventGesture, this)
        },
        {
            static_cast<MmiMessageId>(LIBINPUT_EVENT_GESTURE_PINCH_UPDATE),
            MsgCallbackBind1(&InputEventHandler::OnEventGesture, this)
        },
        {
            static_cast<MmiMessageId>(LIBINPUT_EVENT_GESTURE_PINCH_END),
            MsgCallbackBind1(&InputEventHandler::OnEventGesture, this)
        },
    };
    for (auto &item : funs) {
        if (!RegistrationEvent(item)) {
            MMI_LOGW("Failed to register event errCode:%{public}d", EVENT_REG_FAIL);
            continue;
        }
    }
    return;
}

void InputEventHandler::OnEvent(void *event)
{
    CHKPV(event);
    std::lock_guard<std::mutex> lock(mu_);
    auto *lpEvent = static_cast<libinput_event *>(event);
    CHKPV(lpEvent);
    if (initSysClock_ != 0 && lastSysClock_ == 0) {
        MMI_LOGE("Event not handled. id:%{public}" PRId64 ",eventType:%{public}d,initSysClock:%{public}" PRId64,
                 idSeed_, eventType_, initSysClock_);
    }

    eventType_ = libinput_event_get_type(lpEvent);
    auto tid = GetThisThreadIdOfLL();
    initSysClock_ = GetSysClockTime();
    lastSysClock_ = 0;
    idSeed_ += 1;
    const uint64_t maxUInt64 = (std::numeric_limits<uint64_t>::max)() - 1;
    if (idSeed_ >= maxUInt64) {
        MMI_LOGE("Invaild value. id:%{public}" PRId64, idSeed_);
        idSeed_ = 1;
        return;
    }

    MMI_LOGD("Event reporting. id:%{public}" PRId64 ",tid:%{public}" PRId64 ",eventType:%{public}d,"
             "initSysClock:%{public}" PRId64, idSeed_, tid, eventType_, initSysClock_);

    OnEventHandler(lpEvent);
    lastSysClock_ = GetSysClockTime();
    int64_t lostTime = lastSysClock_ - initSysClock_;
    MMI_LOGD("Event handling completed. id:%{public}" PRId64 ",lastSynClock:%{public}" PRId64
             ",lostTime:%{public}" PRId64, idSeed_, lastSysClock_, lostTime);
}

int32_t InputEventHandler::OnEventHandler(libinput_event *event)
{
    CHKPR(event, ERROR_NULL_POINTER);
    auto type = libinput_event_get_type(event);
    TimeCostChk chk("InputEventHandler::OnEventHandler", "overtime 1000(us)", MAX_INPUT_EVENT_TIME, type);
    auto callback = GetMsgCallback(static_cast<MmiMessageId>(type));
    if (callback == nullptr) {
        MMI_LOGE("Unknown event type:%{public}d,errCode:%{public}d", type, UNKNOWN_EVENT);
        return UNKNOWN_EVENT;
    }
    auto ret = (*callback)(event);
    if (ret != 0) {
        MMI_LOGE("Event handling failed. type:%{public}d,ret:%{public}d,errCode:%{public}d",
                 type, ret, EVENT_CONSUM_FAIL);
        return ret;
    }
    return ret;
}

void InputEventHandler::OnCheckEventReport()
{
    std::lock_guard<std::mutex> lock(mu_);
    if (initSysClock_ == 0 || lastSysClock_ != 0) {
        return;
    }
    constexpr int64_t MAX_DID_TIME = 1000 * 1000 * 3;
    auto curSysClock = GetSysClockTime();
    auto lostTime = curSysClock - initSysClock_;
    if (lostTime < MAX_DID_TIME) {
        return;
    }
    MMI_LOGE("Event not responding. id:%{public}" PRId64 ",eventType:%{public}d,initSysClock:%{public}" PRId64 ","
             "lostTime:%{public}" PRId64, idSeed_, eventType_, initSysClock_, lostTime);
}

UDSServer* InputEventHandler::GetUDSServer()
{
    return udsServer_;
}

int32_t InputEventHandler::AddInputEventFilter(sptr<IEventFilter> filter)
{
    return eventDispatch_.AddInputEventFilter(filter);
}

int32_t InputEventHandler::OnEventDeviceAdded(libinput_event *event)
{
    CHKPR(event, ERROR_NULL_POINTER);
    auto device = libinput_event_get_device(event);
    InputDevMgr->OnInputDeviceAdded(device);
    return RET_OK;
}
int32_t InputEventHandler::OnEventDeviceRemoved(libinput_event *event)
{
    CHKPR(event, ERROR_NULL_POINTER);
    auto device = libinput_event_get_device(event);
    InputDevMgr->OnInputDeviceRemoved(device);
    return RET_OK;
}

int32_t InputEventHandler::OnEventKey(libinput_event *event)
{
    CHKPR(event, PARAM_INPUT_INVALID);
    CHKPR(udsServer_, ERROR_NULL_POINTER);
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

    auto ret = eventDispatch_.DispatchKeyEventPid(*udsServer_, keyEvent_);
    if (ret != RET_OK) {
        MMI_LOGE("KeyEvent dispatch failed. ret:%{public}d,errCode:%{public}d",
                 ret, KEY_EVENT_DISP_FAIL);
        return KEY_EVENT_DISP_FAIL;
    }
    int32_t keyCode = keyEvent_->GetKeyCode();
    std::string keyEventString = "service dispatch keyCode=" + std::to_string(keyCode);
    BYTRACE_NAME(BYTRACE_TAG_MULTIMODALINPUT, keyEventString);
    int32_t keyId = keyEvent_->GetId();
    keyEventString = "OnKeyEvent";
    FinishAsyncTrace(BYTRACE_TAG_MULTIMODALINPUT, keyEventString, keyId);
    MMI_LOGD("Inject keyCode=%{public}d, action=%{public}d", keyEvent_->GetKeyCode(), keyEvent_->GetKeyAction());
    return RET_OK;
}

int32_t InputEventHandler::OnKeyEventDispatch(libinput_event *event)
{
    if (keyEvent_ == nullptr) {
        keyEvent_ = KeyEvent::Create();
    }
    CHKPR(udsServer_, ERROR_NULL_POINTER);
    auto packageResult = eventPackage_.PackageKeyEvent(event, keyEvent_);
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
    return OnEventKey(event);
}

int32_t InputEventHandler::OnKeyboardEvent(libinput_event *event)
{
    CHKPR(event, ERROR_NULL_POINTER);
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

    auto oKey = KeyValueTransformationInput(keyBoard.key); // libinput key transformed into key
    keyBoard.unicode = 0;
    if (keyEvent_ == nullptr) {
        keyEvent_ = KeyEvent::Create();
    }
    keyBoard.key = static_cast<uint32_t>(oKey.keyValueOfSys);
    if (EventPackage::KeyboardToKeyEvent(keyBoard, keyEvent_) == RET_ERR) {
        MMI_LOGE("On the OnKeyboardEvent translate key event error");
        return RET_ERR;
    }
    int32_t keyId = keyEvent_->GetId();
    std::string keyEventString = "OnKeyEvent";
    StartAsyncTrace(BYTRACE_TAG_MULTIMODALINPUT, keyEventString, keyId);
    keyEventString = "service report keyId=" + std::to_string(keyId);
    BYTRACE_NAME(BYTRACE_TAG_MULTIMODALINPUT, keyEventString);
    auto result = eventDispatch_.DispatchKeyEventPid(*udsServer_, keyEvent_);
    if (result != RET_OK) {
        MMI_LOGE("Key event dispatch failed. ret:%{public}d,errCode:%{public}d", result, KEY_EVENT_DISP_FAIL);
        return KEY_EVENT_DISP_FAIL;
    }
    return RET_OK;
}

int32_t InputEventHandler::OnEventPointer(libinput_event *event)
{
    CHKPR(event, ERROR_NULL_POINTER);
    return OnMouseEventHandler(event);
}

int32_t InputEventHandler::OnEventTouchSecond(libinput_event *event)
{
    MMI_LOGD("Enter");
    CHKPR(event, ERROR_NULL_POINTER);
    auto type = libinput_event_get_type(event);
    if (type == LIBINPUT_EVENT_TOUCH_CANCEL || type == LIBINPUT_EVENT_TOUCH_FRAME) {
        MMI_LOGD("This touch event is canceled type:%{public}d", type);
        return RET_OK;
    }
    auto pointerEvent = TouchTransformPointManger->OnLibInput(event, INPUT_DEVICE_CAP_TOUCH);
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    int32_t pointerId = pointerEvent->GetId();
    std::string touchEvent = "OnEventTouch";
    StartAsyncTrace(BYTRACE_TAG_MULTIMODALINPUT, touchEvent, pointerId);
    eventDispatch_.HandlePointerEvent(pointerEvent);
    if (type == LIBINPUT_EVENT_TOUCH_UP) {
        pointerEvent->RemovePointerItem(pointerEvent->GetPointerId());
        MMI_LOGD("This touch event is up remove this finger");
        if (pointerEvent->GetPointersIdList().empty()) {
            MMI_LOGD("This touch event is final finger up remove this finger");
            pointerEvent->Reset();
        }
        return RET_OK;
    }
    MMI_LOGD("Leave");
    return RET_OK;
}

int32_t InputEventHandler::OnEventTouchPadSecond(libinput_event *event)
{
    MMI_LOGD("Enter");
    CHKPR(event, ERROR_NULL_POINTER);

    auto pointerEvent = TouchTransformPointManger->OnLibInput(event, INPUT_DEVICE_CAP_TOUCH_PAD);
    CHKPR(pointerEvent, RET_ERR);
    eventDispatch_.HandlePointerEvent(pointerEvent);
    auto type = libinput_event_get_type(event);
    if (type == LIBINPUT_EVENT_TOUCHPAD_UP) {
        pointerEvent->RemovePointerItem(pointerEvent->GetPointerId());
        MMI_LOGD("This touch pad event is up remove this finger");
        if (pointerEvent->GetPointersIdList().empty()) {
            MMI_LOGD("This touch pad event is final finger up remove this finger");
            pointerEvent->Reset();
        }
        return RET_OK;
    }
    MMI_LOGD("Leave");
    return RET_OK;
}

int32_t InputEventHandler::OnEventTouch(libinput_event *event)
{
    CHKPR(event, ERROR_NULL_POINTER);
    SInput::LoginfoPackagingTool(event);
    return OnEventTouchSecond(event);
}

int32_t InputEventHandler::OnEventTouchpad(libinput_event *event)
{
    OnEventTouchPadSecond(event);
    return RET_OK;
}

int32_t InputEventHandler::OnGestureEvent(libinput_event *event)
{
    CHKPR(event, ERROR_NULL_POINTER);
    auto pointerEvent = TouchTransformPointManger->OnLibInput(event, INPUT_DEVICE_CAP_GESTURE);
    CHKPR(pointerEvent, GESTURE_EVENT_PKG_FAIL);
    MMI_LOGD("GestrueEvent package, eventType:%{public}d,actionTime:%{public}" PRId64 ","
             "action:%{public}d,actionStartTime:%{public}" PRId64 ","
             "pointerAction:%{public}d,sourceType:%{public}d,"
             "PinchAxisValue:%{public}.2f",
             pointerEvent->GetEventType(), pointerEvent->GetActionTime(),
             pointerEvent->GetAction(), pointerEvent->GetActionStartTime(),
             pointerEvent->GetPointerAction(), pointerEvent->GetSourceType(),
             pointerEvent->GetAxisValue(PointerEvent::AXIS_TYPE_PINCH));

    PointerEvent::PointerItem item;
    pointerEvent->GetPointerItem(pointerEvent->GetPointerId(), item);
    MMI_LOGD("Item:DownTime:%{public}" PRId64 ",IsPressed:%{public}s,"
             "GlobalX:%{public}d,GlobalY:%{public}d,LocalX:%{public}d,LocalY:%{public}d,"
             "Width:%{public}d,Height:%{public}d",
             item.GetDownTime(), (item.IsPressed() ? "true" : "false"),
             item.GetGlobalX(), item.GetGlobalY(), item.GetLocalX(), item.GetLocalY(),
             item.GetWidth(), item.GetHeight());

    int32_t ret = eventDispatch_.HandlePointerEvent(pointerEvent);
    if (ret != RET_OK) {
        MMI_LOGE("Gesture event dispatch failed, errCode:%{public}d", GESTURE_EVENT_DISP_FAIL);
        return GESTURE_EVENT_DISP_FAIL;
    }
    return RET_OK;
}

int32_t InputEventHandler::OnEventGesture(libinput_event *event)
{
    CHKPR(event, ERROR_NULL_POINTER);
    OnGestureEvent(event);
    return RET_OK;
}

int32_t InputEventHandler::OnMouseEventHandler(libinput_event *event)
{
    CHKPR(event, ERROR_NULL_POINTER);

    // 更新 全局 鼠标事件 数据
    MouseEventHdr->Normalize(event);

    auto pointerEvent = MouseEventHdr->GetPointerEvent();
    CHKPR(pointerEvent, ERROR_NULL_POINTER);

    // 处理 按键 + 鼠标
    if (keyEvent_ == nullptr) {
        keyEvent_ = KeyEvent::Create();
    }
    CHKPR(keyEvent_, ERROR_NULL_POINTER);
    std::vector<int32_t> pressedKeys = keyEvent_->GetPressedKeys();
    for (const int32_t& keyCode : pressedKeys) {
        MMI_LOGI("Pressed keyCode:%{public}d", keyCode);
    }
    pointerEvent->SetPressedKeys(pressedKeys);
    int32_t pointerId = keyEvent_->GetId();
    const std::string pointerEventstring = "OnEventPointer";
    StartAsyncTrace(BYTRACE_TAG_MULTIMODALINPUT, pointerEventstring, pointerId);
    // 派发
    eventDispatch_.HandlePointerEvent(pointerEvent);
    // 返回值 代表是 鼠标事件有没有处理过， 不关心成功与失败
    return RET_OK;
}

int32_t InputEventHandler::OnMouseEventEndTimerHandler(std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    // Mouse Axis Data
    MMI_LOGI("MouseEvent Normalization Results, PointerAction:%{public}d,PointerId:%{public}d,"
             "SourceType:%{public}d,ButtonId:%{public}d,"
             "VerticalAxisValue:%{public}lf,HorizontalAxisValue:%{public}lf",
             pointerEvent->GetPointerAction(), pointerEvent->GetPointerId(), pointerEvent->GetSourceType(),
             pointerEvent->GetButtonId(), pointerEvent->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL),
             pointerEvent->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL));
    PointerEvent::PointerItem item;
    if (!pointerEvent->GetPointerItem(pointerEvent->GetPointerId(), item)) {
        MMI_LOGE("Get pointer item failed. pointer:%{public}d", pointerEvent->GetPointerId());
        return RET_ERR;
    }
    MMI_LOGI("MouseEvent Item Normalization Results, DownTime:%{public}" PRId64 ",IsPressed:%{public}d,"
             "GlobalX:%{public}d,GlobalY:%{public}d,LocalX:%{public}d,LocalY:%{public}d,"
             "Width:%{public}d,Height:%{public}d,Pressure:%{public}d,Device:%{public}d",
             item.GetDownTime(), static_cast<int32_t>(item.IsPressed()), item.GetGlobalX(), item.GetGlobalY(),
             item.GetLocalX(), item.GetLocalY(), item.GetWidth(), item.GetHeight(), item.GetPressure(),
             item.GetDeviceId());

    eventDispatch_.HandlePointerEvent(pointerEvent);
    return RET_OK;
}

bool InputEventHandler::SendMsg(const int32_t fd, NetPacket& pkt) const
{
    CHKPF(udsServer_);
    return udsServer_->SendMsg(fd, pkt);
}
} // namespace MMI
} // namespace OHOS
