/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "event_normalize_handler.h"

#include "dfx_hisysevent.h"
#include "bytrace_adapter.h"
#include "define_multimodal.h"
#include "error_multimodal.h"
#include "event_log_helper.h"
#ifdef OHOS_BUILD_ENABLE_COOPERATE
#include "input_device_cooperate_sm.h"
#include "input_device_cooperate_util.h"
#endif // OHOS_BUILD_ENABLE_COOPERATE
#include "input_device_manager.h"
#include "input_event_handler.h"
#include "key_auto_repeat.h"
#include "key_event_normalize.h"
#include "key_event_value_transformation.h"
#include "libinput_adapter.h"
#include "mmi_log.h"
#include "time_cost_chk.h"
#include "timer_manager.h"
#include "touch_event_normalize.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "EventNormalizeHandler" };
}

void EventNormalizeHandler::HandleEvent(libinput_event* event)
{
    CALL_DEBUG_ENTER;
    CHKPV(event);
    DfxHisysevent::GetDispStartTime();
    auto type = libinput_event_get_type(event);
    TimeCostChk chk("HandleLibinputEvent", "overtime 1000(us)", MAX_INPUT_EVENT_TIME, type);
    if (type == LIBINPUT_EVENT_TOUCH_CANCEL || type == LIBINPUT_EVENT_TOUCH_FRAME) {
        MMI_HILOGD("This touch event is canceled type:%{public}d", type);
        return;
    }
    switch (type) {
        case LIBINPUT_EVENT_DEVICE_ADDED: {
            OnEventDeviceAdded(event);
            break;
        }
        case LIBINPUT_EVENT_DEVICE_REMOVED: {
            OnEventDeviceRemoved(event);
            break;
        }
        case LIBINPUT_EVENT_KEYBOARD_KEY: {
            HandleKeyboardEvent(event);
            DfxHisysevent::CalcKeyDispTimes();
            break;
        }
        case LIBINPUT_EVENT_POINTER_MOTION:
        case LIBINPUT_EVENT_POINTER_MOTION_ABSOLUTE:
        case LIBINPUT_EVENT_POINTER_BUTTON:
        case LIBINPUT_EVENT_POINTER_AXIS: {
            HandleMouseEvent(event);
            DfxHisysevent::CalcPointerDispTimes();
            break;
        }
        case LIBINPUT_EVENT_TOUCHPAD_DOWN:
        case LIBINPUT_EVENT_TOUCHPAD_UP:
        case LIBINPUT_EVENT_TOUCHPAD_MOTION: {
            HandleTouchPadEvent(event);
            DfxHisysevent::CalcPointerDispTimes();
            break;
        }
        case LIBINPUT_EVENT_GESTURE_SWIPE_BEGIN:
        case LIBINPUT_EVENT_GESTURE_SWIPE_UPDATE:
        case LIBINPUT_EVENT_GESTURE_SWIPE_END:
        case LIBINPUT_EVENT_GESTURE_PINCH_BEGIN:
        case LIBINPUT_EVENT_GESTURE_PINCH_UPDATE:
        case LIBINPUT_EVENT_GESTURE_PINCH_END: {
            HandleGestureEvent(event);
            DfxHisysevent::CalcPointerDispTimes();
            break;
        }
        case LIBINPUT_EVENT_TOUCH_DOWN:
        case LIBINPUT_EVENT_TOUCH_UP:
        case LIBINPUT_EVENT_TOUCH_MOTION: {
            HandleTouchEvent(event);
            DfxHisysevent::CalcPointerDispTimes();
            break;
        }
        case LIBINPUT_EVENT_TABLET_TOOL_AXIS:
        case LIBINPUT_EVENT_TABLET_TOOL_PROXIMITY:
        case LIBINPUT_EVENT_TABLET_TOOL_TIP: {
            HandleTableToolEvent(event);
            break;
        }
        default: {
            MMI_HILOGW("This device does not support");
            break;
        }
    }
    DfxHisysevent::ReportDispTimes();
}

int32_t EventNormalizeHandler::OnEventDeviceAdded(libinput_event *event)
{
    CHKPR(event, ERROR_NULL_POINTER);
    auto device = libinput_event_get_device(event);
    CHKPR(device, ERROR_NULL_POINTER);
    InputDevMgr->OnInputDeviceAdded(device);
    KeyMapMgr->ParseDeviceConfigFile(device);
    KeyRepeat->AddDeviceConfig(device);
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    KeyEventHdr->ResetKeyEvent(device);
#endif // OHOS_BUILD_ENABLE_KEYBOARD
    return RET_OK;
}

int32_t EventNormalizeHandler::OnEventDeviceRemoved(libinput_event *event)
{
    CHKPR(event, ERROR_NULL_POINTER);
    auto device = libinput_event_get_device(event);
    CHKPR(device, ERROR_NULL_POINTER);
    KeyMapMgr->RemoveKeyValue(device);
    KeyRepeat->RemoveDeviceConfig(device);
    InputDevMgr->OnInputDeviceRemoved(device);
    return RET_OK;
}

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
void EventNormalizeHandler::HandleKeyEvent(const std::shared_ptr<KeyEvent> keyEvent)
{
    if (nextHandler_ == nullptr) {
        MMI_HILOGW("Keyboard device does not support");
        return;
    }
    DfxHisysevent::GetDispStartTime();
    CHKPV(keyEvent);
    EventLogHelper::PrintEventData(keyEvent);
#ifdef OHOS_BUILD_ENABLE_COOPERATE
    if (!CheckKeyboardWhiteList(keyEvent)) {
        MMI_HILOGI("Check white list return false, keyboard event dropped");
        return;
    }
#endif // OHOS_BUILD_ENABLE_COOPERATE
    nextHandler_->HandleKeyEvent(keyEvent);
    DfxHisysevent::CalcKeyDispTimes();
    DfxHisysevent::ReportDispTimes();
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

#ifdef OHOS_BUILD_ENABLE_POINTER
void EventNormalizeHandler::HandlePointerEvent(const std::shared_ptr<PointerEvent> pointerEvent)
{
    if (nextHandler_ == nullptr) {
        MMI_HILOGW("Pointer device does not support");
        return;
    }
    DfxHisysevent::GetDispStartTime();
    CHKPV(pointerEvent);
    if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_AXIS_END) {
        MMI_HILOGI("MouseEvent Normalization Results, PointerAction:%{public}d,PointerId:%{public}d,"
            "SourceType:%{public}d,ButtonId:%{public}d,"
            "VerticalAxisValue:%{public}lf,HorizontalAxisValue:%{public}lf",
            pointerEvent->GetPointerAction(), pointerEvent->GetPointerId(), pointerEvent->GetSourceType(),
            pointerEvent->GetButtonId(), pointerEvent->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL),
            pointerEvent->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL));
        PointerEvent::PointerItem item;
        if (!pointerEvent->GetPointerItem(pointerEvent->GetPointerId(), item)) {
            MMI_HILOGE("Get pointer item failed. pointer:%{public}d", pointerEvent->GetPointerId());
            return;
        }
        MMI_HILOGI("MouseEvent Item Normalization Results, DownTime:%{public}" PRId64 ",IsPressed:%{public}d,"
            "DisplayX:%{public}d,DisplayY:%{public}d,WindowX:%{public}d,WindowY:%{public}d,"
            "Width:%{public}d,Height:%{public}d,Pressure:%{public}f,Device:%{public}d",
            item.GetDownTime(), static_cast<int32_t>(item.IsPressed()), item.GetDisplayX(), item.GetDisplayY(),
            item.GetWindowX(), item.GetWindowY(), item.GetWidth(), item.GetHeight(), item.GetPressure(),
            item.GetDeviceId());
    }
    WinMgr->UpdateTargetPointer(pointerEvent);
    nextHandler_->HandlePointerEvent(pointerEvent);
    DfxHisysevent::CalcPointerDispTimes();
    DfxHisysevent::ReportDispTimes();
}
#endif // OHOS_BUILD_ENABLE_POINTER

#ifdef OHOS_BUILD_ENABLE_TOUCH
void EventNormalizeHandler::HandleTouchEvent(const std::shared_ptr<PointerEvent> pointerEvent)
{
    if (nextHandler_ == nullptr) {
        MMI_HILOGW("Touchscreen device does not support");
        return;
    }
    DfxHisysevent::GetDispStartTime();
    CHKPV(pointerEvent);
    WinMgr->UpdateTargetPointer(pointerEvent);
    nextHandler_->HandleTouchEvent(pointerEvent);
    DfxHisysevent::CalcPointerDispTimes();
    DfxHisysevent::ReportDispTimes();
}
#endif // OHOS_BUILD_ENABLE_TOUCH

int32_t EventNormalizeHandler::HandleKeyboardEvent(libinput_event* event)
{
    if (nextHandler_ == nullptr) {
        MMI_HILOGW("Keyboard device does not support");
        return ERROR_UNSUPPORT;
    }
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    auto keyEvent = KeyEventHdr->GetKeyEvent();
    CHKPR(keyEvent, ERROR_NULL_POINTER);
    CHKPR(event, ERROR_NULL_POINTER);
    std::vector<int32_t> pressedKeys = keyEvent->GetPressedKeys();
    int32_t lastPressedKey = -1;
    if (!pressedKeys.empty()) {
        lastPressedKey = pressedKeys.back();
        MMI_HILOGD("The last repeat button, keyCode:%{public}d", lastPressedKey);
    }
    auto packageResult = KeyEventHdr->Normalize(event, keyEvent);
    if (packageResult == MULTIDEVICE_SAME_EVENT_MARK) {
        MMI_HILOGD("The same event reported by multi_device should be discarded");
        return RET_OK;
    }
    if (packageResult != RET_OK) {
        MMI_HILOGE("KeyEvent package failed, ret:%{public}d,errCode:%{public}d", packageResult, KEY_EVENT_PKG_FAIL);
        return KEY_EVENT_PKG_FAIL;
    }

    BytraceAdapter::StartBytrace(keyEvent);
    EventLogHelper::PrintEventData(keyEvent);
#ifdef OHOS_BUILD_ENABLE_COOPERATE
    if (!CheckKeyboardWhiteList(keyEvent)) {
        MMI_HILOGI("Check white list return false, keyboard event dropped");
        return RET_OK;
    }
#endif // OHOS_BUILD_ENABLE_COOPERATE
    nextHandler_->HandleKeyEvent(keyEvent);
    KeyRepeat->SelectAutoRepeat(keyEvent);
    MMI_HILOGD("keyCode:%{public}d, action:%{public}d", keyEvent->GetKeyCode(), keyEvent->GetKeyAction());
#else
    MMI_HILOGW("Keyboard device does not support");
#endif // OHOS_BUILD_ENABLE_KEYBOARD
    return RET_OK;
}

#ifdef OHOS_BUILD_ENABLE_COOPERATE
bool EventNormalizeHandler::CheckKeyboardWhiteList(std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPF(keyEvent);
    InputHandler->SetJumpInterceptState(false);
    int32_t keyCode = keyEvent->GetKeyCode();
    if (keyCode == KeyEvent::KEYCODE_BACK || keyCode == KeyEvent::KEYCODE_VOLUME_UP
        || keyCode == KeyEvent::KEYCODE_VOLUME_DOWN || keyCode == KeyEvent::KEYCODE_POWER) {
        return true;
    }
    CooperateState state = InputDevCooSM->GetCurrentCooperateState();
    MMI_HILOGI("Get current cooperate state:%{public}d", state);
    if (state == CooperateState::STATE_IN) {
        int32_t deviceId = keyEvent->GetDeviceId();
        if (InputDevMgr->IsRemote(deviceId)) {
            auto networkId = InputDevMgr->GetOriginNetworkId(deviceId);
            return !IsNeedFilterOut(networkId, keyEvent);
        }
    } else if (state == CooperateState::STATE_OUT) {
        std::string networkId = GetLocalDeviceId();
        if (!IsNeedFilterOut(networkId, keyEvent)) {
            if (keyEvent->GetKeyAction() == KeyEvent::KEY_ACTION_UP) {
                KeyRepeat->SelectAutoRepeat(keyEvent);
            }
            return false;
        }
        InputHandler->SetJumpInterceptState(true);
    } else {
        MMI_HILOGW("Get current cooperate state:STATE_FREE(%{public}d)", state);
    }
    return true;
}
#endif // OHOS_BUILD_ENABLE_COOPERATE

#ifdef OHOS_BUILD_ENABLE_COOPERATE
bool EventNormalizeHandler::IsNeedFilterOut(const std::string& deviceId, const std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    std::vector<OHOS::MMI::KeyEvent::KeyItem> KeyItems = keyEvent->GetKeyItems();
    std::vector<int32_t> KeyItemsForDInput;
    KeyItemsForDInput.reserve(KeyItems.size());
    for (const auto& item : KeyItems) {
        KeyItemsForDInput.push_back(item.GetKeyCode());
    }
    OHOS::DistributedHardware::DistributedInput::BusinessEvent businessEvent;
    businessEvent.keyCode = keyEvent->GetKeyCode();
    businessEvent.keyAction = keyEvent->GetKeyAction();
    businessEvent.pressedKeys = KeyItemsForDInput;
    MMI_HILOGI("businessEvent.keyCode :%{public}d, keyAction :%{public}d",
        businessEvent.keyCode, businessEvent.keyAction);
    for (const auto &item : businessEvent.pressedKeys) {
        MMI_HILOGI("pressedKeys :%{public}d", item);
    }
    return DistributedAdapter->IsNeedFilterOut(deviceId, businessEvent);
}
#endif // OHOS_BUILD_ENABLE_COOPERATE

int32_t EventNormalizeHandler::HandleMouseEvent(libinput_event* event)
{
    if (nextHandler_ == nullptr) {
        MMI_HILOGW("Pointer device does not support");
        return ERROR_UNSUPPORT;
    }
#ifdef OHOS_BUILD_ENABLE_POINTER
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    const auto &keyEvent = KeyEventHdr->GetKeyEvent();
    CHKPR(keyEvent, ERROR_NULL_POINTER);
#endif // OHOS_BUILD_ENABLE_KEYBOARD
    MouseEventHdr->Normalize(event);
    auto pointerEvent = MouseEventHdr->GetPointerEvent();
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    std::vector<int32_t> pressedKeys = keyEvent->GetPressedKeys();
    for (const int32_t& keyCode : pressedKeys) {
        MMI_HILOGI("Pressed keyCode:%{public}d", keyCode);
    }
    pointerEvent->SetPressedKeys(pressedKeys);
#endif // OHOS_BUILD_ENABLE_KEYBOARD
    BytraceAdapter::StartBytrace(pointerEvent, BytraceAdapter::TRACE_START);
    nextHandler_->HandlePointerEvent(pointerEvent);
#else
    MMI_HILOGW("Pointer device does not support");
#endif // OHOS_BUILD_ENABLE_POINTER
    return RET_OK;
}

int32_t EventNormalizeHandler::HandleTouchPadEvent(libinput_event* event)
{
    if (nextHandler_ == nullptr) {
        MMI_HILOGW("Pointer device does not support");
        return ERROR_UNSUPPORT;
    }
#ifdef OHOS_BUILD_ENABLE_POINTER
    CHKPR(event, ERROR_NULL_POINTER);
    auto pointerEvent = TouchEventHdr->OnLibInput(event, INPUT_DEVICE_CAP_TOUCH_PAD);
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    nextHandler_->HandlePointerEvent(pointerEvent);
    auto type = libinput_event_get_type(event);
    if (type == LIBINPUT_EVENT_TOUCHPAD_UP) {
        pointerEvent->RemovePointerItem(pointerEvent->GetPointerId());
        MMI_HILOGD("This touch pad event is up remove this finger");
        if (pointerEvent->GetPointerIds().empty()) {
            MMI_HILOGD("This touch pad event is final finger up remove this finger");
            pointerEvent->Reset();
        }
    }
#else
    MMI_HILOGW("Pointer device does not support");
#endif // OHOS_BUILD_ENABLE_POINTER
    return RET_OK;
}

int32_t EventNormalizeHandler::HandleGestureEvent(libinput_event* event)
{
    if (nextHandler_ == nullptr) {
        MMI_HILOGW("Pointer device does not support");
        return ERROR_UNSUPPORT;
    }
#ifdef OHOS_BUILD_ENABLE_POINTER
    CHKPR(event, ERROR_NULL_POINTER);
    auto pointerEvent = TouchEventHdr->OnLibInput(event, INPUT_DEVICE_CAP_GESTURE);
    CHKPR(pointerEvent, GESTURE_EVENT_PKG_FAIL);
    MMI_HILOGD("GestureEvent package, eventType:%{public}d,actionTime:%{public}" PRId64 ","
               "action:%{public}d,actionStartTime:%{public}" PRId64 ","
               "pointerAction:%{public}d,sourceType:%{public}d,"
               "PinchAxisValue:%{public}.2f",
                pointerEvent->GetEventType(), pointerEvent->GetActionTime(),
                pointerEvent->GetAction(), pointerEvent->GetActionStartTime(),
                pointerEvent->GetPointerAction(), pointerEvent->GetSourceType(),
                pointerEvent->GetAxisValue(PointerEvent::AXIS_TYPE_PINCH));

    PointerEvent::PointerItem item;
    pointerEvent->GetPointerItem(pointerEvent->GetPointerId(), item);
    MMI_HILOGD("Item:DownTime:%{public}" PRId64 ",IsPressed:%{public}s,"
               "DisplayX:%{public}d,DisplayY:%{public}d,WindowX:%{public}d,WindowY:%{public}d,"
               "Width:%{public}d,Height:%{public}d",
               item.GetDownTime(), (item.IsPressed() ? "true" : "false"),
               item.GetDisplayX(), item.GetDisplayY(), item.GetWindowX(), item.GetWindowY(),
               item.GetWidth(), item.GetHeight());
    nextHandler_->HandlePointerEvent(pointerEvent);
#else
    MMI_HILOGW("Pointer device does not support");
#endif // OHOS_BUILD_ENABLE_POINTER
    return RET_OK;
}

int32_t EventNormalizeHandler::HandleTouchEvent(libinput_event* event)
{
    LibinputAdapter::LoginfoPackagingTool(event);
    if (nextHandler_ == nullptr) {
        MMI_HILOGW("Touchscreen device does not support");
        return ERROR_UNSUPPORT;
    }
#ifdef OHOS_BUILD_ENABLE_TOUCH
    CHKPR(event, ERROR_NULL_POINTER);
    auto pointerEvent = TouchEventHdr->OnLibInput(event, INPUT_DEVICE_CAP_TOUCH);
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    BytraceAdapter::StartBytrace(pointerEvent, BytraceAdapter::TRACE_START);
    nextHandler_->HandleTouchEvent(pointerEvent);
    ResetTouchUpEvent(pointerEvent, event);
#else
    MMI_HILOGW("Touchscreen device does not support");
#endif // OHOS_BUILD_ENABLE_TOUCH
    return RET_OK;
}

void EventNormalizeHandler::ResetTouchUpEvent(std::shared_ptr<PointerEvent> pointerEvent,
    struct libinput_event *event)
{
    CHKPV(pointerEvent);
    CHKPV(event);
    auto type = libinput_event_get_type(event);
    if (type == LIBINPUT_EVENT_TOUCH_UP) {
        pointerEvent->RemovePointerItem(pointerEvent->GetPointerId());
        MMI_HILOGD("This touch event is up remove this finger");
        if (pointerEvent->GetPointerIds().empty()) {
            MMI_HILOGD("This touch event is final finger up remove this finger");
            pointerEvent->Reset();
        }
    }
}

int32_t EventNormalizeHandler::HandleTableToolEvent(libinput_event* event)
{
    if (nextHandler_ == nullptr) {
        MMI_HILOGW("Touchscreen device does not support");
        return ERROR_UNSUPPORT;
    }
#ifdef OHOS_BUILD_ENABLE_TOUCH
    CHKPR(event, ERROR_NULL_POINTER);
    auto pointerEvent = TouchEventHdr->OnLibInput(event, INPUT_DEVICE_CAP_TABLET_TOOL);
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    BytraceAdapter::StartBytrace(pointerEvent, BytraceAdapter::TRACE_START);
    nextHandler_->HandleTouchEvent(pointerEvent);
    if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_UP) {
        pointerEvent->Reset();
    }
#else
    MMI_HILOGW("Touchscreen device does not support");
#endif // OHOS_BUILD_ENABLE_TOUCH
    return RET_OK;
}

int32_t EventNormalizeHandler::AddHandleTimer(int32_t timeout)
{
    CALL_DEBUG_ENTER;
    timerId_ = TimerMgr->AddTimer(timeout, 1, [this]() {
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
        auto keyEvent = KeyEventHdr->GetKeyEvent();
        CHKPV(keyEvent);
        CHKPV(nextHandler_);
        nextHandler_->HandleKeyEvent(keyEvent);
        int32_t triggerTime = KeyRepeat->GetIntervalTime(keyEvent->GetDeviceId());
        this->AddHandleTimer(triggerTime);
#endif // OHOS_BUILD_ENABLE_KEYBOARD
    });
    return timerId_;
}
} // namespace MMI
} // namespace OHOS
