/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "js_input_monitor.h"

#include <cinttypes>

#include "define_multimodal.h"
#include "error_multimodal.h"
#include "input_manager.h"
#include "js_input_monitor_manager.h"
#include "util_napi_value.h"
#include "napi_constants.h"
#include "securec.h"
#include "util_napi_error.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "JsInputMonitor"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t AXIS_TYPE_SCROLL_VERTICAL { 0 };
constexpr int32_t AXIS_TYPE_SCROLL_HORIZONTAL { 1 };
constexpr int32_t AXIS_TYPE_PINCH { 2 };
constexpr int32_t NAPI_ERR { 3 };
constexpr int32_t CANCEL { 0 };
constexpr int32_t MOVE { 1 };
constexpr int32_t BUTTON_DOWN { 2 };
constexpr int32_t BUTTON_UP { 3 };
constexpr int32_t AXIS_BEGIN { 4 };
constexpr int32_t AXIS_UPDATE { 5 };
constexpr int32_t AXIS_END { 6 };
constexpr int32_t MIDDLE { 1 };
constexpr int32_t RIGHT { 2 };
constexpr int32_t MOUSE_FLOW { 10 };
constexpr int32_t ONE_FINGERS { 1 };
constexpr int32_t THREE_FINGERS { 3 };
constexpr int32_t FOUR_FINGERS { 4 };
constexpr int32_t GESTURE_BEGIN { 1 };
constexpr int32_t GESTURE_UPDATE { 2 };
constexpr int32_t GESTURE_END { 3 };
const std::string INVALID_TYPE_NAME { "" };
#ifdef OHOS_BUILD_ENABLE_FINGERPRINT
constexpr int32_t FINGERPRINT_DOWN { 0 };
constexpr int32_t FINGERPRINT_UP { 1 };
constexpr int32_t FINGERPRINT_SLIDE { 2 };
constexpr int32_t FINGERPRINT_RETOUCH { 3 };
constexpr int32_t FINGERPRINT_CLICK { 4 };
#endif // OHOS_BUILD_ENABLE_FINGERPRINT

enum TypeName : int32_t {
    TOUCH = 0,
    MOUSE = 1,
    PINCH = 2,
    THREE_FINGERS_SWIPE = 3,
    FOUR_FINGERS_SWIPE = 4,
    ROTATE = 5,
    THREE_FINGERS_TAP = 6,
    JOYSTICK = 7,
    FINGERPRINT = 8,
    SWIPE_INWARD = 9,
};

std::map<std::string, int32_t> TO_GESTURE_TYPE = {
    { "touch", TOUCH },
    { "mouse", MOUSE },
    { "pinch", PINCH },
    { "threeFingersSwipe", THREE_FINGERS_SWIPE },
    { "fourFingersSwipe", FOUR_FINGERS_SWIPE },
    { "rotate", ROTATE },
    { "threeFingersTap", THREE_FINGERS_TAP },
    { "joystick", JOYSTICK},
    { "fingerprint", FINGERPRINT},
    { "swipeInward", SWIPE_INWARD},
};

struct MonitorInfo {
    int32_t monitorId;
    int32_t fingers;
};

std::map<JsJoystickEvent::Axis, PointerEvent::AxisType> g_joystickAxisType = {
    { JsJoystickEvent::Axis::ABS_X, PointerEvent::AXIS_TYPE_ABS_X },
    { JsJoystickEvent::Axis::ABS_Y, PointerEvent::AXIS_TYPE_ABS_Y },
    { JsJoystickEvent::Axis::ABS_Z, PointerEvent::AXIS_TYPE_ABS_Z },
    { JsJoystickEvent::Axis::ABS_RZ, PointerEvent::AXIS_TYPE_ABS_RZ },
    { JsJoystickEvent::Axis::ABS_GAS, PointerEvent::AXIS_TYPE_ABS_GAS },
    { JsJoystickEvent::Axis::ABS_BRAKE, PointerEvent::AXIS_TYPE_ABS_BRAKE },
    { JsJoystickEvent::Axis::ABS_HAT0X, PointerEvent::AXIS_TYPE_ABS_HAT0X },
    { JsJoystickEvent::Axis::ABS_HAT0Y, PointerEvent::AXIS_TYPE_ABS_HAT0Y },
    { JsJoystickEvent::Axis::ABS_THROTTLE, PointerEvent::AXIS_TYPE_ABS_THROTTLE }
};

std::map<JsJoystickEvent::Button, int32_t> g_joystickButtonType = {
    { JsJoystickEvent::Button::BUTTON_TL2, PointerEvent::JOYSTICK_BUTTON_TL2 },
    { JsJoystickEvent::Button::BUTTON_TR2, PointerEvent::JOYSTICK_BUTTON_TR2 },
    { JsJoystickEvent::Button::BUTTON_TL, PointerEvent::JOYSTICK_BUTTON_TL },
    { JsJoystickEvent::Button::BUTTON_TR, PointerEvent::JOYSTICK_BUTTON_TR },
    { JsJoystickEvent::Button::BUTTON_WEST, PointerEvent::JOYSTICK_BUTTON_WEST },
    { JsJoystickEvent::Button::BUTTON_SOUTH, PointerEvent::JOYSTICK_BUTTON_SOUTH },
    { JsJoystickEvent::Button::BUTTON_NORTH, PointerEvent::JOYSTICK_BUTTON_NORTH },
    { JsJoystickEvent::Button::BUTTON_EAST, PointerEvent::JOYSTICK_BUTTON_EAST },
    { JsJoystickEvent::Button::BUTTON_START, PointerEvent::JOYSTICK_BUTTON_START },
    { JsJoystickEvent::Button::BUTTON_SELECT, PointerEvent::JOYSTICK_BUTTON_SELECT },
    { JsJoystickEvent::Button::BUTTON_HOMEPAGE, PointerEvent::JOYSTICK_BUTTON_HOMEPAGE },
    { JsJoystickEvent::Button::BUTTON_THUMBL, PointerEvent::JOYSTICK_BUTTON_THUMBL },
    { JsJoystickEvent::Button::BUTTON_THUMBR, PointerEvent::JOYSTICK_BUTTON_THUMBR },
    { JsJoystickEvent::Button::BUTTON_TRIGGER, PointerEvent::JOYSTICK_BUTTON_TRIGGER },
    { JsJoystickEvent::Button::BUTTON_THUMB, PointerEvent::JOYSTICK_BUTTON_THUMB },
    { JsJoystickEvent::Button::BUTTON_THUMB2, PointerEvent::JOYSTICK_BUTTON_THUMB2 },
    { JsJoystickEvent::Button::BUTTON_TOP, PointerEvent::JOYSTICK_BUTTON_TOP },
    { JsJoystickEvent::Button::BUTTON_TOP2, PointerEvent::JOYSTICK_BUTTON_TOP2 },
    { JsJoystickEvent::Button::BUTTON_PINKIE, PointerEvent::JOYSTICK_BUTTON_PINKIE },
    { JsJoystickEvent::Button::BUTTON_BASE, PointerEvent::JOYSTICK_BUTTON_BASE },
    { JsJoystickEvent::Button::BUTTON_BASE2, PointerEvent::JOYSTICK_BUTTON_BASE2 },
    { JsJoystickEvent::Button::BUTTON_BASE3, PointerEvent::JOYSTICK_BUTTON_BASE3 },
    { JsJoystickEvent::Button::BUTTON_BASE4, PointerEvent::JOYSTICK_BUTTON_BASE4 },
    { JsJoystickEvent::Button::BUTTON_BASE5, PointerEvent::JOYSTICK_BUTTON_BASE5 },
    { JsJoystickEvent::Button::BUTTON_BASE6, PointerEvent::JOYSTICK_BUTTON_BASE6 },
    { JsJoystickEvent::Button::BUTTON_DEAD, PointerEvent::JOYSTICK_BUTTON_DEAD },
    { JsJoystickEvent::Button::BUTTON_C, PointerEvent::JOYSTICK_BUTTON_C },
    { JsJoystickEvent::Button::BUTTON_Z, PointerEvent::JOYSTICK_BUTTON_Z },
    { JsJoystickEvent::Button::BUTTON_MODE, PointerEvent::JOYSTICK_BUTTON_MODE }
};

void CleanData(MonitorInfo** monitorInfo, uv_work_t** work)
{
    if (*monitorInfo != nullptr) {
        delete *monitorInfo;
        *monitorInfo = nullptr;
    }
    if (*work != nullptr) {
        delete *work;
        *work = nullptr;
    }
}
} // namespace

int32_t InputMonitor::Start()
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    if (monitorId_ < 0) {
        monitorId_ = InputManager::GetInstance()->AddMonitor(shared_from_this());
    }
    return monitorId_;
}

void InputMonitor::Stop()
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    if (monitorId_ < 0) {
        MMI_HILOGE("Invalid values");
        return;
    }
    InputManager::GetInstance()->RemoveMonitor(monitorId_);
    monitorId_ = -1;
    return;
}

std::string InputMonitor::GetTypeName() const
{
    return typeName_;
}

void InputMonitor::SetTypeName(const std::string &typeName)
{
    typeName_ = typeName;
}

void InputMonitor::SetCallback(std::function<void(std::shared_ptr<PointerEvent>)> callback)
{
    std::lock_guard<std::mutex> guard(mutex_);
    callback_ = callback;
}

void InputMonitor::OnInputEvent(std::shared_ptr<PointerEvent> pointerEvent) const
{
    CALL_DEBUG_ENTER;
    CHKPV(pointerEvent);
    if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_MOUSE
        && pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_MOVE) {
        if (++flowCtrl_ < MOUSE_FLOW) {
            return;
        } else {
            flowCtrl_ = 0;
        }
    }
    std::function<void(std::shared_ptr<PointerEvent>)> callback;
    {
        std::lock_guard<std::mutex> guard(mutex_);
        auto typeName = JS_INPUT_MONITOR_MGR.GetMonitorTypeName(id_, fingers_);
        if (typeName == INVALID_TYPE_NAME) {
            MMI_HILOGE("Failed to process pointer event, id:%{public}d", id_);
            return;
        }
        if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_TOUCHSCREEN) {
            if (typeName != "touch") {
                return;
            }
            SetConsumeState(pointerEvent);
        }
        if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_MOUSE) {
            if (typeName != "mouse" && typeName != "pinch" && typeName != "rotate") {
                return;
            }
            SetConsumeState(pointerEvent);
        }
        if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_TOUCHPAD) {
            if (!IsGestureEvent(pointerEvent)) {
                return;
            }
        }
        if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_JOYSTICK) {
            if (JS_INPUT_MONITOR_MGR.GetMonitor(id_, fingers_)->GetTypeName() != "joystick") {
                MMI_HILOGE("Failed to process joystick event");
                return;
            }
        }
        callback = callback_;
    }
    CHKPV(callback);
    callback(pointerEvent);
}

void InputMonitor::SetConsumeState(std::shared_ptr<PointerEvent> pointerEvent) const
{
    CHKPV(pointerEvent);
    if (pointerEvent->GetPointerIds().size() == 1) {
        if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_DOWN) {
            consumed_ = false;
        }
    }
}

bool InputMonitor::IsGestureEvent(std::shared_ptr<PointerEvent> pointerEvent) const
{
    CHKPF(pointerEvent);
    auto ret = JS_INPUT_MONITOR_MGR.GetMonitor(id_, fingers_)->GetTypeName();
    if (ret != "pinch" && ret != "threeFingersSwipe" &&
        ret != "fourFingersSwipe" && ret != "threeFingersTap" &&
        ret != "swipeInward") {
        return false;
    }
    if (pointerEvent->GetPointerIds().size() == 1) {
        if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_AXIS_BEGIN ||
            PointerEvent::POINTER_ACTION_SWIPE_BEGIN) {
            consumed_ = false;
        }
    }
    return true;
}

void InputMonitor::SetId(int32_t id)
{
    id_ = id;
}

void InputMonitor::SetFingers(int32_t fingers)
{
    fingers_ = fingers;
}

void InputMonitor::SetHotRectArea(std::vector<Rect> hotRectArea)
{
    hotRectArea_ = hotRectArea;
}

std::vector<Rect> InputMonitor::GetHotRectArea()
{
    return hotRectArea_;
}

void InputMonitor::SetRectTotal(uint32_t rectTotal)
{
    rectTotal_ = rectTotal;
}

uint32_t InputMonitor::GetRectTotal()
{
    return rectTotal_;
}

void InputMonitor::OnInputEvent(std::shared_ptr<KeyEvent> keyEvent) const {}

void InputMonitor::OnInputEvent(std::shared_ptr<AxisEvent> axisEvent) const {}

void InputMonitor::MarkConsumed(int32_t eventId)
{
    std::lock_guard<std::mutex> guard(mutex_);
    if (consumed_) {
        MMI_HILOGD("The consumed_ is true");
        return;
    }
    if (monitorId_ < 0) {
        MMI_HILOGE("Invalid values");
        return;
    }
    InputManager::GetInstance()->MarkConsumed(monitorId_, eventId);
    consumed_ = true;
}

JsInputMonitor::JsInputMonitor(napi_env jsEnv, const std::string &typeName, std::vector<Rect> rectParam,
    int32_t rectTotal, napi_value callback, int32_t id, int32_t fingers)
    : monitor_(std::make_shared<InputMonitor>()), jsEnv_(jsEnv), typeName_(typeName), monitorId_(id),
    fingers_(fingers)
{
    SetCallback(callback);
    CHKPV(monitor_);
    monitor_->SetCallback([jsId = id, jsFingers = fingers](std::shared_ptr<PointerEvent> pointerEvent) {
        JS_INPUT_MONITOR_MGR.OnPointerEventByMonitorId(jsId, jsFingers, pointerEvent);
    });
    monitor_->SetTypeName(typeName_);
    monitor_->SetId(monitorId_);
    monitor_->SetFingers(fingers_);
    if (rectTotal != 0) {
        monitor_->SetHotRectArea(rectParam);
        monitor_->SetRectTotal(rectTotal);
    }
}

JsInputMonitor::JsInputMonitor(napi_env jsEnv, const std::string &typeName,
    napi_value callback, int32_t id, int32_t fingers)
    : monitor_(std::make_shared<InputMonitor>()), jsEnv_(jsEnv), typeName_(typeName), monitorId_(id),
    fingers_(fingers)
{
    SetCallback(callback);
    CHKPV(monitor_);
    monitor_->SetCallback([jsId = id, jsFingers = fingers](std::shared_ptr<PointerEvent> pointerEvent) {
        JS_INPUT_MONITOR_MGR.OnPointerEventByMonitorId(jsId, jsFingers, pointerEvent);
    });
    monitor_->SetTypeName(typeName_);
    monitor_->SetId(monitorId_);
    monitor_->SetFingers(fingers_);
}

void JsInputMonitor::SetCallback(napi_value callback)
{
    if (receiver_ == nullptr && jsEnv_ != nullptr) {
        uint32_t refCount = 1;
        auto status = napi_create_reference(jsEnv_, callback, refCount, &receiver_);
        if (status != napi_ok) {
            THROWERR(jsEnv_, "napi_create_reference is failed");
            return;
        }
    }
}

void JsInputMonitor::MarkConsumed(int32_t eventId)
{
    CHKPV(monitor_);
    monitor_->MarkConsumed(eventId);
}

int32_t JsInputMonitor::IsMatch(napi_env jsEnv, napi_value callback)
{
    CHKPR(callback, ERROR_NULL_POINTER);
    if (jsEnv_ == jsEnv) {
        napi_value handlerTemp = nullptr;
        auto status = napi_get_reference_value(jsEnv_, receiver_, &handlerTemp);
        if (status != napi_ok) {
            THROWERR(jsEnv_, "napi_get_reference_value is failed");
            return NAPI_ERR;
        }
        bool isEquals = false;
        status = napi_strict_equals(jsEnv_, handlerTemp, callback, &isEquals);
        if (status != napi_ok) {
            THROWERR(jsEnv_, "napi_strict_equals is failed");
            return NAPI_ERR;
        }
        if (isEquals) {
            MMI_HILOGI("Js callback match success");
            return RET_OK;
        }
        MMI_HILOGI("Js callback match failed");
        return RET_ERR;
    }
    MMI_HILOGI("Js callback match failed");
    return RET_ERR;
}

int32_t JsInputMonitor::IsMatch(napi_env jsEnv)
{
    if (jsEnv_ == jsEnv) {
        MMI_HILOGI("Env match success");
        return RET_OK;
    }
    MMI_HILOGI("Env match failed");
    return RET_ERR;
}

MapFun JsInputMonitor::GetInputEventFunc(const std::shared_ptr<InputEvent> inputEvent)
{
    MapFun mapFunc;
    mapFunc["id"] = [inputEvent] { return inputEvent->GetId(); };
    mapFunc["deviceId"] = [inputEvent] { return inputEvent->GetDeviceId(); };
    mapFunc["actionTime"] = [inputEvent] { return inputEvent->GetActionTime(); };
    mapFunc["screenId"] = [inputEvent] { return inputEvent->GetTargetDisplayId(); };
    mapFunc["windowId"] = [inputEvent] { return inputEvent->GetTargetWindowId(); };

    return mapFunc;
}

int32_t JsInputMonitor::SetInputEventProperty(const std::shared_ptr<InputEvent> inputEvent, napi_value result)
{
    CHKPR(inputEvent, ERROR_NULL_POINTER);
    auto mapFun = GetInputEventFunc(inputEvent);
    for (const auto &it : mapFun) {
        auto setProperty = "Set" + it.first;
        CHKRR(SetNameProperty(jsEnv_, result, it.first, it.second()), setProperty, RET_ERR);
    }
    return RET_OK;
}

int32_t JsInputMonitor::GetAction(int32_t action) const
{
    switch (action) {
        case PointerEvent::POINTER_ACTION_CANCEL: {
            return static_cast<int32_t>(JsTouchEvent::Action::CANCEL);
        }
        case PointerEvent::POINTER_ACTION_DOWN: {
            return static_cast<int32_t>(JsTouchEvent::Action::DOWN);
        }
        case PointerEvent::POINTER_ACTION_MOVE: {
            return static_cast<int32_t>(JsTouchEvent::Action::MOVE);
        }
        case PointerEvent::POINTER_ACTION_UP: {
            return static_cast<int32_t>(JsTouchEvent::Action::UP);
        }
        case PointerEvent::POINTER_ACTION_PULL_DOWN: {
            return static_cast<int32_t>(JsTouchEvent::Action::PULL_DOWN);
        }
        case PointerEvent::POINTER_ACTION_PULL_MOVE: {
            return static_cast<int32_t>(JsTouchEvent::Action::PULL_MOVE);
        }
        case PointerEvent::POINTER_ACTION_PULL_UP: {
            return static_cast<int32_t>(JsTouchEvent::Action::PULL_UP);
        }
        default: {
            return RET_ERR;
        }
    }
}

int32_t JsInputMonitor::GetSourceType(int32_t sourceType) const
{
    switch (sourceType) {
        case PointerEvent::SOURCE_TYPE_TOUCHSCREEN: {
            return static_cast<int32_t>(JsTouchEvent::SourceType::TOUCH_SCREEN);
        }
        case PointerEvent::SOURCE_TYPE_TOUCHPAD: {
            return static_cast<int32_t>(JsTouchEvent::SourceType::TOUCH_PAD);
        }
        default: {
            return RET_ERR;
        }
    }
}

int32_t JsInputMonitor::GetJsPointerItem(const PointerEvent::PointerItem &item, napi_value value) const
{
    CHKRR(SetNameProperty(jsEnv_, value, "id", item.GetPointerId()), "Set id", RET_ERR);
    CHKRR(SetNameProperty(jsEnv_, value, "pressedTime", item.GetDownTime()), "Set pressedTime", RET_ERR);
    CHKRR(SetNameProperty(jsEnv_, value, "screenX", item.GetDisplayX()), "Set screenX", RET_ERR);
    CHKRR(SetNameProperty(jsEnv_, value, "screenY", item.GetDisplayY()), "Set screenY", RET_ERR);
    CHKRR(SetNameProperty(jsEnv_, value, "windowX", item.GetWindowX()), "Set windowX", RET_ERR);
    CHKRR(SetNameProperty(jsEnv_, value, "windowY", item.GetWindowY()), "Set windowY", RET_ERR);
    CHKRR(SetNameProperty(jsEnv_, value, "pressure", item.GetPressure()), "Set pressure", RET_ERR);
    CHKRR(SetNameProperty(jsEnv_, value, "width", item.GetWidth()), "Set width", RET_ERR);
    CHKRR(SetNameProperty(jsEnv_, value, "height", item.GetHeight()), "Set height", RET_ERR);
    CHKRR(SetNameProperty(jsEnv_, value, "tiltX", item.GetTiltX()), "Set tiltX", RET_ERR);
    CHKRR(SetNameProperty(jsEnv_, value, "tiltY", item.GetTiltY()), "Set tiltY", RET_ERR);
    CHKRR(SetNameProperty(jsEnv_, value, "toolX", item.GetToolDisplayX()), "Set toolX", RET_ERR);
    CHKRR(SetNameProperty(jsEnv_, value, "toolY", item.GetToolDisplayY()), "Set toolY", RET_ERR);
    CHKRR(SetNameProperty(jsEnv_, value, "toolWidth", item.GetToolWidth()), "Set toolWidth", RET_ERR);
    CHKRR(SetNameProperty(jsEnv_, value, "toolHeight", item.GetToolHeight()), "Set toolHeight", RET_ERR);
    CHKRR(SetNameProperty(jsEnv_, value, "rawX", item.GetRawDx()), "Set rawX", RET_ERR);
    CHKRR(SetNameProperty(jsEnv_, value, "rawY", item.GetRawDy()), "Set rawY", RET_ERR);
    CHKRR(SetNameProperty(jsEnv_, value, "toolType", item.GetToolType()), "Set toolType", RET_ERR);
    return RET_OK;
}

int32_t JsInputMonitor::TransformPointerEvent(const std::shared_ptr<PointerEvent> pointerEvent, napi_value result)
{
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    if (SetInputEventProperty(pointerEvent, result) != RET_OK) {
        MMI_HILOGE("Set inputEvent property failed");
        return RET_ERR;
    }
    if (SetNameProperty(jsEnv_, result, "action", GetAction(pointerEvent->GetPointerAction())) != napi_ok) {
        MMI_HILOGE("Set action property failed");
        return RET_ERR;
    }
    if (SetNameProperty(jsEnv_, result, "sourceType", GetSourceType(pointerEvent->GetSourceType())) != napi_ok) {
        MMI_HILOGE("Set sourceType property failed");
        return RET_ERR;
    }
    napi_value pointers = nullptr;
    CHKRR(napi_create_array(jsEnv_, &pointers), "napi_create_array is", RET_ERR);
    std::vector<PointerEvent::PointerItem> pointerItems;
    for (const auto &item : pointerEvent->GetPointerIds()) {
        PointerEvent::PointerItem pointerItem;
        if (!pointerEvent->GetPointerItem(item, pointerItem)) {
            MMI_HILOGE("Get pointer item failed");
            return RET_ERR;
        }
        pointerItems.push_back(pointerItem);
    }
    uint32_t index = 0;
    for (const auto &it : pointerItems) {
        napi_value element = nullptr;
        CHKRR(napi_create_object(jsEnv_, &element), "napi_create_object is", RET_ERR);
        if (GetJsPointerItem(it, element) != RET_OK) {
            MMI_HILOGE("Transform pointerItem failed");
            return RET_ERR;
        }
        CHKRR(napi_set_element(jsEnv_, pointers, index, element), "napi_set_element is", RET_ERR);
        ++index;
    }
    CHKRR(SetNameProperty(jsEnv_, result, "touches", pointers), "Set touches", RET_ERR);
    return RET_OK;
}

int32_t JsInputMonitor::TransformPinchEvent(std::shared_ptr<PointerEvent> pointerEvent, napi_value result)
{
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    int32_t actionValue = GetPinchAction(pointerEvent->GetPointerAction());
    if (actionValue == RET_ERR) {
        MMI_HILOGE("Get action value failed");
        return RET_ERR;
    }
    if (SetNameProperty(jsEnv_, result, "type", actionValue) != napi_ok) {
        MMI_HILOGE("Set type property failed");
        return RET_ERR;
    }
    if (SetNameProperty(jsEnv_, result, "scale",
        pointerEvent->GetAxisValue(PointerEvent::AXIS_TYPE_PINCH)) != napi_ok) {
        MMI_HILOGE("Set scale property failed");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t JsInputMonitor::TransformRotateEvent(std::shared_ptr<PointerEvent> pointerEvent, napi_value result)
{
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    int32_t actionValue = GetRotateAction(pointerEvent->GetPointerAction());
    if (actionValue == RET_ERR) {
        MMI_HILOGE("Get action value failed");
        return RET_ERR;
    }
    if (SetNameProperty(jsEnv_, result, "type", actionValue) != napi_ok) {
        MMI_HILOGE("Set type property failed");
        return RET_ERR;
    }
    if (SetNameProperty(jsEnv_, result, "angle",
        pointerEvent->GetAxisValue(PointerEvent::AXIS_TYPE_ROTATE)) != napi_ok) {
        MMI_HILOGE("Set scale property failed");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t JsInputMonitor::GetPinchAction(int32_t action) const
{
    switch (action) {
        case PointerEvent::POINTER_ACTION_AXIS_BEGIN: {
            return GESTURE_BEGIN;
        }
        case PointerEvent::POINTER_ACTION_AXIS_UPDATE: {
            return GESTURE_UPDATE;
        }
        case PointerEvent::POINTER_ACTION_AXIS_END: {
            return GESTURE_END;
        }
        default: {
            MMI_HILOGD("Abnormal pointer action in pinch event");
            return RET_ERR;
        }
    }
}

int32_t JsInputMonitor::GetRotateAction(int32_t action) const
{
    switch (action) {
        case PointerEvent::POINTER_ACTION_ROTATE_BEGIN: {
            return GESTURE_BEGIN;
        }
        case PointerEvent::POINTER_ACTION_ROTATE_UPDATE: {
            return GESTURE_UPDATE;
        }
        case PointerEvent::POINTER_ACTION_ROTATE_END: {
            return GESTURE_END;
        }
        default: {
            MMI_HILOGD("Abnormal pointer action in pinch event");
            return RET_ERR;
        }
    }
}

int32_t JsInputMonitor::TransformSwipeEvent(std::shared_ptr<PointerEvent> pointerEvent, napi_value result)
{
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    int32_t actionValue = GetSwipeAction(pointerEvent->GetPointerAction());
    if (actionValue == RET_ERR) {
        if (pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_SWIPE_UPDATE) {
            MMI_HILOGE("Get action value failed");
        }
        return RET_ERR;
    }
    if (SetNameProperty(jsEnv_, result, "type", actionValue) != napi_ok) {
        MMI_HILOGE("Set type property failed");
        return RET_ERR;
    }
    PointerEvent::PointerItem pointeritem;
    int32_t pointerId = 0;
    if (!pointerEvent->GetPointerItem(pointerId, pointeritem)) {
        MMI_HILOGE("Can't find this pointerItem");
        return RET_ERR;
    }
    if (SetNameProperty(jsEnv_, result, "x", pointeritem.GetDisplayX()) != napi_ok) {
        MMI_HILOGE("Set displayX property failed");
        return RET_ERR;
    }
    if (SetNameProperty(jsEnv_, result, "y", pointeritem.GetDisplayY()) != napi_ok) {
        MMI_HILOGE("Set displayY property failed");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t JsInputMonitor::GetSwipeAction(int32_t action) const
{
    switch (action) {
        case PointerEvent::POINTER_ACTION_SWIPE_BEGIN: {
            return GESTURE_BEGIN;
        }
        case PointerEvent::POINTER_ACTION_SWIPE_UPDATE: {
            return GESTURE_UPDATE;
        }
        case PointerEvent::POINTER_ACTION_SWIPE_END: {
            return GESTURE_END;
        }
        default: {
            MMI_HILOGD("Abnormal pointer action in swipe event");
            return RET_ERR;
        }
    }
}

int32_t JsInputMonitor::TransformMultiTapEvent(std::shared_ptr<PointerEvent> pointerEvent, napi_value result)
{
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    int32_t actionValue = GetMultiTapAction(pointerEvent->GetPointerAction());
    if (actionValue == RET_ERR) {
        MMI_HILOGE("Get action value failed");
        return RET_ERR;
    }
    if (SetNameProperty(jsEnv_, result, "type", actionValue) != napi_ok) {
        MMI_HILOGE("Set type property failed");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t JsInputMonitor::GetMultiTapAction(int32_t action) const
{
    switch (action) {
        case PointerEvent::POINTER_ACTION_TRIPTAP: {
            return GESTURE_END;
        }
        default: {
            MMI_HILOGD("Abnormal pointer action in multi tap event");
            return RET_ERR;
        }
    }
}

int32_t JsInputMonitor::TransformSwipeInwardEvent(std::shared_ptr<PointerEvent> pointerEvent, napi_value result)
{
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    int32_t actionValue = pointerEvent->GetPointerAction();
    if (actionValue == RET_ERR) {
        MMI_HILOGE("Get action value failed");
        return RET_ERR;
    }
    int32_t actionTypeTemp = actionValue;
    switch (actionTypeTemp) {
        case PointerEvent::POINTER_ACTION_DOWN: {
            actionValue = GESTURE_BEGIN;
            break;
        }
        case PointerEvent::POINTER_ACTION_MOVE: {
            actionValue = GESTURE_UPDATE;
            break;
        }
        case PointerEvent::POINTER_ACTION_UP: {
            actionValue = GESTURE_END;
            break;
        }
        default: {
            MMI_HILOGE("Abnormal pointer action in swipe event");
            return RET_ERR;
        }
    }
    if (SetNameProperty(jsEnv_, result, "type", actionValue) != napi_ok) {
        MMI_HILOGE("Set type property failed");
        return RET_ERR;
    }
    PointerEvent::PointerItem pointeritem;
    int32_t pointerId = 0;
    if (!pointerEvent->GetPointerItem(pointerId, pointeritem)) {
        MMI_HILOGE("Can't find this pointerItem");
        return RET_ERR;
    }
    if (SetNameProperty(jsEnv_, result, "x", pointeritem.GetDisplayX()) != napi_ok) {
        MMI_HILOGE("Set displayX property failed");
        return RET_ERR;
    }
    if (SetNameProperty(jsEnv_, result, "y", pointeritem.GetDisplayY()) != napi_ok) {
        MMI_HILOGE("Set displayY property failed");
        return RET_ERR;
    }
    return RET_OK;
}

#ifdef OHOS_BUILD_ENABLE_FINGERPRINT
int32_t JsInputMonitor::GetFingerprintAction(int32_t action) const
{
    MMI_HILOGD("GetFingerprintAction enter, action is %{public}d", action);
    switch (action) {
        case PointerEvent::POINTER_ACTION_FINGERPRINT_DOWN: {
            return FINGERPRINT_DOWN;
        }
        case PointerEvent::POINTER_ACTION_FINGERPRINT_UP: {
            return FINGERPRINT_UP;
        }
        case PointerEvent::POINTER_ACTION_FINGERPRINT_SLIDE: {
            return FINGERPRINT_SLIDE;
        }
        case PointerEvent::POINTER_ACTION_FINGERPRINT_RETOUCH: {
            return FINGERPRINT_RETOUCH;
        }
        case PointerEvent::POINTER_ACTION_FINGERPRINT_CLICK: {
            return FINGERPRINT_CLICK;
        }
        default: {
            MMI_HILOGE("wrong action is %{public}d", action);
            return RET_ERR;
        }
    }
}
#endif // OHOS_BUILD_ENABLE_FINGERPRINT

MapFun JsInputMonitor::GetFuns(const std::shared_ptr<PointerEvent> pointerEvent, const PointerEvent::PointerItem& item)
{
    MapFun mapFun;
    mapFun["actionTime"] = [pointerEvent] { return pointerEvent->GetActionTime(); };
    mapFun["screenId"] = [pointerEvent] { return pointerEvent->GetTargetDisplayId(); };
    mapFun["windowId"] = [pointerEvent] { return pointerEvent->GetTargetWindowId(); };
    mapFun["deviceId"] = [item] { return item.GetDeviceId(); };
    mapFun["windowX"] = [item] { return item.GetWindowX(); };
    mapFun["windowY"] = [item] { return item.GetWindowY(); };
    mapFun["screenX"] = [item] { return item.GetDisplayX(); };
    mapFun["screenY"] = [item] { return item.GetDisplayY(); };
    mapFun["rawDeltaX"] = [item] { return item.GetRawDx(); };
    mapFun["rawDeltaY"] = [item] { return item.GetRawDy(); };
    return mapFun;
}

bool JsInputMonitor::SetMouseProperty(const std::shared_ptr<PointerEvent> pointerEvent,
    const PointerEvent::PointerItem& item, napi_value result)
{
    CHKPF(pointerEvent);
    int32_t buttonId = pointerEvent->GetButtonId();
    if (buttonId == PointerEvent::MOUSE_BUTTON_MIDDLE) {
        buttonId = MIDDLE;
    } else if (buttonId == PointerEvent::MOUSE_BUTTON_RIGHT) {
        buttonId = RIGHT;
    }
    if (SetNameProperty(jsEnv_, result, "button", buttonId) != napi_ok) {
        THROWERR(jsEnv_, "Set property failed");
        return false;
    }

    auto mapFun = GetFuns(pointerEvent, item);
    for (const auto &it : mapFun) {
        if (SetNameProperty(jsEnv_, result, it.first, it.second()) != napi_ok) {
            THROWERR(jsEnv_, "Set property failed");
            return false;
        }
    }
    return true;
}

bool JsInputMonitor::GetAxesValue(const std::shared_ptr<PointerEvent> pointerEvent, napi_value element)
{
    CALL_DEBUG_ENTER;
    CHKPF(pointerEvent);
    double axisValue = -1.0;
    int32_t axis = -1;
    if (pointerEvent->HasAxis(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL)) {
        axisValue = pointerEvent->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL);
        axis = AXIS_TYPE_SCROLL_VERTICAL;
    }
    if (pointerEvent->HasAxis(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL)) {
        axisValue = pointerEvent->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL);
        axis = AXIS_TYPE_SCROLL_HORIZONTAL;
    }
    if (pointerEvent->HasAxis(PointerEvent::AXIS_TYPE_PINCH)) {
        axisValue = pointerEvent->GetAxisValue(PointerEvent::AXIS_TYPE_PINCH);
        axis = AXIS_TYPE_PINCH;
    }
    if (SetNameProperty(jsEnv_, element, "axis", axis) != napi_ok) {
        THROWERR(jsEnv_, "Set property of axis failed");
        return false;
    }
    if (SetNameProperty(jsEnv_, element, "value", axisValue) != napi_ok) {
        THROWERR(jsEnv_, "Set property of value failed");
        return false;
    }
    return true;
}

std::optional<int32_t> JsInputMonitor::GetJoystickAction(int32_t action)
{
    switch (action) {
        case PointerEvent::POINTER_ACTION_CANCEL: {
            return std::make_optional(static_cast<int32_t>(JsJoystickEvent::Action::CANCEL));
        }
        case PointerEvent::POINTER_ACTION_BUTTON_DOWN: {
            return std::make_optional(static_cast<int32_t>(JsJoystickEvent::Action::BUTTON_DOWN));
        }
        case PointerEvent::POINTER_ACTION_BUTTON_UP: {
            return std::make_optional(static_cast<int32_t>(JsJoystickEvent::Action::BUTTON_UP));
        }
        case PointerEvent::POINTER_ACTION_AXIS_BEGIN: {
            return std::make_optional(static_cast<int32_t>(JsJoystickEvent::Action::ABS_BEGIN));
        }
        case PointerEvent::POINTER_ACTION_AXIS_UPDATE: {
            return std::make_optional(static_cast<int32_t>(JsJoystickEvent::Action::ABS_UPDATE));
        }
        case PointerEvent::POINTER_ACTION_AXIS_END: {
            return std::make_optional(static_cast<int32_t>(JsJoystickEvent::Action::ABS_END));
        }
        default: {
            MMI_HILOGW("action:%{public}d is unknown", action);
            return std::nullopt;
        }
    }
}

int32_t JsInputMonitor::GetJoystickButton(int32_t buttonId)
{
    int32_t currentButtonId = -1;
    for (const auto &item : g_joystickButtonType) {
        if (buttonId == item.second) {
            currentButtonId = static_cast<int32_t>(item.first);
            break;
        }
    }
    return currentButtonId;
}

bool JsInputMonitor::GetJoystickPressedButtons(const std::set<int32_t>& pressedButtons, napi_value result)
{
    CALL_DEBUG_ENTER;
    napi_value value = nullptr;
    napi_status status = napi_create_array(jsEnv_, &value);
    if (status != napi_ok || value == nullptr) {
        THROWERR_CUSTOM(jsEnv_, COMMON_PARAMETER_ERROR, "napi_create_array is failed");
        return false;
    }
    uint32_t index = 0;
    for (const auto &item : pressedButtons) {
        int32_t buttonId = GetJoystickButton(item);
        napi_value element = nullptr;
        if (napi_create_int32(jsEnv_, buttonId, &element) != napi_ok) {
            THROWERR_CUSTOM(jsEnv_, COMMON_PARAMETER_ERROR, "Napi create int32 failed");
            return false;
        }
        status = napi_set_element(jsEnv_, value, index, element);
        if (status != napi_ok) {
            THROWERR_CUSTOM(jsEnv_, COMMON_PARAMETER_ERROR, "Napi set element failed");
            return false;
        }
        ++index;
    }
    if (SetNameProperty(jsEnv_, result, "pressedButtons", value) != napi_ok) {
        THROWERR_CUSTOM(jsEnv_, COMMON_PARAMETER_ERROR, "Set property of pressedButtons failed");
        return false;
    }
    return true;
}

int32_t JsInputMonitor::GetMousePointerItem(const std::shared_ptr<PointerEvent> pointerEvent, napi_value result)
{
    CALL_DEBUG_ENTER;
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    napi_value axes = nullptr;
    napi_status status = napi_create_array(jsEnv_, &axes);
    if (status != napi_ok || axes == nullptr) {
        THROWERR(jsEnv_, "napi_create_array is failed");
        return RET_ERR;
    }
    uint32_t index = 0;
    int32_t currentPointerId = pointerEvent->GetPointerId();
    std::vector<int32_t> pointerIds { pointerEvent->GetPointerIds() };
    for (const auto& pointerId : pointerIds) {
        if (pointerId == currentPointerId) {
            PointerEvent::PointerItem item;
            if (!pointerEvent->GetPointerItem(pointerId, item)) {
                MMI_HILOGE("Invalid pointer:%{public}d", pointerId);
                return RET_ERR;
            }
            if (SetNameProperty(jsEnv_, result, "id", currentPointerId) != napi_ok) {
                THROWERR(jsEnv_, "Set property of id failed");
                return false;
            }
            if (!SetMouseProperty(pointerEvent, item, result)) {
                MMI_HILOGE("Set property of mouse failed");
                return RET_ERR;
            }
        }
        napi_value element = nullptr;
        if (napi_create_object(jsEnv_, &element) != napi_ok) {
            THROWERR(jsEnv_, "napi_create_object is failed");
            return RET_ERR;
        }
        if (!GetAxesValue(pointerEvent, element)) {
            THROWERR(jsEnv_, "Get axesValue failed");
            return RET_ERR;
        }
        status = napi_set_element(jsEnv_, axes, index, element);
        if (status != napi_ok) {
            THROWERR(jsEnv_, "Napi set element in axes failed");
            return RET_ERR;
        }
        ++index;
    }
    if (SetNameProperty(jsEnv_, result, "axes", axes) != napi_ok) {
        THROWERR(jsEnv_, "Set property of axes failed");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t JsInputMonitor::GetJoystickPointerItem(const std::shared_ptr<PointerEvent> pointerEvent, napi_value result)
{
    CALL_DEBUG_ENTER;
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    napi_value axes = nullptr;
    napi_status status = napi_create_array(jsEnv_, &axes);
    if (status != napi_ok || axes == nullptr) {
        THROWERR_CUSTOM(jsEnv_, COMMON_PARAMETER_ERROR, "napi_create_array is failed");
        return RET_ERR;
    }

    int32_t currentPointerId = pointerEvent->GetPointerId();
    if (SetNameProperty(jsEnv_, result, "id", currentPointerId) != napi_ok) {
        THROWERR_CUSTOM(jsEnv_, COMMON_PARAMETER_ERROR, "Set property of id failed");
        return RET_ERR;
    }

    uint32_t index = 0;
    for (const auto &item : g_joystickAxisType) {
        if (!pointerEvent->HasAxis(item.second)) {
            continue;
        }
        double axisValue = pointerEvent->GetAxisValue(item.second);
        int32_t axis = static_cast<int32_t>(item.first);
        napi_value element = nullptr;
        if (napi_create_object(jsEnv_, &element) != napi_ok) {
            THROWERR_CUSTOM(jsEnv_, COMMON_PARAMETER_ERROR, "napi_create_object is failed");
            return RET_ERR;
        }

        if (SetNameProperty(jsEnv_, element, "axis", axis) != napi_ok) {
            THROWERR_CUSTOM(jsEnv_, COMMON_PARAMETER_ERROR, "Set property of axis failed");
            return RET_ERR;
        }
        if (SetNameProperty(jsEnv_, element, "value", axisValue) != napi_ok) {
            THROWERR_CUSTOM(jsEnv_, COMMON_PARAMETER_ERROR, "Set property of value failed");
            return RET_ERR;
        }

        status = napi_set_element(jsEnv_, axes, index, element);
        if (status != napi_ok) {
            THROWERR_CUSTOM(jsEnv_, COMMON_PARAMETER_ERROR, "Napi set element in axes failed");
            return RET_ERR;
        }
        ++index;
    }

    if (SetNameProperty(jsEnv_, result, "axes", axes) != napi_ok) {
        THROWERR_CUSTOM(jsEnv_, COMMON_PARAMETER_ERROR, "Set property of axes failed");
        return RET_ERR;
    }

    return RET_OK;
}


bool JsInputMonitor::GetPressedButtons(const std::set<int32_t>& pressedButtons, napi_value result)
{
    CALL_DEBUG_ENTER;
    napi_value value = nullptr;
    napi_status status = napi_create_array(jsEnv_, &value);
    if (status != napi_ok || value == nullptr) {
        THROWERR(jsEnv_, "napi_create_array is failed");
        return false;
    }
    uint32_t index = 0;
    for (const auto &item : pressedButtons) {
        int32_t buttonId = item;
        if (buttonId == PointerEvent::MOUSE_BUTTON_MIDDLE) {
            buttonId = MIDDLE;
        } else if (buttonId == PointerEvent::MOUSE_BUTTON_RIGHT) {
            buttonId = RIGHT;
        }
        napi_value element = nullptr;
        if (napi_create_int32(jsEnv_, buttonId, &element) != napi_ok) {
            THROWERR(jsEnv_, "Napi create int32 failed");
            return false;
        }
        status = napi_set_element(jsEnv_, value, index, element);
        if (status != napi_ok) {
            THROWERR(jsEnv_, "Napi set element failed");
            return false;
        }
        ++index;
    }
    if (SetNameProperty(jsEnv_, result, "pressedButtons", value) != napi_ok) {
        THROWERR(jsEnv_, "Set property of pressedButtons failed");
        return false;
    }
    return true;
}

bool JsInputMonitor::GetPressedKeys(const std::vector<int32_t>& pressedKeys, napi_value result)
{
    CALL_DEBUG_ENTER;
    napi_value value = nullptr;
    napi_status status = napi_create_array(jsEnv_, &value);
    if (status != napi_ok || value == nullptr) {
        THROWERR(jsEnv_, "napi_create_array is failed");
        return false;
    }
    uint32_t index = 0;
    for (const auto &it : pressedKeys) {
        napi_value element = nullptr;
        if (napi_create_int32(jsEnv_, it, &element) != napi_ok) {
            THROWERR(jsEnv_, "Napi create int32 failed");
            return false;
        }
        status = napi_set_element(jsEnv_, value, index, element);
        if (status != napi_ok) {
            THROWERR(jsEnv_, "Napi set element failed");
            return false;
        }
        ++index;
    }
    if (SetNameProperty(jsEnv_, result, "pressedKeys", value) != napi_ok) {
        THROWERR(jsEnv_, "Set property of pressedKeys failed");
        return false;
    }
    return true;
}

bool JsInputMonitor::HasKeyCode(const std::vector<int32_t>& pressedKeys, int32_t keyCode)
{
    return std::find(pressedKeys.begin(), pressedKeys.end(), keyCode) != pressedKeys.end();
}

bool JsInputMonitor::GetPressedKey(const std::vector<int32_t>& pressedKeys, napi_value result)
{
    CALL_DEBUG_ENTER;
    bool isExists = HasKeyCode(pressedKeys, KeyEvent::KEYCODE_CTRL_LEFT)
        || HasKeyCode(pressedKeys, KeyEvent::KEYCODE_CTRL_RIGHT);
    if (SetNameProperty(jsEnv_, result, "ctrlKey", isExists) != napi_ok) {
        THROWERR(jsEnv_, "Set ctrlKey with failed");
        return false;
    }
    isExists = HasKeyCode(pressedKeys, KeyEvent::KEYCODE_ALT_LEFT)
        || HasKeyCode(pressedKeys, KeyEvent::KEYCODE_ALT_RIGHT);
    if (SetNameProperty(jsEnv_, result, "altKey", isExists) != napi_ok) {
        THROWERR(jsEnv_, "Set altKey failed");
        return false;
    }
    isExists = HasKeyCode(pressedKeys, KeyEvent::KEYCODE_SHIFT_LEFT)
        || HasKeyCode(pressedKeys, KeyEvent::KEYCODE_SHIFT_RIGHT);
    if (SetNameProperty(jsEnv_, result, "shiftKey", isExists) != napi_ok) {
        THROWERR(jsEnv_, "Set shiftKey failed");
        return false;
    }
    isExists = HasKeyCode(pressedKeys, KeyEvent::KEYCODE_META_LEFT)
        || HasKeyCode(pressedKeys, KeyEvent::KEYCODE_META_RIGHT);
    if (SetNameProperty(jsEnv_, result, "logoKey", isExists) != napi_ok) {
        THROWERR(jsEnv_, "Set logoKey failed");
        return false;
    }
    isExists = HasKeyCode(pressedKeys, KeyEvent::KEYCODE_FN);
    if (SetNameProperty(jsEnv_, result, "fnKey", isExists) != napi_ok) {
        THROWERR(jsEnv_, "Set fnKey failed");
        return false;
    }
    return true;
}

int32_t JsInputMonitor::TransformTsActionValue(int32_t pointerAction)
{
    switch (pointerAction) {
        case PointerEvent::POINTER_ACTION_CANCEL: {
            return CANCEL;
        }
        case PointerEvent::POINTER_ACTION_MOVE:
        case PointerEvent::POINTER_ACTION_PULL_MOVE: {
            return MOVE;
        }
        case PointerEvent::POINTER_ACTION_BUTTON_DOWN:
        case PointerEvent::POINTER_ACTION_PULL_DOWN: {
            return BUTTON_DOWN;
        }
        case PointerEvent::POINTER_ACTION_BUTTON_UP:
        case PointerEvent::POINTER_ACTION_PULL_UP: {
            return BUTTON_UP;
        }
        case PointerEvent::POINTER_ACTION_AXIS_BEGIN: {
            return AXIS_BEGIN;
        }
        case PointerEvent::POINTER_ACTION_AXIS_UPDATE: {
            return AXIS_UPDATE;
        }
        case PointerEvent::POINTER_ACTION_AXIS_END: {
            return AXIS_END;
        }
        default: {
            MMI_HILOGD("Abnormal pointer action");
            return RET_ERR;
        }
    }
}

int32_t JsInputMonitor::TransformMousePointerEvent(std::shared_ptr<PointerEvent> pointerEvent, napi_value result)
{
    CALL_DEBUG_ENTER;
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    int32_t actionValue = TransformTsActionValue(pointerEvent->GetPointerAction());
    if (actionValue == RET_ERR) {
        MMI_HILOGD("Transform action value failed");
        return RET_ERR;
    }
    if (SetNameProperty(jsEnv_, result, "action", actionValue) != napi_ok) {
        MMI_HILOGE("Set property of action failed");
        return RET_ERR;
    }
    std::vector<int32_t> pressedKeys = pointerEvent->GetPressedKeys();
    if (!GetPressedKeys(pressedKeys, result)) {
        MMI_HILOGE("Get pressedButtons failed");
        return RET_ERR;
    }
    if (!GetPressedKey(pressedKeys, result)) {
        MMI_HILOGE("Get singlePressedKey failed");
        return RET_ERR;
    }
    if (GetMousePointerItem(pointerEvent, result) != RET_OK) {
        MMI_HILOGE("Get item of mousePointer failed");
        return RET_ERR;
    }
    std::set<int32_t> pressedButtons = pointerEvent->GetPressedButtons();
    if (!GetPressedButtons(pressedButtons, result)) {
        MMI_HILOGE("Get pressedKeys failed");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t JsInputMonitor::TransformJoystickPointerEvent(std::shared_ptr<PointerEvent> pointerEvent,
    napi_value result)
{
    CALL_DEBUG_ENTER;
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    int32_t pointerAction = pointerEvent->GetPointerAction();
    if (pointerAction <= 0) {
        MMI_HILOGE("GetPointerAction failed");
        return RET_ERR;
    }
    std::optional<int32_t> tempActionValue = GetJoystickAction(pointerAction);
    if (!tempActionValue) {
        MMI_HILOGE("Get joystick action value failed");
        return RET_ERR;
    }
    int32_t actionValue = tempActionValue.value();
    if (actionValue <= 0) {
        MMI_HILOGE("actionValue:%{public}d error", actionValue);
        return RET_ERR;
    }
    if (SetNameProperty(jsEnv_, result, "action", actionValue) != napi_ok) {
        MMI_HILOGE("Set property of action failed");
        return RET_ERR;
    }

    int32_t actionTime = pointerEvent->GetActionTime();
    if (SetNameProperty(jsEnv_, result, "actionTime", actionTime) != napi_ok) {
        THROWERR(jsEnv_, "Set actionTime failed");
        return RET_ERR;
    }

    int32_t deviceId = pointerEvent->GetDeviceId();
    if (SetNameProperty(jsEnv_, result, "deviceId", deviceId) != napi_ok) {
        THROWERR(jsEnv_, "Set deviceId failed");
        return RET_ERR;
    }

    int32_t buttonId = GetJoystickButton(pointerEvent->GetButtonId());
    if (SetNameProperty(jsEnv_, result, "button", buttonId) != napi_ok) {
        THROWERR(jsEnv_, "Set property of button failed");
        return RET_ERR;
    }

    if (GetJoystickPointerItem(pointerEvent, result) != RET_OK) {
        MMI_HILOGE("Get item of mousePointer failed");
        return RET_ERR;
    }

    std::set<int32_t> pressedButtons = pointerEvent->GetPressedButtons();
    if (!GetJoystickPressedButtons(pressedButtons, result)) {
        MMI_HILOGE("Get pressedKeys failed");
        return RET_ERR;
    }

    return RET_OK;
}

#ifdef OHOS_BUILD_ENABLE_FINGERPRINT
int32_t JsInputMonitor::TransformFingerprintEvent(const std::shared_ptr<PointerEvent> pointerEvent, napi_value result)
{
    CALL_DEBUG_ENTER;
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    int32_t actionValue = GetFingerprintAction(pointerEvent->GetPointerAction());
    if (actionValue == RET_ERR) {
        MMI_HILOGW("Get action value failed");
        return RET_ERR;
    }
    if (SetNameProperty(jsEnv_, result, "action", actionValue) != napi_ok) {
        MMI_HILOGW("Set name property failed");
        return RET_ERR;
    }
    if (SetNameProperty(jsEnv_, result, "distanceX", pointerEvent->GetFingerprintDistanceX()) != napi_ok) {
        MMI_HILOGW("Set distanceX property failed");
        return RET_ERR;
    }
    if (SetNameProperty(jsEnv_, result, "distanceY", pointerEvent->GetFingerprintDistanceY()) != napi_ok) {
        MMI_HILOGW("Set distanceY property failed");
        return RET_ERR;
    }
    MMI_HILOGD("jsfingerprint key:%{public}d, x:%{public}f, y:%{public}f", actionValue,
        pointerEvent->GetFingerprintDistanceX(), pointerEvent->GetFingerprintDistanceY());
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_FINGERPRINT

int32_t JsInputMonitor::Start()
{
    CALL_DEBUG_ENTER;
    CHKPF(monitor_);
    if (isMonitoring_) {
        MMI_HILOGW("Js is monitoring");
        return RET_OK;
    }
    int32_t ret = monitor_->Start();
    if (ret >= 0) {
        isMonitoring_ = true;
    }
    return ret;
}

JsInputMonitor::~JsInputMonitor()
{
    CALL_DEBUG_ENTER;
    if (isMonitoring_) {
        isMonitoring_ = false;
        if (monitor_ != nullptr) {
            monitor_->Stop();
        }
    }
    uint32_t refCount = 0;
    auto status = napi_reference_unref(jsEnv_, receiver_, &refCount);
    if (status != napi_ok) {
        THROWERR(jsEnv_, "napi_reference_unref is failed");
        return;
    }
}

void JsInputMonitor::Stop()
{
    CALL_DEBUG_ENTER;
    CHKPV(monitor_);
    if (isMonitoring_) {
        isMonitoring_ = false;
        if (monitor_ != nullptr) {
            monitor_->Stop();
        }
    }
}

int32_t JsInputMonitor::GetId() const
{
    return monitorId_;
}

int32_t JsInputMonitor::GetFingers() const
{
    return fingers_;
}

std::string JsInputMonitor::GetTypeName() const
{
    return typeName_;
}

void JsInputMonitor::OnPointerEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    if (!isMonitoring_) {
        MMI_HILOGE("Js monitor stop");
        return;
    }
    CHKPV(monitor_);
    CHKPV(pointerEvent);
    {
        std::lock_guard<std::mutex> guard(mutex_);
        if (!evQueue_.empty()) {
            if (IsBeginAndEnd(pointerEvent)) {
                std::queue<std::shared_ptr<PointerEvent>> tmp;
                std::swap(evQueue_, tmp);
            }
        }
        evQueue_.push(pointerEvent);
    }

    if (!evQueue_.empty()) {
        uv_work_t *work = new (std::nothrow) uv_work_t;
        CHKPV(work);
        MonitorInfo *monitorInfo = new (std::nothrow) MonitorInfo();
        if (monitorInfo == nullptr) {
            MMI_HILOGE("monitorInfo is nullptr");
            delete work;
            work = nullptr;
            return;
        }
        monitorInfo->monitorId = monitorId_;
        monitorInfo->fingers = fingers_;
        work->data = monitorInfo;
        uv_loop_s *loop = nullptr;
        auto status = napi_get_uv_event_loop(jsEnv_, &loop);
        if (status != napi_ok) {
            THROWERR(jsEnv_, "napi_get_uv_event_loop is failed");
            CleanData(&monitorInfo, &work);
            return;
        }
        int32_t ret = uv_queue_work_with_qos(
            loop, work,
            [](uv_work_t *work) {
                MMI_HILOGD("uv_queue_work callback function is called");
            },
            &JsInputMonitor::JsCallback, uv_qos_user_initiated);
        if (ret != 0) {
            MMI_HILOGE("add uv_queue failed, ret is %{public}d", ret);
            CleanData(&monitorInfo, &work);
        }
    }
}

bool JsInputMonitor::IsBeginAndEnd(std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPF(pointerEvent);
    bool res = pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_DOWN ||
        pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_UP ||
        pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_SWIPE_BEGIN ||
        pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_SWIPE_END;
    return res;
}

void JsInputMonitor::JsCallback(uv_work_t *work, int32_t status)
{
    CALL_DEBUG_ENTER;
    CHKPV(work);
    auto temp = static_cast<MonitorInfo*>(work->data);
    delete work;
    work = nullptr;
    auto jsMonitor { JS_INPUT_MONITOR_MGR.GetMonitor(temp->monitorId, temp->fingers) };
    CHKPV(jsMonitor);
    jsMonitor->OnPointerEventInJsThread(jsMonitor->GetTypeName(), temp->fingers);
    delete temp;
    temp = nullptr;
}

void JsInputMonitor::OnPointerEventInJsThread(const std::string &typeName, int32_t fingers)
{
    CALL_DEBUG_ENTER;
    {
        std::lock_guard<std::mutex> guard(mutex_);
        if (!isMonitoring_) {
            MMI_HILOGE("Js monitor stop");
            return;
        }
        CHKPV(jsEnv_);
        CHKPV(receiver_);
        while (!evQueue_.empty()) {
            if (!isMonitoring_) {
                MMI_HILOGE("Js monitor stop handle callback");
                break;
            }
            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(jsEnv_, &scope);
            CHKPV(scope);
            auto pointerEvent = evQueue_.front();
            if (pointerEvent == nullptr) {
                MMI_HILOGE("scope is nullptr");
                napi_close_handle_scope(jsEnv_, scope);
                continue;
            }
            evQueue_.pop();
            pointerQueue_.push(pointerEvent);
        }
    }
    std::lock_guard<std::mutex> guard(resourcemutex_);
    while (!pointerQueue_.empty()) {
        auto pointerEventItem = pointerQueue_.front();
        pointerQueue_.pop();
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(jsEnv_, &scope);
        CHKPV(scope);
        LogTracer lt(pointerEventItem->GetId(), pointerEventItem->GetEventType(), pointerEventItem->GetPointerAction());
        napi_value napiPointer = nullptr;
        CHECK_SCOPE_BEFORE_BREAK(jsEnv_, napi_create_object(jsEnv_, &napiPointer),
                                CREATE_OBJECT, scope, pointerEventItem);
        auto ret = RET_ERR;
        switch (TO_GESTURE_TYPE[typeName.c_str()]) {
            case TypeName::TOUCH: {
                ret = TransformPointerEvent(pointerEventItem, napiPointer);
                break;
            }
            case TypeName::MOUSE: {
                ret = TransformMousePointerEvent(pointerEventItem, napiPointer);
                break;
            }
            case TypeName::ROTATE: {
                if (!IsRotate(pointerEventItem)) {
                    napi_close_handle_scope(jsEnv_, scope);
                    continue;
                }
                ret = TransformRotateEvent(pointerEventItem, napiPointer);
                break;
            }
            case TypeName::PINCH: {
                if (!IsPinch(pointerEventItem, fingers)) {
                    napi_close_handle_scope(jsEnv_, scope);
                    continue;
                }
                ret = TransformPinchEvent(pointerEventItem, napiPointer);
                break;
            }
            case TypeName::THREE_FINGERS_SWIPE: {
                bool canUse = false;
                if (IsThreeFingersSwipe(pointerEventItem)) {
                    InputManager::GetInstance()->GetTouchpadThreeFingersTapSwitch(canUse);
                }
                if (!canUse) {
                    napi_close_handle_scope(jsEnv_, scope);
                    continue;
                }
                ret = TransformSwipeEvent(pointerEventItem, napiPointer);
                break;
            }
            case TypeName::FOUR_FINGERS_SWIPE: {
                if (!IsFourFingersSwipe(pointerEventItem)) {
                    napi_close_handle_scope(jsEnv_, scope);
                    continue;
                }
                ret = TransformSwipeEvent(pointerEventItem, napiPointer);
                break;
            }
            case TypeName::THREE_FINGERS_TAP: {
                bool canUse = false;
                InputManager::GetInstance()->GetTouchpadThreeFingersTapSwitch(canUse);
                if (canUse) {
                    ret = TransformMultiTapEvent(pointerEventItem, napiPointer);
                }
                break;
            }
            case TypeName::JOYSTICK:{
                if (!IsJoystick(pointerEventItem)) {
                    napi_close_handle_scope(jsEnv_, scope);
                    continue;
                }
                ret = TransformJoystickPointerEvent(pointerEventItem, napiPointer);
                break;
            }
            case TypeName::SWIPE_INWARD: {
                if (!IsSwipeInward(pointerEventItem)) {
                    napi_close_handle_scope(jsEnv_, scope);
                    continue;
                }
                ret = TransformSwipeInwardEvent(pointerEventItem, napiPointer);
                break;
            }
#ifdef OHOS_BUILD_ENABLE_FINGERPRINT
            case TypeName::FINGERPRINT: {
                if (!IsFingerprint(pointerEventItem)) {
                    napi_close_handle_scope(jsEnv_, scope);
                    continue;
                }
                ret = TransformFingerprintEvent(pointerEventItem, napiPointer);
                break;
            }
#endif // OHOS_BUILD_ENABLE_FINGERPRINT
            default: {
                MMI_HILOGE("This event is invalid");
                break;
            }
        }
        bool checkFlag = ret != RET_OK || napiPointer == nullptr;
        if (checkFlag) {
            napi_close_handle_scope(jsEnv_, scope);
            break;
        }
        napi_value callback = nullptr;
        CHECK_SCOPE_BEFORE_BREAK(jsEnv_, napi_get_reference_value(jsEnv_, receiver_, &callback),
            GET_REFERENCE_VALUE, scope, pointerEventItem);
        napi_value result = nullptr;
        if (monitor_->GetRectTotal() == 0
            || IsLocaledWithinRect(jsEnv_, napiPointer, monitor_->GetRectTotal(), monitor_->GetHotRectArea())) {
            CHECK_SCOPE_BEFORE_BREAK(jsEnv_, napi_call_function(jsEnv_, nullptr, callback, 1, &napiPointer, &result),
                CALL_FUNCTION, scope, pointerEventItem);
        }

        bool typeNameFlag = typeName == "touch" || typeName == "pinch" || typeName == "threeFingersSwipe" ||
            typeName == "fourFingersSwipe" || typeName == "rotate" || typeName == "threeFingersTap" ||
            typeName == "joystick" || typeName == "fingerprint" || typeName == "swipeInward";
        if (typeNameFlag) {
            if (pointerEventItem->GetPointerAction() != PointerEvent::POINTER_ACTION_SWIPE_UPDATE &&
                pointerEventItem->GetPointerAction() != PointerEvent::POINTER_ACTION_PULL_MOVE) {
                MMI_HILOGI("pointer:%{public}d,pointerAction:%{public}s", pointerEventItem->GetPointerId(),
                    pointerEventItem->DumpPointerAction());
            }
            bool retValue = false;
            CHKRV_SCOPE(jsEnv_, napi_get_value_bool(jsEnv_, result, &retValue), GET_VALUE_BOOL, scope);
            CheckConsumed(retValue, pointerEventItem);
        }
        napi_close_handle_scope(jsEnv_, scope);
    }
}

bool JsInputMonitor::IsLocaledWithinRect(napi_env env, napi_value napiPointer,
    uint32_t rectTotal, std::vector<Rect> hotRectArea)
{
    napi_value xProperty;
    CHKRF(napi_get_named_property(env, napiPointer, "screenX", &xProperty), GET_NAMED_PROPERTY);
    CHKPF(xProperty);
    int32_t xInt { 0 };
    CHKRF(napi_get_value_int32(env, xProperty, &xInt), GET_VALUE_INT32);

    napi_value yProperty;
    CHKRF(napi_get_named_property(env, napiPointer, "screenY", &yProperty), GET_NAMED_PROPERTY);
    CHKPF(yProperty);
    int32_t yInt { 0 };
    CHKRF(napi_get_value_int32(env, yProperty, &yInt), GET_VALUE_INT32);

    for (uint32_t i = 0; i < rectTotal; i++) {
        int32_t hotAreaX = hotRectArea.at(i).x;
        int32_t hotAreaY = hotRectArea.at(i).y;
        int32_t hotAreaWidth = hotRectArea.at(i).width;
        int32_t hotAreaHeight = hotRectArea.at(i).height;
        if ((xInt >= hotAreaX) && (xInt <= hotAreaX + hotAreaWidth)
            && (yInt >= hotAreaY) && (yInt <= hotAreaY + hotAreaHeight)) {
            return true;
        }
    }
    return false;
}

void JsInputMonitor::CheckConsumed(bool retValue, std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(pointerEvent);
    if (retValue) {
        auto eventId = pointerEvent->GetId();
        MarkConsumed(eventId);
    }
}

bool JsInputMonitor::IsPinch(std::shared_ptr<PointerEvent> pointerEvent, const int32_t fingers)
{
    CHKPF(pointerEvent);
    if ((fingers > 0 && ((pointerEvent->GetSourceType() != PointerEvent::SOURCE_TYPE_MOUSE &&
        pointerEvent->GetSourceType() != PointerEvent::SOURCE_TYPE_TOUCHPAD) ||
        pointerEvent->GetFingerCount() != fingers)) ||
        (fingers == 0 && (pointerEvent->GetSourceType() != PointerEvent::SOURCE_TYPE_TOUCHPAD ||
        pointerEvent->GetFingerCount() < THREE_FINGERS))) {
        return false;
    }
    if ((pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_AXIS_BEGIN &&
        pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_AXIS_UPDATE &&
        pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_AXIS_END)) {
        return false;
    }
    return true;
}

bool JsInputMonitor::IsRotate(std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPF(pointerEvent);
    if (pointerEvent->GetSourceType() != PointerEvent::SOURCE_TYPE_MOUSE ||
        (pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_ROTATE_BEGIN &&
        pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_ROTATE_UPDATE &&
        pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_ROTATE_END)) {
        return false;
    }
    return true;
}


bool JsInputMonitor::IsThreeFingersSwipe(std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPF(pointerEvent);
    if (pointerEvent->GetSourceType() != PointerEvent::SOURCE_TYPE_TOUCHPAD ||
        pointerEvent->GetFingerCount() != THREE_FINGERS ||
        (pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_SWIPE_BEGIN &&
        pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_SWIPE_UPDATE &&
        pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_SWIPE_END)) {
        return false;
    }
    return true;
}

bool JsInputMonitor::IsFourFingersSwipe(std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPF(pointerEvent);
    if (pointerEvent->GetSourceType() != PointerEvent::SOURCE_TYPE_TOUCHPAD ||
        pointerEvent->GetFingerCount() != FOUR_FINGERS ||
        (pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_SWIPE_BEGIN &&
        pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_SWIPE_UPDATE &&
        pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_SWIPE_END)) {
        return false;
    }
    return true;
}

bool JsInputMonitor::IsThreeFingersTap(std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPF(pointerEvent);
    if (pointerEvent->GetSourceType() != PointerEvent::SOURCE_TYPE_TOUCHPAD ||
        pointerEvent->GetFingerCount() != THREE_FINGERS ||
        (pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_TRIPTAP)) {
        return false;
    }
    return true;
}

bool JsInputMonitor::IsJoystick(std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPR(pointerEvent, ERROR_NULL_POINTER);

    return (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_JOYSTICK &&
        (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_BUTTON_UP ||
        pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_BUTTON_DOWN ||
        pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_AXIS_UPDATE));
}

bool JsInputMonitor::IsSwipeInward(std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPF(pointerEvent);
    if (pointerEvent->GetSourceType() != PointerEvent::SOURCE_TYPE_TOUCHPAD) {
        MMI_HILOGE("failed to do swipe inward, wrong source: %{public}d ", pointerEvent->GetSourceType());
        return false;
    } else if (pointerEvent->GetPointerCount() != ONE_FINGERS) {
        MMI_HILOGE("failed to do swipe inward, more than one finger");
        return false;
    } else if (pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_DOWN &&
        pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_MOVE &&
        pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_UP) {
        MMI_HILOGE("failed to do swipe inward, wrong action");
        return false;
    }
    return true;
}

bool JsInputMonitor::IsFingerprint(std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_FINGERPRINT &&
        (PointerEvent::POINTER_ACTION_FINGERPRINT_DOWN <= pointerEvent->GetPointerAction() &&
        pointerEvent->GetPointerAction() <= PointerEvent::POINTER_ACTION_FINGERPRINT_CLICK)) {
            return true;
    }
    MMI_HILOGD("not fingerprint event");
    return false;
}
} // namespace MMI
} // namespace OHOS
