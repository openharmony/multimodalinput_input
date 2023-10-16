/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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
#include "napi_constants.h"
#include "util_napi_value.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "JsInputMonitor" };
constexpr int32_t AXIS_TYPE_SCROLL_VERTICAL = 0;
constexpr int32_t AXIS_TYPE_SCROLL_HORIZONTAL = 1;
constexpr int32_t AXIS_TYPE_PINCH = 2;
constexpr int32_t NAPI_ERR = 3;
constexpr int32_t CANCEL = 0;
constexpr int32_t MOVE = 1;
constexpr int32_t BUTTON_DOWN = 2;
constexpr int32_t BUTTON_UP = 3;
constexpr int32_t AXIS_BEGIN = 4;
constexpr int32_t AXIS_UPDATE = 5;
constexpr int32_t AXIS_END = 6;
constexpr int32_t MIDDLE = 1;
constexpr int32_t RIGHT = 2;
constexpr int32_t MOUSE_FLOW = 10;
constexpr int32_t THREE_FINGERS = 3;
constexpr int32_t FOUR_FINGERS = 4;
constexpr int32_t GESTURE_BEGIN = 1;
constexpr int32_t GESTURE_UPDATE = 2;
constexpr int32_t GESTURE_END = 3;
enum TypeName : int32_t {
    TOUCH = 0,
    MOUSE = 1,
    PINCH = 2,
    THREE_FINGERS_SWIPE = 3,
    FOUR_FINGERS_SWIPE = 4,
};
std::map<std::string, int32_t> TO_GESTURE_TYPE = {
    { "touch", TOUCH },
    { "mouse", MOUSE },
    { "pinch", PINCH },
    { "threeFingersSwipe", THREE_FINGERS_SWIPE },
    { "fourFingersSwipe", FOUR_FINGERS_SWIPE }
};
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

void InputMonitor::SetCallback(std::function<void(std::shared_ptr<PointerEvent>)> callback)
{
    std::lock_guard<std::mutex> guard(mutex_);
    callback_ = callback;
}

void InputMonitor::OnInputEvent(std::shared_ptr<PointerEvent> pointerEvent) const
{
    CALL_DEBUG_ENTER;
    CHKPV(pointerEvent);
    if (JsInputMonMgr.GetMonitor(id_) == nullptr) {
        MMI_HILOGE("Failed to process pointer event, id:%{public}d", id_);
        return;
    }
    if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_MOUSE
        && pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_MOVE) {
        if (++flowCtrl_ < MOUSE_FLOW) {
            pointerEvent->MarkProcessed();
            return;
        } else {
            flowCtrl_ = 0;
        }
    }
    std::function<void(std::shared_ptr<PointerEvent>)> callback;
    {
        std::lock_guard<std::mutex> guard(mutex_);
        if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_TOUCHSCREEN) {
            if (JsInputMonMgr.GetMonitor(id_)->GetTypeName() != "touch") {
                pointerEvent->MarkProcessed();
                return;
            }
            SetConsumeState(pointerEvent);
        }
        if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_MOUSE) {
            if (JsInputMonMgr.GetMonitor(id_)->GetTypeName() != "mouse") {
                return;
            }
            SetConsumeState(pointerEvent);
        }
        if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_TOUCHPAD) {
            if (!IsGestureEvent(pointerEvent)) {
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
    if (pointerEvent->GetPointerIds().size() == 1) {
        if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_DOWN) {
            consumed_ = false;
        }
    }
}

bool InputMonitor::IsGestureEvent(std::shared_ptr<PointerEvent> pointerEvent) const
{
    if (JsInputMonMgr.GetMonitor(id_)->GetTypeName() != "pinch" &&
        JsInputMonMgr.GetMonitor(id_)->GetTypeName() != "threeFingersSwipe" &&
        JsInputMonMgr.GetMonitor(id_)->GetTypeName() != "fourFingersSwipe") {
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

JsInputMonitor::JsInputMonitor(napi_env jsEnv, const std::string &typeName, napi_value callback, int32_t id)
    : monitor_(std::make_shared<InputMonitor>()),
      jsEnv_(jsEnv),
      typeName_(typeName),
      monitorId_(id)
{
    SetCallback(callback);
    if (monitor_ == nullptr) {
        MMI_HILOGE("The monitor is null");
        return;
    }
    monitor_->SetCallback([jsId = id](std::shared_ptr<PointerEvent> pointerEvent) {
        auto& jsMonitor {JsInputMonMgr.GetMonitor(jsId)};
        CHKPV(jsMonitor);
        jsMonitor->OnPointerEvent(pointerEvent);
    });
    monitor_->SetId(monitorId_);
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
    mapFunc["id"] = std::bind(&InputEvent::GetId, inputEvent);
    mapFunc["deviceId"] = std::bind(&InputEvent::GetDeviceId, inputEvent);
    mapFunc["actionTime"] = std::bind(&InputEvent::GetActionTime, inputEvent);
    mapFunc["screenId"] = std::bind(&InputEvent::GetTargetDisplayId, inputEvent);
    mapFunc["windowId"] = std::bind(&InputEvent::GetTargetWindowId, inputEvent);
    return mapFunc;
}

int32_t JsInputMonitor::SetInputEventProperty(const std::shared_ptr<InputEvent> inputEvent, napi_value result)
{
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

int32_t JsInputMonitor::TransformPinchEvent(const std::shared_ptr<PointerEvent> pointerEvent, napi_value result)
{
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    int32_t actionValue = GetPinchAction(pointerEvent->GetPointerAction());
    if (actionValue == RET_ERR) {
        MMI_HILOGE("Get action Value failed");
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
            MMI_HILOGE("Abnormal pointer action in pinch event");
            return RET_ERR;
        }
    }
}

int32_t JsInputMonitor::TransformSwipeEvent(const std::shared_ptr<PointerEvent> pointerEvent, napi_value result)
{
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    int32_t actionValue = GetSwipeAction(pointerEvent->GetPointerAction());
    if (actionValue == RET_ERR) {
        MMI_HILOGE("Get action Value failed");
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
            MMI_HILOGE("Abnormal pointer action in swipe event");
            return RET_ERR;
        }
    }
}

MapFun JsInputMonitor::GetFuns(const std::shared_ptr<PointerEvent> pointerEvent, const PointerEvent::PointerItem& item)
{
    MapFun mapFun;
    mapFun["actionTime"] = std::bind(&PointerEvent::GetActionTime, pointerEvent);
    mapFun["screenId"] = std::bind(&PointerEvent::GetTargetDisplayId, pointerEvent);
    mapFun["windowId"] = std::bind(&PointerEvent::GetTargetWindowId, pointerEvent);
    mapFun["deviceId"] = std::bind(&PointerEvent::PointerItem::GetDeviceId, item);
    mapFun["windowX"] = std::bind(&PointerEvent::PointerItem::GetWindowX, item);
    mapFun["windowY"] = std::bind(&PointerEvent::PointerItem::GetWindowY, item);
    mapFun["screenX"] = std::bind(&PointerEvent::PointerItem::GetDisplayX, item);
    mapFun["screenY"] = std::bind(&PointerEvent::PointerItem::GetDisplayY, item);
    mapFun["rawDeltaX"] = std::bind(&PointerEvent::PointerItem::GetRawDx, item);
    mapFun["rawDeltaY"] = std::bind(&PointerEvent::PointerItem::GetRawDy, item);
    return mapFun;
}

bool JsInputMonitor::SetMouseProperty(const std::shared_ptr<PointerEvent> pointerEvent,
    const PointerEvent::PointerItem& item, napi_value result)
{
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
            return false;
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
        case PointerEvent::POINTER_ACTION_BUTTON_DOWN: {
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
            MMI_HILOGE("Abnormal pointer action");
            return RET_ERR;
        }
    }
}

int32_t JsInputMonitor::TransformMousePointerEvent(const std::shared_ptr<PointerEvent> pointerEvent, napi_value result)
{
    CALL_DEBUG_ENTER;
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    int32_t actionValue = TransformTsActionValue(pointerEvent->GetPointerAction());
    if (actionValue == RET_ERR) {
        MMI_HILOGE("Transform Action Value failed");
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
            if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_DOWN ||
                pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_UP ||
                pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_AXIS_BEGIN ||
                pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_AXIS_END ||
                pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_SWIPE_BEGIN ||
                pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_SWIPE_END) {
                auto markProcessedEvent = evQueue_.front();
                CHKPV(markProcessedEvent);
                markProcessedEvent->MarkProcessed();
                std::queue<std::shared_ptr<PointerEvent>> tmp;
                std::swap(evQueue_, tmp);
                evQueue_.push(pointerEvent);
            }
        } else {
            evQueue_.push(pointerEvent);
        }
        jsTaskNum_ = 1;
    }

    if (!evQueue_.empty()) {
        int32_t *id = &monitorId_;
        uv_work_t *work = new (std::nothrow) uv_work_t;
        CHKPV(work);
        work->data = id;
        uv_loop_s *loop = nullptr;
        auto status = napi_get_uv_event_loop(jsEnv_, &loop);
        if (status != napi_ok) {
            THROWERR(jsEnv_, "napi_get_uv_event_loop is failed");
            delete work;
            {
                std::lock_guard<std::mutex> guard(mutex_);
                jsTaskNum_ = 0;
            }
            return;
        }
        uv_queue_work_with_qos(loop, work, [](uv_work_t *work) {}, &JsInputMonitor::JsCallback, uv_qos_user_initiated);
    }
}

void JsInputMonitor::JsCallback(uv_work_t *work, int32_t status)
{
    CALL_DEBUG_ENTER;
    CHKPV(work);
    int32_t *id = static_cast<int32_t *>(work->data);
    delete work;
    work = nullptr;
    auto& jsMonitor {JsInputMonMgr.GetMonitor(*id)};
    CHKPV(jsMonitor);
    jsMonitor->OnPointerEventInJsThread(jsMonitor->GetTypeName());
    id = nullptr;
}

void JsInputMonitor::OnPointerEventInJsThread(const std::string &typeName)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    jsTaskNum_ = 0;
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
        napi_value napiPointer = nullptr;
        CHECK_SCOPE_BEFORE_BREAK(jsEnv_, napi_create_object(jsEnv_, &napiPointer), CREATE_OBJECT, scope, pointerEvent);
        auto ret = RET_ERR;
        switch (TO_GESTURE_TYPE[typeName.c_str()]) {
            case TypeName::TOUCH: {
                ret = TransformPointerEvent(pointerEvent, napiPointer);
                break;
            }
            case TypeName::MOUSE: {
                ret = TransformMousePointerEvent(pointerEvent, napiPointer);
                break;
            }
            case TypeName::PINCH: {
                if (!IsPinch(pointerEvent)) {
                    MMI_HILOGE("This event is not pinchEvent");
                    napi_close_handle_scope(jsEnv_, scope);
                    continue;
                }
                ret = TransformPinchEvent(pointerEvent, napiPointer);
                break;
            }
            case TypeName::THREE_FINGERS_SWIPE: {
                if (!IsThreeFingersSwipe(pointerEvent)) {
                    MMI_HILOGE("This event is not three fingers swipeEvent");
                    napi_close_handle_scope(jsEnv_, scope);
                    continue;
                }
                ret = TransformSwipeEvent(pointerEvent, napiPointer);
                break;
            }
            case TypeName::FOUR_FINGERS_SWIPE: {
                if (!IsFourFingersSwipe(pointerEvent)) {
                    MMI_HILOGE("This event is not four fingers swipeEvent");
                    napi_close_handle_scope(jsEnv_, scope);
                    continue;
                }
                ret = TransformSwipeEvent(pointerEvent, napiPointer);
                break;
            }
            default: {
                MMI_HILOGE("This event is invalid");
                break;
            }
        }
        bool checkFlag = ret != RET_OK || napiPointer == nullptr;
        if (checkFlag) {
            pointerEvent->MarkProcessed();
            napi_close_handle_scope(jsEnv_, scope);
            break;
        }
        napi_value callback = nullptr;
        CHECK_SCOPE_BEFORE_BREAK(jsEnv_, napi_get_reference_value(jsEnv_, receiver_, &callback),
            GET_REFERENCE_VALUE, scope, pointerEvent);
        napi_value result = nullptr;
        CHECK_SCOPE_BEFORE_BREAK(jsEnv_, napi_call_function(jsEnv_, nullptr, callback, 1, &napiPointer, &result),
            CALL_FUNCTION, scope, pointerEvent);
        bool typeNameFlag = typeName == "touch" || typeName == "pinch" || typeName == "threeFingersSwipe" ||
            typeName == "fourFingersSwipe";
        if (typeNameFlag) {
            pointerEvent->MarkProcessed();
            bool retValue = false;
            CHKRV_SCOPE(jsEnv_, napi_get_value_bool(jsEnv_, result, &retValue), GET_VALUE_BOOL, scope);
            CheckConsumed(retValue, pointerEvent);
        }
        napi_close_handle_scope(jsEnv_, scope);
    }
}

void JsInputMonitor::CheckConsumed(bool retValue, std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    if (retValue) {
        auto eventId = pointerEvent->GetId();
        MarkConsumed(eventId);
    }
}

bool JsInputMonitor::IsPinch(std::shared_ptr<PointerEvent> pointerEvent)
{
    if (pointerEvent->GetSourceType() != PointerEvent::SOURCE_TYPE_TOUCHPAD ||
        (pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_AXIS_BEGIN &&
        pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_AXIS_UPDATE &&
        pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_AXIS_END)) {
        return false;
    }
    return true;
}

bool JsInputMonitor::IsThreeFingersSwipe(std::shared_ptr<PointerEvent> pointerEvent)
{
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
    if (pointerEvent->GetSourceType() != PointerEvent::SOURCE_TYPE_TOUCHPAD ||
        pointerEvent->GetFingerCount() != FOUR_FINGERS ||
        (pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_SWIPE_BEGIN &&
        pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_SWIPE_UPDATE &&
        pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_SWIPE_END)) {
        return false;
    }
    return true;
}
} // namespace MMI
} // namespace OHOS
