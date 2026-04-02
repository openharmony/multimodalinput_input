/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "js_mouse_controller.h"

#include <mutex>

#include "define_multimodal.h"
#include "input_manager.h"
#include "js_register_module.h"
#include "mmi_log.h"
#include "util.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "JsMouseController"

namespace OHOS {
namespace MMI {

namespace {
// TODO: Add these error codes to ani_common.h or util_napi_error.h
// Error codes
constexpr int32_t ERROR_CODE_STATE_ERROR = 4300001;  // Button/axis state error
constexpr int32_t ERROR_CODE_DISPLAY_NOT_EXIST = 4300002;  // Display not exist

// Button mapping: JS enum -> PointerEvent constant
// Use JS_MOUSE_BUTTON_* constants from js_register_module.h
const std::map<int32_t, int32_t> JS_BUTTON_TO_NATIVE = {
    { JS_MOUSE_BUTTON_LEFT, PointerEvent::MOUSE_BUTTON_LEFT },
    { JS_MOUSE_BUTTON_MIDDLE, PointerEvent::MOUSE_BUTTON_MIDDLE },
    { JS_MOUSE_BUTTON_RIGHT, PointerEvent::MOUSE_BUTTON_RIGHT },
    { JS_MOUSE_BUTTON_SIDE, PointerEvent::MOUSE_BUTTON_SIDE },
    { JS_MOUSE_BUTTON_EXTRA, PointerEvent::MOUSE_BUTTON_EXTRA },
    { JS_MOUSE_BUTTON_FORWARD, PointerEvent::MOUSE_BUTTON_FORWARD },
    { JS_MOUSE_BUTTON_BACK, PointerEvent::MOUSE_BUTTON_BACK },
    { JS_MOUSE_BUTTON_TASK, PointerEvent::MOUSE_BUTTON_TASK }
};

// Axis mapping: JS enum -> PointerEvent AxisType
// Use JS_MOUSE_AXIS_* constants from js_register_module.h
const std::map<int32_t, PointerEvent::AxisType> JS_AXIS_TO_NATIVE = {
    { JS_MOUSE_AXIS_SCROLL_VERTICAL, PointerEvent::AXIS_TYPE_SCROLL_VERTICAL },
    { JS_MOUSE_AXIS_SCROLL_HORIZONTAL, PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL },
    { JS_MOUSE_AXIS_PINCH, PointerEvent::AXIS_TYPE_PINCH }
};

int32_t ConvertJsButtonToNative(int32_t jsButton)
{
    auto it = JS_BUTTON_TO_NATIVE.find(jsButton);
    if (it != JS_BUTTON_TO_NATIVE.end()) {
        return it->second;
    }
    MMI_HILOGW("Unknown JS button: %{public}d, using as-is", jsButton);
    return jsButton;
}

PointerEvent::AxisType ConvertJsAxisToNative(int32_t jsAxis)
{
    auto it = JS_AXIS_TO_NATIVE.find(jsAxis);
    if (it != JS_AXIS_TO_NATIVE.end()) {
        return it->second;
    }
    MMI_HILOGW("Unknown JS axis: %{public}d, using UNKNOWN", jsAxis);
    return PointerEvent::AXIS_TYPE_UNKNOWN;
}
} // namespace

JsMouseController::JsMouseController()
{
    MMI_HILOGD("JsMouseController created");
}

JsMouseController::~JsMouseController()
{
    MMI_HILOGD("JsMouseController destroying, cleaning up state");

    // Auto cleanup: Release all pressed buttons
    for (auto& [button, pressed] : buttonStates_) {
        if (!pressed) {
            continue;  // Skip unpressed buttons
        }

        MMI_HILOGW("Auto-releasing button %{public}d in destructor", button);

        // Directly create and inject BUTTON_UP event (bypass state validation)
        auto pointerEvent = CreatePointerEvent(PointerEvent::POINTER_ACTION_BUTTON_UP);
        if (pointerEvent == nullptr) {
            MMI_HILOGE("Failed to create pointer event for button %{public}d", button);
            continue;  // Continue trying to release other buttons
        }

        pointerEvent->SetTargetDisplayId(cursorPos_.displayId);
        int32_t nativeButton = ConvertJsButtonToNative(button);
        pointerEvent->SetButtonId(nativeButton);

        // Create and add pointer item
        PointerEvent::PointerItem item = CreatePointerItem();
        item.SetDownTime(buttonDownTimes_[button]);
        pointerEvent->AddPointerItem(item);

        int32_t ret = InjectPointerEvent(pointerEvent);
        if (ret != RET_OK) {
            MMI_HILOGE("Failed to auto-release button %{public}d, ret=%{public}d", button, ret);
            // Continue trying to release other buttons
        }
    }

    // Auto cleanup: End ongoing axis event
    if (!axisState_.inProgress) {
        // Ensure all state is cleared
        buttonStates_.clear();
        buttonDownTimes_.clear();
        return;  // No axis event in progress
    }

    MMI_HILOGW("Auto-ending axis %{public}d in destructor", axisState_.axisType);

    // Directly create and inject AXIS_END event (bypass state validation)
    auto pointerEvent = CreatePointerEvent(PointerEvent::POINTER_ACTION_AXIS_END);
    if (pointerEvent == nullptr) {
        MMI_HILOGE("Failed to create pointer event for axis %{public}d", axisState_.axisType);
        // Ensure all state is cleared
        buttonStates_.clear();
        buttonDownTimes_.clear();
        return;
    }

    pointerEvent->SetTargetDisplayId(cursorPos_.displayId);
    PointerEvent::AxisType nativeAxis = ConvertJsAxisToNative(axisState_.axisType);
    pointerEvent->SetAxisValue(nativeAxis, static_cast<double>(axisState_.lastValue));

    // Create and add pointer item (no downTime needed for axis events)
    PointerEvent::PointerItem item = CreatePointerItem();
    pointerEvent->AddPointerItem(item);

    int32_t ret = InjectPointerEvent(pointerEvent);
    if (ret != RET_OK) {
        MMI_HILOGE("Failed to auto-end axis %{public}d, ret=%{public}d", axisState_.axisType, ret);
    }

    // Ensure all state is cleared
    buttonStates_.clear();
    buttonDownTimes_.clear();
}

int32_t JsMouseController::MoveTo(int32_t displayId, int32_t x, int32_t y)
{
    MMI_HILOGD("MoveTo: displayId=%{public}d, x=%{public}d, y=%{public}d", displayId, x, y);

    // Validate and clamp coordinates
    if (!ValidateCoordinates(x, y, displayId)) {
        MMI_HILOGE("Invalid coordinates");
        return RET_ERR;
    }

    std::shared_ptr<PointerEvent> pointerEvent;

    // Lock scope: update position and create event
    {
        std::lock_guard<std::mutex> lock(mutex_);

        // Update internal cursor position
        cursorPos_.displayId = displayId;
        cursorPos_.x = x;
        cursorPos_.y = y;

        // Create MOVE event
        pointerEvent = CreatePointerEvent(PointerEvent::POINTER_ACTION_MOVE);
        if (pointerEvent == nullptr) {
            MMI_HILOGE("Failed to create pointer event");
            return RET_ERR;
        }

        // Set target display
        pointerEvent->SetTargetDisplayId(displayId);

        // Set down time: use earliest pressed button's time if any button is pressed
        int64_t downTime = !buttonDownTimes_.empty() ? buttonDownTimes_.begin()->second : -1;

        // Create and add pointer item
        PointerEvent::PointerItem item = CreatePointerItem();
        item.SetDownTime(downTime);
        pointerEvent->AddPointerItem(item);

        // Set pressed buttons state
        for (const auto& [button, pressed] : buttonStates_) {
            if (pressed) {
                int32_t nativeButton = ConvertJsButtonToNative(button);
                pointerEvent->SetButtonPressed(nativeButton);
            }
        }
    }
    // Lock released here

    // Inject event outside lock
    return InjectPointerEvent(pointerEvent);
}

int32_t JsMouseController::PressButton(int32_t button)
{
    MMI_HILOGD("PressButton: button=%{public}d", button);

    std::shared_ptr<PointerEvent> pointerEvent;

    // Lock scope: state check, modification, and event creation
    {
        std::lock_guard<std::mutex> lock(mutex_);

        // State validation: button must not be already pressed
        if (buttonStates_[button]) {
            MMI_HILOGE("Button %{public}d already pressed", button);
            return ERROR_CODE_STATE_ERROR;
        }

        // Update state and record down time
        buttonStates_[button] = true;
        buttonDownTimes_[button] = GetSysClockTime();

        // Create BUTTON_DOWN event
        pointerEvent = CreatePointerEvent(PointerEvent::POINTER_ACTION_BUTTON_DOWN);
        if (pointerEvent == nullptr) {
            MMI_HILOGE("Failed to create pointer event");
            buttonStates_[button] = false;  // Rollback state
            buttonDownTimes_.erase(button);
            return RET_ERR;
        }

        // Set target display
        pointerEvent->SetTargetDisplayId(cursorPos_.displayId);

        // Set button ID
        int32_t nativeButton = ConvertJsButtonToNative(button);
        pointerEvent->SetButtonId(nativeButton);

        // Set all pressed buttons state (including the current one)
        for (const auto& [btn, pressed] : buttonStates_) {
            if (pressed) {
                int32_t nativeBtn = ConvertJsButtonToNative(btn);
                pointerEvent->SetButtonPressed(nativeBtn);
            }
        }

        // Create and add pointer item
        PointerEvent::PointerItem item = CreatePointerItem();
        item.SetDownTime(buttonDownTimes_[button]);
        pointerEvent->AddPointerItem(item);
    }
    // Lock released here

    // Inject event outside lock
    int32_t ret = InjectPointerEvent(pointerEvent);
    if (ret != RET_OK) {
        // Rollback state on failure
        std::lock_guard<std::mutex> lock(mutex_);
        buttonStates_[button] = false;
        buttonDownTimes_.erase(button);
    }

    return ret;
}

int32_t JsMouseController::ReleaseButton(int32_t button)
{
    MMI_HILOGD("ReleaseButton: button=%{public}d", button);

    std::shared_ptr<PointerEvent> pointerEvent;
    int64_t downTime;

    // Lock scope: state check and event creation
    {
        std::lock_guard<std::mutex> lock(mutex_);

        // State validation: button must be pressed
        if (!buttonStates_[button]) {
            MMI_HILOGE("Button %{public}d not pressed", button);
            return ERROR_CODE_STATE_ERROR;
        }

        // Save down time before creating event
        downTime = buttonDownTimes_[button];

        // Create BUTTON_UP event
        pointerEvent = CreatePointerEvent(PointerEvent::POINTER_ACTION_BUTTON_UP);
        if (pointerEvent == nullptr) {
            MMI_HILOGE("Failed to create pointer event");
            return RET_ERR;
        }

        // Set target display
        pointerEvent->SetTargetDisplayId(cursorPos_.displayId);

        // Set button ID
        int32_t nativeButton = ConvertJsButtonToNative(button);
        pointerEvent->SetButtonId(nativeButton);

        // Set pressed buttons state (excluding the button being released)
        for (const auto& [btn, pressed] : buttonStates_) {
            if (pressed && btn != button) {
                int32_t nativeBtn = ConvertJsButtonToNative(btn);
                pointerEvent->SetButtonPressed(nativeBtn);
            }
        }

        // Create and add pointer item
        PointerEvent::PointerItem item = CreatePointerItem();
        item.SetDownTime(downTime);
        pointerEvent->AddPointerItem(item);
    }
    // Lock released here

    // Inject event outside lock
    int32_t ret = InjectPointerEvent(pointerEvent);
    if (ret == RET_OK) {
        // Update state after successful injection
        std::lock_guard<std::mutex> lock(mutex_);
        buttonStates_[button] = false;
        buttonDownTimes_.erase(button);
    }

    return ret;
}

int32_t JsMouseController::BeginAxis(int32_t axis, int32_t value)
{
    MMI_HILOGD("BeginAxis: axis=%{public}d, value=%{public}d", axis, value);

    std::shared_ptr<PointerEvent> pointerEvent;

    // Lock scope: state check, modification, and event creation
    {
        std::lock_guard<std::mutex> lock(mutex_);

        // State validation: no axis event should be in progress
        if (axisState_.inProgress) {
            MMI_HILOGE("Axis event already in progress: %{public}d", axisState_.axisType);
            return ERROR_CODE_STATE_ERROR;
        }

        // Update state
        axisState_.inProgress = true;
        axisState_.axisType = axis;
        axisState_.lastValue = value;

        // Create AXIS_BEGIN event
        pointerEvent = CreatePointerEvent(PointerEvent::POINTER_ACTION_AXIS_BEGIN);
        if (pointerEvent == nullptr) {
            MMI_HILOGE("Failed to create pointer event");
            axisState_.inProgress = false;  // Rollback state
            return RET_ERR;
        }

        // Set target display
        pointerEvent->SetTargetDisplayId(cursorPos_.displayId);

        // Set axis value
        PointerEvent::AxisType nativeAxis = ConvertJsAxisToNative(axis);
        pointerEvent->SetAxisValue(nativeAxis, static_cast<double>(value));

        // Create and add pointer item (no downTime needed for axis events)
        PointerEvent::PointerItem item = CreatePointerItem();
        pointerEvent->AddPointerItem(item);
    }
    // Lock released here

    // Inject event outside lock
    int32_t ret = InjectPointerEvent(pointerEvent);
    if (ret != RET_OK) {
        // Rollback state on failure
        std::lock_guard<std::mutex> lock(mutex_);
        axisState_.inProgress = false;
    }

    return ret;
}

int32_t JsMouseController::UpdateAxis(int32_t axis, int32_t value)
{
    MMI_HILOGD("UpdateAxis: axis=%{public}d, value=%{public}d", axis, value);

    std::shared_ptr<PointerEvent> pointerEvent;

    // Lock scope: state check, modification, and event creation
    {
        std::lock_guard<std::mutex> lock(mutex_);

        // State validation: axis event must be in progress
        if (!axisState_.inProgress) {
            MMI_HILOGE("No axis event in progress");
            return ERROR_CODE_STATE_ERROR;
        }

        // State validation: axis type must match
        if (axisState_.axisType != axis) {
            MMI_HILOGE("Axis type mismatch: expected %{public}d, got %{public}d",
                axisState_.axisType, axis);
            return ERROR_CODE_STATE_ERROR;
        }

        // Update state
        axisState_.lastValue = value;

        // Create AXIS_UPDATE event
        pointerEvent = CreatePointerEvent(PointerEvent::POINTER_ACTION_AXIS_UPDATE);
        if (pointerEvent == nullptr) {
            MMI_HILOGE("Failed to create pointer event");
            return RET_ERR;
        }

        // Set target display
        pointerEvent->SetTargetDisplayId(cursorPos_.displayId);

        // Set axis value
        PointerEvent::AxisType nativeAxis = ConvertJsAxisToNative(axis);
        pointerEvent->SetAxisValue(nativeAxis, static_cast<double>(value));

        // Create and add pointer item (no downTime needed for axis events)
        PointerEvent::PointerItem item = CreatePointerItem();
        pointerEvent->AddPointerItem(item);
    }
    // Lock released here

    // Inject event outside lock
    return InjectPointerEvent(pointerEvent);
}

int32_t JsMouseController::EndAxis(int32_t axis)
{
    MMI_HILOGD("EndAxis: axis=%{public}d", axis);

    std::shared_ptr<PointerEvent> pointerEvent;
    int32_t lastValue;

    // Lock scope: state check and event creation
    {
        std::lock_guard<std::mutex> lock(mutex_);

        // State validation: axis event must be in progress
        if (!axisState_.inProgress) {
            MMI_HILOGE("No axis event in progress");
            return ERROR_CODE_STATE_ERROR;
        }

        // State validation: axis type must match
        if (axisState_.axisType != axis) {
            MMI_HILOGE("Axis type mismatch: expected %{public}d, got %{public}d",
                axisState_.axisType, axis);
            return ERROR_CODE_STATE_ERROR;
        }

        // Save last value before creating event
        lastValue = axisState_.lastValue;

        // Create AXIS_END event
        pointerEvent = CreatePointerEvent(PointerEvent::POINTER_ACTION_AXIS_END);
        if (pointerEvent == nullptr) {
            MMI_HILOGE("Failed to create pointer event");
            return RET_ERR;
        }

        // Set target display
        pointerEvent->SetTargetDisplayId(cursorPos_.displayId);

        // Set axis value (use last value)
        PointerEvent::AxisType nativeAxis = ConvertJsAxisToNative(axis);
        pointerEvent->SetAxisValue(nativeAxis, static_cast<double>(lastValue));

        // Create and add pointer item (no downTime needed for axis events)
        PointerEvent::PointerItem item = CreatePointerItem();
        pointerEvent->AddPointerItem(item);
    }
    // Lock released here

    // Inject event outside lock
    int32_t ret = InjectPointerEvent(pointerEvent);
    if (ret == RET_OK) {
        // Clear state after successful injection
        std::lock_guard<std::mutex> lock(mutex_);
        axisState_.inProgress = false;
        axisState_.axisType = -1;
        axisState_.lastValue = 0;
    }

    return ret;
}

PointerEvent::PointerItem JsMouseController::CreatePointerItem()
{
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayX(cursorPos_.x);
    item.SetDisplayY(cursorPos_.y);
    item.SetDisplayXPos(cursorPos_.x);
    item.SetDisplayYPos(cursorPos_.y);
    item.SetToolType(PointerEvent::TOOL_TYPE_MOUSE);
    item.SetDeviceId(-1);
    return item;
}

std::shared_ptr<PointerEvent> JsMouseController::CreatePointerEvent(int32_t action)
{
    auto pointerEvent = PointerEvent::Create();
    if (pointerEvent == nullptr) {
        MMI_HILOGE("Failed to create PointerEvent");
        return nullptr;
    }

    // Set basic properties
    pointerEvent->SetPointerAction(action);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetDeviceId(-1);  // Virtual device (not from real hardware)

    // Set action time
    int64_t time = GetSysClockTime();
    pointerEvent->SetActionTime(time);

    // Mark as simulated/injected event
    pointerEvent->AddFlag(InputEvent::EVENT_FLAG_SIMULATE);

    // Note: SetTargetDisplayId() is set by each method individually

    return pointerEvent;
}

int32_t JsMouseController::InjectPointerEvent(std::shared_ptr<PointerEvent> event)
{
    if (event == nullptr) {
        MMI_HILOGE("PointerEvent is nullptr");
        return RET_ERR;
    }

    // Inject event using InputManager
    // Note: SimulateInputEvent returns void, so we assume success
    // Parameters:
    // - pointerEvent: the event to inject
    // - isAutoToVirtualScreen: false (we specify displayId explicitly)
    // - useCoordinate: DISPLAY_COORDINATE (use display coordinates)
    InputManager::GetInstance()->SimulateInputEvent(event, false, PointerEvent::DISPLAY_COORDINATE);

    return RET_OK;
}

bool JsMouseController::ValidateCoordinates(int32_t& x, int32_t& y, int32_t displayId)
{
    // Clamp negative coordinates to 0
    if (x < 0) {
        MMI_HILOGW("Clamping negative x coordinate: %{public}d -> 0", x);
        x = 0;
    }
    if (y < 0) {
        MMI_HILOGW("Clamping negative y coordinate: %{public}d -> 0", y);
        y = 0;
    }

    // TODO: Get screen size and clamp to screen boundaries
    // This requires calling DisplayManager API to get display dimensions
    // For now, we only clamp negative values
    // The service will validate displayId and return ERROR_CODE_DISPLAY_NOT_EXIST if invalid

    return true;
}

} // namespace MMI
} // namespace OHOS
