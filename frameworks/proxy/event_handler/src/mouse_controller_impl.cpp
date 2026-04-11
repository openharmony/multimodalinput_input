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

#include "mouse_controller_impl.h"

#include "define_multimodal.h"
#include "input_manager.h"
#include "mmi_log.h"
#include "util.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "MouseControllerImpl"

namespace OHOS {
namespace MMI {

namespace {
// Error codes
constexpr int32_t ERROR_CODE_STATE_ERROR = 4300001;  // Button/axis state error
constexpr int32_t ERROR_CODE_DISPLAY_NOT_EXIST = 4300002;  // Display not exist
} // namespace

MouseControllerImpl::MouseControllerImpl()
{
    MMI_HILOGD("MouseControllerImpl created");
}

MouseControllerImpl::~MouseControllerImpl()
{
    MMI_HILOGD("MouseControllerImpl destroying, cleaning up state");

    // Auto cleanup: Release all pressed buttons
    for (auto& [button, pressed] : buttonStates_) {
        if (!pressed) {
            continue;
        }

        MMI_HILOGW("Auto-releasing button %{public}d in destructor", button);

        auto pointerEvent = CreatePointerEvent(PointerEvent::POINTER_ACTION_BUTTON_UP);
        if (pointerEvent == nullptr) {
            MMI_HILOGE("Failed to create pointer event for button %{public}d", button);
            continue;
        }

        pointerEvent->SetTargetDisplayId(cursorPos_.displayId);
        pointerEvent->SetButtonId(button);

        PointerEvent::PointerItem item = CreatePointerItem();
        item.SetDownTime(buttonDownTimes_[button]);
        pointerEvent->AddPointerItem(item);

        int32_t ret = InjectPointerEvent(pointerEvent);
        if (ret != RET_OK) {
            MMI_HILOGE("Failed to auto-release button %{public}d, ret=%{public}d", button, ret);
        }
    }

    // Auto cleanup: End ongoing axis event
    if (!axisState_.inProgress) {
        buttonStates_.clear();
        buttonDownTimes_.clear();
        return;
    }

    MMI_HILOGW("Auto-ending axis %{public}d in destructor", axisState_.axisType);

    auto pointerEvent = CreatePointerEvent(PointerEvent::POINTER_ACTION_AXIS_END);
    if (pointerEvent == nullptr) {
        MMI_HILOGE("Failed to create pointer event for axis %{public}d", axisState_.axisType);
        buttonStates_.clear();
        buttonDownTimes_.clear();
        return;
    }

    pointerEvent->SetTargetDisplayId(cursorPos_.displayId);
    pointerEvent->SetAxisValue(static_cast<PointerEvent::AxisType>(axisState_.axisType),
                               static_cast<double>(axisState_.lastValue));

    PointerEvent::PointerItem item = CreatePointerItem();
    pointerEvent->AddPointerItem(item);

    int32_t ret = InjectPointerEvent(pointerEvent);
    if (ret != RET_OK) {
        MMI_HILOGE("Failed to auto-end axis %{public}d, ret=%{public}d", axisState_.axisType, ret);
    }

    buttonStates_.clear();
    buttonDownTimes_.clear();
}

int32_t MouseControllerImpl::MoveTo(int32_t displayId, int32_t x, int32_t y)
{
    MMI_HILOGD("MoveTo: displayId=%{public}d, x=%{public}d, y=%{public}d", displayId, x, y);

    std::shared_ptr<PointerEvent> pointerEvent;

    {
        std::lock_guard<std::mutex> lock(mutex_);

        cursorPos_.displayId = displayId;
        cursorPos_.x = x;
        cursorPos_.y = y;

        pointerEvent = CreatePointerEvent(PointerEvent::POINTER_ACTION_MOVE);
        if (pointerEvent == nullptr) {
            MMI_HILOGE("Failed to create pointer event");
            return RET_ERR;
        }

        pointerEvent->SetTargetDisplayId(displayId);

        int64_t downTime = !buttonDownTimes_.empty() ? buttonDownTimes_.begin()->second : -1;

        PointerEvent::PointerItem item = CreatePointerItem();
        item.SetDownTime(downTime);
        pointerEvent->AddPointerItem(item);

        for (const auto& [button, pressed] : buttonStates_) {
            if (pressed) {
                pointerEvent->SetButtonPressed(button);
            }
        }
    }

    return InjectPointerEvent(pointerEvent);
}

int32_t MouseControllerImpl::PressButton(int32_t button)
{
    MMI_HILOGD("PressButton: button=%{public}d", button);

    std::shared_ptr<PointerEvent> pointerEvent;

    {
        std::lock_guard<std::mutex> lock(mutex_);

        if (buttonStates_[button]) {
            MMI_HILOGE("Button %{public}d already pressed", button);
            return ERROR_CODE_STATE_ERROR;
        }

        buttonStates_[button] = true;
        buttonDownTimes_[button] = GetSysClockTime();

        pointerEvent = CreatePointerEvent(PointerEvent::POINTER_ACTION_BUTTON_DOWN);
        if (pointerEvent == nullptr) {
            MMI_HILOGE("Failed to create pointer event");
            buttonStates_[button] = false;
            buttonDownTimes_.erase(button);
            return RET_ERR;
        }

        pointerEvent->SetTargetDisplayId(cursorPos_.displayId);
        pointerEvent->SetButtonId(button);

        for (const auto& [btn, pressed] : buttonStates_) {
            if (pressed) {
                pointerEvent->SetButtonPressed(btn);
            }
        }

        PointerEvent::PointerItem item = CreatePointerItem();
        item.SetDownTime(buttonDownTimes_[button]);
        pointerEvent->AddPointerItem(item);
    }

    int32_t ret = InjectPointerEvent(pointerEvent);
    if (ret != RET_OK) {
        std::lock_guard<std::mutex> lock(mutex_);
        buttonStates_[button] = false;
        buttonDownTimes_.erase(button);
    }

    return ret;
}

int32_t MouseControllerImpl::ReleaseButton(int32_t button)
{
    MMI_HILOGD("ReleaseButton: button=%{public}d", button);

    std::shared_ptr<PointerEvent> pointerEvent;
    int64_t downTime;

    {
        std::lock_guard<std::mutex> lock(mutex_);

        if (!buttonStates_[button]) {
            MMI_HILOGE("Button %{public}d not pressed", button);
            return ERROR_CODE_STATE_ERROR;
        }

        downTime = buttonDownTimes_[button];

        pointerEvent = CreatePointerEvent(PointerEvent::POINTER_ACTION_BUTTON_UP);
        if (pointerEvent == nullptr) {
            MMI_HILOGE("Failed to create pointer event");
            return RET_ERR;
        }

        pointerEvent->SetTargetDisplayId(cursorPos_.displayId);
        pointerEvent->SetButtonId(button);

        for (const auto& [btn, pressed] : buttonStates_) {
            if (pressed && btn != button) {
                pointerEvent->SetButtonPressed(btn);
            }
        }

        PointerEvent::PointerItem item = CreatePointerItem();
        item.SetDownTime(downTime);
        pointerEvent->AddPointerItem(item);
    }

    int32_t ret = InjectPointerEvent(pointerEvent);
    if (ret == RET_OK) {
        std::lock_guard<std::mutex> lock(mutex_);
        buttonStates_[button] = false;
        buttonDownTimes_.erase(button);
    }

    return ret;
}

int32_t MouseControllerImpl::BeginAxis(int32_t axis, int32_t value)
{
    MMI_HILOGD("BeginAxis: axis=%{public}d, value=%{public}d", axis, value);

    std::shared_ptr<PointerEvent> pointerEvent;

    {
        std::lock_guard<std::mutex> lock(mutex_);

        if (axisState_.inProgress) {
            MMI_HILOGE("Axis event already in progress: %{public}d", axisState_.axisType);
            return ERROR_CODE_STATE_ERROR;
        }

        axisState_.inProgress = true;
        axisState_.axisType = axis;
        axisState_.lastValue = value;

        pointerEvent = CreatePointerEvent(PointerEvent::POINTER_ACTION_AXIS_BEGIN);
        if (pointerEvent == nullptr) {
            MMI_HILOGE("Failed to create pointer event");
            axisState_.inProgress = false;
            return RET_ERR;
        }

        pointerEvent->SetTargetDisplayId(cursorPos_.displayId);
        pointerEvent->SetAxisValue(static_cast<PointerEvent::AxisType>(axis), static_cast<double>(value));

        PointerEvent::PointerItem item = CreatePointerItem();
        pointerEvent->AddPointerItem(item);
    }

    int32_t ret = InjectPointerEvent(pointerEvent);
    if (ret != RET_OK) {
        std::lock_guard<std::mutex> lock(mutex_);
        axisState_.inProgress = false;
    }

    return ret;
}

int32_t MouseControllerImpl::UpdateAxis(int32_t axis, int32_t value)
{
    MMI_HILOGD("UpdateAxis: axis=%{public}d, value=%{public}d", axis, value);

    std::shared_ptr<PointerEvent> pointerEvent;

    {
        std::lock_guard<std::mutex> lock(mutex_);

        if (!axisState_.inProgress) {
            MMI_HILOGE("No axis event in progress");
            return ERROR_CODE_STATE_ERROR;
        }

        if (axisState_.axisType != axis) {
            MMI_HILOGE("Axis type mismatch: expected %{public}d, got %{public}d",
                axisState_.axisType, axis);
            return ERROR_CODE_STATE_ERROR;
        }

        axisState_.lastValue = value;

        pointerEvent = CreatePointerEvent(PointerEvent::POINTER_ACTION_AXIS_UPDATE);
        if (pointerEvent == nullptr) {
            MMI_HILOGE("Failed to create pointer event");
            return RET_ERR;
        }

        pointerEvent->SetTargetDisplayId(cursorPos_.displayId);
        pointerEvent->SetAxisValue(static_cast<PointerEvent::AxisType>(axis), static_cast<double>(value));

        PointerEvent::PointerItem item = CreatePointerItem();
        pointerEvent->AddPointerItem(item);
    }

    return InjectPointerEvent(pointerEvent);
}

int32_t MouseControllerImpl::EndAxis(int32_t axis)
{
    MMI_HILOGD("EndAxis: axis=%{public}d", axis);

    std::shared_ptr<PointerEvent> pointerEvent;
    int32_t lastValue;

    {
        std::lock_guard<std::mutex> lock(mutex_);

        if (!axisState_.inProgress) {
            MMI_HILOGE("No axis event in progress");
            return ERROR_CODE_STATE_ERROR;
        }

        if (axisState_.axisType != axis) {
            MMI_HILOGE("Axis type mismatch: expected %{public}d, got %{public}d",
                axisState_.axisType, axis);
            return ERROR_CODE_STATE_ERROR;
        }

        lastValue = axisState_.lastValue;

        pointerEvent = CreatePointerEvent(PointerEvent::POINTER_ACTION_AXIS_END);
        if (pointerEvent == nullptr) {
            MMI_HILOGE("Failed to create pointer event");
            return RET_ERR;
        }

        pointerEvent->SetTargetDisplayId(cursorPos_.displayId);
        pointerEvent->SetAxisValue(static_cast<PointerEvent::AxisType>(axis), static_cast<double>(lastValue));

        PointerEvent::PointerItem item = CreatePointerItem();
        pointerEvent->AddPointerItem(item);
    }

    int32_t ret = InjectPointerEvent(pointerEvent);
    if (ret == RET_OK) {
        std::lock_guard<std::mutex> lock(mutex_);
        axisState_.inProgress = false;
        axisState_.axisType = -1;
        axisState_.lastValue = 0;
    }

    return ret;
}

PointerEvent::PointerItem MouseControllerImpl::CreatePointerItem()
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

std::shared_ptr<PointerEvent> MouseControllerImpl::CreatePointerEvent(int32_t action)
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

    int64_t time = GetSysClockTime();
    pointerEvent->SetActionTime(time);

    pointerEvent->AddFlag(InputEvent::EVENT_FLAG_SIMULATE);

    // moveTo events use Controller-maintained coordinates
    // Button/Axis events use current system cursor position (server-side calibration)
    bool isMoveTo = (action == PointerEvent::POINTER_ACTION_MOVE);

    if (!isMoveTo) {
        pointerEvent->AddFlag(InputEvent::EVENT_FLAG_CALIBRATE_POSITION);
        MMI_HILOGD("Setting calibration flag for action=%{public}d", action);
    }

    return pointerEvent;
}

int32_t MouseControllerImpl::InjectPointerEvent(std::shared_ptr<PointerEvent> event)
{
    if (event == nullptr) {
        MMI_HILOGE("PointerEvent is nullptr");
        return RET_ERR;
    }

    // Add Controller Flag to mark this event uses CONTROL_DEVICE permission check
    event->AddFlag(InputEvent::EVENT_FLAG_CONTROLLER);

    InputManager::GetInstance()->SimulateInputEvent(event, false, PointerEvent::DISPLAY_COORDINATE);

    return RET_OK;
}

} // namespace MMI
} // namespace OHOS
