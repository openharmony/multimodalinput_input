/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "mouse_transform_processor.h"

#include <cinttypes>
#include <chrono>
#include <functional>

#include <linux/input-event-codes.h>

#include "define_multimodal.h"
#include "dfx_hisysevent.h"
#include "event_log_helper.h"
#include "i_input_windows_manager.h"
#include "i_pointer_drawing_manager.h"
#include "i_preference_manager.h"
#include "input_device_manager.h"
#include "input_event_handler.h"
#include "mouse_device_state.h"
#include "parameters.h"
#include "preferences.h"
#include "preferences_errno.h"
#include "preferences_helper.h"
#include "scene_board_judgement.h"
#include "timer_manager.h"
#include "touchpad_transform_processor.h"
#include "util.h"
#include "util_ex.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_DISPATCH
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "MouseTransformProcessor"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t MIN_SPEED { 1 };
constexpr int32_t MAX_SPEED { 11 };
constexpr int32_t DEFAULT_SPEED { 7 };
constexpr int32_t DEFAULT_TOUCHPAD_SPEED { 6 };
constexpr int32_t DEFAULT_ROWS { 3 };
constexpr int32_t MIN_ROWS { 1 };
constexpr int32_t MAX_ROWS { 100 };
constexpr int32_t BTN_RIGHT_MENUE_CODE { 0x118 };
constexpr int32_t RIGHT_CLICK_TYPE_MIN { 1 };
constexpr int32_t RIGHT_CLICK_TYPE_MAX { 3 };
constexpr int32_t TP_CLICK_FINGER_ONE { 1 };
constexpr int32_t TP_RIGHT_CLICK_FINGER_CNT { 2 };
constexpr int32_t HARD_HARDEN_DEVICE_WIDTH { 2880 };
constexpr int32_t HARD_HARDEN_DEVICE_HEIGHT { 1920 };
constexpr int32_t SOFT_HARDEN_DEVICE_WIDTH { 3120 };
constexpr int32_t SOFT_HARDEN_DEVICE_HEIGHT { 2080 };
const std::string DEVICE_TYPE_HARDEN { "HAD" };
const std::string PRODUCT_TYPE = OHOS::system::GetParameter("const.build.product", "HYM");
const std::string MOUSE_FILE_NAME { "mouse_settings.xml" };
const int32_t ROTATE_POLICY = system::GetIntParameter("const.window.device.rotate_policy", 0);
constexpr int32_t WINDOW_ROTATE { 0 };
constexpr int32_t WAIT_TIME_FOR_BUTTON_UP { 15 };
} // namespace

int32_t MouseTransformProcessor::globalPointerSpeed_ = DEFAULT_SPEED;

MouseTransformProcessor::MouseTransformProcessor(int32_t deviceId)
    : pointerEvent_(PointerEvent::Create()), deviceId_(deviceId)
{
    globalPointerSpeed_ = GetPointerSpeed();
}

std::shared_ptr<PointerEvent> MouseTransformProcessor::GetPointerEvent() const
{
    return pointerEvent_;
}

int32_t MouseTransformProcessor::HandleMotionInner(struct libinput_event_pointer* data, struct libinput_event* event)
{
    CALL_DEBUG_ENTER;
    CHKPR(data, ERROR_NULL_POINTER);
    CHKPR(pointerEvent_, ERROR_NULL_POINTER);
    pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent_->SetButtonId(buttonId_);

    CursorPosition cursorPos = WIN_MGR->GetCursorPos();
    if (cursorPos.displayId < 0) {
        MMI_HILOGE("No display");
        return RET_ERR;
    }
    unaccelerated_.dx = libinput_event_pointer_get_dx_unaccelerated(data);
    unaccelerated_.dy = libinput_event_pointer_get_dy_unaccelerated(data);

    Offset offset { unaccelerated_.dx, unaccelerated_.dy };
    auto displayInfo = WIN_MGR->GetPhysicalDisplay(cursorPos.displayId);
    CHKPR(displayInfo, ERROR_NULL_POINTER);
#ifndef OHOS_BUILD_EMULATOR
    if (ROTATE_POLICY == WINDOW_ROTATE && Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        CalculateOffset(displayInfo->direction, offset);
    }
#endif // OHOS_BUILD_EMULATOR
    const int32_t type = libinput_event_get_type(event);
    int32_t ret = RET_ERR;
    DeviceType deviceType = CheckDeviceType(displayInfo->width, displayInfo->height);
    if (type == LIBINPUT_EVENT_POINTER_MOTION_TOUCHPAD) {
        pointerEvent_->AddFlag(InputEvent::EVENT_FLAG_TOUCHPAD_POINTER);
        ret = HandleMotionAccelerateTouchpad(&offset, WIN_MGR->GetMouseIsCaptureMode(),
            &cursorPos.cursorPos.x, &cursorPos.cursorPos.y, GetTouchpadSpeed(), static_cast<int32_t>(deviceType));
    } else {
        pointerEvent_->ClearFlag(InputEvent::EVENT_FLAG_TOUCHPAD_POINTER);
        ret = HandleMotionAccelerateMouse(&offset, WIN_MGR->GetMouseIsCaptureMode(),
            &cursorPos.cursorPos.x, &cursorPos.cursorPos.y, globalPointerSpeed_, static_cast<int32_t>(deviceType));
    }
    if (ret != RET_OK) {
        MMI_HILOGE("Failed to handle motion correction");
        return ret;
    }
#ifdef OHOS_BUILD_EMULATOR
    cursorPos.cursorPos.x = offset.dx;
    cursorPos.cursorPos.y = offset.dy;
#endif // OHOS_BUILD_EMULATOR
    WIN_MGR->UpdateAndAdjustMouseLocation(cursorPos.displayId, cursorPos.cursorPos.x, cursorPos.cursorPos.y);
    pointerEvent_->SetTargetDisplayId(cursorPos.displayId);
    MMI_HILOGD("Change coordinate: x:%{public}.2f, y:%{public}.2f, currentDisplayId:%{public}d",
        cursorPos.cursorPos.x, cursorPos.cursorPos.y, cursorPos.displayId);
    return RET_OK;
}

void MouseTransformProcessor::CalculateOffset(Direction direction, Offset &offset)
{
    std::negate<double> neg;
    if (direction == DIRECTION90) {
        double tmp = offset.dx;
        offset.dx = offset.dy;
        offset.dy = neg(tmp);
    } else if (direction == DIRECTION180) {
        offset.dx = neg(offset.dx);
        offset.dy = neg(offset.dy);
    } else if (direction == DIRECTION270) {
        double tmp = offset.dx;
        offset.dx = neg(offset.dy);
        offset.dy = tmp;
    }
}

int32_t MouseTransformProcessor::HandleButtonInner(struct libinput_event_pointer* data, struct libinput_event* event)
{
    CALL_DEBUG_ENTER;
    CHKPR(data, ERROR_NULL_POINTER);
    CHKPR(event, ERROR_NULL_POINTER);
    CHKPR(pointerEvent_, ERROR_NULL_POINTER);
    MMI_HILOGD("Current action:%{public}d", pointerEvent_->GetPointerAction());

    uint32_t button = libinput_event_pointer_get_button(data);
    uint32_t originButton = button;
    const int32_t type = libinput_event_get_type(event);
    bool tpTapSwitch = true;
    GetTouchpadTapSwitch(tpTapSwitch);

    // touch pad tap switch is disable
    if (type == LIBINPUT_EVENT_POINTER_TAP && !tpTapSwitch) {
        MMI_HILOGD("Touch pad is disable");
        return RET_ERR;
    }

    TransTouchpadRightButton(data, type, button);

    if (button == MouseDeviceState::LIBINPUT_BUTTON_CODE::LIBINPUT_MIDDLE_BUTTON_CODE &&
        type == LIBINPUT_EVENT_POINTER_BUTTON_TOUCHPAD) {
        button = MouseDeviceState::LIBINPUT_BUTTON_CODE::LIBINPUT_LEFT_BUTTON_CODE;
    }

    auto ret = HandleButtonValueInner(data, button, type);
    if (ret != RET_OK) {
        MMI_HILOGE("The button value does not exist");
        return RET_ERR;
    }

    auto state = libinput_event_pointer_get_button_state(data);
    if (state == LIBINPUT_BUTTON_STATE_RELEASED) {
        int32_t switchTypeData = RIGHT_CLICK_TYPE_MIN;
        GetTouchpadRightClickType(switchTypeData);
        RightClickType switchType = RightClickType(switchTypeData);
        if (type == LIBINPUT_EVENT_POINTER_TAP && switchType == RightClickType::TP_TWO_FINGER_TAP &&
            button == MouseDeviceState::LIBINPUT_BUTTON_CODE::LIBINPUT_RIGHT_BUTTON_CODE) {
            MMI_HILOGD("Right click up, do sleep");
            std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_TIME_FOR_BUTTON_UP));
        }
        MouseState->MouseBtnStateCounts(button, BUTTON_STATE_RELEASED);
        pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_UP);
        int32_t buttonId = MouseState->LibinputChangeToPointer(button);
        pointerEvent_->DeleteReleaseButton(buttonId);
        DeletePressedButton(originButton);
        isPressed_ = false;
        buttonId_ = PointerEvent::BUTTON_NONE;
    } else if (state == LIBINPUT_BUTTON_STATE_PRESSED) {
        MouseState->MouseBtnStateCounts(button, BUTTON_STATE_PRESSED);
        pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_DOWN);
        int32_t buttonId = MouseState->LibinputChangeToPointer(button);
        pointerEvent_->SetButtonPressed(buttonId);
        buttonMapping_[originButton] = buttonId;
        isPressed_ = true;
        buttonId_ = pointerEvent_->GetButtonId();
    } else {
        MMI_HILOGE("Unknown state, state:%{public}u", state);
        return RET_ERR;
    }
    return RET_OK;
}

void MouseTransformProcessor::DeletePressedButton(uint32_t originButton)
{
    auto iter = buttonMapping_.find(originButton);
    if (iter != buttonMapping_.end()) {
        pointerEvent_->DeleteReleaseButton(iter->second);
        buttonMapping_.erase(iter);
    }
}

int32_t MouseTransformProcessor::HandleButtonValueInner(struct libinput_event_pointer *data, uint32_t button,
    int32_t type)
{
    CALL_DEBUG_ENTER;
    CHKPR(data, ERROR_NULL_POINTER);
    CHKPR(pointerEvent_, ERROR_NULL_POINTER);
    int32_t buttonId = MouseState->LibinputChangeToPointer(button);
    if (buttonId == PointerEvent::BUTTON_NONE) {
        MMI_HILOGE("Unknown btn, btn:%{public}u", button);
        return RET_ERR;
    }

    std::string name = "primaryButton";
    int32_t primaryButton = PREFERENCES_MGR->GetIntValue(name, 0);
    MMI_HILOGD("Set mouse primary button:%{public}d", primaryButton);
    if (type == LIBINPUT_EVENT_POINTER_BUTTON && primaryButton == RIGHT_BUTTON) {
        if (buttonId == PointerEvent::MOUSE_BUTTON_LEFT) {
            buttonId = PointerEvent::MOUSE_BUTTON_RIGHT;
        } else if (buttonId == PointerEvent::MOUSE_BUTTON_RIGHT) {
            buttonId = PointerEvent::MOUSE_BUTTON_LEFT;
        } else {
            MMI_HILOGD("buttonId does not switch");
        }
    }

    pointerEvent_->SetButtonId(buttonId);
    return RET_OK;
}

int32_t MouseTransformProcessor::SetMouseScrollRows(int32_t rows)
{
    CALL_DEBUG_ENTER;
    if (rows < MIN_ROWS) {
        rows = MIN_ROWS;
    } else if (rows > MAX_ROWS) {
        rows = MAX_ROWS;
    }
    std::string name = "rows";
    int32_t ret = PREFERENCES_MGR->SetIntValue(name, MOUSE_FILE_NAME, rows);
    MMI_HILOGD("Set mouse scroll rows successfully, rows:%{public}d", rows);
    return ret;
}

int32_t MouseTransformProcessor::GetMouseScrollRows()
{
    CALL_DEBUG_ENTER;
    std::string name = "rows";
    int32_t rows = PREFERENCES_MGR->GetIntValue(name, DEFAULT_ROWS);
    MMI_HILOGD("Get mouse scroll rows successfully, rows:%{public}d", rows);
    return rows;
}

void MouseTransformProcessor::HandleTouchPadAxisState(libinput_pointer_axis_source source,
    int32_t& direction, bool& tpScrollSwitch)
{
    bool scrollDirectionState = true;
    GetTouchpadScrollSwitch(tpScrollSwitch);
    GetTouchpadScrollDirection(scrollDirectionState);
    if (scrollDirectionState == true && source == LIBINPUT_POINTER_AXIS_SOURCE_FINGER) {
        direction = -1;
    }
}

int32_t MouseTransformProcessor::HandleAxisInner(struct libinput_event_pointer* data)
{
    CALL_DEBUG_ENTER;
    CHKPR(data, ERROR_NULL_POINTER);
    CHKPR(pointerEvent_, ERROR_NULL_POINTER);

    bool tpScrollSwitch = true;
    int32_t tpScrollDirection = 1;

    libinput_pointer_axis_source source = libinput_event_pointer_get_axis_source(data);
    HandleTouchPadAxisState(source, tpScrollDirection, tpScrollSwitch);
    if (!tpScrollSwitch && source == LIBINPUT_POINTER_AXIS_SOURCE_FINGER) {
        MMI_HILOGD("TouchPad axis event is disable");
        return RET_ERR;
    }

    if (buttonId_ == PointerEvent::BUTTON_NONE && pointerEvent_->GetButtonId() != PointerEvent::BUTTON_NONE) {
        pointerEvent_->SetButtonId(PointerEvent::BUTTON_NONE);
    }
    if (libinput_event_pointer_get_axis_source(data) == LIBINPUT_POINTER_AXIS_SOURCE_FINGER) {
        MMI_HILOGD("Libinput event axis source type is finger");
        if (!isAxisBegin_) {
            return RET_ERR;
        }
        pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_UPDATE);
    } else {
        if (TimerMgr->IsExist(timerId_)) {
            pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_UPDATE);
            TimerMgr->ResetTimer(timerId_);
            MMI_HILOGD("Axis update");
        } else {
            static constexpr int32_t timeout = 100;
            std::weak_ptr<MouseTransformProcessor> weakPtr = shared_from_this();
            timerId_ = TimerMgr->AddTimer(timeout, 1, [weakPtr]() {
                CALL_DEBUG_ENTER;
                auto sharedPtr = weakPtr.lock();
                CHKPV(sharedPtr);
                MMI_HILOGI("Timer:%{public}d", sharedPtr->timerId_);
                sharedPtr->timerId_ = -1;
                auto pointerEvent = sharedPtr->GetPointerEvent();
                CHKPV(pointerEvent);
                pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_END);
                pointerEvent->UpdateId();
                LogTracer lt(pointerEvent->GetId(), pointerEvent->GetEventType(), pointerEvent->GetPointerAction());
                auto inputEventNormalizeHandler = InputHandler->GetEventNormalizeHandler();
                CHKPV(inputEventNormalizeHandler);
                inputEventNormalizeHandler->HandlePointerEvent(pointerEvent);
            });

            pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_BEGIN);
            MMI_HILOGI("Axis begin");
        }
    }

    const int32_t initRows = 3;
    if (libinput_event_pointer_has_axis(data, LIBINPUT_POINTER_AXIS_SCROLL_VERTICAL)) {
        double axisValue = libinput_event_pointer_get_axis_value(data, LIBINPUT_POINTER_AXIS_SCROLL_VERTICAL);
        if (source == LIBINPUT_POINTER_AXIS_SOURCE_FINGER) {
            axisValue = TouchPadTransformProcessor::GetTouchpadScrollRows() * (axisValue / initRows)
                * tpScrollDirection;
            axisValue = HandleAxisAccelateTouchPad(axisValue) * tpScrollDirection;
        } else {
            axisValue = GetMouseScrollRows() * axisValue * tpScrollDirection;
        }
        pointerEvent_->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL, axisValue);
    }
    if (libinput_event_pointer_has_axis(data, LIBINPUT_POINTER_AXIS_SCROLL_HORIZONTAL)) {
        double axisValue = libinput_event_pointer_get_axis_value(data, LIBINPUT_POINTER_AXIS_SCROLL_HORIZONTAL);
        if (source == LIBINPUT_POINTER_AXIS_SOURCE_FINGER) {
            axisValue = TouchPadTransformProcessor::GetTouchpadScrollRows() * (axisValue / initRows)
                * tpScrollDirection;
            axisValue = HandleAxisAccelateTouchPad(axisValue) * tpScrollDirection;
        } else {
            axisValue = GetMouseScrollRows() * axisValue * tpScrollDirection;
        }
        pointerEvent_->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL, axisValue);
    }
    return RET_OK;
}

double MouseTransformProcessor::HandleAxisAccelateTouchPad(double axisValue)
{
    const int32_t initRows = 3;
    DeviceType deviceType = DeviceType::DEVICE_KLV;
    if (PRODUCT_TYPE == DEVICE_TYPE_HARDEN) {
        deviceType = DeviceType::DEVICE_SOFT_HARDEN;
    }
    int32_t ret =
        HandleAxisAccelerateTouchpad(WIN_MGR->GetMouseIsCaptureMode(), &axisValue, static_cast<int32_t>(deviceType));
    if (ret != RET_OK) {
        MMI_HILOGW("Fail accelerate axis");
        axisValue = GetMouseScrollRows() * (axisValue / initRows);
    }
    return axisValue;
}

int32_t MouseTransformProcessor::HandleAxisBeginEndInner(struct libinput_event *event)
{
    CALL_DEBUG_ENTER;
    CHKPR(event, ERROR_NULL_POINTER);
    CHKPR(pointerEvent_, ERROR_NULL_POINTER);
    if (buttonId_ == PointerEvent::BUTTON_NONE && pointerEvent_->GetButtonId() != PointerEvent::BUTTON_NONE) {
        pointerEvent_->SetButtonId(PointerEvent::BUTTON_NONE);
    }
    if (!isAxisBegin_ && isPressed_) {
        MMI_HILOGE("Axis is invalid");
        return RET_ERR;
    }
    if (isAxisBegin_ && isPressed_) {
        pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_END);
        isAxisBegin_ = false;
        MMI_HILOGD("Axis end due to a pressed event");
        return RET_OK;
    }
    if (libinput_event_get_type(event) == LIBINPUT_EVENT_TOUCHPAD_DOWN && !isPressed_) {
        pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_BEGIN);
        isAxisBegin_ = true;
        MMI_HILOGD("Axis begin");
        return RET_OK;
    }
    if (libinput_event_get_type(event) == LIBINPUT_EVENT_TOUCHPAD_UP && !isPressed_) {
        pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_END);
        isAxisBegin_ = false;
        MMI_HILOGD("Axis end");
        return RET_OK;
    }
    MMI_HILOGE("Axis is invalid");
    return RET_ERR;
}

void MouseTransformProcessor::HandleAxisPostInner(PointerEvent::PointerItem &pointerItem)
{
    CALL_DEBUG_ENTER;
    CHKPV(pointerEvent_);
    auto mouseInfo = WIN_MGR->GetMouseInfo();
    MouseState->SetMouseCoords(mouseInfo.physicalX, mouseInfo.physicalY);
    pointerItem.SetDisplayX(mouseInfo.physicalX);
    pointerItem.SetDisplayY(mouseInfo.physicalY);
    pointerItem.SetWindowX(0);
    pointerItem.SetWindowY(0);
    pointerItem.SetPointerId(0);
    pointerItem.SetPressed(isPressed_);
    int64_t time = GetSysClockTime();
    pointerItem.SetDownTime(time);
    pointerItem.SetWidth(0);
    pointerItem.SetHeight(0);
    pointerItem.SetPressure(0);
    pointerItem.SetToolType(PointerEvent::TOOL_TYPE_TOUCHPAD);
    pointerItem.SetDeviceId(deviceId_);
    pointerItem.SetRawDx(0);
    pointerItem.SetRawDy(0);
    pointerEvent_->UpdateId();
    StartLogTraceId(pointerEvent_->GetId(), pointerEvent_->GetEventType(), pointerEvent_->GetPointerAction());
    pointerEvent_->UpdatePointerItem(pointerEvent_->GetPointerId(), pointerItem);
    pointerEvent_->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent_->SetActionTime(time);
    pointerEvent_->SetActionStartTime(time);
    pointerEvent_->SetPointerId(0);
    pointerEvent_->SetDeviceId(deviceId_);
    pointerEvent_->SetTargetDisplayId(mouseInfo.displayId);
    pointerEvent_->SetTargetWindowId(-1);
    pointerEvent_->SetAgentWindowId(-1);
}

bool MouseTransformProcessor::HandlePostInner(struct libinput_event_pointer* data,
    PointerEvent::PointerItem &pointerItem)
{
    CALL_DEBUG_ENTER;
    CHKPF(data);
    CHKPF(pointerEvent_);
    auto mouseInfo = WIN_MGR->GetMouseInfo();
    MouseState->SetMouseCoords(mouseInfo.physicalX, mouseInfo.physicalY);
    pointerItem.SetDisplayX(mouseInfo.physicalX);
    pointerItem.SetDisplayY(mouseInfo.physicalY);
    pointerItem.SetWindowX(0);
    pointerItem.SetWindowY(0);
    pointerItem.SetPointerId(0);
    pointerItem.SetPressed(isPressed_);

    int64_t time = GetSysClockTime();
    pointerItem.SetDownTime(time);
    pointerItem.SetWidth(0);
    pointerItem.SetHeight(0);
    pointerItem.SetPressure(0);
    if (libinput_event_pointer_get_axis_source(data) == LIBINPUT_POINTER_AXIS_SOURCE_FINGER) {
        pointerItem.SetToolType(PointerEvent::TOOL_TYPE_TOUCHPAD);
        MMI_HILOGD("ToolType is touchpad");
    } else {
        pointerItem.SetToolType(PointerEvent::TOOL_TYPE_MOUSE);
    }
    pointerItem.SetDeviceId(deviceId_);
    pointerItem.SetRawDx(static_cast<int32_t>(unaccelerated_.dx));
    pointerItem.SetRawDy(static_cast<int32_t>(unaccelerated_.dy));

    pointerEvent_->UpdateId();
    StartLogTraceId(pointerEvent_->GetId(), pointerEvent_->GetEventType(), pointerEvent_->GetPointerAction());
    pointerEvent_->UpdatePointerItem(pointerEvent_->GetPointerId(), pointerItem);
    pointerEvent_->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent_->SetActionTime(time);
    pointerEvent_->SetActionStartTime(time);
    pointerEvent_->SetDeviceId(deviceId_);
    pointerEvent_->SetPointerId(0);
    pointerEvent_->SetTargetDisplayId(mouseInfo.displayId);
    pointerEvent_->SetTargetWindowId(-1);
    pointerEvent_->SetAgentWindowId(-1);
    return true;
}

bool MouseTransformProcessor::CheckAndPackageAxisEvent()
{
    CALL_INFO_TRACE;
    if (!isAxisBegin_) {
        return false;
    }
    pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_END);
    isAxisBegin_ = false;
    PointerEvent::PointerItem item;
    HandleAxisPostInner(item);
    WIN_MGR->UpdateTargetPointer(pointerEvent_);
    return true;
}

int32_t MouseTransformProcessor::Normalize(struct libinput_event *event)
{
    CALL_DEBUG_ENTER;
    CHKPR(event, ERROR_NULL_POINTER);
    CHKPR(pointerEvent_, ERROR_NULL_POINTER);
    const int32_t type = libinput_event_get_type(event);
    auto data = libinput_event_get_pointer_event(event);
    if (type != LIBINPUT_EVENT_TOUCHPAD_DOWN && type != LIBINPUT_EVENT_TOUCHPAD_UP) {
        CHKPR(data, ERROR_NULL_POINTER);
    }
    pointerEvent_->ClearAxisValue();
    int32_t result;
    switch (type) {
        case LIBINPUT_EVENT_POINTER_MOTION:
        case LIBINPUT_EVENT_POINTER_MOTION_ABSOLUTE:
        case LIBINPUT_EVENT_POINTER_MOTION_TOUCHPAD:
            result = HandleMotionInner(data, event);
            break;
        case LIBINPUT_EVENT_POINTER_TAP:
        case LIBINPUT_EVENT_POINTER_BUTTON:
        case LIBINPUT_EVENT_POINTER_BUTTON_TOUCHPAD:
            result = HandleButtonInner(data, event);
            break;
        case LIBINPUT_EVENT_POINTER_AXIS:
            result = HandleAxisInner(data);
            break;
        case LIBINPUT_EVENT_TOUCHPAD_DOWN:
        case LIBINPUT_EVENT_TOUCHPAD_UP:
            result = HandleAxisBeginEndInner(event);
            break;
        default:
            MMI_HILOGE("Unknown type:%{public}d", type);
            return RET_ERR;
    }
    if (result == RET_ERR) {
        return result;
    }
    PointerEvent::PointerItem pointerItem;
    if (type == LIBINPUT_EVENT_TOUCHPAD_DOWN || type == LIBINPUT_EVENT_TOUCHPAD_UP) {
        HandleAxisPostInner(pointerItem);
    } else if (!HandlePostInner(data, pointerItem)) {
        CHKPL(data);
        CHKPL(pointerEvent_);
        return RET_ERR;
    }
    WIN_MGR->UpdateTargetPointer(pointerEvent_);
    DumpInner();
    return result;
}

int32_t MouseTransformProcessor::NormalizeRotateEvent(struct libinput_event *event, int32_t type, double angle)
{
    CALL_DEBUG_ENTER;
    CHKPR(event, ERROR_NULL_POINTER);
    CHKPR(pointerEvent_, ERROR_NULL_POINTER);
    auto data = libinput_event_get_pointer_event(event);
    pointerEvent_->SetPointerAction(type);
    pointerEvent_->ClearAxisValue();
    pointerEvent_->SetAxisValue(PointerEvent::AXIS_TYPE_ROTATE, angle);
    PointerEvent::PointerItem pointerItem;
    if (!HandlePostInner(data, pointerItem)) {
        CHKPL(data);
        CHKPL(pointerEvent_);
        return ERROR_NULL_POINTER;
    }
    WIN_MGR->UpdateTargetPointer(pointerEvent_);
    DumpInner();
    return RET_OK;
}

#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
void MouseTransformProcessor::HandleMotionMoveMouse(int32_t offsetX, int32_t offsetY)
{
    CALL_DEBUG_ENTER;
    CHKPV(pointerEvent_);
    pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    CursorPosition cursorPos = WIN_MGR->GetCursorPos();
    cursorPos.cursorPos.x += offsetX;
    cursorPos.cursorPos.y += offsetY;
    WIN_MGR->UpdateAndAdjustMouseLocation(cursorPos.displayId, cursorPos.cursorPos.x, cursorPos.cursorPos.y);
}

void MouseTransformProcessor::OnDisplayLost(int32_t displayId)
{
    CursorPosition cursorPos = WIN_MGR->GetCursorPos();
    if (cursorPos.displayId != displayId) {
        cursorPos = WIN_MGR->ResetCursorPos();
        WIN_MGR->UpdateAndAdjustMouseLocation(cursorPos.displayId, cursorPos.cursorPos.x, cursorPos.cursorPos.y);
    }
}

int32_t MouseTransformProcessor::GetDisplayId()
{
    return WIN_MGR->GetCursorPos().displayId;
}

void MouseTransformProcessor::HandlePostMoveMouse(PointerEvent::PointerItem& pointerItem)
{
    CALL_DEBUG_ENTER;
    auto mouseInfo = WIN_MGR->GetMouseInfo();
    CHKPV(pointerEvent_);
    MouseState->SetMouseCoords(mouseInfo.physicalX, mouseInfo.physicalY);
    pointerItem.SetDisplayX(mouseInfo.physicalX);
    pointerItem.SetDisplayY(mouseInfo.physicalY);
    pointerItem.SetWindowX(0);
    pointerItem.SetWindowY(0);
    pointerItem.SetPointerId(0);
    pointerItem.SetPressed(isPressed_);

    int64_t time = GetSysClockTime();
    pointerItem.SetDownTime(time);
    pointerItem.SetWidth(0);
    pointerItem.SetHeight(0);
    pointerItem.SetPressure(0);

    pointerEvent_->UpdateId();
    StartLogTraceId(pointerEvent_->GetId(), pointerEvent_->GetEventType(), pointerEvent_->GetPointerAction());
    pointerEvent_->UpdatePointerItem(pointerEvent_->GetPointerId(), pointerItem);
    pointerEvent_->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent_->SetActionTime(time);
    pointerEvent_->SetActionStartTime(time);

    pointerEvent_->SetPointerId(0);
    pointerEvent_->SetTargetDisplayId(-1);
    pointerEvent_->SetTargetWindowId(-1);
    pointerEvent_->SetAgentWindowId(-1);
}

bool MouseTransformProcessor::NormalizeMoveMouse(int32_t offsetX, int32_t offsetY)
{
    CALL_DEBUG_ENTER;
    CHKPF(pointerEvent_);
    bool bHasPointerDevice = INPUT_DEV_MGR->HasPointerDevice();
    if (!bHasPointerDevice) {
        MMI_HILOGE("There hasn't any pointer device");
        return false;
    }

    PointerEvent::PointerItem pointerItem;
    HandleMotionMoveMouse(offsetX, offsetY);
    HandlePostMoveMouse(pointerItem);
    DumpInner();
    return bHasPointerDevice;
}
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING

void MouseTransformProcessor::DumpInner()
{
    EventLogHelper::PrintEventData(pointerEvent_, MMI_LOG_FREEZE);
    auto device = INPUT_DEV_MGR->GetInputDevice(pointerEvent_->GetDeviceId());
    CHKPV(device);
    aggregator_.Record(MMI_LOG_FREEZE, "Pointer event created by: " + device->GetName() + ", target window: " +
        std::to_string(pointerEvent_->GetTargetWindowId()) + ", action: " + pointerEvent_->DumpPointerAction(),
        std::to_string(pointerEvent_->GetId()));
}

DeviceType MouseTransformProcessor::CheckDeviceType(int32_t width, int32_t height)
{
    CALL_DEBUG_ENTER;
    DeviceType ret = DeviceType::DEVICE_KLV;
    if (PRODUCT_TYPE == DEVICE_TYPE_HARDEN) {
        if (width == HARD_HARDEN_DEVICE_WIDTH && height == HARD_HARDEN_DEVICE_HEIGHT) {
            ret = DeviceType::DEVICE_HARD_HARDEN;
        } else if (width == SOFT_HARDEN_DEVICE_WIDTH && height == SOFT_HARDEN_DEVICE_HEIGHT) {
            ret = DeviceType::DEVICE_SOFT_HARDEN;
        } else {
            MMI_HILOGE("Undefined width:%{public}d, height:%{public}d", width, height);
        }
        MMI_HILOGD("Device width:%{public}d, height:%{public}d", width, height);
    }
    return ret;
}

void MouseTransformProcessor::Dump(int32_t fd, const std::vector<std::string> &args)
{
    CALL_DEBUG_ENTER;
    PointerEvent::PointerItem item;
    CHKPV(pointerEvent_);
    pointerEvent_->GetPointerItem(pointerEvent_->GetPointerId(), item);
    mprintf(fd, "Mouse device state information:\t");
    mprintf(fd,
            "PointerId:%d | SourceType:%s | PointerAction:%s | WindowX:%d | WindowY:%d | ButtonId:%d "
            "| AgentWindowId:%d | TargetWindowId:%d | DownTime:%" PRId64 " | IsPressed:%s \t",
            pointerEvent_->GetPointerId(), pointerEvent_->DumpSourceType(), pointerEvent_->DumpPointerAction(),
            item.GetWindowX(), item.GetWindowY(), pointerEvent_->GetButtonId(), pointerEvent_->GetAgentWindowId(),
            pointerEvent_->GetTargetWindowId(), item.GetDownTime(), item.IsPressed() ? "true" : "false");
}

int32_t MouseTransformProcessor::SetMousePrimaryButton(int32_t primaryButton)
{
    CALL_DEBUG_ENTER;
    MMI_HILOGD("Set mouse primary button:%{public}d", primaryButton);
    std::string name = "primaryButton";
    PREFERENCES_MGR->SetIntValue(name, MOUSE_FILE_NAME, primaryButton);
    return RET_OK;
}

int32_t MouseTransformProcessor::GetMousePrimaryButton()
{
    CALL_DEBUG_ENTER;
    std::string name = "primaryButton";
    int32_t primaryButton = PREFERENCES_MGR->GetIntValue(name, 0);
    MMI_HILOGD("Set mouse primary button:%{public}d", primaryButton);
    return primaryButton;
}

int32_t MouseTransformProcessor::SetPointerSpeed(int32_t speed)
{
    CALL_DEBUG_ENTER;
    if (speed < MIN_SPEED) {
        speed = MIN_SPEED;
    } else if (speed > MAX_SPEED) {
        speed = MAX_SPEED;
    }
    globalPointerSpeed_ = speed;
    std::string name = "speed";
    int32_t ret = PREFERENCES_MGR->SetIntValue(name, MOUSE_FILE_NAME, speed);
    MMI_HILOGD("Set pointer speed successfully, speed:%{public}d", speed);
    return ret;
}

int32_t MouseTransformProcessor::GetPointerSpeed()
{
    std::string name = "speed";
    int32_t speed = PREFERENCES_MGR->GetIntValue(name, DEFAULT_SPEED);
    MMI_HILOGD("Pointer speed:%{public}d", speed);
    return speed;
}

int32_t MouseTransformProcessor::GetTouchpadSpeed()
{
    int32_t speed = DEFAULT_TOUCHPAD_SPEED;
    GetTouchpadPointerSpeed(speed);
    MMI_HILOGD("TouchPad pointer speed:%{public}d", speed);
    return speed;
}

int32_t MouseTransformProcessor::SetPointerLocation(int32_t x, int32_t y)
{
    MMI_HILOGI("SetPointerLocation x:%{public}d, y:%{public}d", x, y);
    CursorPosition cursorPos = WIN_MGR->GetCursorPos();
    if (cursorPos.displayId < 0) {
        MMI_HILOGE("No display");
        return RET_ERR;
    }
    cursorPos.cursorPos.x = x;
    cursorPos.cursorPos.y = y;

    WIN_MGR->UpdateAndAdjustMouseLocation(cursorPos.displayId, cursorPos.cursorPos.x, cursorPos.cursorPos.y, false);
    auto mouseLoc = WIN_MGR->GetMouseInfo();
    IPointerDrawingManager::GetInstance()->SetPointerLocation(mouseLoc.physicalX, mouseLoc.physicalY);
    return RET_OK;
}

void MouseTransformProcessor::HandleTouchpadRightButton(struct libinput_event_pointer *data, const int32_t evenType,
    uint32_t &button)
{
    // touchpad left click 280 -> 272
    if (button == BTN_RIGHT_MENUE_CODE) {
        button = MouseDeviceState::LIBINPUT_BUTTON_CODE::LIBINPUT_LEFT_BUTTON_CODE;
        return;
    }

    // touchpad two finger tap 273 -> 0
    if (button == MouseDeviceState::LIBINPUT_BUTTON_CODE::LIBINPUT_RIGHT_BUTTON_CODE &&
        evenType == LIBINPUT_EVENT_POINTER_TAP) {
        button = 0;
        return;
    }

    // touchpad two finger button 272 -> 0
    if (button == MouseDeviceState::LIBINPUT_BUTTON_CODE::LIBINPUT_LEFT_BUTTON_CODE &&
        evenType == LIBINPUT_EVENT_POINTER_BUTTON_TOUCHPAD) {
        return;
    }
}

void MouseTransformProcessor::HandleTouchpadLeftButton(struct libinput_event_pointer *data, const int32_t evenType,
    uint32_t &button)
{
    // touchpad left click 280 -> 273
    if (button == BTN_RIGHT_MENUE_CODE) {
        button = MouseDeviceState::LIBINPUT_BUTTON_CODE::LIBINPUT_RIGHT_BUTTON_CODE;
        return;
    }

    // touchpad right click 273 -> 272
    if (button == MouseDeviceState::LIBINPUT_BUTTON_CODE::LIBINPUT_RIGHT_BUTTON_CODE &&
        evenType != LIBINPUT_EVENT_POINTER_TAP) {
        button = MouseDeviceState::LIBINPUT_BUTTON_CODE::LIBINPUT_LEFT_BUTTON_CODE;
        return;
    }

    // touchpad two finger tap 273 -> 0
    if (button == MouseDeviceState::LIBINPUT_BUTTON_CODE::LIBINPUT_RIGHT_BUTTON_CODE &&
        evenType == LIBINPUT_EVENT_POINTER_TAP) {
        button = 0;
        return;
    }

    // touchpad two finger button 272 -> 0
    if (button == MouseDeviceState::LIBINPUT_BUTTON_CODE::LIBINPUT_LEFT_BUTTON_CODE &&
        evenType == LIBINPUT_EVENT_POINTER_BUTTON_TOUCHPAD) {
        return;
    }
}

void MouseTransformProcessor::HandleTouchpadTwoFingerButton(struct libinput_event_pointer *data, const int32_t evenType,
    uint32_t &button)
{
    // touchpad two finger button -> 273
    uint32_t fingerCount = libinput_event_pointer_get_finger_count(data);
    if (fingerCount == TP_RIGHT_CLICK_FINGER_CNT) {
        button = MouseDeviceState::LIBINPUT_BUTTON_CODE::LIBINPUT_RIGHT_BUTTON_CODE;
        return;
    }

    // touchpad right click 273 -> 272
    if (button == MouseDeviceState::LIBINPUT_BUTTON_CODE::LIBINPUT_RIGHT_BUTTON_CODE &&
        evenType == LIBINPUT_EVENT_POINTER_BUTTON_TOUCHPAD) {
        button = MouseDeviceState::LIBINPUT_BUTTON_CODE::LIBINPUT_LEFT_BUTTON_CODE;
        return;
    }

    // touchpad left click 280 -> 272
    if (button == BTN_RIGHT_MENUE_CODE) {
        button = MouseDeviceState::LIBINPUT_BUTTON_CODE::LIBINPUT_LEFT_BUTTON_CODE;
        return;
    }
}

void MouseTransformProcessor::TransTouchpadRightButton(struct libinput_event_pointer *data, const int32_t evenType,
    uint32_t &button)
{
    int32_t switchTypeData = RIGHT_CLICK_TYPE_MIN;
    GetTouchpadRightClickType(switchTypeData);

    RightClickType switchType = RightClickType(switchTypeData);
    if (evenType != LIBINPUT_EVENT_POINTER_TAP && evenType != LIBINPUT_EVENT_POINTER_BUTTON_TOUCHPAD) {
        MMI_HILOGE("Event not from touchpad");
        return;
    }

    switch (switchType) {
        case RightClickType::TP_RIGHT_BUTTON:
            HandleTouchpadRightButton(data, evenType, button);
            break;

        case RightClickType::TP_LEFT_BUTTON:
            HandleTouchpadLeftButton(data, evenType, button);
            break;

        case RightClickType::TP_TWO_FINGER_TAP:
            HandleTouchpadTwoFingerButton(data, evenType, button);
            break;
        default:
            MMI_HILOGD("Invalid type, switchType:%{public}d", switchType);
            break;
    }
}

int32_t MouseTransformProcessor::SetTouchpadScrollSwitch(bool switchFlag)
{
    std::string name = "scrollSwitch";
    if (PutConfigDataToDatabase(name, switchFlag) != RET_OK) {
        MMI_HILOGE("Failed to set scroll switch flag to mem, name:%s, switchFlag:%{public}d", name.c_str(), switchFlag);
        return RET_ERR;
    }
    DfxHisysevent::ReportTouchpadSettingState(DfxHisysevent::TOUCHPAD_SETTING_CODE::TOUCHPAD_SCROLL_SETTING,
        switchFlag);

    return RET_OK;
}

void MouseTransformProcessor::GetTouchpadScrollSwitch(bool &switchFlag)
{
    std::string name = "scrollSwitch";
    GetConfigDataFromDatabase(name, switchFlag);
}

int32_t MouseTransformProcessor::SetTouchpadScrollDirection(bool state)
{
    std::string name = "scrollDirection";
    if (PutConfigDataToDatabase(name, state) != RET_OK) {
        MMI_HILOGE("Failed to set scroll direct switch flag to mem");
        return RET_ERR;
    }

    DfxHisysevent::ReportTouchpadSettingState(DfxHisysevent::TOUCHPAD_SETTING_CODE::TOUCHPAD_SCROLL_DIR_SETTING,
        state);

    return RET_OK;
}

void MouseTransformProcessor::GetTouchpadScrollDirection(bool &state)
{
    std::string name = "scrollDirection";
    GetConfigDataFromDatabase(name, state);
}

int32_t MouseTransformProcessor::SetTouchpadTapSwitch(bool switchFlag)
{
    std::string name = "touchpadTap";
    if (PutConfigDataToDatabase(name, switchFlag) != RET_OK) {
        MMI_HILOGE("Failed to set scroll direct switch flag to mem");
        return RET_ERR;
    }

    DfxHisysevent::ReportTouchpadSettingState(DfxHisysevent::TOUCHPAD_SETTING_CODE::TOUCHPAD_TAP_SETTING,
        switchFlag);

    return RET_OK;
}

void MouseTransformProcessor::GetTouchpadTapSwitch(bool &switchFlag)
{
    std::string name = "touchpadTap";
    GetConfigDataFromDatabase(name, switchFlag);
}

int32_t MouseTransformProcessor::SetTouchpadPointerSpeed(int32_t speed)
{
    std::string name = "touchPadPointerSpeed";
    if (PutConfigDataToDatabase(name, speed) != RET_OK) {
        MMI_HILOGE("Failed to set touch pad pointer speed to mem");
        return RET_ERR;
    }

    DfxHisysevent::ReportTouchpadSettingState(DfxHisysevent::TOUCHPAD_SETTING_CODE::TOUCHPAD_POINTER_SPEED_SETTING,
        speed);

    return RET_OK;
}

void MouseTransformProcessor::GetTouchpadPointerSpeed(int32_t &speed)
{
    std::string name = "touchPadPointerSpeed";
    GetConfigDataFromDatabase(name, speed);
    speed = speed == 0 ? DEFAULT_TOUCHPAD_SPEED : speed;
    speed = speed < MIN_SPEED ? MIN_SPEED : speed;
    speed = speed > MAX_SPEED ? MAX_SPEED : speed;
}

int32_t MouseTransformProcessor::SetTouchpadRightClickType(int32_t type)
{
    std::string name = "rightMenuSwitch";
    if (PutConfigDataToDatabase(name, type) != RET_OK) {
        MMI_HILOGE("Failed to set right click type to mem");
        return RET_ERR;
    }
    DfxHisysevent::ReportTouchpadSettingState(DfxHisysevent::TOUCHPAD_SETTING_CODE::TOUCHPAD_RIGHT_CLICK_SETTING,
        type);
    return RET_OK;
}

void MouseTransformProcessor::GetTouchpadRightClickType(int32_t &type)
{
    std::string name = "rightMenuSwitch";
    GetConfigDataFromDatabase(name, type);

    if (type < RIGHT_CLICK_TYPE_MIN || type > RIGHT_CLICK_TYPE_MAX) {
        type = RIGHT_CLICK_TYPE_MIN;
    }
}

int32_t MouseTransformProcessor::PutConfigDataToDatabase(std::string &key, bool value)
{
    return PREFERENCES_MGR->SetBoolValue(key, MOUSE_FILE_NAME, value);
}

void MouseTransformProcessor::GetConfigDataFromDatabase(std::string &key, bool &value)
{
    value = PREFERENCES_MGR->GetBoolValue(key, true);
}

int32_t MouseTransformProcessor::PutConfigDataToDatabase(std::string &key, int32_t value)
{
    return PREFERENCES_MGR->SetIntValue(key, MOUSE_FILE_NAME, value);
}

void MouseTransformProcessor::GetConfigDataFromDatabase(std::string &key, int32_t &value)
{
    int32_t defaultValue = value;
    value = PREFERENCES_MGR->GetIntValue(key, defaultValue);
}
} // namespace MMI
} // namespace OHOS
