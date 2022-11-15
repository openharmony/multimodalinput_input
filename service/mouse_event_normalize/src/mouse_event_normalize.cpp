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

#include "mouse_event_normalize.h"

#include <cinttypes>

#include "input-event-codes.h"

#include "define_multimodal.h"
#include "event_log_helper.h"
#include "i_pointer_drawing_manager.h"
#include "input_device_manager.h"
#include "input_event_handler.h"
#include "input_windows_manager.h"
#include "mouse_device_state.h"
#include "timer_manager.h"
#include "util_ex.h"
#include "util.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "MouseEventNormalize" };
const std::vector<AccelerateCurve> ACCELERATE_CURVES {
    { { 8, 32, 128 }, { 0.16, 0.30, 0.56 }, { 0.0, -1.12, -9.44 } },
    { { 8, 32, 128 }, { 0.32, 0.60, 1.12 }, { 0.0, -2.24, -18.88 } },
    { { 8, 32, 128 }, { 0.48, 0.90, 1.68 }, { 0.0, -3.36, -28.32 } },
    { { 8, 32, 128 }, { 0.64, 1.20, 2.24 }, { 0.0, -4.48, -37.76 } },
    { { 8, 32, 128 }, { 0.80, 1.50, 2.80 }, { 0.0, -5.60, -47.20 } },
    { { 8, 32, 128 }, { 0.86, 1.95, 3.64 }, { 0.0, -8.72, -62.80 } },
    { { 8, 32, 128 }, { 0.92, 2.40, 4.48 }, { 0.0, -11.84, -78.40 } },
    { { 8, 32, 128 }, { 0.98, 2.85, 5.32 }, { 0.0, -14.96, -94.00 } },
    { { 8, 32, 128 }, { 1.04, 3.30, 6.16 }, { 0.0, -18.08, -109.60 } },
    { { 8, 32, 128 }, { 1.10, 3.75, 7.00 }, { 0.0, -21.20, -125.20 } },
    { { 8, 32, 128 }, { 1.16, 4.20, 7.84 }, { 0.0, -24.32, -140.80 } }
    };
constexpr double DOUBLE_ZERO = 1e-6;
constexpr int32_t MIN_SPEED = 1;
constexpr int32_t MAX_SPEED = 11;
#ifdef OHOS_BUILD_ENABLE_COOPERATE
constexpr double PERCENT_CONST = 100.0;
#endif // OHOS_BUILD_ENABLE_COOPERATE
} // namespace
MouseEventNormalize::MouseEventNormalize()
{
    pointerEvent_ = PointerEvent::Create();
    CHKPL(pointerEvent_);
}

MouseEventNormalize::~MouseEventNormalize() {}

std::shared_ptr<PointerEvent> MouseEventNormalize::GetPointerEvent() const
{
    return pointerEvent_;
}

bool MouseEventNormalize::GetSpeedGain(double vin, double &gain) const
{
    if (fabs(vin) < DOUBLE_ZERO) {
        MMI_HILOGE("The value of the parameter passed in is 0");
        return false;
    }
    if (speed_ < 1) {
        MMI_HILOGE("The speed value can't be less than 1");
        return false;
    }
    const AccelerateCurve& curve = ACCELERATE_CURVES[speed_ - 1];
    int32_t num = static_cast<int32_t>(ceil(fabs(vin)));
    for (size_t i = 0; i < curve.speeds.size(); ++i) {
        if (num <= curve.speeds[i]) {
            gain = (curve.slopes[i] * vin + curve.diffNums[i]) / vin;
            return true;
        }
    }
    gain = (curve.slopes.back() * vin + curve.diffNums.back()) / vin;
    return true;
}

int32_t MouseEventNormalize::HandleMotionInner(struct libinput_event_pointer* data)
{
    CALL_DEBUG_ENTER;
    CHKPR(data, ERROR_NULL_POINTER);
    CHKPR(pointerEvent_, ERROR_NULL_POINTER);
    pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent_->SetButtonId(buttonId_);

    InitAbsolution();
    if (currentDisplayId_ == -1) {
        absolutionX_ = -1;
        absolutionY_ = -1;
        MMI_HILOGI("The currentDisplayId_ is -1");
        return RET_ERR;
    }

    int32_t ret = HandleMotionAccelerate(data);
    if (ret != RET_OK) {
        MMI_HILOGE("Failed to handle motion correction");
        return ret;
    }
    WinMgr->UpdateAndAdjustMouseLocation(currentDisplayId_, absolutionX_, absolutionY_);
    pointerEvent_->SetTargetDisplayId(currentDisplayId_);
    MMI_HILOGD("Change coordinate: x:%{public}lf, y:%{public}lf, currentDisplayId_:%{public}d",
        absolutionX_, absolutionY_, currentDisplayId_);
    return RET_OK;
}

int32_t MouseEventNormalize::HandleMotionAccelerate(struct libinput_event_pointer* data)
{
    CHKPR(data, ERROR_NULL_POINTER);
    double dx = libinput_event_pointer_get_dx(data);
    double dy = libinput_event_pointer_get_dy(data);
    double vin = (fmax(abs(dx), abs(dy)) + fmin(abs(dx), abs(dy))) / 2.0;
    double gain { 0.0 };
    if (!GetSpeedGain(vin, gain)) {
        MMI_HILOGE("Get speed gain failed");
        return RET_ERR;
    }
    double correctionX = dx * gain;
    double correctionY = dy * gain;
    MMI_HILOGD("Get and process the movement coordinates, dx:%{public}lf, dy:%{public}lf,"
               "correctionX:%{public}lf, correctionY:%{public}lf, gain:%{public}lf",
               dx, dy, correctionX, correctionY, gain);
    absolutionX_ += correctionX;
    absolutionY_ += correctionY;
    return RET_OK;
}

void MouseEventNormalize::InitAbsolution()
{
    if (absolutionX_ != -1 || absolutionY_ != -1 || currentDisplayId_ != -1) {
        return;
    }
    MMI_HILOGD("Init absolution");
    auto dispalyGroupInfo = WinMgr->GetDisplayGroupInfo();
    if (dispalyGroupInfo.displaysInfo.empty()) {
        MMI_HILOGI("The displayInfo is empty");
        return;
    }
    currentDisplayId_ = dispalyGroupInfo.displaysInfo[0].id;
    absolutionX_ = dispalyGroupInfo.displaysInfo[0].width * 1.0 / 2;
    absolutionY_ = dispalyGroupInfo.displaysInfo[0].height * 1.0 / 2;
}

int32_t MouseEventNormalize::HandleButtonInner(struct libinput_event_pointer* data)
{
    CALL_DEBUG_ENTER;
    CHKPR(data, ERROR_NULL_POINTER);
    MMI_HILOGD("Current action:%{public}d", pointerEvent_->GetPointerAction());

    auto ret = HandleButtonValueInner(data);
    if (ret != RET_OK) {
        MMI_HILOGE("The button value does not exist");
        return RET_ERR;
    }
    uint32_t button = libinput_event_pointer_get_button(data);
    auto state = libinput_event_pointer_get_button_state(data);
    if (state == LIBINPUT_BUTTON_STATE_RELEASED) {
        MouseState->MouseBtnStateCounts(button, BUTTON_STATE_RELEASED);
        pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_UP);
        int32_t buttonId = MouseState->LibinputChangeToPointer(button);
        pointerEvent_->DeleteReleaseButton(buttonId);
        isPressed_ = false;
        buttonId_ = PointerEvent::BUTTON_NONE;
    } else if (state == LIBINPUT_BUTTON_STATE_PRESSED) {
        MouseState->MouseBtnStateCounts(button, BUTTON_STATE_PRESSED);
        pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_DOWN);
        int32_t buttonId = MouseState->LibinputChangeToPointer(button);
        pointerEvent_->SetButtonPressed(buttonId);
        isPressed_ = true;
        buttonId_ = pointerEvent_->GetButtonId();
    } else {
        MMI_HILOGE("Unknown state, state:%{public}u", state);
        return RET_ERR;
    }
    return RET_OK;
}

int32_t MouseEventNormalize::HandleButtonValueInner(struct libinput_event_pointer* data)
{
    CALL_DEBUG_ENTER;
    CHKPR(data, ERROR_NULL_POINTER);

    uint32_t button = libinput_event_pointer_get_button(data);
    int32_t buttonId = MouseState->LibinputChangeToPointer(button);
    if (buttonId == PointerEvent::BUTTON_NONE) {
        MMI_HILOGE("Unknown btn, btn:%{public}u", button);
        return RET_ERR;
    }
    pointerEvent_->SetButtonId(buttonId);
    return RET_OK;
}

int32_t MouseEventNormalize::HandleAxisInner(struct libinput_event_pointer* data)
{
    CALL_DEBUG_ENTER;
    CHKPR(data, ERROR_NULL_POINTER);
    if (buttonId_ == PointerEvent::BUTTON_NONE && pointerEvent_->GetButtonId() != PointerEvent::BUTTON_NONE) {
        pointerEvent_->SetButtonId(PointerEvent::BUTTON_NONE);
    }
    if (TimerMgr->IsExist(timerId_)) {
        pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_UPDATE);
        TimerMgr->ResetTimer(timerId_);
        MMI_HILOGD("Axis update");
    } else {
        static constexpr int32_t timeout = 100;
        std::weak_ptr<MouseEventNormalize> weakPtr = shared_from_this();
        timerId_ = TimerMgr->AddTimer(timeout, 1, [weakPtr]() {
            CALL_DEBUG_ENTER;
            auto sharedPtr = weakPtr.lock();
            CHKPV(sharedPtr);
            MMI_HILOGD("timer:%{public}d", sharedPtr->timerId_);
            sharedPtr->timerId_ = -1;
            auto pointerEvent = sharedPtr->GetPointerEvent();
            CHKPV(pointerEvent);
            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_END);
            pointerEvent->UpdateId();
            auto inputEventNormalizeHandler = InputHandler->GetEventNormalizeHandler();
            CHKPV(inputEventNormalizeHandler);
            inputEventNormalizeHandler->HandlePointerEvent(pointerEvent);
        });

        pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_BEGIN);
        MMI_HILOGD("Axis begin");
    }

    if (libinput_event_pointer_has_axis(data, LIBINPUT_POINTER_AXIS_SCROLL_VERTICAL)) {
        double axisValue = libinput_event_pointer_get_axis_value(data, LIBINPUT_POINTER_AXIS_SCROLL_VERTICAL);
        pointerEvent_->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL, axisValue);
    }
    if (libinput_event_pointer_has_axis(data, LIBINPUT_POINTER_AXIS_SCROLL_HORIZONTAL)) {
        double axisValue = libinput_event_pointer_get_axis_value(data, LIBINPUT_POINTER_AXIS_SCROLL_HORIZONTAL);
        pointerEvent_->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL, axisValue);
    }
    return RET_OK;
}

void MouseEventNormalize::HandlePostInner(struct libinput_event_pointer* data, int32_t deviceId,
    PointerEvent::PointerItem &pointerItem)
{
    CALL_DEBUG_ENTER;
    CHKPV(data);
    auto mouseInfo = WinMgr->GetMouseInfo();
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
    pointerItem.SetToolType(PointerEvent::TOOL_TYPE_FINGER);
    pointerItem.SetDeviceId(deviceId);
#ifdef OHOS_BUILD_ENABLE_COOPERATE
    SetDxDyForDInput(pointerItem, data);
#endif // OHOS_BUILD_ENABLE_COOPERATE
    pointerEvent_->UpdateId();
    pointerEvent_->UpdatePointerItem(pointerEvent_->GetPointerId(), pointerItem);
    pointerEvent_->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent_->SetActionTime(time);
    pointerEvent_->SetActionStartTime(time);
    pointerEvent_->SetDeviceId(deviceId);
    pointerEvent_->SetPointerId(0);
    pointerEvent_->SetTargetDisplayId(currentDisplayId_);
    pointerEvent_->SetTargetWindowId(-1);
    pointerEvent_->SetAgentWindowId(-1);
}

int32_t MouseEventNormalize::Normalize(struct libinput_event *event)
{
    CALL_DEBUG_ENTER;
    CHKPR(event, ERROR_NULL_POINTER);
    auto data = libinput_event_get_pointer_event(event);
    CHKPR(data, ERROR_NULL_POINTER);
    CHKPR(pointerEvent_, ERROR_NULL_POINTER);
    pointerEvent_->ClearAxisValue();
    int32_t result;
    const int32_t type = libinput_event_get_type(event);
    switch (type) {
        case LIBINPUT_EVENT_POINTER_MOTION:
        case LIBINPUT_EVENT_POINTER_MOTION_ABSOLUTE: {
            result = HandleMotionInner(data);
            break;
        }
        case LIBINPUT_EVENT_POINTER_BUTTON: {
            result = HandleButtonInner(data);
            break;
        }
        case LIBINPUT_EVENT_POINTER_AXIS: {
            result = HandleAxisInner(data);
            break;
        }
        default: {
            MMI_HILOGE("Unknow type:%{public}d", type);
            return RET_ERR;
        }
    }
    int32_t deviceId = InputDevMgr->FindInputDeviceId(libinput_event_get_device(event));
    PointerEvent::PointerItem pointerItem;
    HandlePostInner(data, deviceId, pointerItem);
    WinMgr->UpdateTargetPointer(pointerEvent_);
    DumpInner();
    return result;
}
#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
void MouseEventNormalize::HandleMotionMoveMouse(int32_t offsetX, int32_t offsetY)
{
    CALL_DEBUG_ENTER;
    CHKPV(pointerEvent_);
    pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    InitAbsolution();
    absolutionX_ += offsetX;
    absolutionY_ += offsetY;
    WinMgr->UpdateAndAdjustMouseLocation(currentDisplayId_, absolutionX_, absolutionY_);
}

void MouseEventNormalize::OnDisplayLost(int32_t displayId)
{
    if (currentDisplayId_ != displayId) {
        currentDisplayId_ = -1;
        absolutionX_ = -1;
        absolutionY_ = -1;
        InitAbsolution();
        WinMgr->UpdateAndAdjustMouseLocation(currentDisplayId_, absolutionX_, absolutionY_);
    }
}

int32_t MouseEventNormalize::GetDisplayId() const
{
    return currentDisplayId_;
}

void MouseEventNormalize::HandlePostMoveMouse(PointerEvent::PointerItem& pointerItem)
{
    CALL_DEBUG_ENTER;
    auto mouseInfo = WinMgr->GetMouseInfo();
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
    pointerEvent_->UpdatePointerItem(pointerEvent_->GetPointerId(), pointerItem);
    pointerEvent_->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent_->SetActionTime(time);
    pointerEvent_->SetActionStartTime(time);

    pointerEvent_->SetPointerId(0);
    pointerEvent_->SetTargetDisplayId(-1);
    pointerEvent_->SetTargetWindowId(-1);
    pointerEvent_->SetAgentWindowId(-1);
}

bool MouseEventNormalize::NormalizeMoveMouse(int32_t offsetX, int32_t offsetY)
{
    CALL_DEBUG_ENTER;
    CHKPF(pointerEvent_);
    bool bHasPoinerDevice = InputDevMgr->HasPointerDevice();
    if (!bHasPoinerDevice) {
        MMI_HILOGE("There hasn't any pointer device");
        return false;
    }

    PointerEvent::PointerItem pointerItem;
    HandleMotionMoveMouse(offsetX, offsetY);
    HandlePostMoveMouse(pointerItem);
    DumpInner();
    return bHasPoinerDevice;
}
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING

void MouseEventNormalize::DumpInner()
{
    EventLogHelper::PrintEventData(pointerEvent_);
}

void MouseEventNormalize::Dump(int32_t fd, const std::vector<std::string> &args)
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

int32_t MouseEventNormalize::SetPointerSpeed(int32_t speed)
{
    CALL_DEBUG_ENTER;
    if (speed < MIN_SPEED) {
        speed_ = MIN_SPEED;
    } else if (speed > MAX_SPEED) {
        speed_ = MAX_SPEED;
    } else {
        speed_ = speed;
    }
    MMI_HILOGD("Set pointer speed:%{public}d", speed_);
    return RET_OK;
}

int32_t MouseEventNormalize::GetPointerSpeed() const
{
    CALL_DEBUG_ENTER;
    MMI_HILOGD("Get pointer speed:%{public}d", speed_);
    return speed_;
}

#ifdef OHOS_BUILD_ENABLE_COOPERATE
void MouseEventNormalize::SetDxDyForDInput(PointerEvent::PointerItem& pointerItem, libinput_event_pointer* data)
{
    double dx = libinput_event_pointer_get_dx(data);
    double dy = libinput_event_pointer_get_dy(data);
    int32_t rawDx = static_cast<int32_t>(dx);
    int32_t rawDy = static_cast<int32_t>(dy);
    pointerItem.SetRawDx(rawDx);
    pointerItem.SetRawDy(rawDy);
    MMI_HILOGD("MouseEventNormalize SetDxDyForDInput, dx:%{public}d, dy:%{public}d", rawDx, rawDy);
}

void MouseEventNormalize::SetAbsolutionLocation(double xPercent, double yPercent)
{
    MMI_HILOGI("Cross screen location, xPercent:%{public}lf, yPercent:%{public}lf",
        xPercent, yPercent);
    auto displayGroupInfo = WinMgr->GetDisplayGroupInfo();
    if (currentDisplayId_ == -1) {
        if (displayGroupInfo.displaysInfo.empty()) {
            MMI_HILOGI("The displayInfo is empty");
            return;
        }
        currentDisplayId_ = displayGroupInfo.displaysInfo[0].id;
    }
    struct DisplayInfo display;
    for (auto &it : displayGroupInfo.displaysInfo) {
        if (it.id == currentDisplayId_) {
            display = it;
            break;
        }
    }
    absolutionX_ = display.width * xPercent / PERCENT_CONST;
    absolutionY_ = display.height * yPercent / PERCENT_CONST;
    WinMgr->UpdateAndAdjustMouseLocation(currentDisplayId_, absolutionX_, absolutionY_);
    int32_t physicalX = WinMgr->GetMouseInfo().physicalX;
    int32_t physicalY = WinMgr->GetMouseInfo().physicalY;
    IPointerDrawingManager::GetInstance()->SetPointerLocation(getpid(), physicalX, physicalY);
}
#endif // OHOS_BUILD_ENABLE_COOPERATE
} // namespace MMI
} // namespace OHOS
