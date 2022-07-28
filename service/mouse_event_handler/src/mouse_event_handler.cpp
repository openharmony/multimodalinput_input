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

#include "mouse_event_handler.h"

#include <cinttypes>

#include "input-event-codes.h"

#include "define_multimodal.h"
#include "input_device_manager.h"
#include "input_event_handler.h"
#include "input_windows_manager.h"
#include "mouse_device_state.h"
#include "timer_manager.h"
#include "util.h"
#include "util_ex.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "MouseEventHandler"};
constexpr int32_t MIN_SPEED = 1;
constexpr int32_t MAX_SPEED = 20;
} // namespace
MouseEventHandler::MouseEventHandler()
{
    pointerEvent_ = PointerEvent::Create();
    CHKPL(pointerEvent_);
}

std::shared_ptr<PointerEvent> MouseEventHandler::GetPointerEvent() const
{
    return pointerEvent_;
}

int32_t MouseEventHandler::HandleMotionInner(libinput_event_pointer* data)
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

    absolutionX_ += libinput_event_pointer_get_dx(data);
    absolutionY_ += libinput_event_pointer_get_dy(data);
    WinMgr->UpdateAndAdjustMouseLocation(currentDisplayId_, absolutionX_, absolutionY_);
    pointerEvent_->SetTargetDisplayId(currentDisplayId_);
    MMI_HILOGD("Change Coordinate : x:%{public}lf,y:%{public}lf",  absolutionX_, absolutionY_);
    return RET_OK;
}

void MouseEventHandler::InitAbsolution()
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

int32_t MouseEventHandler::HandleButtonInner(libinput_event_pointer* data)
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

int32_t MouseEventHandler::HandleButtonValueInner(libinput_event_pointer* data)
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

int32_t MouseEventHandler::HandleAxisInner(libinput_event_pointer* data)
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
        std::weak_ptr<MouseEventHandler> weakPtr = shared_from_this();
        timerId_ = TimerMgr->AddTimer(timeout, 1, [weakPtr]() {
            CALL_DEBUG_ENTER;
            auto sharedPtr = weakPtr.lock();
            CHKPV(sharedPtr);
            MMI_HILOGD("timer:%{public}d", sharedPtr->timerId_);
            sharedPtr->timerId_ = -1;
            auto pointerEvent = sharedPtr->GetPointerEvent();
            CHKPV(pointerEvent);
            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_END);
            auto inputEventNormalizeHandler = InputHandler->GetInputEventNormalizeHandler();
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

void MouseEventHandler::HandlePostInner(libinput_event_pointer* data, int32_t deviceId,
                                        PointerEvent::PointerItem& pointerItem)
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

int32_t MouseEventHandler::Normalize(struct libinput_event *event)
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
void MouseEventHandler::HandleMotionMoveMouse(int32_t offsetX, int32_t offsetY)
{
    CALL_DEBUG_ENTER;
    CHKPV(pointerEvent_);
    pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    InitAbsolution();
    absolutionX_ += offsetX;
    absolutionY_ += offsetY;
    WinMgr->UpdateAndAdjustMouseLocation(currentDisplayId_, absolutionX_, absolutionY_);
}

void MouseEventHandler::HandlePostMoveMouse(PointerEvent::PointerItem& pointerItem)
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

bool MouseEventHandler::NormalizeMoveMouse(int32_t offsetX, int32_t offsetY)
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

void MouseEventHandler::DumpInner()
{
    PrintEventData(pointerEvent_);
}

void MouseEventHandler::Dump(int32_t fd, const std::vector<std::string> &args)
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

int32_t MouseEventHandler::SetPointerSpeed(int32_t speed)
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

int32_t MouseEventHandler::GetPointerSpeed() const
{
    CALL_DEBUG_ENTER;
    MMI_HILOGD("Get pointer speed:%{public}d", speed_);
    return speed_;
}
} // namespace MMI
} // namespace OHOS
