/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "mouse_event_handler.h"
#include <cinttypes>
#include "libmmi_util.h"
#include "input-event-codes.h"
#include "util.h"
#include "input_windows_manager.h"
#include "input_event_handler.h"
#include "timer_manager.h"
#include "mouse_device_state.h"
#include "input_device_manager.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "MouseEventHandler"};
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

void MouseEventHandler::HandleMotionInner(libinput_event_pointer* data)
{
    CALL_LOG_ENTER;
    CHKPV(data);
    pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent_->SetButtonId(buttionId_);

    InitAbsolution();
    absolutionX_ += libinput_event_pointer_get_dx(data);
    absolutionY_ += libinput_event_pointer_get_dy(data);

    WinMgr->UpdateAndAdjustMouseLoction(absolutionX_, absolutionY_);

    MMI_LOGD("Change Coordinate : x:%{public}lf,y:%{public}lf",  absolutionX_, absolutionY_);
}

void MouseEventHandler::InitAbsolution()
{
    if (absolutionX_ != -1 || absolutionY_ != -1) {
        return;
    }
    MMI_LOGD("init absolution");
    auto logicalDisplayInfo = WinMgr->GetLogicalDisplayInfo();
    if (!logicalDisplayInfo.empty()) {
        absolutionX_ = logicalDisplayInfo[0].width * 1.0 / 2;
        absolutionY_ = logicalDisplayInfo[0].height * 1.0 / 2;
    }
}

void MouseEventHandler::HandleButonInner(libinput_event_pointer* data)
{
    CALL_LOG_ENTER;
    CHKPV(data);
    MMI_LOGD("current action:%{public}d", pointerEvent_->GetPointerAction());

    auto button = libinput_event_pointer_get_button(data);
    if (button == BTN_LEFT) {
        pointerEvent_->SetButtonId(PointerEvent::MOUSE_BUTTON_LEFT);
    } else if (button == BTN_RIGHT) {
        pointerEvent_->SetButtonId(PointerEvent::MOUSE_BUTTON_RIGHT);
    } else if (button == BTN_MIDDLE) {
        pointerEvent_->SetButtonId(PointerEvent::MOUSE_BUTTON_MIDDLE);
    } else {
        MMI_LOGW("unknown btn, btn:%{public}u", button);
    }

    auto state = libinput_event_pointer_get_button_state(data);
    if (state == LIBINPUT_BUTTON_STATE_RELEASED) {
        MouseState->MouseBtnStateCounts(button, BUTTON_STATE_RELEASED);
        pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_UP);
        pointerEvent_->DeleteReleaseButton(button);
        isPressed_ = false;
        buttionId_ = PointerEvent::BUTTON_NONE;
    } else if (state == LIBINPUT_BUTTON_STATE_PRESSED) {
        MouseState->MouseBtnStateCounts(button, BUTTON_STATE_PRESSED);
        pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_DOWN);
        pointerEvent_->SetButtonPressed(button);
        isPressed_ = true;
        buttionId_ = pointerEvent_->GetButtonId();
    } else {
        MMI_LOGW("unknown state, state:%{public}u", state);
    }
}

void MouseEventHandler::HandleAxisInner(libinput_event_pointer* data)
{
    CHKPV(data);
    if (TimerMgr->IsExist(timerId_)) {
        pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_UPDATE);
        TimerMgr->ResetTimer(timerId_);
        MMI_LOGD("axis update");
    } else {
        constexpr int32_t timeout = 100; // 100 ms
        std::weak_ptr<MouseEventHandler> weakPtr = shared_from_this();
        timerId_ = TimerMgr->AddTimer(timeout, 1, [weakPtr]() {
            CALL_LOG_ENTER;
            auto sharedPtr = weakPtr.lock();
            CHKPV(sharedPtr);
            MMI_LOGD("timer:%{public}d", sharedPtr->timerId_);
            sharedPtr->timerId_ = -1;
            auto pointerEvent = sharedPtr->GetPointerEvent();
            CHKPV(pointerEvent);
            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_END);
            InputHandler->OnMouseEventEndTimerHandler(pointerEvent);
        });

        pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_BEGIN);
        MMI_LOGD("axis begin");
    }

    if (libinput_event_pointer_has_axis(data, LIBINPUT_POINTER_AXIS_SCROLL_VERTICAL)) {
        auto axisValue = libinput_event_pointer_get_axis_value(data, LIBINPUT_POINTER_AXIS_SCROLL_VERTICAL);
        pointerEvent_->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL, axisValue);
    }
    if (libinput_event_pointer_has_axis(data, LIBINPUT_POINTER_AXIS_SCROLL_HORIZONTAL)) {
        auto axisValue = libinput_event_pointer_get_axis_value(data, LIBINPUT_POINTER_AXIS_SCROLL_HORIZONTAL);
        pointerEvent_->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL, axisValue);
    }
}

void MouseEventHandler::HandlePostInner(libinput_event_pointer* data, int32_t deviceId,
                                        PointerEvent::PointerItem& pointerItem)
{
    CALL_LOG_ENTER;
    CHKPV(data);
    auto mouseInfo = WinMgr->GetMouseInfo();
    MouseState->SetMouseCoords(mouseInfo.globalX, mouseInfo.globalY);
    pointerItem.SetGlobalX(mouseInfo.globalX);
    pointerItem.SetGlobalY(mouseInfo.globalY);
    pointerItem.SetLocalX(0);
    pointerItem.SetLocalY(0);
    pointerItem.SetPointerId(0);
    pointerItem.SetPressed(isPressed_);

    int64_t time = GetSysClockTime();
    pointerItem.SetDownTime(time);
    pointerItem.SetWidth(0);
    pointerItem.SetHeight(0);
    pointerItem.SetPressure(0);
    pointerItem.SetDeviceId(deviceId);

    pointerEvent_->UpdateId();
    pointerEvent_->UpdatePointerItem(pointerEvent_->GetPointerId(), pointerItem);
    pointerEvent_->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent_->SetActionTime(time);
    pointerEvent_->SetActionStartTime(time);
    pointerEvent_->SetDeviceId(deviceId);
    pointerEvent_->SetPointerId(0);
    pointerEvent_->SetTargetDisplayId(-1);
    pointerEvent_->SetTargetWindowId(-1);
    pointerEvent_->SetAgentWindowId(-1);
}

void MouseEventHandler::Normalize(struct libinput_event *event)
{
    CALL_LOG_ENTER;
    CHKPV(event);
    auto data = libinput_event_get_pointer_event(event);
    CHKPV(data);
    CHKPV(pointerEvent_);
    PointerEvent::PointerItem pointerItem;
    const int32_t type = libinput_event_get_type(event);
    switch (type) {
        case LIBINPUT_EVENT_POINTER_MOTION:
        case LIBINPUT_EVENT_POINTER_MOTION_ABSOLUTE: {
            HandleMotionInner(data);
            break;
        }
        case LIBINPUT_EVENT_POINTER_BUTTON: {
            HandleButonInner(data);
            break;
        }
        case LIBINPUT_EVENT_POINTER_AXIS: {
            HandleAxisInner(data);
            break;
        }
        default: {
            MMI_LOGW("unknow type:%{public}d", type);
            break;
        }
    }
    int32_t deviceId = InputDevMgr->FindInputDeviceId(libinput_event_get_device(event));
    HandlePostInner(data, deviceId, pointerItem);
    DumpInner();
}

void MouseEventHandler::DumpInner()
{
    MMI_LOGD("PointerAction:%{public}d,PointerId:%{public}d,SourceType:%{public}d,"
        "ButtonId:%{public}d,VerticalAxisValue:%{public}lf,HorizontalAxisValue:%{public}lf",
        pointerEvent_->GetPointerAction(), pointerEvent_->GetPointerId(), pointerEvent_->GetSourceType(),
        pointerEvent_->GetButtonId(), pointerEvent_->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL),
        pointerEvent_->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL));

    PointerEvent::PointerItem item;
    if (!pointerEvent_->GetPointerItem(pointerEvent_->GetPointerId(), item)) {
        MMI_LOGE("Can't find the pointer item data, pointer:%{public}d, errCode:%{public}d",
                 pointerEvent_->GetPointerId(), PARAM_INPUT_FAIL);
                 return;
    }
    MMI_LOGD("Item: DownTime:%{public}" PRId64 ",IsPressed:%{public}s,GlobalX:%{public}d,GlobalY:%{public}d,"
        "Width:%{public}d,Height:%{public}d,Pressure:%{public}d",
        item.GetDownTime(), (item.IsPressed() ? "true" : "false"), item.GetGlobalX(), item.GetGlobalY(),
        item.GetWidth(), item.GetHeight(), item.GetPressure());
}
} // namespace MMI
} // namespace OHOS

