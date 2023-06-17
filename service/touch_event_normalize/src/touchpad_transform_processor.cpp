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

#include "touchpad_transform_processor.h"

#include <sstream>

#include <linux/input.h>

#include "event_log_helper.h"
#include "input_windows_manager.h"
#include "mmi_log.h"
#include "mouse_device_state.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL { LOG_CORE, MMI_LOG_DOMAIN, "TouchPadTransformProcessor" };
constexpr int32_t MT_TOOL_NONE { -1 };
constexpr int32_t BTN_DOWN { 1 };
constexpr int32_t FINGER_COUNT_MAX { 5 };
} // namespace

TouchPadTransformProcessor::TouchPadTransformProcessor(int32_t deviceId)
    : deviceId_(deviceId)
{
    InitToolType();
}

void TouchPadTransformProcessor::OnEventTouchPadDown(struct libinput_event *event)
{
    CALL_DEBUG_ENTER;
    CHKPV(event);
    auto touchpad = libinput_event_get_touchpad_event(event);
    CHKPV(touchpad);
    auto device = libinput_event_get_device(event);
    CHKPV(device);

    uint64_t time = libinput_event_touchpad_get_time_usec(touchpad);
    auto pointIds = pointerEvent_->GetPointerIds();
    if (pointIds.empty()) {
        pointerEvent_->SetActionStartTime(time);
    }
    pointerEvent_->SetActionTime(time);
    pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    PointerEvent::PointerItem item;
    int32_t longAxis = libinput_event_touchpad_get_touch_contact_long_axis(touchpad);
    int32_t shortAxis = libinput_event_touchpad_get_touch_contact_short_axis(touchpad);
    double pressure = libinput_event_touchpad_get_pressure(touchpad);
    int32_t seatSlot = libinput_event_touchpad_get_seat_slot(touchpad);
    double logicalX = libinput_event_touchpad_get_x(touchpad);
    double logicalY = libinput_event_touchpad_get_y(touchpad);
    double toolPhysicalX = libinput_event_touchpad_get_tool_x(touchpad);
    double toolPhysicalY = libinput_event_touchpad_get_tool_y(touchpad);
    double toolWidth = libinput_event_touchpad_get_tool_width(touchpad);
    double toolHeight = libinput_event_touchpad_get_tool_height(touchpad);
    int32_t toolType = GetTouchPadToolType(touchpad, device);

    item.SetLongAxis(longAxis);
    item.SetShortAxis(shortAxis);
    item.SetPressure(pressure);
    item.SetToolType(toolType);
    item.SetPointerId(seatSlot);
    item.SetDownTime(time);
    item.SetPressed(true);
    item.SetDisplayX(static_cast<int32_t>(logicalX));
    item.SetDisplayY(static_cast<int32_t>(logicalY));
    item.SetToolDisplayX(static_cast<int32_t>(toolPhysicalX));
    item.SetToolDisplayY(static_cast<int32_t>(toolPhysicalY));
    item.SetToolWidth(static_cast<int32_t>(toolWidth));
    item.SetToolHeight(static_cast<int32_t>(toolHeight));
    item.SetDeviceId(deviceId_);
    pointerEvent_->SetDeviceId(deviceId_);
    pointerEvent_->AddPointerItem(item);
    pointerEvent_->SetPointerId(seatSlot);
}

void TouchPadTransformProcessor::OnEventTouchPadMotion(struct libinput_event *event)
{
    CALL_DEBUG_ENTER;
    CHKPV(event);
    auto touchpad = libinput_event_get_touchpad_event(event);
    CHKPV(touchpad);
    int32_t seatSlot = libinput_event_touchpad_get_seat_slot(touchpad);

    uint64_t time = libinput_event_touchpad_get_time_usec(touchpad);
    pointerEvent_->SetActionTime(time);
    pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    PointerEvent::PointerItem item;
    if (!pointerEvent_->GetPointerItem(seatSlot, item)) {
        MMI_HILOGE("Can't find the pointer item data, seatSlot:%{public}d, errCode:%{public}d",
                   seatSlot, PARAM_INPUT_FAIL);
        return;
    }
    int32_t longAxis = libinput_event_touchpad_get_touch_contact_long_axis(touchpad);
    int32_t shortAxis = libinput_event_touchpad_get_touch_contact_short_axis(touchpad);
    double pressure = libinput_event_touchpad_get_pressure(touchpad);
    double logicalX = libinput_event_touchpad_get_x(touchpad);
    double logicalY = libinput_event_touchpad_get_y(touchpad);
    double toolPhysicalX = libinput_event_touchpad_get_tool_x(touchpad);
    double toolPhysicalY = libinput_event_touchpad_get_tool_y(touchpad);
    double toolWidth = libinput_event_touchpad_get_tool_width(touchpad);
    double toolHeight = libinput_event_touchpad_get_tool_height(touchpad);

    item.SetLongAxis(longAxis);
    item.SetShortAxis(shortAxis);
    item.SetPressure(pressure);
    item.SetDisplayX(static_cast<int32_t>(logicalX));
    item.SetDisplayY(static_cast<int32_t>(logicalY));
    item.SetToolDisplayX(static_cast<int32_t>(toolPhysicalX));
    item.SetToolDisplayY(static_cast<int32_t>(toolPhysicalY));
    item.SetToolWidth(static_cast<int32_t>(toolWidth));
    item.SetToolHeight(static_cast<int32_t>(toolHeight));
    pointerEvent_->UpdatePointerItem(seatSlot, item);
    pointerEvent_->SetPointerId(seatSlot);
}

void TouchPadTransformProcessor::OnEventTouchPadUp(struct libinput_event *event)
{
    CALL_DEBUG_ENTER;
    CHKPV(event);
    auto touchpad = libinput_event_get_touchpad_event(event);
    CHKPV(touchpad);
    int32_t seatSlot = libinput_event_touchpad_get_seat_slot(touchpad);

    uint64_t time = libinput_event_touchpad_get_time_usec(touchpad);
    pointerEvent_->SetActionTime(time);
    pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_UP);

    PointerEvent::PointerItem item;
    if (!pointerEvent_->GetPointerItem(seatSlot, item)) {
        MMI_HILOGE("Can't find the pointer item data, seatSlot:%{public}d, errCode:%{public}d",
                   seatSlot, PARAM_INPUT_FAIL);
        return;
    }
    item.SetPressed(false);
    pointerEvent_->UpdatePointerItem(seatSlot, item);
    pointerEvent_->SetPointerId(seatSlot);
}

std::shared_ptr<PointerEvent> TouchPadTransformProcessor::OnEvent(struct libinput_event *event)
{
    CALL_DEBUG_ENTER;
    CHKPP(event);
    if (pointerEvent_ == nullptr) {
        pointerEvent_ = PointerEvent::Create();
        CHKPP(pointerEvent_);
    }
    int32_t type = libinput_event_get_type(event);
    switch (type) {
        case LIBINPUT_EVENT_TOUCHPAD_DOWN: {
            OnEventTouchPadDown(event);
            break;
        }
        case LIBINPUT_EVENT_TOUCHPAD_UP: {
            OnEventTouchPadUp(event);
            break;
        }
        case LIBINPUT_EVENT_TOUCHPAD_MOTION: {
            OnEventTouchPadMotion(event);
            break;
        }
        case LIBINPUT_EVENT_GESTURE_SWIPE_BEGIN: {
            OnEventTouchPadSwipeBegin(event);
            break;
        }
        case LIBINPUT_EVENT_GESTURE_SWIPE_UPDATE: {
            OnEventTouchPadSwipeUpdate(event);
            break;
        }
        case LIBINPUT_EVENT_GESTURE_SWIPE_END: {
            OnEventTouchPadSwipeEnd(event);
            break;
        }

        case LIBINPUT_EVENT_GESTURE_PINCH_BEGIN: {
            OnEventTouchPadPinchBegin(event);
            break;
        }
        case LIBINPUT_EVENT_GESTURE_PINCH_UPDATE: {
            OnEventTouchPadPinchUpdate(event);
            break;
        }
        case LIBINPUT_EVENT_GESTURE_PINCH_END: {
            OnEventTouchPadPinchEnd(event);
            break;
        }
        default: {
            return nullptr;
        }
    }
    pointerEvent_->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    pointerEvent_->UpdateId();
    MMI_HILOGD("Pointer event dispatcher of server:");
    EventLogHelper::PrintEventData(pointerEvent_, pointerEvent_->GetPointerAction(),
        pointerEvent_->GetPointerIds().size());
    return pointerEvent_;
}

int32_t TouchPadTransformProcessor::GetTouchPadToolType(
    struct libinput_event_touch *touchpad, struct libinput_device *device)
{
    int32_t toolType = libinput_event_touchpad_get_tool_type(touchpad);
    switch (toolType) {
        case MT_TOOL_NONE: {
            return GetTouchPadToolType(device);
        }
        case MT_TOOL_FINGER: {
            return PointerEvent::TOOL_TYPE_FINGER;
        }
        case MT_TOOL_PEN: {
            return PointerEvent::TOOL_TYPE_PEN;
        }
        default : {
            MMI_HILOGW("Unknown tool type, identified as finger, toolType:%{public}d", toolType);
            return PointerEvent::TOOL_TYPE_FINGER;
        }
    }
}

int32_t TouchPadTransformProcessor::GetTouchPadToolType(struct libinput_device *device)
{
    for (const auto &item : vecToolType_) {
        if (libinput_device_touchpad_btn_tool_type_down(device, item.first) == BTN_DOWN) {
            return item.second;
        }
    }
    MMI_HILOGW("Unknown Btn tool type, identified as finger");
    return PointerEvent::TOOL_TYPE_FINGER;
}

void TouchPadTransformProcessor::SetTouchPadSwipeData(struct libinput_event *event, int32_t action)
{
    CALL_DEBUG_ENTER;
    CHKPV(event);
    struct libinput_event_gesture *gesture = libinput_event_get_gesture_event(event);
    CHKPV(gesture);

    int64_t time = static_cast<int64_t>(libinput_event_gesture_get_time(gesture));
    pointerEvent_->SetActionTime(GetSysClockTime());
    pointerEvent_->SetActionStartTime(time);
    pointerEvent_->SetPointerAction(action);

    int32_t fingerCount = libinput_event_gesture_get_finger_count(gesture);
    if (fingerCount < 0 || fingerCount > FINGER_COUNT_MAX) {
        MMI_HILOGE("Finger count is invalid.");
        return;
    }
    pointerEvent_->SetFingerCount(fingerCount);

    if (fingerCount == 0) {
        MMI_HILOGD("There is no finger in swipe action %{public}d.", action);
        return;
    }

    int32_t sumX = 0;
    int32_t sumY = 0;
    for (int32_t i = 0; i < fingerCount; i++) {
        sumX += libinput_event_gesture_get_device_coords_x(gesture, i);
        sumY += libinput_event_gesture_get_device_coords_y(gesture, i);
    }

    PointerEvent::PointerItem pointerItem;
    pointerEvent_->GetPointerItem(defaultPointerId, pointerItem);
    pointerItem.SetPressed(MouseState->IsLeftBtnPressed());
    pointerItem.SetDownTime(time);
    pointerItem.SetDisplayX(sumX / fingerCount);
    pointerItem.SetDisplayY(sumY / fingerCount);
    pointerItem.SetDeviceId(deviceId_);
    pointerItem.SetPointerId(defaultPointerId);
    pointerEvent_->UpdatePointerItem(defaultPointerId, pointerItem);
}

void TouchPadTransformProcessor::OnEventTouchPadSwipeBegin(struct libinput_event *event)
{
    CALL_DEBUG_ENTER;
    SetTouchPadSwipeData(event, PointerEvent::POINTER_ACTION_SWIPE_BEGIN);
}

void TouchPadTransformProcessor::OnEventTouchPadSwipeUpdate(struct libinput_event *event)
{
    CALL_DEBUG_ENTER;
    SetTouchPadSwipeData(event, PointerEvent::POINTER_ACTION_SWIPE_UPDATE);
}

void TouchPadTransformProcessor::OnEventTouchPadSwipeEnd(struct libinput_event *event)
{
    CALL_DEBUG_ENTER;
    SetTouchPadSwipeData(event, PointerEvent::POINTER_ACTION_SWIPE_END);
}

void TouchPadTransformProcessor::SetTouchPadPinchData(struct libinput_event *event, int32_t action)
{
    CALL_DEBUG_ENTER;
    CHKPV(event);
    auto gesture = libinput_event_get_gesture_event(event);
    CHKPV(gesture);
    int64_t time = static_cast<int64_t>(libinput_event_gesture_get_time(gesture));
    double scale = libinput_event_gesture_get_scale(gesture);
    pointerEvent_->SetActionTime(GetSysClockTime());
    pointerEvent_->SetActionStartTime(time);

    PointerEvent::PointerItem pointerItem;
    pointerItem.SetDownTime(time);
    pointerItem.SetPressed(MouseState->IsLeftBtnPressed());
    pointerEvent_->UpdatePointerItem(defaultPointerId, pointerItem);

    pointerEvent_->ClearButtonPressed();
    std::vector<int32_t> pressedButtons;
    MouseState->GetPressedButtons(pressedButtons);
    for (const auto &item : pressedButtons) {
        pointerEvent_->SetButtonPressed(item);
    }

    int32_t fingerCount = libinput_event_gesture_get_finger_count(gesture);
    if (fingerCount <= 0 || fingerCount > FINGER_COUNT_MAX) {
        MMI_HILOGE("Finger count is invalid.");
        return;
    }
    pointerEvent_->SetFingerCount(fingerCount);
    pointerEvent_->SetDeviceId(deviceId_);
    pointerEvent_->SetTargetDisplayId(0);
    pointerEvent_->SetPointerId(defaultPointerId);
    pointerEvent_->SetPointerAction(action);
    pointerEvent_->SetAxisValue(PointerEvent::AXIS_TYPE_PINCH, scale);
}

void TouchPadTransformProcessor::OnEventTouchPadPinchBegin(struct libinput_event *event)
{
    CALL_DEBUG_ENTER;
    SetTouchPadPinchData(event, PointerEvent::POINTER_ACTION_AXIS_BEGIN);
}

void TouchPadTransformProcessor::OnEventTouchPadPinchUpdate(struct libinput_event *event)
{
    CALL_DEBUG_ENTER;
    SetTouchPadPinchData(event, PointerEvent::POINTER_ACTION_AXIS_UPDATE);
}

void TouchPadTransformProcessor::OnEventTouchPadPinchEnd(struct libinput_event *event)
{
    CALL_DEBUG_ENTER;
    SetTouchPadPinchData(event, PointerEvent::POINTER_ACTION_AXIS_END);
}

void TouchPadTransformProcessor::InitToolType()
{
    vecToolType_.push_back(std::make_pair(BTN_TOOL_PEN, PointerEvent::TOOL_TYPE_PEN));
    vecToolType_.push_back(std::make_pair(BTN_TOOL_RUBBER, PointerEvent::TOOL_TYPE_RUBBER));
    vecToolType_.push_back(std::make_pair(BTN_TOOL_BRUSH, PointerEvent::TOOL_TYPE_BRUSH));
    vecToolType_.push_back(std::make_pair(BTN_TOOL_PENCIL, PointerEvent::TOOL_TYPE_PENCIL));
    vecToolType_.push_back(std::make_pair(BTN_TOOL_AIRBRUSH, PointerEvent::TOOL_TYPE_AIRBRUSH));
    vecToolType_.push_back(std::make_pair(BTN_TOOL_FINGER, PointerEvent::TOOL_TYPE_FINGER));
    vecToolType_.push_back(std::make_pair(BTN_TOOL_MOUSE, PointerEvent::TOOL_TYPE_MOUSE));
    vecToolType_.push_back(std::make_pair(BTN_TOOL_LENS, PointerEvent::TOOL_TYPE_LENS));
}
} // namespace MMI
} // namespace OHOS
