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

#include "touchpad_transform_processor.h"

#include <sstream>

#include <linux/input.h>

#include "event_log_helper.h"
#include "input_windows_manager.h"
#include "mmi_log.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL { LOG_CORE, MMI_LOG_DOMAIN, "TouchPadTransformProcessor" };
constexpr int32_t MT_TOOL_NONE { -1 };
constexpr int32_t BTN_DOWN { 1 };
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

    int64_t time = GetSysClockTime();
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

    int64_t time = GetSysClockTime();
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

    int64_t time = GetSysClockTime();
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
