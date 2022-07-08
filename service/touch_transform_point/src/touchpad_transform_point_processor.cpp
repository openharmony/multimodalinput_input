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

#include "touchpad_transform_point_processor.h"

#include <sstream>

#include "mmi_log.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN,
    "TouchPadTransformPointProcessor"};
constexpr int32_t MT_TOOL_NONE      = -1;
constexpr int32_t MT_TOOL_FINGER    = 0;
constexpr int32_t MT_TOOL_PEN       = 1;
constexpr int32_t BTN_TOOL_PEN      = 0x140;
constexpr int32_t BTN_TOOL_RUBBER   = 0x141;
constexpr int32_t BTN_TOOL_BRUSH    = 0x142;
constexpr int32_t BTN_TOOL_PENCIL   = 0x143;
constexpr int32_t BTN_TOOL_AIRBRUSH = 0x144;
constexpr int32_t BTN_TOOL_FINGER   = 0x145;
constexpr int32_t BTN_TOOL_MOUSE    = 0x146;
constexpr int32_t BTN_TOOL_LENS     = 0x147;
constexpr int32_t BTN_DOWN          = 1;
} // namespace

TouchPadTransformPointProcessor::TouchPadTransformPointProcessor(int32_t deviceId) : deviceId_(deviceId)
{
    pointerEvent_ = PointerEvent::Create();
    CHKPL(pointerEvent_);
    InitToolType();
}

TouchPadTransformPointProcessor::~TouchPadTransformPointProcessor() {}

void TouchPadTransformPointProcessor::OnEventTouchPadDown(struct libinput_event *event)
{
    CALL_DEBUG_ENTER;
    CHKPV(event);
    auto data = libinput_event_get_touchpad_event(event);
    CHKPV(data);
    auto device = libinput_event_get_device(event);
    CHKPV(device);

    int64_t time = GetSysClockTime();
    auto pointIds = pointerEvent_->GetPointersIdList();
    if (pointIds.empty()) {
        pointerEvent_->SetActionStartTime(time);
    }
    pointerEvent_->SetActionTime(time);
    pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    PointerEvent::PointerItem item;
    int32_t longAxis = libinput_event_touchpad_get_touch_contact_long_axis(data);
    int32_t shortAxis = libinput_event_touchpad_get_touch_contact_short_axis(data);
    double pressure = libinput_event_touchpad_get_pressure(data);
    int32_t seatSlot = libinput_event_touchpad_get_seat_slot(data);
    double logicalX = libinput_event_touchpad_get_x(data);
    double logicalY = libinput_event_touchpad_get_y(data);
    double toolPhysicalX = libinput_event_touchpad_get_tool_x(data);
    double toolPhysicalY = libinput_event_touchpad_get_tool_y(data);
    double toolWidth = libinput_event_touchpad_get_tool_width(data);
    double toolHeight = libinput_event_touchpad_get_tool_height(data);
    int32_t toolType = GetTouchPadToolType(data, device);

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

void TouchPadTransformPointProcessor::OnEventTouchPadMotion(struct libinput_event *event)
{
    CALL_DEBUG_ENTER;
    CHKPV(event);
    auto data = libinput_event_get_touchpad_event(event);
    CHKPV(data);
    int32_t seatSlot = libinput_event_touchpad_get_seat_slot(data);

    int64_t time = GetSysClockTime();
    pointerEvent_->SetActionTime(time);
    pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    PointerEvent::PointerItem item;
    if (!pointerEvent_->GetPointerItem(seatSlot, item)) {
        MMI_HILOGE("Can't find the pointer item data, seatSlot:%{public}d, errCode:%{public}d",
                   seatSlot, PARAM_INPUT_FAIL);
        return;
    }
    int32_t longAxis = libinput_event_touchpad_get_touch_contact_long_axis(data);
    int32_t shortAxis = libinput_event_touchpad_get_touch_contact_short_axis(data);
    double pressure = libinput_event_touchpad_get_pressure(data);
    double logicalX = libinput_event_touchpad_get_x(data);
    double logicalY = libinput_event_touchpad_get_y(data);
    double toolPhysicalX = libinput_event_touchpad_get_tool_x(data);
    double toolPhysicalY = libinput_event_touchpad_get_tool_y(data);
    double toolWidth = libinput_event_touchpad_get_tool_width(data);
    double toolHeight = libinput_event_touchpad_get_tool_height(data);

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

void TouchPadTransformPointProcessor::OnEventTouchPadUp(struct libinput_event *event)
{
    CALL_DEBUG_ENTER;
    CHKPV(event);
    auto data = libinput_event_get_touchpad_event(event);
    CHKPV(data);
    int32_t seatSlot = libinput_event_touchpad_get_seat_slot(data);

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

std::shared_ptr<PointerEvent> TouchPadTransformPointProcessor::OnLibinputTouchPadEvent(
    struct libinput_event *event)
{
    CALL_DEBUG_ENTER;
    CHKPP(event);
    CHKPP(pointerEvent_);
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
    PrintEventData(pointerEvent_, pointerEvent_->GetPointerAction(), pointerEvent_->GetPointersIdList().size());
    return pointerEvent_;
}

int32_t TouchPadTransformPointProcessor::GetTouchPadToolType(struct libinput_event_touch *data,
    struct libinput_device *device)
{
    int32_t toolType = libinput_event_touchpad_get_tool_type(data);
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

int32_t TouchPadTransformPointProcessor::GetTouchPadToolType(struct libinput_device *device)
{
    for (const auto &item : vecToolType_) {
        if (libinput_device_touchpad_btn_tool_type_down(device, item.first) == BTN_DOWN) {
            return item.second;
        }
    }
    MMI_HILOGW("Unknown Btn tool type, identified as finger");
    return PointerEvent::TOOL_TYPE_FINGER;
}

void TouchPadTransformPointProcessor::InitToolType()
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
