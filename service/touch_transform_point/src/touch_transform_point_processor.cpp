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

#include "touch_transform_point_processor.h"

#include "mmi_log.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "TouchTransformPointProcessor"};
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

TouchTransformPointProcessor::TouchTransformPointProcessor(int32_t deviceId) : deviceId_(deviceId)
{
    pointerEvent_ = PointerEvent::Create();
    CHKPL(pointerEvent_);
}

TouchTransformPointProcessor::~TouchTransformPointProcessor() {}

bool TouchTransformPointProcessor::OnEventTouchDown(struct libinput_event *event)
{
    CALL_LOG_ENTER;
    CHKPF(event);
    auto data = libinput_event_get_touch_event(event);
    CHKPF(data);
    int32_t logicalY = -1;
    int32_t logicalX = -1;
    int32_t logicalDisplayId = -1;
    if (!WinMgr->TouchDownPointToDisplayPoint(data, logicalX, logicalY, logicalDisplayId)) {
        MMI_HILOGE("TouchDownPointToDisplayPoint failed");
        return false;
    }
    auto pointIds = pointerEvent_->GetPointersIdList();
    int64_t time = GetSysClockTime();
    if (pointIds.empty()) {
        pointerEvent_->SetActionStartTime(time);
        pointerEvent_->SetTargetDisplayId(logicalDisplayId);
    }
    pointerEvent_->SetActionTime(time);
    pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);

    PointerEvent::PointerItem item;
    auto pressure = libinput_event_touch_get_pressure(data);
    auto seatSlot = libinput_event_touch_get_seat_slot(data);
    auto axisLong = libinput_event_get_touch_contact_axis_Long(data);
    auto axisShort = libinput_event_get_touch_contact_axis_short(data);
    item.SetPressure(pressure);
    item.SetAxisLong(axisLong);
    item.SetAxisShort(axisShort);
    int32_t toolType = GetTouchToolType(event);
    item.SetToolType(toolType);
    item.SetPointerId(seatSlot);
    item.SetDownTime(time);
    item.SetPressed(true);
    item.SetGlobalX(logicalX);
    item.SetGlobalY(logicalY);
    item.SetDeviceId(deviceId_);
    pointerEvent_->SetDeviceId(deviceId_);
    pointerEvent_->AddPointerItem(item);
    pointerEvent_->SetPointerId(seatSlot);
    MMI_HILOGD("LogicalX:%{public}d, logicalY:%{public}d, logicalDisplay:%{public}d, pressure:%{public}f,"
               "axisLong:%{public}d, axisShort:%{public}d",
               logicalX, logicalY, logicalDisplayId, pressure, axisLong, axisShort);
    return true;
}

bool TouchTransformPointProcessor::OnEventTouchMotion(struct libinput_event *event)
{
    CALL_LOG_ENTER;
    CHKPF(event);
    auto data = libinput_event_get_touch_event(event);
    CHKPF(data);
    int64_t time = GetSysClockTime();
    pointerEvent_->SetActionTime(time);
    pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    int32_t logicalY = -1;
    int32_t logicalX = -1;
    int32_t logicalDisplayId = pointerEvent_->GetTargetDisplayId();
    if (!WinMgr->TouchMotionPointToDisplayPoint(data, logicalDisplayId, logicalX, logicalY)) {
        MMI_HILOGE("Get TouchMotionPointToDisplayPoint failed");
        return false;
    }
    PointerEvent::PointerItem item;
    auto seatSlot = libinput_event_touch_get_seat_slot(data);
    if (!(pointerEvent_->GetPointerItem(seatSlot, item))) {
        MMI_HILOGE("Get pointer parameter failed");
        return false;
    }
    auto pressure = libinput_event_touch_get_pressure(data);
    auto axisLong = libinput_event_get_touch_contact_axis_Long(data);
    auto axisShort = libinput_event_get_touch_contact_axis_short(data);
    item.SetPressure(pressure);
    item.SetAxisLong(axisLong);
    item.SetAxisShort(axisShort);
    item.SetGlobalX(logicalX);
    item.SetGlobalY(logicalY);
    pointerEvent_->UpdatePointerItem(seatSlot, item);
    pointerEvent_->SetPointerId(seatSlot);
    MMI_HILOGD("LogicalX:%{public}d, logicalY:%{public}d, pressure:%{public}f,"
               "axisLong:%{public}d, axisShort:%{public}d",
               logicalX, logicalY, pressure, axisLong, axisShort);
    return true;
}

bool TouchTransformPointProcessor::OnEventTouchUp(struct libinput_event *event)
{
    CALL_LOG_ENTER;
    CHKPF(event);
    auto data = libinput_event_get_touch_event(event);
    CHKPF(data);
    int64_t time = GetSysClockTime();
    pointerEvent_->SetActionTime(time);
    pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_UP);

    PointerEvent::PointerItem item;
    auto seatSlot = libinput_event_touch_get_seat_slot(data);
    if (!(pointerEvent_->GetPointerItem(seatSlot, item))) {
        MMI_HILOGE("Get pointer parameter failed");
        return false;
    }
    item.SetPressed(false);
    pointerEvent_->UpdatePointerItem(seatSlot, item);
    pointerEvent_->SetPointerId(seatSlot);
    return true;
}

std::shared_ptr<PointerEvent> TouchTransformPointProcessor::OnLibinputTouchEvent(struct libinput_event *event)
{
    CALL_LOG_ENTER;
    CHKPP(event);
    CHKPP(pointerEvent_);
    auto type = libinput_event_get_type(event);
    switch (type) {
        case LIBINPUT_EVENT_TOUCH_DOWN: {
            if (!OnEventTouchDown(event)) {
                MMI_HILOGE("Get OnEventTouchDown failed");
                return nullptr;
            }
            break;
        }
        case LIBINPUT_EVENT_TOUCH_UP: {
            if (!OnEventTouchUp(event)) {
                MMI_HILOGE("Get OnEventTouchUp failed");
                return nullptr;
            }
            break;
        }
        case LIBINPUT_EVENT_TOUCH_MOTION: {
            if (!OnEventTouchMotion(event)) {
                MMI_HILOGE("Get OnEventTouchMotion failed");
                return nullptr;
            }
            break;
        }
        default: {
            MMI_HILOGE("Unknown event type, touchType:%{public}d", type);
            return nullptr;
        }
    }
    pointerEvent_->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent_->UpdateId();
    return pointerEvent_;
}

int32_t TouchTransformPointProcessor::GetTouchToolType(struct libinput_event *event)
{
    auto data = libinput_event_get_touch_event(event);
    CHKPR(data, PointerEvent::TOOL_TYPE_FINGER);
    auto toolTypeTmp = libinput_event_touch_get_tool_type(data);
    switch (toolTypeTmp) {
        case MT_TOOL_NONE: {
            auto device = libinput_event_get_device(event);
            CHKPR(device, PointerEvent::TOOL_TYPE_FINGER);
            return GetTouchToolType(device);
        }
        case MT_TOOL_FINGER: {
            return PointerEvent::TOOL_TYPE_FINGER;
        }
        case MT_TOOL_PEN: {
            return PointerEvent::TOOL_TYPE_PEN;
        }
        default : {
            MMI_HILOGW("Unknown tool type, identified as finger, toolType:%{public}d", toolTypeTmp);
            return PointerEvent::TOOL_TYPE_FINGER;
        }
    }
}

int32_t TouchTransformPointProcessor::GetTouchToolType(struct libinput_device *device)
{
    if (libinput_device_touch_btn_tool_type_down(device, BTN_TOOL_PEN) == BTN_DOWN) {
        return PointerEvent::TOOL_TYPE_PEN;
    } else if (libinput_device_touch_btn_tool_type_down(device, BTN_TOOL_RUBBER) == BTN_DOWN) {
        return PointerEvent::TOOL_TYPE_RUBBER;
    } else if (libinput_device_touch_btn_tool_type_down(device, BTN_TOOL_BRUSH) == BTN_DOWN) {
        return PointerEvent::TOOL_TYPE_BRUSH;
    } else if (libinput_device_touch_btn_tool_type_down(device, BTN_TOOL_PENCIL) == BTN_DOWN) {
        return PointerEvent::TOOL_TYPE_PENCIL;
    } else if (libinput_device_touch_btn_tool_type_down(device, BTN_TOOL_AIRBRUSH) == BTN_DOWN) {
        return PointerEvent::TOOL_TYPE_AIRBRUSH;
    } else if (libinput_device_touch_btn_tool_type_down(device, BTN_TOOL_FINGER) == BTN_DOWN) {
        return PointerEvent::TOOL_TYPE_FINGER;
    } else if (libinput_device_touch_btn_tool_type_down(device, BTN_TOOL_MOUSE) == BTN_DOWN) {
        return PointerEvent::TOOL_TYPE_MOUSE;
    } else if (libinput_device_touch_btn_tool_type_down(device, BTN_TOOL_LENS) == BTN_DOWN) {
        return PointerEvent::TOOL_TYPE_LENS;
    } else {
        MMI_HILOGW("Unknown Btn tool type, identified as finger");
        return PointerEvent::TOOL_TYPE_FINGER;
    }
}
} // namespace MMI
} // namespace OHOS
