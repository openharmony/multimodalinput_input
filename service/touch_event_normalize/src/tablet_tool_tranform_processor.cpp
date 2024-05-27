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

#include "tablet_tool_tranform_processor.h"
#include "input_windows_manager.h"
#include "mmi_log.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_DISPATCH
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TabletToolTransformProcessor"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t DEFAULT_POINTER_ID { 0 };
} // namespace

TabletToolTransformProcessor::TabletToolTransformProcessor(int32_t deviceId)
    : deviceId_(deviceId) {}

std::shared_ptr<PointerEvent> TabletToolTransformProcessor::OnEvent(struct libinput_event* event)
{
    CHKPP(event);
    if (pointerEvent_ == nullptr) {
        pointerEvent_ = PointerEvent::Create();
        CHKPP(pointerEvent_);
    }
    enum libinput_event_type type = libinput_event_get_type(event);
    switch (type) {
        case LIBINPUT_EVENT_TABLET_TOOL_AXIS: {
            if (!OnTipMotion(event)) {
                MMI_HILOGE("OnTipMotion failed");
                return nullptr;
            }
            break;
        }
        case LIBINPUT_EVENT_TABLET_TOOL_PROXIMITY: {
            MMI_HILOGE("Proximity event");
            return nullptr;
        }
        case LIBINPUT_EVENT_TABLET_TOOL_TIP: {
            if (!OnTip(event)) {
                MMI_HILOGE("OnTip failed");
                return nullptr;
            }
            break;
        }
        default: {
            MMI_HILOGE("Unexpected event type");
            return nullptr;
        }
    }
    pointerEvent_->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent_->UpdateId();
    StartLogTraceId(pointerEvent_->GetId(), pointerEvent_->GetEventType(), pointerEvent_->GetPointerAction());
    WIN_MGR->UpdateTargetPointer(pointerEvent_);
    return pointerEvent_;
}

int32_t TabletToolTransformProcessor::GetToolType(struct libinput_event_tablet_tool* tabletEvent)
{
    int32_t toolType = libinput_event_tablet_tool_get_tool_type(tabletEvent);
    if (toolType != 0) {
        return PointerEvent::TOOL_TYPE_PEN;
    }
    auto tool = libinput_event_tablet_tool_get_tool(tabletEvent);
    CHKPR(tool, PointerEvent::TOOL_TYPE_PEN);
    int32_t type = libinput_tablet_tool_get_type(tool);
    switch (type) {
        case LIBINPUT_TABLET_TOOL_TYPE_PEN: {
            return PointerEvent::TOOL_TYPE_PEN;
        }
        case LIBINPUT_TABLET_TOOL_TYPE_ERASER: {
            return PointerEvent::TOOL_TYPE_RUBBER;
        }
        case LIBINPUT_TABLET_TOOL_TYPE_BRUSH: {
            return PointerEvent::TOOL_TYPE_BRUSH;
        }
        case LIBINPUT_TABLET_TOOL_TYPE_PENCIL: {
            return PointerEvent::TOOL_TYPE_PENCIL;
        }
        case LIBINPUT_TABLET_TOOL_TYPE_AIRBRUSH: {
            return PointerEvent::TOOL_TYPE_AIRBRUSH;
        }
        case LIBINPUT_TABLET_TOOL_TYPE_MOUSE: {
            return PointerEvent::TOOL_TYPE_MOUSE;
        }
        case LIBINPUT_TABLET_TOOL_TYPE_LENS: {
            return PointerEvent::TOOL_TYPE_LENS;
        }
        default: {
            MMI_HILOGW("Invalid type");
            return PointerEvent::TOOL_TYPE_PEN;
        }
    }
}

bool TabletToolTransformProcessor::OnTip(struct libinput_event* event)
{
    CHKPF(event);
    auto tabletEvent = libinput_event_get_tablet_tool_event(event);
    CHKPF(tabletEvent);
    auto tipState = libinput_event_tablet_tool_get_tip_state(tabletEvent);
    bool ret = false;
    switch (tipState) {
        case LIBINPUT_TABLET_TOOL_TIP_DOWN: {
            ret = OnTipDown(tabletEvent);
            if (!ret) {
                MMI_HILOGE("OnTipDown failed");
            }
            break;
        }
        case LIBINPUT_TABLET_TOOL_TIP_UP: {
            ret = OnTipUp(tabletEvent);
            if (!ret) {
                MMI_HILOGE("OnTipUp failed");
            }
            break;
        }
        default: {
            MMI_HILOGE("Invalid tip state");
            break;
        }
    }
    return ret;
}

bool TabletToolTransformProcessor::OnTipDown(struct libinput_event_tablet_tool* event)
{
    CALL_DEBUG_ENTER;
    CHKPF(event);
    int32_t targetDisplayId = -1;
    PhysicalCoordinate tCoord;
    if (!WIN_MGR->CalculateTipPoint(event, targetDisplayId, tCoord)) {
        MMI_HILOGE("CalculateTipPoint failed");
        return false;
    }
    double tiltX = libinput_event_tablet_tool_get_tilt_x(event);
    double tiltY = libinput_event_tablet_tool_get_tilt_y(event);
    double pressure = libinput_event_tablet_tool_get_pressure(event);
    int32_t toolType = GetToolType(event);

    uint64_t time = libinput_event_tablet_tool_get_time_usec(event);
    pointerEvent_->SetActionStartTime(time);
    pointerEvent_->SetTargetDisplayId(targetDisplayId);
    pointerEvent_->SetActionTime(time);
    pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);

    PointerEvent::PointerItem item;
    if (pointerEvent_->GetPointerItem(DEFAULT_POINTER_ID, item)) {
        pointerEvent_->RemovePointerItem(DEFAULT_POINTER_ID);
    }
    item.SetPointerId(DEFAULT_POINTER_ID);
    item.SetDeviceId(deviceId_);
    item.SetDownTime(time);
    item.SetPressed(true);
    item.SetDisplayX(static_cast<int32_t>(tCoord.x));
    item.SetDisplayY(static_cast<int32_t>(tCoord.y));
    item.SetDisplayXPos(tCoord.x);
    item.SetDisplayYPos(tCoord.y);
    item.SetTiltX(tiltX);
    item.SetTiltY(tiltY);
    item.SetToolType(toolType);
    item.SetPressure(pressure);
    item.SetTargetWindowId(-1);

    pointerEvent_->SetDeviceId(deviceId_);
    pointerEvent_->AddPointerItem(item);
    pointerEvent_->SetPointerId(DEFAULT_POINTER_ID);
    return true;
}

bool TabletToolTransformProcessor::OnTipMotion(struct libinput_event* event)
{
    CALL_DEBUG_ENTER;
    CHKPF(event);
    auto tabletEvent = libinput_event_get_tablet_tool_event(event);
    CHKPF(tabletEvent);
    uint64_t time = libinput_event_tablet_tool_get_time_usec(tabletEvent);
    pointerEvent_->SetActionTime(time);
    pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);

    int32_t targetDisplayId = pointerEvent_->GetTargetDisplayId();
    PhysicalCoordinate tCoord;
    if (!WIN_MGR->CalculateTipPoint(tabletEvent, targetDisplayId, tCoord)) {
        MMI_HILOGE("CalculateTipPoint failed");
        return false;
    }
    double tiltX = libinput_event_tablet_tool_get_tilt_x(tabletEvent);
    double tiltY = libinput_event_tablet_tool_get_tilt_y(tabletEvent);
    double pressure = libinput_event_tablet_tool_get_pressure(tabletEvent);
    int32_t toolType = GetToolType(tabletEvent);

    PointerEvent::PointerItem item;
    if (!pointerEvent_->GetPointerItem(DEFAULT_POINTER_ID, item)) {
        MMI_HILOGW("The pointer is expected, but not found");
        pointerEvent_->SetActionStartTime(time);
        pointerEvent_->SetTargetDisplayId(targetDisplayId);
        pointerEvent_->SetDeviceId(deviceId_);
        pointerEvent_->SetPointerId(DEFAULT_POINTER_ID);

        item.SetPointerId(DEFAULT_POINTER_ID);
        item.SetDeviceId(deviceId_);
        item.SetDownTime(time);
        item.SetPressed(true);
        item.SetToolType(toolType);
    }
    item.SetDisplayX(static_cast<int32_t>(tCoord.x));
    item.SetDisplayY(static_cast<int32_t>(tCoord.y));
    item.SetDisplayXPos(tCoord.x);
    item.SetDisplayYPos(tCoord.y);
    item.SetTiltX(tiltX);
    item.SetTiltY(tiltY);
    item.SetPressure(pressure);
    pointerEvent_->UpdatePointerItem(DEFAULT_POINTER_ID, item);
    return true;
}

bool TabletToolTransformProcessor::OnTipUp(struct libinput_event_tablet_tool* event)
{
    CALL_DEBUG_ENTER;
    CHKPF(event);
    uint64_t time = libinput_event_tablet_tool_get_time_usec(event);
    pointerEvent_->SetActionTime(time);
    pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_UP);

    PointerEvent::PointerItem item;
    if (!pointerEvent_->GetPointerItem(DEFAULT_POINTER_ID, item)) {
        MMI_HILOGE("GetPointerItem failed");
        return false;
    }
    item.SetPressed(false);
    pointerEvent_->UpdatePointerItem(DEFAULT_POINTER_ID, item);
    return true;
}
} // namespace MMI
} // namespace OHOS
