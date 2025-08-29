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

#include "i_input_windows_manager.h"

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
    : deviceId_(deviceId)
{
    current_ = [this]() {
        DrawTouchGraphicIdle();
    };
}

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
            if (!OnTipProximity(event)) {
                MMI_HILOGE("OnTipProximity failed");
                return nullptr;
            }
            break;
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
    DrawTouchGraphic();
    return pointerEvent_;
}

void TabletToolTransformProcessor::OnDeviceRemoved()
{}

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
    PointerEvent::PointerItem item;
    if (pointerEvent_->GetPointerItem(DEFAULT_POINTER_ID, item)) {
        pointerEvent_->RemovePointerItem(DEFAULT_POINTER_ID);
    }
    item.SetPointerId(DEFAULT_POINTER_ID);
    item.SetDeviceId(deviceId_);
    int32_t toolType = GetToolType(event);
    item.SetToolType(toolType);
    if (!WIN_MGR->CalculateTipPoint(event, targetDisplayId, tCoord, item)) {
        MMI_HILOGE("CalculateTipPoint failed");
        return false;
    }
    double tiltX = libinput_event_tablet_tool_get_tilt_x(event);
    double tiltY = libinput_event_tablet_tool_get_tilt_y(event);
    double pressure = libinput_event_tablet_tool_get_pressure(event);
    int32_t twist = libinput_event_tablet_tool_get_twist(event);

    uint64_t time = libinput_event_tablet_tool_get_time_usec(event);
    pointerEvent_->SetActionStartTime(time);
    pointerEvent_->SetTargetDisplayId(targetDisplayId);
    pointerEvent_->SetActionTime(time);
    pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);

    item.SetDownTime(time);
    item.SetPressed(true);
    item.SetDisplayX(static_cast<int32_t>(tCoord.x));
    item.SetDisplayY(static_cast<int32_t>(tCoord.y));
    item.SetDisplayXPos(tCoord.x);
    item.SetDisplayYPos(tCoord.y);
    item.SetRawDisplayX(static_cast<int32_t>(tCoord.x));
    item.SetRawDisplayY(static_cast<int32_t>(tCoord.y));
    item.SetTiltX(tiltX);
    item.SetTiltY(tiltY);
    item.SetPressure(pressure);
    item.SetTargetWindowId(-1);
    item.SetTwist(twist);

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
    }

    double tiltX = libinput_event_tablet_tool_get_tilt_x(tabletEvent);
    double tiltY = libinput_event_tablet_tool_get_tilt_y(tabletEvent);
    double pressure = libinput_event_tablet_tool_get_pressure(tabletEvent);
    int32_t toolType = GetToolType(tabletEvent);
    int32_t twist = libinput_event_tablet_tool_get_twist(tabletEvent);

    item.SetToolType(toolType);
    PhysicalCoordinate tCoord;
    if (!WIN_MGR->CalculateTipPoint(tabletEvent, targetDisplayId, tCoord, item)) {
        MMI_HILOGE("CalculateTipPoint failed");
        return false;
    }
    item.SetDisplayX(static_cast<int32_t>(tCoord.x));
    item.SetDisplayY(static_cast<int32_t>(tCoord.y));
    item.SetDisplayXPos(tCoord.x);
    item.SetDisplayYPos(tCoord.y);
    item.SetRawDisplayX(static_cast<int32_t>(tCoord.x));
    item.SetRawDisplayY(static_cast<int32_t>(tCoord.y));
    item.SetTiltX(tiltX);
    item.SetTiltY(tiltY);
    item.SetPressure(pressure);
    item.SetTwist(twist);
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

bool TabletToolTransformProcessor::OnTipProximity(struct libinput_event* event)
{
    CALL_DEBUG_ENTER;
    CHKPF(event);
    auto tabletEvent = libinput_event_get_tablet_tool_event(event);
    CHKPF(tabletEvent);
    uint64_t time = libinput_event_tablet_tool_get_time_usec(tabletEvent);
    pointerEvent_->SetActionTime(time);

    bool tabletProximityState = libinput_event_tablet_tool_get_proximity_state(tabletEvent);
    if (tabletProximityState) {
        MMI_HILOGD("The pen is getting close and report proximity in event");
        pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_PROXIMITY_IN);
    } else {
        MMI_HILOGD("The pen is getting away and report proximity out event");
        pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_PROXIMITY_OUT);
    }

    int32_t targetDisplayId = pointerEvent_->GetTargetDisplayId();
    double tiltX = libinput_event_tablet_tool_get_tilt_x(tabletEvent);
    double tiltY = libinput_event_tablet_tool_get_tilt_y(tabletEvent);
    double pressure = libinput_event_tablet_tool_get_pressure(tabletEvent);
    int32_t toolType = GetToolType(tabletEvent);

    PointerEvent::PointerItem item;
    if (!pointerEvent_->GetPointerItem(DEFAULT_POINTER_ID, item)) {
        MMI_HILOGW("The pointer is expected, but not found");
    }

    pointerEvent_->SetActionStartTime(time);
    pointerEvent_->SetTargetDisplayId(targetDisplayId);
    pointerEvent_->SetDeviceId(deviceId_);
    pointerEvent_->SetPointerId(DEFAULT_POINTER_ID);

    item.SetPointerId(DEFAULT_POINTER_ID);
    item.SetDeviceId(deviceId_);
    item.SetDownTime(time);
    item.SetPressed(false);
    item.SetToolType(toolType);
    PhysicalCoordinate coord;
    if (!WIN_MGR->CalculateTipPoint(tabletEvent, targetDisplayId, coord, item)) {
        MMI_HILOGE("CalculateTipPoint failed");
        return false;
    }
    item.SetDisplayX(static_cast<int32_t>(coord.x));
    item.SetDisplayY(static_cast<int32_t>(coord.y));
    item.SetDisplayXPos(coord.x);
    item.SetDisplayYPos(coord.y);
    item.SetRawDisplayX(static_cast<int32_t>(coord.x));
    item.SetRawDisplayY(static_cast<int32_t>(coord.y));
    item.SetTiltX(tiltX);
    item.SetTiltY(tiltY);
    item.SetPressure(pressure);
    pointerEvent_->UpdatePointerItem(DEFAULT_POINTER_ID, item);
    return true;
}

void TabletToolTransformProcessor::DrawTouchGraphic()
{
    CHKPV(current_);
    current_();
}

void TabletToolTransformProcessor::DrawTouchGraphicIdle()
{
    CHKPV(pointerEvent_);
    auto pointerAction = pointerEvent_->GetPointerAction();
    switch (pointerAction) {
        case PointerEvent::POINTER_ACTION_PROXIMITY_IN:
        case PointerEvent::POINTER_ACTION_DOWN:
        case PointerEvent::POINTER_ACTION_MOVE: {
            pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
            current_ = [this]() {
                DrawTouchGraphicDrawing();
            };
            break;
        }
        default: {
            return;
        }
    }
    WIN_MGR->DrawTouchGraphic(pointerEvent_);
    pointerEvent_->SetPointerAction(pointerAction);
}

void TabletToolTransformProcessor::DrawTouchGraphicDrawing()
{
    CHKPV(pointerEvent_);
    bool originalPressedStatus = false;
    PointerEvent::PointerItem pointerItem;
    bool isPointerItemExist = pointerEvent_->GetPointerItem(DEFAULT_POINTER_ID, pointerItem);
    auto pointerAction = pointerEvent_->GetPointerAction();
    switch (pointerAction) {
        case PointerEvent::POINTER_ACTION_MOVE: {
            if (isPointerItemExist) {
                originalPressedStatus = pointerItem.IsPressed();
                pointerItem.SetPressed(true);
                pointerEvent_->UpdatePointerItem(DEFAULT_POINTER_ID, pointerItem);
            }
        }
        case PointerEvent::POINTER_ACTION_UP: {
            pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
            break;
        }
        case PointerEvent::POINTER_ACTION_PROXIMITY_OUT: {
            auto pointerEvent = std::make_shared<PointerEvent>(*pointerEvent_);
            PointerEvent::PointerItem item {};
            if (pointerEvent->GetPointerItem(pointerEvent->GetPointerId(), item)) {
                item.SetPressed(true);
                pointerEvent->UpdatePointerItem(pointerEvent->GetPointerId(), item);
                pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
                WIN_MGR->DrawTouchGraphic(pointerEvent);
            }
            pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
            current_ = [this]() {
                DrawTouchGraphicIdle();
            };
            break;
        }
        default: {
            return;
        }
    }
    WIN_MGR->DrawTouchGraphic(pointerEvent_);
    pointerEvent_->SetPointerAction(pointerAction);
    if (isPointerItemExist) {
        pointerItem.SetPressed(originalPressedStatus);
        pointerEvent_->UpdatePointerItem(DEFAULT_POINTER_ID, pointerItem);
    }
}
} // namespace MMI
} // namespace OHOS
