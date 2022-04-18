/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "tablet_tool_processor.h"
#include "input_windows_manager.h"
#include "mmi_log.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "TabletToolProcessor" };
constexpr int32_t DEFAULT_POINTER_ID { 0 };
} // namespace

TabletToolProcessor::TabletToolProcessor(int32_t deviceId)
    : deviceId_(deviceId)
{}

std::shared_ptr<PointerEvent> TabletToolProcessor::OnEvent(struct libinput_event* event)
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
            MMI_HILOGE("proximity event");
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
    return pointerEvent_;
}

bool TabletToolProcessor::OnTip(struct libinput_event* event)
{
    auto tabletEvent = libinput_event_get_tablet_tool_event(event);
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

bool TabletToolProcessor::OnTipDown(struct libinput_event_tablet_tool* event)
{
    CALL_LOG_ENTER;
    int32_t targetDisplayId = -1;
    LogicalCoordinate tCoord;
    if (!WinMgr->CalculateTipPoint(event, targetDisplayId, tCoord)) {
        MMI_HILOGE("CalculateTipPoint failed");
        return false;
    }
    auto tiltX = libinput_event_tablet_tool_get_tilt_x(event);
    auto tiltY = libinput_event_tablet_tool_get_tilt_y(event);
    auto pressure = libinput_event_tablet_tool_get_pressure(event);

    int64_t time = GetSysClockTime();
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
    item.SetGlobalX(tCoord.x);
    item.SetGlobalY(tCoord.y);
    item.SetTiltX(tiltX);
    item.SetTiltY(tiltY);
    item.SetPressure(static_cast<int32_t>(pressure * 1000));

    pointerEvent_->SetDeviceId(deviceId_);
    pointerEvent_->AddPointerItem(item);
    pointerEvent_->SetPointerId(DEFAULT_POINTER_ID);
    return true;
}

bool TabletToolProcessor::OnTipMotion(struct libinput_event* event)
{
    CALL_LOG_ENTER;
    auto tabletEvent = libinput_event_get_tablet_tool_event(event);
    int64_t time = GetSysClockTime();
    pointerEvent_->SetActionTime(time);
    pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);

    int32_t targetDisplayId = pointerEvent_->GetTargetDisplayId();
    LogicalCoordinate tCoord;
    if (!WinMgr->CalculateTipPoint(tabletEvent, targetDisplayId, tCoord)) {
        MMI_HILOGE("CalculateTipPoint failed");
        return false;
    }
    auto tiltX = libinput_event_tablet_tool_get_tilt_x(tabletEvent);
    auto tiltY = libinput_event_tablet_tool_get_tilt_y(tabletEvent);
    auto pressure = libinput_event_tablet_tool_get_pressure(tabletEvent);

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
    }
    item.SetGlobalX(tCoord.x);
    item.SetGlobalY(tCoord.y);
    item.SetTiltX(tiltX);
    item.SetTiltY(tiltY);
    item.SetPressure(static_cast<int32_t>(pressure * 1000));
    pointerEvent_->UpdatePointerItem(DEFAULT_POINTER_ID, item);
    return true;
}

bool TabletToolProcessor::OnTipUp(struct libinput_event_tablet_tool*)
{
    CALL_LOG_ENTER;
    int64_t time = GetSysClockTime();
    pointerEvent_->SetActionTime(time);
    pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_UP);

    PointerEvent::PointerItem item;
    if (!pointerEvent_->GetPointerItem(DEFAULT_POINTER_ID, item)) {
        MMI_HILOGE("GetPointerItem failed");
        return false;
    }
    item.SetPressed(false);
    item.SetPressure(0);
    pointerEvent_->UpdatePointerItem(DEFAULT_POINTER_ID, item);
    return true;
}
} // namespace MMI
} // namespace OHOS
