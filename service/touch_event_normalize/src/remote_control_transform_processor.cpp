/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "remote_control_transform_processor.h"

#include <linux/input.h>

#include "event_log_helper.h"
#include "input_device_manager.h"
#include "i_input_windows_manager.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_DISPATCH
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "Remote_ControlTransformProcessor"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t POINTER_MOVEFLAG { 7 };
constexpr int32_t PRINT_INTERVAL_COUNT { 100 };
}

Remote_ControlTransformProcessor::Remote_ControlTransformProcessor(int32_t deviceId)
    : deviceId_(deviceId)
{
    InitToolTypes();
}

bool Remote_ControlTransformProcessor::DumpInner()
{
    static std::string deviceName("default");
    auto deviceId = pointerEvent_->GetDeviceId();
    auto device = INPUT_DEV_MGR->GetInputDevice(deviceId);
    CHKPF(device);
    deviceName = device->GetName();
    EventLogHelper::PrintEventData(pointerEvent_, MMI_LOG_FREEZE);
    aggregator_.Record(MMI_LOG_FREEZE, deviceName + ", TW: " +
        std::to_string(pointerEvent_->GetTargetWindowId()), std::to_string(pointerEvent_->GetId()));
    return true;
}

std::shared_ptr<PointerEvent> Remote_ControlTransformProcessor::OnEvent(struct libinput_event *event)
{
    CALL_DEBUG_ENTER;
    CHKPP(event);
    if (pointerEvent_ == nullptr) {
        pointerEvent_ = PointerEvent::Create();
        CHKPP(pointerEvent_);
    }
    const int32_t type = libinput_event_get_type(event);
    pointerEvent_->ClearAxisValue();
    switch (type) {
        case LIBINPUT_EVENT_TOUCH_DOWN: {
            MMI_HILOGD("Tv Touch event is not Motion");
            return pointerEvent_;
        }
        case LIBINPUT_EVENT_TOUCH_UP: {
            MMI_HILOGD("Tv Touch event is not Motion");
            return pointerEvent_;
        }
        case LIBINPUT_EVENT_TOUCH_MOTION: {
            processedCount_++;
            if (!OnEventTouchMotion(event) && (processedCount_ == PRINT_INTERVAL_COUNT)) {
                MMI_HILOGE("Get OnEventTvTouchMotion failed");
                processedCount_ = 0;
            }
            break;
        }
        default: {
            MMI_HILOGE("Unknown event type, touchType:%{public}d", type);
            return nullptr;
        }
    }

    if (!HandlePostInner(event)) {
        CHKPP(pointerEvent_);
        return nullptr;
    }
    MMI_HILOGD("TW:%{public}d", pointerEvent_->GetTargetWindowId());
    WIN_MGR->UpdateTargetPointer(pointerEvent_);
    MMI_HILOGD("TW:%{public}d", pointerEvent_->GetTargetWindowId());
    DumpInner();
    return pointerEvent_;
}

void Remote_ControlTransformProcessor::OnDeviceRemoved()
{}

bool Remote_ControlTransformProcessor::OnEventTouchMotion(struct libinput_event* event)
{
    CALL_DEBUG_ENTER;
    CHKPF(pointerEvent_);
#ifndef OHOS_BUILD_ENABLE_WATCH
    pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent_->SetButtonId(buttonId_);
    auto touch = libinput_event_get_touch_event(event);
    CHKPF(touch);
    EventTouch touchInfo;
    int32_t logicalDisplayId = pointerEvent_->GetTargetDisplayId();
    if (!WIN_MGR->TouchPointToDisplayPoint(deviceId_, touch, touchInfo, logicalDisplayId)) {
        MMI_HILOGE("Get TouchMotionPointToDisplayPoint failed");
        return false;
    }
    double x = touchInfo.point.x;
    double y = touchInfo.point.y;
    MMI_HILOGD("Change coordinate: x:%.2f, y:%.2f, currentDisplayId:%d",
        x, y, logicalDisplayId);
    WIN_MGR->UpdateAndAdjustMouseLocation(logicalDisplayId, x, y);
    pointerEvent_->SetTargetDisplayId(logicalDisplayId);
    MMI_HILOGD("Change coordinate: x:%.2f, y:%.2f, currentDisplayId:%d",
        x, y, logicalDisplayId);
#endif // OHOS_BUILD_ENABLE_WATCH
    return true;
}

bool Remote_ControlTransformProcessor::HandlePostInner(struct libinput_event* event)
{
    CALL_DEBUG_ENTER;
    CHKPF(pointerEvent_);
    auto mouseInfo = WIN_MGR->GetMouseInfo();
    PointerEvent::PointerItem pointerItem;
    pointerItem.SetDisplayX(mouseInfo.physicalX);
    pointerItem.SetDisplayY(mouseInfo.physicalY);
    pointerItem.SetDisplayXPos(mouseInfo.physicalX);
    pointerItem.SetDisplayYPos(mouseInfo.physicalY);
    pointerItem.SetWindowX(0);
    pointerItem.SetWindowY(0);
    pointerItem.SetWindowXPos(0.0);
    pointerItem.SetWindowYPos(0.0);
    auto touch = libinput_event_get_touch_event(event);
    CHKPF(touch);
    int32_t seatSlot = libinput_event_touch_get_seat_slot(touch);
    pointerItem.SetPointerId(seatSlot);
    pointerItem.SetPressed(isPressed_);

    int64_t time = GetSysClockTime();
    pointerItem.SetDownTime(time);
    pointerItem.SetWidth(0);
    pointerItem.SetHeight(0);
    pointerItem.SetDeviceId(deviceId_);
    double pressure = libinput_event_touch_get_pressure(touch);
    int32_t longAxis = libinput_event_get_touch_contact_long_axis(touch);
    int32_t shortAxis = libinput_event_get_touch_contact_short_axis(touch);
    pointerItem.SetMoveFlag(POINTER_MOVEFLAG);
    pointerItem.SetPressure(pressure);
    pointerItem.SetLongAxis(longAxis);
    pointerItem.SetShortAxis(shortAxis);

    pointerEvent_->UpdateId();
    StartLogTraceId(pointerEvent_->GetId(), pointerEvent_->GetEventType(), pointerEvent_->GetPointerAction());
    pointerEvent_->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent_->SetActionTime(time);
    pointerEvent_->SetActionStartTime(time);
    pointerEvent_->SetDeviceId(deviceId_);
    pointerEvent_->SetPointerId(seatSlot);
    pointerEvent_->SetTargetDisplayId(mouseInfo.displayId);
    pointerEvent_->SetTargetWindowId(-1);
    pointerEvent_->SetAgentWindowId(-1);
    pointerItem.SetToolType(PointerEvent::TOOL_TYPE_MOUSE);
    pointerEvent_->UpdatePointerItem(pointerEvent_->GetPointerId(), pointerItem);
    return true;
}
void Remote_ControlTransformProcessor::InitToolTypes()
{
    vecToolType_.emplace_back(std::make_pair(BTN_TOOL_PEN, PointerEvent::TOOL_TYPE_PEN));
    vecToolType_.emplace_back(std::make_pair(BTN_TOOL_RUBBER, PointerEvent::TOOL_TYPE_RUBBER));
    vecToolType_.emplace_back(std::make_pair(BTN_TOOL_BRUSH, PointerEvent::TOOL_TYPE_BRUSH));
    vecToolType_.emplace_back(std::make_pair(BTN_TOOL_PENCIL, PointerEvent::TOOL_TYPE_PENCIL));
    vecToolType_.emplace_back(std::make_pair(BTN_TOOL_AIRBRUSH, PointerEvent::TOOL_TYPE_AIRBRUSH));
    vecToolType_.emplace_back(std::make_pair(BTN_TOOL_FINGER, PointerEvent::TOOL_TYPE_FINGER));
    vecToolType_.emplace_back(std::make_pair(BTN_TOOL_MOUSE, PointerEvent::TOOL_TYPE_MOUSE));
    vecToolType_.emplace_back(std::make_pair(BTN_TOOL_LENS, PointerEvent::TOOL_TYPE_LENS));
}
} // namespace MMI
} // namespace OHOS
