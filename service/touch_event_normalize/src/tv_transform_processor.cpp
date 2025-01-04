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

#include "tv_transform_processor.h"

#include <linux/input.h>

#include "aggregator.h"
#include "bytrace_adapter.h"
#include "event_log_helper.h"
#include "input_device_manager.h"
#include "i_input_windows_manager.h"
#include "fingersense_wrapper.h"
#include "mmi_log.h"
#include "timer_manager.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_DISPATCH
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TVTransformProcessor"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t POINTER_MOVEFLAG = { 7 };
}

TVTransformProcessor::TVTransformProcessor(int32_t deviceId)
    : deviceId_(deviceId)
{
    InitToolTypes();
}

bool TVTransformProcessor::DumpInner()
{
    static int32_t lastDeviceId = -1;
    static std::string lastDeviceName("default");
    auto nowId = pointerEvent_->GetDeviceId();
    if (lastDeviceId != nowId) {
        auto device = INPUT_DEV_MGR->GetInputDevice(nowId);
        CHKPF(device);
        lastDeviceId = nowId;
        lastDeviceName = device->GetName();
    }
    EventLogHelper::PrintEventData(pointerEvent_, MMI_LOG_FREEZE);
    aggregator_.Record(MMI_LOG_FREEZE, lastDeviceName + ", TW: " +
        std::to_string(pointerEvent_->GetTargetWindowId()), std::to_string(pointerEvent_->GetId()));
    return true;
}

std::shared_ptr<PointerEvent> TVTransformProcessor::OnEvent(struct libinput_event *event)
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
            break;
        }
        case LIBINPUT_EVENT_TOUCH_UP: {
            break;
        }
        case LIBINPUT_EVENT_TOUCH_MOTION: {
            CHKFR(OnEventTvTouchMotion(event), nullptr, "Get OnEventTvTouchMotion failed");
            break;
        }
        default: {
            MMI_HILOGE("Unknown event type, touchType:%{public}d", type);
            return nullptr;
        }
    }
    PointerEvent::PointerItem pointerItem;

    if (!HandlePostInner(event, pointerItem)) {
        CHKPP(pointerEvent_);
        return nullptr;
    }
    MMI_HILOGI("TW:%{public}d", pointerEvent_->GetTargetWindowId());
    WIN_MGR->UpdateTargetPointer(pointerEvent_);
    MMI_HILOGI("TW:%{public}d", pointerEvent_->GetTargetWindowId());
    DumpInner();
    return pointerEvent_;
}

bool TVTransformProcessor::OnEventTvTouchMotion(struct libinput_event* event)
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
    MMI_HILOGI("Change coordinate: x:%.2f, y:%.2f, currentDisplayId:%d",
       x, y, logicalDisplayId);
    WIN_MGR->UpdateAndAdjustMouseLocation(logicalDisplayId, x, y);
    pointerEvent_->SetTargetDisplayId(logicalDisplayId);
    MMI_HILOGI("Change coordinate: x:%.2f, y:%.2f, currentDisplayId:%d",
        x, y, logicalDisplayId);
#endif // OHOS_BUILD_ENABLE_WATCH
    return true;
}

bool TVTransformProcessor::HandlePostInner(struct libinput_event* event, PointerEvent::PointerItem &pointerItem)
{
    CALL_DEBUG_ENTER;
    CHKPF(pointerEvent_);
    auto mouseInfo = WIN_MGR->GetMouseInfo();
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
    pointerItem.SetDeviceId(deviceId_);
    auto touch = libinput_event_get_touch_event(event);
    CHKPF(touch);
    int32_t moveFlag = libinput_event_touch_get_move_flag(touch);
    double pressure = libinput_event_touch_get_pressure(touch);
    int32_t longAxis = libinput_event_get_touch_contact_long_axis(touch);
    int32_t shortAxis = libinput_event_get_touch_contact_short_axis(touch);
    int32_t seatSlot = libinput_event_touch_get_seat_slot(touch);
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
void TVTransformProcessor::InitToolTypes()
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
