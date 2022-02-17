/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "log.h"

namespace OHOS {
namespace MMI {
namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "TouchTransformPointProcessor"};
}

TouchTransformPointProcessor::TouchTransformPointProcessor(int32_t deviceId) : deviceId_(deviceId)
{
    pointerEvent_ = PointerEvent::Create();
}

TouchTransformPointProcessor::~TouchTransformPointProcessor() {}

void TouchTransformPointProcessor::SetPointEventSource(int32_t sourceType)
{
    pointerEvent_->SetSourceType(sourceType);
}

void TouchTransformPointProcessor::OnEventTouchDown(libinput_event *event)
{
    MMI_LOGD("Enter");
    CHKPV(event);
    auto data = libinput_event_get_touch_event(event);
    CHKPV(data);
    auto seatSlot = libinput_event_touch_get_seat_slot(data);
    auto pressure = libinput_event_get_touch_pressure(event);
    int32_t logicalY = -1;
    int32_t logicalX = -1;
    int32_t logicalDisplayId = -1;
    WinMgr->TouchDownPointToDisplayPoint(data, logicalX, logicalY, logicalDisplayId);
    auto pointIds = pointerEvent_->GetPointersIdList();
    auto time = libinput_event_touch_get_time(data);
    if (pointIds.empty()) {
        pointerEvent_->SetActionStartTime(time);
        pointerEvent_->SetTargetDisplayId(logicalDisplayId);
    }
    pointerEvent_->SetActionTime(time);
    pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);

    PointerEvent::PointerItem pointer;
    pointer.SetPointerId(seatSlot);
    pointer.SetDownTime(time);
    pointer.SetPressed(true);
    pointer.SetGlobalX(logicalX);
    pointer.SetGlobalY(logicalY);
    pointer.SetPressure(pressure);
    pointer.SetDeviceId(deviceId_);
    pointerEvent_->SetDeviceId(deviceId_);
    pointerEvent_->AddPointerItem(pointer);
    pointerEvent_->SetPointerId(seatSlot);
    MMI_LOGD("LogicalX:%{public}d,logicalY:%{public}d,logicalDisplayId:%{public}d",
             logicalX, logicalY, logicalDisplayId);
    MMI_LOGD("Leave");
}

void TouchTransformPointProcessor::OnEventTouchMotion(libinput_event *event)
{
    MMI_LOGD("Enter");
    CHKPV(event);
    auto data = libinput_event_get_touch_event(event);
    CHKPV(data);
    auto seatSlot = libinput_event_touch_get_seat_slot(data);
    auto pressure = libinput_event_get_touch_pressure(event);
    auto time = libinput_event_touch_get_time(data);
    pointerEvent_->SetActionTime(time);
    pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    int32_t logicalY = -1;
    int32_t logicalX = -1;
    int32_t logicalDisplayId = pointerEvent_->GetTargetDisplayId();
    WinMgr->TouchMotionPointToDisplayPoint(data, logicalDisplayId, logicalX, logicalY);
    PointerEvent::PointerItem pointer;
    CHK(pointerEvent_->GetPointerItem(seatSlot, pointer), PARAM_INPUT_FAIL);
    pointer.SetPressure(pressure);
    pointer.SetGlobalX(logicalX);
    pointer.SetGlobalY(logicalY);
    pointerEvent_->UpdatePointerItem(seatSlot, pointer);
    pointerEvent_->SetPointerId(seatSlot);
    MMI_LOGD("Leave");
}

void TouchTransformPointProcessor::OnEventTouchUp(libinput_event *event)
{
    MMI_LOGD("Enter");
    CHKPV(event);
    auto data = libinput_event_get_touch_event(event);
    CHKPV(data);
    auto seatSlot = libinput_event_touch_get_seat_slot(data);
    auto time = libinput_event_touch_get_time(data);
    pointerEvent_->SetActionTime(time);
    pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_UP);

    PointerEvent::PointerItem pointer;
    CHK(pointerEvent_->GetPointerItem(seatSlot, pointer), PARAM_INPUT_FAIL);
    pointer.SetPressed(false);
    pointerEvent_->UpdatePointerItem(seatSlot, pointer);
    pointerEvent_->SetPointerId(seatSlot);
    MMI_LOGD("Leave");
}

std::shared_ptr<PointerEvent> TouchTransformPointProcessor::OnLibinputTouchEvent(libinput_event *event)
{
    MMI_LOGD("begin");
    CHKPP(event, nullptr);
    if (pointerEvent_ == nullptr) {
        MMI_LOGE("PointerEvent_ is nullptr");
        return nullptr;
    }
    pointerEvent_->UpdateId();
    auto type = libinput_event_get_type(event);
    switch (type) {
        case LIBINPUT_EVENT_TOUCH_DOWN: {
            OnEventTouchDown(event);
            break;
        }
        case LIBINPUT_EVENT_TOUCH_UP: {
            OnEventTouchUp(event);
            break;
        }
        case LIBINPUT_EVENT_TOUCH_MOTION: {
            OnEventTouchMotion(event);
            break;
        }
        default: {
            MMI_LOGE("Unknown event type, touchType:%{public}d", type);
            return nullptr;
        }
    }
    MMI_LOGD("end");
    return pointerEvent_;
}
} // namespace MMI
} // namespace OHOS

