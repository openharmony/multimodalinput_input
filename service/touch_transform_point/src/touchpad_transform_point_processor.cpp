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
#include "log.h"

namespace OHOS {
namespace MMI {
    namespace {
        constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN,
            "TouchPadTransformPointProcessor"};
    }

TouchPadTransformPointProcessor::TouchPadTransformPointProcessor(int32_t deviceId) : deviceId_(deviceId)
{
    pointerEvent_ = PointerEvent::Create();
}

TouchPadTransformPointProcessor::~TouchPadTransformPointProcessor() {}

void TouchPadTransformPointProcessor::SetPointEventSource(int32_t sourceType)
{
    pointerEvent_->SetSourceType(sourceType);
}

void TouchPadTransformPointProcessor::OnEventTouchPadDown(libinput_event *event)
{
    MMI_LOGD("Enter");
    CHKPV(event);
    auto data = libinput_event_get_touchpad_event(event);
    CHKPV(data);
    auto seatSlot = libinput_event_touchpad_get_seat_slot(data);
    auto logicalX = libinput_event_touchpad_get_x(data);
    auto logicalY = libinput_event_touchpad_get_y(data);

    auto time = static_cast<int64_t>(libinput_event_touchpad_get_time(data));
    auto pointIds = pointerEvent_->GetPointersIdList();
    if (pointIds.empty()) {
        pointerEvent_->SetActionStartTime(time);
    }
    pointerEvent_->SetActionTime(time);
    pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    PointerEvent::PointerItem pointer;
    pointer.SetPointerId(seatSlot);
    pointer.SetDownTime(time);
    pointer.SetPressed(true);
    pointer.SetGlobalX((int32_t)logicalX);
    pointer.SetGlobalY((int32_t)logicalY);
    pointer.SetDeviceId(deviceId_);
    pointerEvent_->SetDeviceId(deviceId_);
    pointerEvent_->AddPointerItem(pointer);
    pointerEvent_->SetPointerId(seatSlot);
    MMI_LOGD("End");
}

void TouchPadTransformPointProcessor::OnEventTouchPadMotion(libinput_event *event)
{
    MMI_LOGD("Enter");
    CHKPV(event);
    auto data = libinput_event_get_touchpad_event(event);
    CHKPV(data);
    auto seatSlot = libinput_event_touchpad_get_seat_slot(data);
    auto logicalX = libinput_event_touchpad_get_x(data);
    auto logicalY = libinput_event_touchpad_get_y(data);

    auto time = static_cast<int64_t>(libinput_event_touchpad_get_time(data));
    pointerEvent_->SetActionTime(time);
    pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    PointerEvent::PointerItem pointer;
    CHK(pointerEvent_->GetPointerItem(seatSlot, pointer), PARAM_INPUT_FAIL);
    pointer.SetGlobalX((int32_t)logicalX);
    pointer.SetGlobalY((int32_t)logicalY);
    pointerEvent_->UpdatePointerItem(seatSlot, pointer);
    pointerEvent_->SetPointerId(seatSlot);
    MMI_LOGD("End");
}

void TouchPadTransformPointProcessor::OnEventTouchPadUp(libinput_event *event)
{
    MMI_LOGD("Enter");
    CHKPV(event);
    auto data = libinput_event_get_touchpad_event(event);
    CHKPV(data);
    auto seatSlot = libinput_event_touchpad_get_seat_slot(data);
    auto logicalX = libinput_event_touchpad_get_x(data);
    auto logicalY = libinput_event_touchpad_get_y(data);

    auto time = static_cast<int64_t>(libinput_event_touchpad_get_time(data));
    pointerEvent_->SetActionTime(time);
    pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_UP);

    PointerEvent::PointerItem pointer;
    CHK(pointerEvent_->GetPointerItem(seatSlot, pointer), PARAM_INPUT_FAIL);
    pointer.SetPressed(false);
    pointer.SetGlobalX((int32_t)logicalX);
    pointer.SetGlobalY((int32_t)logicalY);
    pointerEvent_->UpdatePointerItem(seatSlot, pointer);
    pointerEvent_->SetPointerId(seatSlot);
    MMI_LOGD("End");
}

std::shared_ptr<PointerEvent> TouchPadTransformPointProcessor::OnLibinputTouchPadEvent(
    libinput_event *event)
{
    MMI_LOGD("begin");
    CHKPP(event, nullptr);
    auto type = libinput_event_get_type(event);
    pointerEvent_->UpdateId();
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
    MMI_LOGD("end");
    return pointerEvent_;
}
} // namespace MMI
} // namespace OHOS
