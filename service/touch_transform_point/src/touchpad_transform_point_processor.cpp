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

#include "touchpad_transform_point_processor.h"
#include "log.h"

namespace OHOS::MMI {
    namespace {
        static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN,
            "TouchPadTransformPointProcessor"};
    }
}

OHOS::MMI::TouchPadTransformPointProcessor::TouchPadTransformPointProcessor()
{
    this->pointerEvent_ = PointerEvent::Create();
}

OHOS::MMI::TouchPadTransformPointProcessor::~TouchPadTransformPointProcessor() {}

void OHOS::MMI::TouchPadTransformPointProcessor::SetPointEventSource(int32_t sourceType)
{
    pointerEvent_->SetSourceType(sourceType);
}

void OHOS::MMI::TouchPadTransformPointProcessor::OnEventTouchPadDown(libinput_event *event)
{
    CHKP(event, PARAM_INPUT_INVALID);
    MMI_LOGD("this touch pad event is down begin");
    auto data = libinput_event_get_touchpad_event(event);
    auto time = libinput_event_touchpad_get_time(data);
    auto seatSlot = libinput_event_touchpad_get_seat_slot(data);
    auto logicalX = libinput_event_touchpad_get_x(data);
    auto logicalY = libinput_event_touchpad_get_y(data);

    int32_t id = 1;
    auto pointIds = pointerEvent_->GetPointersIdList();
    if (pointIds.size() == 0) {
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
    pointer.SetDeviceId(id);
    pointerEvent_->SetDeviceId(id);
    pointerEvent_->AddPointerItem(pointer);
    pointerEvent_->SetPointerId(seatSlot);
    MMI_LOGD("this touch pad event is down end");
}

void OHOS::MMI::TouchPadTransformPointProcessor::OnEventTouchPadMotion(libinput_event *event)
{
    CHKP(event, PARAM_INPUT_INVALID);
    MMI_LOGD("this touch pad event is motion begin");
    auto data = libinput_event_get_touchpad_event(event);
    auto time = libinput_event_touchpad_get_time(data);
    auto seatSlot = libinput_event_touchpad_get_seat_slot(data);
    auto logicalX = libinput_event_touchpad_get_x(data);
    auto logicalY = libinput_event_touchpad_get_y(data);

    pointerEvent_->SetActionTime(time);
    pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    PointerEvent::PointerItem pointer;
    pointerEvent_->GetPointerItem(seatSlot, pointer);
    pointer.SetGlobalX((int32_t)logicalX);
    pointer.SetGlobalY((int32_t)logicalY);
    pointerEvent_->RemovePointerItem(seatSlot);
    pointerEvent_->AddPointerItem(pointer);
    pointerEvent_->SetPointerId(seatSlot);
    MMI_LOGD("this touch pad event is motion end");
}

void OHOS::MMI::TouchPadTransformPointProcessor::OnEventTouchPadUp(libinput_event *event)
{
    CHKP(event, PARAM_INPUT_INVALID);
    MMI_LOGD("this touch pad event is up begin");
    auto data = libinput_event_get_touchpad_event(event);
    auto time = libinput_event_touchpad_get_time(data);
    auto seatSlot = libinput_event_touchpad_get_seat_slot(data);
    auto logicalX = libinput_event_touchpad_get_x(data);
    auto logicalY = libinput_event_touchpad_get_y(data);

    pointerEvent_->SetActionTime(time);
    pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_UP);

    PointerEvent::PointerItem pointer;
    pointerEvent_->GetPointerItem(seatSlot, pointer);
    pointerEvent_->RemovePointerItem(seatSlot);
    pointer.SetPressed(false);
    pointer.SetGlobalX((int32_t)logicalX);
    pointer.SetGlobalY((int32_t)logicalY);
    pointerEvent_->AddPointerItem(pointer);
    pointerEvent_->SetPointerId(seatSlot);
    MMI_LOGD("this touch pad event is up end");
}

std::shared_ptr<OHOS::MMI::PointerEvent> OHOS::MMI::TouchPadTransformPointProcessor::OnLibinputTouchPadEvent(
    libinput_event *event)
{
    CHKPR(event, PARAM_INPUT_INVALID, nullptr);
    MMI_LOGD("call  onLibinputTouchPadEvent begin");
    auto type = libinput_event_get_type(event);
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
    MMI_LOGD("call  onLibinputTouchPadEvent end");
    return this->pointerEvent_;
}
