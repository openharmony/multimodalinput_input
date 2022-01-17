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

namespace OHOS::MMI {
namespace {
    static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "TouchTransformPointProcessor"};
}
TouchTransformPointProcessor::TouchTransformPointProcessor()
{
    this->pointerEvent_ = PointerEvent::Create();
}

TouchTransformPointProcessor::~TouchTransformPointProcessor() {}

void TouchTransformPointProcessor::setPointEventSource(int32_t sourceType)
{
    pointerEvent_->SetSourceType(sourceType);
}

void TouchTransformPointProcessor::onEventTouchDown(libinput_event *event)
{
    CHK(event, PARAM_INPUT_INVALID);
    MMI_LOGD("this touch event is down");
    auto data = libinput_event_get_touch_event(event);
    auto time = libinput_event_touch_get_time(data);
    auto seat_slot = libinput_event_touch_get_seat_slot(data);
    auto pressure = libinput_event_get_touch_pressure(event);
    int32_t id = 1;
    int32_t logicalY = -1;
    int32_t logicalX = -1;
    int32_t logicalDisplayId = -1;
    WinMgr->TpPointLogicDisplayPoint(data, logicalX, logicalY, logicalDisplayId);
    auto pointIds = pointerEvent_->GetPointersIdList();
    if (pointIds.size() == 0) {
        pointerEvent_->SetActionStartTime(time);
        pointerEvent_->SetTargetDisplayId(logicalDisplayId);
    }
    pointerEvent_->SetActionTime(time);
    pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    PointerEvent::PointerItem pointer;
    pointer.SetPointerId(seat_slot);
    pointer.SetDownTime(time);
    pointer.SetPressed(true);
    pointer.SetGlobalX(logicalX);
    pointer.SetGlobalY(logicalY);
    pointer.SetLocalX(1);
    pointer.SetLocalY(1);
    pointer.SetWidth(1);
    pointer.SetHeight(1);
    pointer.SetPressure(pressure);
    pointer.SetDeviceId(id);
    pointerEvent_->SetDeviceId(id);
    pointerEvent_->AddPointerItem(pointer);
    pointerEvent_->SetPointerId(seat_slot);
    MMI_LOGD("logicalX is %{public}d, logicalY is %{public}d, logicalDisplayId is %{public}d", logicalX, logicalY, logicalDisplayId);
    MMI_LOGD("this touch event is down end");
}

void TouchTransformPointProcessor::onEventTouchMotion(libinput_event *event)
{
    CHK(event, PARAM_INPUT_INVALID);
    MMI_LOGD("this touch event is motion begin");
    auto data = libinput_event_get_touch_event(event);
    auto time = libinput_event_touch_get_time(data);
    auto seat_slot = libinput_event_touch_get_seat_slot(data);
    auto pressure = libinput_event_get_touch_pressure(event);
    pointerEvent_->SetActionTime(time);
    pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    int32_t logicalY = -1;
    int32_t logicalX = -1;
    int32_t logicalDisplayId = pointerEvent_->GetTargetDisplayId();
    WinMgr->TansformTouchscreePointToLogicalDisplayPoint(data, logicalDisplayId, logicalX, logicalY);
    PointerEvent::PointerItem pointer;
    pointerEvent_->GetPointerItem(seat_slot, pointer);
    pointer.SetPressure(pressure);
    pointer.SetGlobalX(logicalX);
    pointer.SetGlobalY(logicalY);
    pointerEvent_->RemovePointerItem(seat_slot);
    pointerEvent_->AddPointerItem(pointer);
    pointerEvent_->SetPointerId(seat_slot);
    MMI_LOGD("this touch event is motion end");
}

void TouchTransformPointProcessor::onEventTouchUp(libinput_event *event)
{
    CHK(event, PARAM_INPUT_INVALID);
    MMI_LOGD("this touch event is up");
    auto data = libinput_event_get_touch_event(event);
    auto time = libinput_event_touch_get_time(data);
    auto seat_slot = libinput_event_touch_get_seat_slot(data);

    pointerEvent_->SetActionTime(time);
    pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_UP);

    PointerEvent::PointerItem pointer;
    pointerEvent_->GetPointerItem(seat_slot, pointer);
    pointerEvent_->RemovePointerItem(seat_slot);
    pointerEvent_->AddPointerItem(pointer);
    pointer.SetPressed(false);
    pointerEvent_->SetPointerId(seat_slot);
    MMI_LOGD("this touch event is up end");
}

std::shared_ptr<PointerEvent> TouchTransformPointProcessor::onLibinputTouchEvent(libinput_event *event)
{
    CHKR(event, PARAM_INPUT_INVALID, nullptr);
    MMI_LOGD("call  onLibinputTouchEvent begin");
    auto type = libinput_event_get_type(event);
    if (pointerEvent_ == nullptr) {
        MMI_LOGE("pointerEvent_ is nullptr");
        return nullptr;
    }
    pointerEvent_->UpdateId();
    switch (type) {
        case LIBINPUT_EVENT_TOUCH_DOWN: {
            onEventTouchDown(event);
            break;
        }
        case LIBINPUT_EVENT_TOUCH_UP: {
            onEventTouchUp(event);
            break;
        }
        case LIBINPUT_EVENT_TOUCH_MOTION: {
            onEventTouchMotion(event);
            break;
        }
        default: {
            return nullptr;
        }
    }
    MMI_LOGD("call  onLibinputTouchEvent end");
    return this->pointerEvent_;
}
}

