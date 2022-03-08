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
#include "mmi_log.h"

namespace OHOS {
namespace MMI {
    namespace {
        constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN,
            "TouchPadTransformPointProcessor"};
    }

TouchPadTransformPointProcessor::TouchPadTransformPointProcessor(int32_t deviceId) : deviceId_(deviceId)
{
    pointerEvent_ = PointerEvent::Create();
    CHKPL(pointerEvent_);
}

TouchPadTransformPointProcessor::~TouchPadTransformPointProcessor() {}

void TouchPadTransformPointProcessor::SetPointEventSource(int32_t sourceType)
{
    pointerEvent_->SetSourceType(sourceType);
}

void TouchPadTransformPointProcessor::OnEventTouchPadDown(struct libinput_event *event)
{
    MMI_LOGD("Enter");
    CHKPV(event);
    auto data = libinput_event_get_touchpad_event(event);
    CHKPV(data);
    auto seatSlot = libinput_event_touchpad_get_seat_slot(data);
    auto logicalX = libinput_event_touchpad_get_x(data);
    auto logicalY = libinput_event_touchpad_get_y(data);

    int64_t time = GetSysClockTime();
    auto pointIds = pointerEvent_->GetPointersIdList();
    if (pointIds.empty()) {
        pointerEvent_->SetActionStartTime(time);
    }
    pointerEvent_->SetActionTime(time);
    pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    PointerEvent::PointerItem item;
    item.SetPointerId(seatSlot);
    item.SetDownTime(time);
    item.SetPressed(true);
    item.SetGlobalX(static_cast<int32_t>(logicalX));
    item.SetGlobalY(static_cast<int32_t>(logicalY));
    item.SetDeviceId(deviceId_);
    pointerEvent_->SetDeviceId(deviceId_);
    pointerEvent_->AddPointerItem(item);
    pointerEvent_->SetPointerId(seatSlot);
    MMI_LOGD("End");
}

void TouchPadTransformPointProcessor::OnEventTouchPadMotion(struct libinput_event *event)
{
    MMI_LOGD("Enter");
    CHKPV(event);
    auto data = libinput_event_get_touchpad_event(event);
    CHKPV(data);
    auto seatSlot = libinput_event_touchpad_get_seat_slot(data);
    auto logicalX = libinput_event_touchpad_get_x(data);
    auto logicalY = libinput_event_touchpad_get_y(data);

    int64_t time = GetSysClockTime();
    pointerEvent_->SetActionTime(time);
    pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    PointerEvent::PointerItem item;
    if (!pointerEvent_->GetPointerItem(seatSlot, item)) {
        MMI_LOGE("Can't find the pointer item data, seatSlot:%{public}d, errCode:%{public}d",
                 seatSlot, PARAM_INPUT_FAIL);
                 return;
    }
    item.SetGlobalX(static_cast<int32_t>(logicalX));
    item.SetGlobalY(static_cast<int32_t>(logicalY));
    pointerEvent_->UpdatePointerItem(seatSlot, item);
    pointerEvent_->SetPointerId(seatSlot);
    MMI_LOGD("End");
}

void TouchPadTransformPointProcessor::OnEventTouchPadUp(struct libinput_event *event)
{
    MMI_LOGD("Enter");
    CHKPV(event);
    auto data = libinput_event_get_touchpad_event(event);
    CHKPV(data);
    auto seatSlot = libinput_event_touchpad_get_seat_slot(data);
    auto logicalX = libinput_event_touchpad_get_x(data);
    auto logicalY = libinput_event_touchpad_get_y(data);

    int64_t time = GetSysClockTime();
    pointerEvent_->SetActionTime(time);
    pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_UP);

    PointerEvent::PointerItem item;
    if (!pointerEvent_->GetPointerItem(seatSlot, item)) {
        MMI_LOGE("Can't find the pointer item data, seatSlot:%{public}d, errCode:%{public}d",
                 seatSlot, PARAM_INPUT_FAIL);
                 return;
    }
    item.SetPressed(false);
    item.SetGlobalX(static_cast<int32_t>(logicalX));
    item.SetGlobalY(static_cast<int32_t>(logicalY));
    pointerEvent_->UpdatePointerItem(seatSlot, item);
    pointerEvent_->SetPointerId(seatSlot);
    MMI_LOGD("End");
}

std::shared_ptr<PointerEvent> TouchPadTransformPointProcessor::OnLibinputTouchPadEvent(
    struct libinput_event *event)
{
    MMI_LOGD("begin");
    CHKPP(event);
    CHKPP(pointerEvent_);
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
