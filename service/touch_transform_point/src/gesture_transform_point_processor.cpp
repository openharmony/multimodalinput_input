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
#include "gesture_transform_point_processor.h"
#include "mmi_log.h"
#include "mouse_device_state.h"

namespace OHOS {
namespace MMI {
    namespace {
        constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN,
            "GestureTransformPointProcessor"};
    }

GestureTransformPointProcessor::GestureTransformPointProcessor(int32_t deviceId) : deviceId_(deviceId)
{
    pointerEvent_ = PointerEvent::Create();
    CHKPL(pointerEvent_);
}

GestureTransformPointProcessor::~GestureTransformPointProcessor() {}

void GestureTransformPointProcessor::SetPointEventSource(int32_t sourceType)
{
    pointerEvent_->SetSourceType(sourceType);
}

void GestureTransformPointProcessor::OnEventTouchPadPinchBegin(libinput_event_gesture *data)
{
    MMI_LOGD("Touchpad begin event");
    CHKPV(data);
    auto time = static_cast<int64_t>(libinput_event_gesture_get_time(data));
    auto scale = libinput_event_gesture_get_scale(data);
    pointerEvent_->SetActionTime(GetSysClockTime());
    pointerEvent_->SetActionStartTime(time);

    PointerEvent::PointerItem pointerItem;
    pointerItem.SetDownTime(time);
    pointerItem.SetGlobalX(MouseState->GetMouseCoordsX());
    pointerItem.SetGlobalY(MouseState->GetMouseCoordsY());
    pointerItem.SetDeviceId(deviceId_);
    pointerItem.SetPointerId(defaultPointerId);
    pointerItem.SetWidth(0);
    pointerItem.SetHeight(0);
    pointerItem.SetPressed(MouseState->IsLeftBtnPressed());
    pointerEvent_->AddPointerItem(pointerItem);

    pointerEvent_->ClearButtonPressed();
    std::vector<int32_t> pressedButtons;
    MouseState->GetPressedButtons(pressedButtons);
    for (const auto &item : pressedButtons) {
        pointerEvent_->SetButtonPressed(item);
    }

    pointerEvent_->SetDeviceId(deviceId_);
    pointerEvent_->SetTargetDisplayId(0);
    pointerEvent_->SetPointerId(defaultPointerId);
    pointerEvent_->SetAxisValue(PointerEvent::AXIS_TYPE_PINCH, scale);
}

void GestureTransformPointProcessor::OnEventTouchPadPinchUpdate(libinput_event_gesture *data)
{
    MMI_LOGD("Touchpad update event");
    CHKPV(data);
    auto time = static_cast<int64_t>(libinput_event_gesture_get_time(data));
    auto scale = libinput_event_gesture_get_scale(data);
    pointerEvent_->SetActionTime(GetSysClockTime());
    pointerEvent_->SetActionStartTime(time);

    PointerEvent::PointerItem pointerItem;
    pointerEvent_->GetPointerItem(defaultPointerId, pointerItem);
    pointerItem.SetGlobalX(MouseState->GetMouseCoordsX());
    pointerItem.SetGlobalY(MouseState->GetMouseCoordsY());
    pointerItem.SetPressed(MouseState->IsLeftBtnPressed());
    pointerEvent_->UpdatePointerItem(defaultPointerId, pointerItem);

    pointerEvent_->ClearButtonPressed();
    std::vector<int32_t> pressedButtons;
    MouseState->GetPressedButtons(pressedButtons);
    for (const auto &item : pressedButtons) {
        pointerEvent_->SetButtonPressed(item);
    }
    pointerEvent_->SetAxisValue(PointerEvent::AXIS_TYPE_PINCH, scale);
}

void GestureTransformPointProcessor::OnEventTouchPadPinchEnd(libinput_event_gesture *data)
{
    MMI_LOGD("Touchpad end event");
    CHKPV(data);
    auto time = static_cast<int64_t>(libinput_event_gesture_get_time(data));
    auto scale = libinput_event_gesture_get_scale(data);
    pointerEvent_->SetActionTime(GetSysClockTime());
    pointerEvent_->SetActionStartTime(time);

    PointerEvent::PointerItem pointerItem;
    pointerEvent_->GetPointerItem(defaultPointerId, pointerItem);
    pointerItem.SetGlobalX(MouseState->GetMouseCoordsX());
    pointerItem.SetGlobalY(MouseState->GetMouseCoordsY());
    pointerItem.SetPressed(MouseState->IsLeftBtnPressed());
    pointerEvent_->UpdatePointerItem(defaultPointerId, pointerItem);

    pointerEvent_->ClearButtonPressed();
    std::vector<int32_t> pressedButtons;
    MouseState->GetPressedButtons(pressedButtons);
    for (const auto &item : pressedButtons) {
        pointerEvent_->SetButtonPressed(item);
    }
    pointerEvent_->SetAxisValue(PointerEvent::AXIS_TYPE_PINCH, scale);
}

std::shared_ptr<PointerEvent> GestureTransformPointProcessor::OnTouchPadGestrueEvent(
    struct libinput_event *event)
{
    MMI_LOGD("begin");
    CHKPP(event);
    auto data = libinput_event_get_gesture_event(event);
    CHKPP(data);
    pointerEvent_->UpdateId();
    auto type = libinput_event_get_type(event);
    switch (type) {
        case LIBINPUT_EVENT_GESTURE_PINCH_BEGIN: {
            pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_BEGIN);
            OnEventTouchPadPinchBegin(data);
            break;
        }
        case LIBINPUT_EVENT_GESTURE_PINCH_UPDATE: {
            pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_UPDATE);
            OnEventTouchPadPinchUpdate(data);
            break;
        }
        case LIBINPUT_EVENT_GESTURE_PINCH_END: {
            pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_END);
            OnEventTouchPadPinchEnd(data);
            break;
        }
        case LIBINPUT_EVENT_GESTURE_SWIPE_BEGIN:
        case LIBINPUT_EVENT_GESTURE_SWIPE_UPDATE:
        case LIBINPUT_EVENT_GESTURE_SWIPE_END: {
            MMI_LOGW("Three refers to the need to use, preserve the code");
            return nullptr;
        }
        default: {
            MMI_LOGE("Unknown event_type of pointer class has been reported!\n");
            return nullptr;
        }
    }
    MMI_LOGD("end");
    return pointerEvent_;
}
} // namespace MMI
} // namespace OHOS