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

#include "joystick_transform_processor.h"

#include "mmi_log.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_DISPATCH
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "JoystickTransformProcessor"

namespace OHOS {
namespace MMI {
JoystickTransformProcessor::JoystickTransformProcessor(int32_t deviceId) : deviceId_(deviceId)
{
    joystickType.emplace_back(
        std::make_pair(LIBINPUT_JOYSTICK_AXIS_SOURCE_ABS_X, PointerEvent::AXIS_TYPE_ABS_X));
    joystickType.emplace_back(
        std::make_pair(LIBINPUT_JOYSTICK_AXIS_SOURCE_ABS_Y, PointerEvent::AXIS_TYPE_ABS_Y));
    joystickType.emplace_back(
        std::make_pair(LIBINPUT_JOYSTICK_AXIS_SOURCE_ABS_Z, PointerEvent::AXIS_TYPE_ABS_Z));
    joystickType.emplace_back(
        std::make_pair(LIBINPUT_JOYSTICK_AXIS_SOURCE_ABS_RZ, PointerEvent::AXIS_TYPE_ABS_RZ));
    joystickType.emplace_back(
        std::make_pair(LIBINPUT_JOYSTICK_AXIS_SOURCE_ABS_GAS, PointerEvent::AXIS_TYPE_ABS_GAS));
    joystickType.emplace_back(
        std::make_pair(LIBINPUT_JOYSTICK_AXIS_SOURCE_ABS_BRAKE, PointerEvent::AXIS_TYPE_ABS_BRAKE));
    joystickType.emplace_back(
        std::make_pair(LIBINPUT_JOYSTICK_AXIS_SOURCE_ABS_HAT0X, PointerEvent::AXIS_TYPE_ABS_HAT0X));
    joystickType.emplace_back(
        std::make_pair(LIBINPUT_JOYSTICK_AXIS_SOURCE_ABS_HAT0Y, PointerEvent::AXIS_TYPE_ABS_HAT0Y));
    joystickType.emplace_back(
        std::make_pair(LIBINPUT_JOYSTICK_AXIS_SOURCE_ABS_THROTTLE, PointerEvent::AXIS_TYPE_ABS_THROTTLE));
}

bool JoystickTransformProcessor::OnEventJoystickButton(struct libinput_event* event)
{
    CALL_DEBUG_ENTER;
    CHKPF(event);
    auto data = libinput_event_get_joystick_button_event(event);
    CHKPF(data);
    int64_t time = GetSysClockTime();
    pointerEvent_->SetActionTime(time);
    pointerEvent_->SetActionStartTime(time);
    pointerEvent_->SetDeviceId(deviceId_);
    pointerEvent_->SetSourceType(PointerEvent::SOURCE_TYPE_JOYSTICK);
    uint32_t button = libinput_event_joystick_button_get_key(data);
    int32_t buttonId = LibinputButtonToPointer(button);
    if (buttonId == PointerEvent::BUTTON_NONE) {
        MMI_HILOGE("Unknown btn, btn:%{public}u", button);
        return false;
    }
    pointerEvent_->SetButtonId(buttonId);
    auto state = libinput_event_joystick_button_get_key_state(data);
    if (state == LIBINPUT_BUTTON_STATE_RELEASED) {
        pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_UP);
        pointerEvent_->DeleteReleaseButton(buttonId);
        isPressed_ = false;
    } else if (state == LIBINPUT_BUTTON_STATE_PRESSED) {
        pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_DOWN);
        pointerEvent_->SetButtonPressed(buttonId);
        isPressed_ = true;
    } else {
        MMI_HILOGE("Unknown state, state:%{public}u", state);
        return false;
    }
    MMI_HILOGD("button:%{public}u, buttonId:%{public}d, state:%{public}d", button, buttonId, state);
    return true;
}

int32_t JoystickTransformProcessor::LibinputButtonToPointer(const uint32_t button)
{
    auto iter = LibinputChangeToPointer.find(button);
    return (iter == LibinputChangeToPointer.end() ? PointerEvent::BUTTON_NONE : iter->second);
}

bool JoystickTransformProcessor::OnEventJoystickAxis(struct libinput_event *event)
{
    CALL_DEBUG_ENTER;
    CHKPF(event);
    auto data = libinput_event_get_joystick_axis_event(event);
    CHKPF(data);
    int64_t time = GetSysClockTime();
    pointerEvent_->SetActionTime(time);
    pointerEvent_->SetActionStartTime(time);
    pointerEvent_->SetDeviceId(deviceId_);
    pointerEvent_->SetButtonId(PointerEvent::BUTTON_NONE);
    pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_UPDATE);
    pointerEvent_->SetSourceType(PointerEvent::SOURCE_TYPE_JOYSTICK);

    for (const auto &item : joystickType) {
        if (libinput_event_get_joystick_axis_value_is_changed(data, item.first) != 0) {
            struct libinput_event_joystick_axis_abs_info* axisInfo =
                libinput_event_get_joystick_axis_abs_info(data, item.first);
            CHKPF(axisInfo);
            pointerEvent_->SetAxisValue(item.second, axisInfo->value);
            MMI_HILOGD("axis:%{public}d, value:%{public}d", item.second, axisInfo->value);
        }
    }
    return true;
}

std::shared_ptr<PointerEvent> JoystickTransformProcessor::OnEvent(struct libinput_event *event)
{
    CALL_DEBUG_ENTER;
    CHKPP(event);
    if (pointerEvent_ == nullptr) {
        pointerEvent_ = PointerEvent::Create();
        CHKPP(pointerEvent_);
    }
    pointerEvent_->ClearAxisValue();
    auto type = libinput_event_get_type(event);
    switch (type) {
        case LIBINPUT_EVENT_JOYSTICK_BUTTON: {
            if (!OnEventJoystickButton(event)) {
                MMI_HILOGE("Get OnEventJoystickButton failed");
                return nullptr;
            }
            break;
        }
        case LIBINPUT_EVENT_JOYSTICK_AXIS: {
            if (!OnEventJoystickAxis(event)) {
                MMI_HILOGE("Get OnEventJoystickAxis failed");
                return nullptr;
            }
            break;
        }
        default: {
            MMI_HILOGE("Unknown event type, joystickType:%{public}d", type);
            return nullptr;
        }
    }
    WIN_MGR->UpdateTargetPointer(pointerEvent_);
   
    return pointerEvent_;
}
} // namespace MMI
} // namespace OHOS
