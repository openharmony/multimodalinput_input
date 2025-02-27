/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef JOYSTICK_EVENT_PROCESSOR_H
#define JOYSTICK_EVENT_PROCESSOR_H
#include <map>

#include <libinput.h>

#include "key_event.h"
#include "pointer_event.h"

namespace OHOS {
namespace MMI {
class JoystickEventProcessor final {
    struct AxisInfo {
        std::string name;
        PointerEvent::AxisType axisType;
        std::function<double(const struct libinput_event_joystick_axis_abs_info&)> normalize;
    };

public:
    explicit JoystickEventProcessor(int32_t deviceId);
    ~JoystickEventProcessor() = default;
    DISALLOW_COPY_AND_MOVE(JoystickEventProcessor);

    int32_t GetDeviceId() const;
    std::shared_ptr<KeyEvent> OnButtonEvent(struct libinput_event *event);
    std::shared_ptr<PointerEvent> OnAxisEvent(struct libinput_event *event);
    void CheckIntention(std::shared_ptr<PointerEvent> pointerEvent,
        std::function<void(std::shared_ptr<KeyEvent>)> handler);

private:
    void PressButton(int32_t button);
    void LiftButton(int32_t button);
    bool IsButtonPressed(int32_t button) const;
    void UpdateButtonState(const KeyEvent::KeyItem &keyItem);
    void CheckHAT0X(std::shared_ptr<PointerEvent> pointerEvent, std::vector<KeyEvent::KeyItem> &buttonEvents) const;
    void CheckHAT0Y(std::shared_ptr<PointerEvent> pointerEvent, std::vector<KeyEvent::KeyItem> &buttonEvents) const;
    std::shared_ptr<KeyEvent> FormatButtonEvent(const KeyEvent::KeyItem &button) const;
    std::shared_ptr<KeyEvent> CleanUpKeyEvent() const;
    std::string DumpJoystickAxisEvent(std::shared_ptr<PointerEvent> pointerEvent) const;
    static double Normalize(const struct libinput_event_joystick_axis_abs_info &axis, double low, double high);

private:
    const int32_t deviceId_ { -1 };
    std::set<int32_t> pressedButtons_;
    std::shared_ptr<PointerEvent> pointerEvent_ { nullptr };

    const std::map<enum libinput_joystick_axis_source, AxisInfo> axesMap_ {
        {
            LIBINPUT_JOYSTICK_AXIS_SOURCE_ABS_X,
            AxisInfo {
                .name = "X",
                .axisType = PointerEvent::AXIS_TYPE_ABS_X,
                .normalize = [](const struct libinput_event_joystick_axis_abs_info &axis) {
                    return JoystickEventProcessor::Normalize(axis, -1.0, 1.0);
                }
            },
        },
        {
            LIBINPUT_JOYSTICK_AXIS_SOURCE_ABS_Y,
            AxisInfo {
                .name = "Y",
                .axisType = PointerEvent::AXIS_TYPE_ABS_Y,
                .normalize = [](const struct libinput_event_joystick_axis_abs_info &axis) {
                    return JoystickEventProcessor::Normalize(axis, -1.0, 1.0);
                }
            },
        },
        {
            LIBINPUT_JOYSTICK_AXIS_SOURCE_ABS_Z,
            AxisInfo {
                .name = "Z",
                .axisType = PointerEvent::AXIS_TYPE_ABS_Z,
                .normalize = [](const struct libinput_event_joystick_axis_abs_info &axis) {
                    return JoystickEventProcessor::Normalize(axis, -1.0, 1.0);
                }
            },
        },
        {
            LIBINPUT_JOYSTICK_AXIS_SOURCE_ABS_RZ,
            AxisInfo {
                .name = "RZ",
                .axisType = PointerEvent::AXIS_TYPE_ABS_RZ,
                .normalize = [](const struct libinput_event_joystick_axis_abs_info &axis) {
                    return JoystickEventProcessor::Normalize(axis, -1.0, 1.0);
                }
            },
        },
        {
            LIBINPUT_JOYSTICK_AXIS_SOURCE_ABS_GAS,
            AxisInfo {
                .name = "GAS",
                .axisType = PointerEvent::AXIS_TYPE_ABS_GAS,
                .normalize = [](const struct libinput_event_joystick_axis_abs_info &axis) {
                    return JoystickEventProcessor::Normalize(axis, 0.0, 1.0);
                }
            },
        },
        {
            LIBINPUT_JOYSTICK_AXIS_SOURCE_ABS_BRAKE,
            AxisInfo {
                .name = "BRAKE",
                .axisType = PointerEvent::AXIS_TYPE_ABS_BRAKE,
                .normalize = [](const struct libinput_event_joystick_axis_abs_info &axis) {
                    return JoystickEventProcessor::Normalize(axis, 0.0, 1.0);
                }
            },
        },
        {
            LIBINPUT_JOYSTICK_AXIS_SOURCE_ABS_HAT0X,
            AxisInfo {
                .name = "HAT0X",
                .axisType = PointerEvent::AXIS_TYPE_ABS_HAT0X,
                .normalize = [](const struct libinput_event_joystick_axis_abs_info &axis) {
                    return axis.value;
                }
            },
        },
        {
            LIBINPUT_JOYSTICK_AXIS_SOURCE_ABS_HAT0Y,
            AxisInfo {
                .name = "HAT0Y",
                .axisType = PointerEvent::AXIS_TYPE_ABS_HAT0Y,
                .normalize = [](const struct libinput_event_joystick_axis_abs_info &axis) {
                    return axis.value;
                }
            },
        },
        {
            LIBINPUT_JOYSTICK_AXIS_SOURCE_ABS_THROTTLE,
            AxisInfo {
                .name = "THROTTLE",
                .axisType = PointerEvent::AXIS_TYPE_ABS_THROTTLE,
                .normalize = [](const struct libinput_event_joystick_axis_abs_info &axis) {
                    return JoystickEventProcessor::Normalize(axis, 0.0, 1.0);
                }
            },
        },
    };
};

inline int32_t JoystickEventProcessor::GetDeviceId() const
{
    return deviceId_;
}

inline void JoystickEventProcessor::PressButton(int32_t button)
{
    pressedButtons_.emplace(button);
}

inline void JoystickEventProcessor::LiftButton(int32_t button)
{
    pressedButtons_.erase(button);
}

inline bool JoystickEventProcessor::IsButtonPressed(int32_t button) const
{
    return (pressedButtons_.find(button) != pressedButtons_.cend());
}
} // namespace MMI
} // namespace OHOS
#endif // JOYSTICK_EVENT_PROCESSOR_H
