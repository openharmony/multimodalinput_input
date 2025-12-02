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

#include "linux/input.h"
#include "joystick_layout_map.h"

namespace OHOS {
namespace MMI {
class JoystickEventProcessor final {
    struct AxisInfo {
        int32_t rawCode_ { ABS_MAX };
        JoystickLayoutMap::AxisMode mode_ { JoystickLayoutMap::AxisMode::AXIS_MODE_NORMAL };
        PointerEvent::AxisType axis_ { PointerEvent::AXIS_TYPE_UNKNOWN };
        PointerEvent::AxisType highAxis_ { PointerEvent::AXIS_TYPE_UNKNOWN };
        int32_t splitValue_ {};
        int32_t minimum_ {};
        int32_t maximum_ {};
        double low_ {};
        double high_ { 1.0 };
        double scale_ {};
        double highScale_ {};
        double offset_ {};
        double fuzz_ {};
        double flat_ {};
    };

public:
    static std::string MapAxisName(PointerEvent::AxisType axis);
    static bool IsCentrosymmetric(PointerEvent::AxisType axis);

    explicit JoystickEventProcessor(int32_t deviceId);
    ~JoystickEventProcessor() = default;
    DISALLOW_COPY_AND_MOVE(JoystickEventProcessor);

    int32_t GetDeviceId() const;
    std::shared_ptr<KeyEvent> OnButtonEvent(struct libinput_event *event);
    std::shared_ptr<PointerEvent> OnAxisEvent(struct libinput_event *event);
    void CheckIntention(std::shared_ptr<PointerEvent> pointerEvent,
        std::function<void(std::shared_ptr<KeyEvent>)> handler);

private:
    void Initialize();
    void InitializeAxisInfo(struct libinput_device *device, const char *name, AxisInfo &axisInfo) const;
    int32_t MapKey(struct libinput_device *device, int32_t rawCode) const;
    void PressButton(int32_t button);
    void LiftButton(int32_t button);
    bool IsButtonPressed(int32_t button) const;
    void UpdateButtonState(const KeyEvent::KeyItem &keyItem);
    void CheckHAT0X(std::shared_ptr<PointerEvent> pointerEvent, std::vector<KeyEvent::KeyItem> &buttonEvents) const;
    void CheckHAT0Y(std::shared_ptr<PointerEvent> pointerEvent, std::vector<KeyEvent::KeyItem> &buttonEvents) const;
    std::shared_ptr<KeyEvent> FormatButtonEvent(const KeyEvent::KeyItem &button);
    std::shared_ptr<KeyEvent> CleanUpKeyEvent();
    std::string DumpJoystickAxisEvent(std::shared_ptr<PointerEvent> pointerEvent) const;
    void NormalizeAxisValue(const struct libinput_event_joystick_axis_abs_info &absInfo, const AxisInfo &axisInfo);
    void UpdateAxisValue(const AxisInfo &axisInfo, PointerEvent::AxisType axis, double newValue);
    bool HasAxisValueChanged() const;

private:
    static const std::unordered_map<PointerEvent::AxisType, std::string> axisNames_;
    static const std::set<PointerEvent::AxisType> centrosymmetricAxes_;

    const int32_t deviceId_ { -1 };
    std::set<int32_t> pressedButtons_;
    std::shared_ptr<JoystickLayoutMap> layout_ { nullptr };
    std::shared_ptr<PointerEvent> pointerEvent_ { nullptr };
    std::shared_ptr<KeyEvent> keyEvent_ { nullptr };

    std::map<enum libinput_joystick_axis_source, AxisInfo> axesMap_ {
        {
            LIBINPUT_JOYSTICK_AXIS_SOURCE_ABS_X,
            AxisInfo {
                .rawCode_ = ABS_X,
                .axis_ = PointerEvent::AXIS_TYPE_ABS_X,
            },
        },
        {
            LIBINPUT_JOYSTICK_AXIS_SOURCE_ABS_Y,
            AxisInfo {
                .rawCode_ = ABS_Y,
                .axis_ = PointerEvent::AXIS_TYPE_ABS_Y,
            },
        },
        {
            LIBINPUT_JOYSTICK_AXIS_SOURCE_ABS_Z,
            AxisInfo {
                .rawCode_ = ABS_Z,
                .axis_ = PointerEvent::AXIS_TYPE_ABS_Z,
            },
        },
        {
            LIBINPUT_JOYSTICK_AXIS_SOURCE_ABS_RX,
            AxisInfo {
                .rawCode_ = ABS_RX,
                .axis_ = PointerEvent::AXIS_TYPE_ABS_RX,
            },
        },
        {
            LIBINPUT_JOYSTICK_AXIS_SOURCE_ABS_RY,
            AxisInfo {
                .rawCode_ = ABS_RY,
                .axis_ = PointerEvent::AXIS_TYPE_ABS_RY,
            },
        },
        {
            LIBINPUT_JOYSTICK_AXIS_SOURCE_ABS_RZ,
            AxisInfo {
                .rawCode_ = ABS_RZ,
                .axis_ = PointerEvent::AXIS_TYPE_ABS_RZ,
            },
        },
        {
            LIBINPUT_JOYSTICK_AXIS_SOURCE_ABS_THROTTLE,
            AxisInfo {
                .rawCode_ = ABS_THROTTLE,
                .axis_ = PointerEvent::AXIS_TYPE_ABS_THROTTLE,
            },
        },
        {
            LIBINPUT_JOYSTICK_AXIS_SOURCE_ABS_RUDDER,
            AxisInfo {
                .rawCode_ = ABS_RUDDER,
                .axis_ = PointerEvent::AXIS_TYPE_ABS_RUDDER,
            },
        },
        {
            LIBINPUT_JOYSTICK_AXIS_SOURCE_ABS_WHEEL,
            AxisInfo {
                .rawCode_ = ABS_WHEEL,
                .axis_ = PointerEvent::AXIS_TYPE_ABS_WHEEL,
            },
        },
        {
            LIBINPUT_JOYSTICK_AXIS_SOURCE_ABS_GAS,
            AxisInfo {
                .rawCode_ = ABS_GAS,
                .axis_ = PointerEvent::AXIS_TYPE_ABS_GAS,
            },
        },
        {
            LIBINPUT_JOYSTICK_AXIS_SOURCE_ABS_BRAKE,
            AxisInfo {
                .rawCode_ = ABS_BRAKE,
                .axis_ = PointerEvent::AXIS_TYPE_ABS_BRAKE,
            },
        },
        {
            LIBINPUT_JOYSTICK_AXIS_SOURCE_ABS_HAT0X,
            AxisInfo {
                .rawCode_ = ABS_HAT0X,
                .axis_ = PointerEvent::AXIS_TYPE_ABS_HAT0X,
            },
        },
        {
            LIBINPUT_JOYSTICK_AXIS_SOURCE_ABS_HAT0Y,
            AxisInfo {
                .rawCode_ = ABS_HAT0Y,
                .axis_ = PointerEvent::AXIS_TYPE_ABS_HAT0Y,
            },
        },
        {
            LIBINPUT_JOYSTICK_AXIS_SOURCE_ABS_HAT1X,
            AxisInfo {
                .rawCode_ = ABS_HAT1X,
                .axis_ = PointerEvent::AXIS_TYPE_ABS_HAT1X,
            },
        },
        {
            LIBINPUT_JOYSTICK_AXIS_SOURCE_ABS_HAT1Y,
            AxisInfo {
                .rawCode_ = ABS_HAT1Y,
                .axis_ = PointerEvent::AXIS_TYPE_ABS_HAT1Y,
            },
        },
        {
            LIBINPUT_JOYSTICK_AXIS_SOURCE_ABS_HAT2X,
            AxisInfo {
                .rawCode_ = ABS_HAT2X,
                .axis_ = PointerEvent::AXIS_TYPE_ABS_HAT2X,
            },
        },
        {
            LIBINPUT_JOYSTICK_AXIS_SOURCE_ABS_HAT2Y,
            AxisInfo {
                .rawCode_ = ABS_HAT2Y,
                .axis_ = PointerEvent::AXIS_TYPE_ABS_HAT2Y,
            },
        },
        {
            LIBINPUT_JOYSTICK_AXIS_SOURCE_ABS_HAT3X,
            AxisInfo {
                .rawCode_ = ABS_HAT3X,
                .axis_ = PointerEvent::AXIS_TYPE_ABS_HAT3X,
            },
        },
        {
            LIBINPUT_JOYSTICK_AXIS_SOURCE_ABS_HAT3Y,
            AxisInfo {
                .rawCode_ = ABS_HAT3Y,
                .axis_ = PointerEvent::AXIS_TYPE_ABS_HAT3Y,
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
