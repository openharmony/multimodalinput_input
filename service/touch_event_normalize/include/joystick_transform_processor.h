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

#ifndef JOYSTICK_TRANSFORM_PROCESSOR_H
#define JOYSTICK_TRANSFORM_PROCESSOR_H

#include "i_input_windows_manager.h"
#include "transform_processor.h"

namespace OHOS {
namespace MMI {
class JoystickTransformProcessor final : public TransformProcessor {
    enum LIBINPUT_BUTTON_CODE : uint32_t {
        LIBINPUT_HOMEPAGE_BUTTON_CODE = 172,
        LIBINPUT_TRIGGER_BUTTON_CODE = 288,
        LIBINPUT_THUMB_BUTTON_CODE = 289,
        LIBINPUT_THUMB2_BUTTON_CODE = 290,
        LIBINPUT_TOP_BUTTON_CODE = 291,
        LIBINPUT_TOP2_BUTTON_CODE = 292,
        LIBINPUT_PINKIE_BUTTON_CODE = 293,
        LIBINPUT_BASE_BUTTON_CODE = 294,
        LIBINPUT_BASE2_BUTTON_CODE = 295,
        LIBINPUT_BASE3_BUTTON_CODE = 296,
        LIBINPUT_BASE4_BUTTON_CODE = 297,
        LIBINPUT_BASE5_BUTTON_CODE = 298,
        LIBINPUT_BASE6_BUTTON_CODE = 299,
        LIBINPUT_DEAD_BUTTON_CODE = 303,
        LIBINPUT_SOUTH_BUTTON_CODE = 304,
        LIBINPUT_EAST_BUTTON_CODE = 305,
        LIBINPUT_C_BUTTON_CODE = 306,
        LIBINPUT_NORTH_BUTTON_CODE = 307,
        LIBINPUT_WEST_BUTTON_CODE = 308,
        LIBINPUT_Z_BUTTON_CODE = 309,
        LIBINPUT_TL_BUTTON_CODE = 310,
        LIBINPUT_TR_BUTTON_CODE = 311,
        LIBINPUT_TL2_BUTTON_CODE = 312,
        LIBINPUT_TR2_BUTTON_CODE = 313,
        LIBINPUT_SELECT_BUTTON_CODE = 314,
        LIBINPUT_START_BUTTON_CODE = 315,
        LIBINPUT_MODE_BUTTON_CODE = 316,
        LIBINPUT_THUMBL_BUTTON_CODE = 317,
        LIBINPUT_THUMBR_BUTTON_CODE = 318
    };
    const std::map<uint32_t, int32_t> LibinputChangeToPointer = {
        { LIBINPUT_TL2_BUTTON_CODE, PointerEvent::JOYSTICK_BUTTON_TL2 },
        { LIBINPUT_TR2_BUTTON_CODE, PointerEvent::JOYSTICK_BUTTON_TR2 },
        { LIBINPUT_TL_BUTTON_CODE, PointerEvent::JOYSTICK_BUTTON_TL },
        { LIBINPUT_TR_BUTTON_CODE, PointerEvent::JOYSTICK_BUTTON_TR },
        { LIBINPUT_WEST_BUTTON_CODE, PointerEvent::JOYSTICK_BUTTON_WEST },
        { LIBINPUT_SOUTH_BUTTON_CODE, PointerEvent::JOYSTICK_BUTTON_SOUTH },
        { LIBINPUT_NORTH_BUTTON_CODE, PointerEvent::JOYSTICK_BUTTON_NORTH },
        { LIBINPUT_EAST_BUTTON_CODE, PointerEvent::JOYSTICK_BUTTON_EAST },
        { LIBINPUT_START_BUTTON_CODE, PointerEvent::JOYSTICK_BUTTON_START },
        { LIBINPUT_SELECT_BUTTON_CODE, PointerEvent::JOYSTICK_BUTTON_SELECT },
        { LIBINPUT_HOMEPAGE_BUTTON_CODE, PointerEvent::JOYSTICK_BUTTON_HOMEPAGE },
        { LIBINPUT_THUMBL_BUTTON_CODE, PointerEvent::JOYSTICK_BUTTON_THUMBL },
        { LIBINPUT_THUMBR_BUTTON_CODE, PointerEvent::JOYSTICK_BUTTON_THUMBR },
        { LIBINPUT_TRIGGER_BUTTON_CODE, PointerEvent::JOYSTICK_BUTTON_TRIGGER},
        { LIBINPUT_THUMB_BUTTON_CODE, PointerEvent::JOYSTICK_BUTTON_THUMB },
        { LIBINPUT_THUMB2_BUTTON_CODE, PointerEvent::JOYSTICK_BUTTON_THUMB2 },
        { LIBINPUT_TOP_BUTTON_CODE, PointerEvent::JOYSTICK_BUTTON_TOP },
        { LIBINPUT_TOP2_BUTTON_CODE, PointerEvent::JOYSTICK_BUTTON_TOP2 },
        { LIBINPUT_PINKIE_BUTTON_CODE, PointerEvent::JOYSTICK_BUTTON_PINKIE },
        { LIBINPUT_BASE_BUTTON_CODE, PointerEvent::JOYSTICK_BUTTON_BASE },
        { LIBINPUT_BASE2_BUTTON_CODE, PointerEvent::JOYSTICK_BUTTON_BASE2 },
        { LIBINPUT_BASE3_BUTTON_CODE, PointerEvent::JOYSTICK_BUTTON_BASE3 },
        { LIBINPUT_BASE4_BUTTON_CODE, PointerEvent::JOYSTICK_BUTTON_BASE4 },
        { LIBINPUT_BASE5_BUTTON_CODE, PointerEvent::JOYSTICK_BUTTON_BASE5 },
        { LIBINPUT_BASE6_BUTTON_CODE, PointerEvent::JOYSTICK_BUTTON_BASE6 },
        { LIBINPUT_DEAD_BUTTON_CODE, PointerEvent::JOYSTICK_BUTTON_DEAD },
        { LIBINPUT_C_BUTTON_CODE, PointerEvent::JOYSTICK_BUTTON_C },
        { LIBINPUT_Z_BUTTON_CODE, PointerEvent::JOYSTICK_BUTTON_Z },
        { LIBINPUT_MODE_BUTTON_CODE, PointerEvent::JOYSTICK_BUTTON_MODE }
    };

public:
    explicit JoystickTransformProcessor(int32_t deviceId);
    DISALLOW_COPY_AND_MOVE(JoystickTransformProcessor);
    ~JoystickTransformProcessor() = default;
    std::shared_ptr<PointerEvent> OnEvent(struct libinput_event *event) override;
    std::shared_ptr<PointerEvent> GetPointerEvent() override { return nullptr; }

private:
    bool OnEventJoystickButton(struct libinput_event* event);
    bool OnEventJoystickAxis(struct libinput_event *event);
    int32_t LibinputButtonToPointer(const uint32_t button);
private:
    int32_t deviceId_ { 0 };
    bool isPressed_ { false };
    std::shared_ptr<PointerEvent> pointerEvent_ { nullptr };
    std::vector<std::pair<enum libinput_joystick_axis_source, PointerEvent::AxisType>> joystickType;
};
} // namespace MMI
} // namespace OHOS
#endif // JOYSTICK_TRANSFORM_POINT_PROCESSOR_H