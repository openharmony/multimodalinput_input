/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OH_AXIS_TYPE_H
#define OH_AXIS_TYPE_H

/**
 * @addtogroup input
 * @{
 *
 * @brief Provides the C interface in the multi-modal input domain.
 *
 * @since 12
 */

/**
 * @file oh_axis_type.h
 *
 * @brief Defines the axis event-specific structure and enumerations.
 * @kit InputKit
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @library liboh_input.so
 * @since 12
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Enumerates axis types.
 *
 * @since 12
 */
typedef enum {
    /**
     * Indicates an unknown axis type. It is generally used as the initial value.
     *
     * @since 12
     */
    AXIS_TYPE_UNKNOWN,

    /**
     * Indicates the vertical scroll axis. When you scroll the mouse wheel or make certain gestures on the touchpad,
     * the status of the vertical scroll axis changes.
     *
     * @since 12
     */
    AXIS_TYPE_SCROLL_VERTICAL,

    /**
     * Indicates the horizontal scroll axis.
     * When you scroll the mouse wheel or make certain gestures on the touchpad,
     * the status of the horizontal scroll axis changes.
     *
     * @since 12
     */
    AXIS_TYPE_SCROLL_HORIZONTAL,

    /**
     * Indicates the pinch axis, which is used to describe a pinch gesture on the touchscreen or touchpad.
     *
     * @since 12
     */
    AXIS_TYPE_PINCH,

    /**
     * Indicates the rotate axis, which is used to describe a rotate gesture on the touchpad.
     *
     * @since 12
     */
    AXIS_TYPE_ROTATE,

    /**
     * Indicates the x axis. The status of the x axis changes when you operate the joystick.
     *
     * @since 12
     */
    AXIS_TYPE_ABS_X,

    /**
     * Indicates the y axis. The status of the y axis changes when you operate the joystick.
     *
     * @since 12
     */
    AXIS_TYPE_ABS_Y,

    /**
     * Indicates the z axis. The status of the z axis changes when you operate the joystick.
     *
     * @since 12
     */
    AXIS_TYPE_ABS_Z,

    /**
     * Indicates the rz axis. The status of the rz axis changes when you operate the joystick.
     *
     * @since 12
     */
    AXIS_TYPE_ABS_RZ,

    /**
     * Indicates the gas axis. The status of the gas axis changes when you operate the joystick.
     *
     * @since 12
     */
    AXIS_TYPE_ABS_GAS,

    /**
     * Indicates the brake axis. The status of the brake axis changes when you operate the joystick.
     *
     * @since 12
     */
    AXIS_TYPE_ABS_BRAKE,

    /**
     * Indicates the hat0x axis. The status of the hat0x axis changes when you operate the joystick.
     *
     * @since 12
     */
    AXIS_TYPE_ABS_HAT0X,

    /**
     * Indicates the hat0y axis. The status of the hat0y axis changes when you operate the joystick.
     *
     * @since 12
     */
    AXIS_TYPE_ABS_HAT0Y,

    /**
     * Indicates the throttle axis. The status of the throttle axis changes when you operate the joystick.
     *
     * @since 12
     */
    AXIS_TYPE_ABS_THROTTLE,

    /**
     * Indicates the maximum number of defined axis types.
     *
     * @since 12
     */
    AXIS_TYPE_MAX
} InputEvent_AxisType;

/**
 * @brief Enumerates axis event types.
 *
 * @since 12
 */
typedef enum {
    /**
     * @brief Enumerates two-finger pinch events. The axis value can be AXIS_TYPE_PINCH or AXIS_TYPE_ROTATE.
     *
     * @since 12
     */
    AXIS_EVENT_TYPE_PINCH = 1,
    /**
     * @brief Enumerates scroll axis events.
     * The axis value can be AXIS_TYPE_SCROLL_VERTICAL or AXIS_TYPE_SCROLL_HORIZONTAL.
     * Wherein, the value of AXIS_TYPE_SCROLL_HORIZONTAL is 0 for a mouse wheel event.
     *
     * @since 12
     */
    AXIS_EVENT_TYPE_SCROLL = 2
} InputEvent_AxisEventType;

/**
 * @brief Enumerates axis event source types.
 *
 * @since 12
 */
typedef enum {
    /**
     * Indicates that the input source generates events similar to mouse cursor movement,
     * button press and release, and wheel scrolling.
     *
     * @since 12
     */
    SOURCE_TYPE_MOUSE = 1,
    /**
     * Indicates that the input source generates a touchscreen multi-touch event.
     *
     * @since 12
     */
    SOURCE_TYPE_TOUCHSCREEN = 2,
    /**
     * Indicates that the input source generates a touchpad multi-touch event.
     *
     * @since 12
     */
    SOURCE_TYPE_TOUCHPAD = 3
} InputEvent_SourceType;

/**
 * @brief Enumerates axis event actions.
 *
 * @since 12
 */
typedef enum {
    /**
     * Start action for the axis input event.
     *
     * @since 12
     */
    AXIS_ACTION_BEGIN = 5,
    /**
     * Update action for the axis input event.
     *
     * @since 12
     */
    AXIS_ACTION_UPDATE = 6,
    /**
     * End action for the axis input event.
     *
     * @since 12
     */
    AXIS_ACTION_END = 7,
} InputEvent_AxisAction;
#ifdef __cplusplus
}
#endif
/** @} */
#endif