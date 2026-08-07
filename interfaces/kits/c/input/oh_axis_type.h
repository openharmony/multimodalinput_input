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
 * @brief Defines the device axis event struct and enumerates device axis events. The axis type defines the physical
 * behavior characteristics of an input device in different interaction scenarios. The system uses the axis type to
 * distinguish and transmit different gesture interaction information.
 *
 * @kit InputKit
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @library liboh_input.so
 * @since 12
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Defines the axis type of an input device.
 *
 * @since 12
 */
typedef enum InputEvent_AxisType {
    /**
     * Unknown axis type, which is usually used as the initial value.
     * @since 12
     */
    AXIS_TYPE_UNKNOWN,

    /**
     * Vertical scroll axis. When you scroll the mouse wheel or slide with one or two fingers on the touchpad, the
     * status of the vertical scroll axis changes.
     * @since 12
     */
    AXIS_TYPE_SCROLL_VERTICAL,

    /**
     * Horizontal scroll axis. When you scroll the mouse wheel or slide with two fingers on the touchpad, the status of
     * the horizontal scroll axis changes.
     * @since 12
     */
    AXIS_TYPE_SCROLL_HORIZONTAL,

    /**
     * Pinch axis, which is used to describe a two-finger pinch gesture on the touchpad.
     * @since 12
     */
    AXIS_TYPE_PINCH,

    /**
     * Rotation axis, which is used to describe a two-finger rotation gesture on the touchpad.
     * @since 12
     */
    AXIS_TYPE_ROTATE
} InputEvent_AxisType;

/**
 * @brief Event type of the input device.
 *
 * @since 12
 */
typedef enum InputEvent_AxisEventType {
    /**
     * @brief Two-finger pinch event. The value can be **AXIS_TYPE_PINCH** or **AXIS_TYPE_ROTATE**, both of which are
     * of the {@link InputEvent_AxisType} type.
     *
     * @since 12
     */
    AXIS_EVENT_TYPE_PINCH = 1,
    /**
     * @brief Scroll event. The value can be **AXIS_TYPE_SCROLL_VERTICAL** or **AXIS_TYPE_SCROLL_HORIZONTAL**, both of
     * which are of the {@link InputEvent_AxisType} type. For a mouse wheel event, only **AXIS_TYPE_SCROLL_VERTICAL**
     * is supported.
     *
     * @since 12
     */
    AXIS_EVENT_TYPE_SCROLL = 2
} InputEvent_AxisEventType;

/**
 * @brief Action of the input device.
 *
 * @since 12
 */
typedef enum InputEvent_AxisAction {
    /**
     * The axis event is canceled.
     * @since 12
     */
    AXIS_ACTION_CANCEL = 0,
    /**
     * The axis event begins.
     * @since 12
     */
    AXIS_ACTION_BEGIN,
    /**
     * The axis event is updated.
     * @since 12
     */
    AXIS_ACTION_UPDATE,
    /**
     * The axis event ends.
     * @since 12
     */
    AXIS_ACTION_END,
} InputEvent_AxisAction;
#ifdef __cplusplus
}
#endif
/** @} */
#endif