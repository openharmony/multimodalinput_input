/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

 /**
 * @addtogroup input
 * @{
 *
 * @brief Provides the C interface in the multi-modal input domain.
 *
 * @since 22
 */

/**
 * @file oh_pointer_style.h
 *
 * @brief Defines the pointer structure and related enumeration values.
 * @kit InputKit
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @library libohinput.so
 * @since 22
 */

#ifndef OH_POINTER_STYLE_H
#define OH_POINTER_STYLE_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Enumerated values of OpenHarmony pointer style.
 *
 * @since 22
 */

typedef enum Input_PointerStyle {
    /**
    * Default
    * @since 22
    */
    DEFAULT = 0,

    /**
    * East arrow
    * @since 22
    */
    EAST = 1,

    /**
    * West arrow
    * @since 22
    */
    WEST = 2,

    /**
    * South arrow
    * @since 22
    */
    SOUTH = 3,

    /**
    * North arrow
    * @since 22
    */
    NORTH = 4,

    /**
    * East-west arrow
    * @since 22
    */
    WEST_EAST = 5,

    /**
    * North-south arrow
    * @since 22
    */
    NORTH_SOUTH = 6,

    /**
    * North-east arrow
    * @since 22
    */
    NORTH_EAST = 7,

    /**
    * North-west arrow
    * @since 22
    */
    NORTH_WEST = 8,

    /**
    * South-east arrow
    * @since 22
    */
    SOUTH_EAST = 9,

    /**
    *South-west arrow
    * @since 22
    */
    SOUTH_WEST = 10,

    /**
    * Northeast and southwest adjustment
    * @since 22
    */
    NORTH_EAST_SOUTH_WEST = 11,

    /**
    * Northwest and southeast adjustment
    * @since 22
    */
    NORTH_WEST_SOUTH_EAST = 12,

    /**
    * Cross (accurate selection)
    * @since 22
    */
    CROSS = 13,

    /**
    * Copy
    * @since 22
    */
    CURSOR_COPY = 14,

    /**
    * Forbid
    * @since 22
    */
    CURSOR_FORBID = 15,

    /**
    * Sucker
    * @since 22
    */
    COLOR_SUCKER = 16,

    /**
    * Grabbing hand
    * @since 22
    */
    HAND_GRABBING = 17,

    /**
    * Opening hand
    * @since 22
    */
    HAND_OPEN = 18,

    /**
    * Hand-shaped pointer
    * @since 22
    */
    HAND_POINTING = 19,

    /**
    * Help
    * @since 22
    */
    HELP = 20,

    /**
    * Move
    * @since 22
    */
    MOVE = 21,

    /**
    * Left and right resizing
    * @since 22
    */
    RESIZE_LEFT_RIGHT = 22,

    /**
    * Up and down resizing
    * @since 22
    */
    RESIZE_UP_DOWN = 23,

    /**
    * Screenshot crosshair
    * @since 22
    */
    SCREENSHOT_CHOOSE = 24,

    /**
    * Screenshot
    * @since 22
    */
    SCREENSHOT_CURSOR = 25,

    /**
    * Text selection
    * @since 22
    */
    TEXT_CURSOR = 26,

    /**
    * Zoom in
    * @since 22
    */
    ZOOM_IN = 27,

    /**
    * Zoom out
    * @since 22
    */
    ZOOM_OUT = 28,

    /**
    * Scrolling east
    * @since 22
    */
    MIDDLE_BTN_EAST = 29,

    /**
    * Scrolling west
    * @since 22
    */
    MIDDLE_BTN_WEST = 30,

    /**
    * Scrolling south
    * @since 22
    */
    MIDDLE_BTN_SOUTH = 31,

    /**
    * Scrolling north
    * @since 22
    */
    MIDDLE_BTN_NORTH = 32,

    /**
    * Scrolling north and south
    * @since 22
    */
    MIDDLE_BTN_NORTH_SOUTH = 33,

    /**
    * Scrolling northeast
    * @since 22
    */
    MIDDLE_BTN_NORTH_EAST = 34,

    /**
    * Scrolling northwest
    * @since 22
    */
    MIDDLE_BTN_NORTH_WEST = 35,

    /**
    * Scrolling southeast
    * @since 22
    */
    MIDDLE_BTN_SOUTH_EAST = 36,

    /**
    * Scrolling southwest
    * @since 22
    */
    MIDDLE_BTN_SOUTH_WEST = 37,

    /**
    * Moving as a cone in four directions
    * @since 22
    */
    MIDDLE_BTN_NORTH_SOUTH_WEST_EAST = 38,

    /**
    * Horizontal text selection
    * @since 22
    */
    HORIZONTAL_TEXT_CURSOR = 39,

    /**
    * Precise selection
    * @since 22
    */
    CURSOR_CROSS = 40,

    /**
    * Cursor with circle style
    * @since 22
    */
    CURSOR_CIRCLE = 41,

    /**
    * Loading state with dynamic cursor
    * @since 22
    */
    LOADING = 42,

    /**
    * Running state with dynamic cursor
    * @since 22
    */
    RUNNING = 43,

    /**
    * Scrolling east and west
    * @since 22
    */
    MIDDLE_BTN_EAST_WEST = 44,

    /**
    * Left part of running state with dynamic cursor
    * @since 22
    */
    RUNNING_LEFT = 45,

    /**
    * Right part of running state with dynamic cursor
    * @since 22
    */
    RUNNING_RIGHT = 46,

    /**
    * Circular cursor
    * @since 22
    */
    AECH_DEVELOPER_DEFINED_ICON = 47,

    /**
    * Screen Recording
    * @since 22
    */
    SCREENRECORDER_CURSOR = 48,

    /**
    * Laser
    * @since 22
    */
    LASER_CURSOR = 49,

    /**
    * Dot laser
    * @since 22
    */
    LASER_CURSOR_DOT = 50,

    /**
    * Red dot laser
    * @since 22
    */
    LASER_CURSOR_DOT_RED = 51,

    /**
    * Developer defined
    * @since 22
    */
    DEVELOPER_DEFINED_ICON = -100
} Input_PointerStyle;

#ifdef __cplusplus
}
#endif
/** @} */

#endif /* OH_POINTER_STYLE_H */