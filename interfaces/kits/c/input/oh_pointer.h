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
 * @since 12
 */

/**
 * @file oh_pointer.h
 *
 * @brief Defines the pointer structure and related enumeration values.
 *
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @library libohinput.so
 * @since 21
 */

#ifndef OH_POINTER_H
#define OH_POINTER_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Enumerated values of OpenHarmony pointer style.
 *
 * @since 21
 */

typedef enum Input_PointerStyle {
    /**
    * Default
    * @since 21
    */
    DEFAULT = 0,

    /**
    * East arrow
    * @since 21
    */
    EAST = 1,

    /**
    * West arrow
    * @since 21
    */
    WEST = 2,

    /**
    * South arrow
    * @since 21
    */
    SOUTH = 3,

    /**
    * North arrow
    * @since 21
    */
    NORTH = 4,

    /**
    * East-west arrow
    * @since 21
    */
    WEST_EAST = 5,

    /**
    * North-south arrow
    * @since 21
    */
    NORTH_SOUTH = 6,

    /**
    * North-east arrow
    * @since 21
    */
    NORTH_EAST = 7,

    /**
    * North-west arrow
    * @since 21
    */
    NORTH_WEST = 8,

    /**
    * South-east arrow
    * @since 21
    */
    SOUTH_EAST = 9,

    /**
    *South-west arrow
    * @since 21
    */
    SOUTH_WEST = 10,

    /**
    * Northeast and southwest adjustment
    * @since 21
    */
    NORTH_EAST_SOUTH_WEST = 11,

    /**
    * Northwest and southeast adjustment
    * @since 21
    */
    NORTH_WEST_SOUTH_EAST = 12,

    /**
    * Cross (accurate selection)
    * @since 21
    */
    CROSS = 13,

    /**
    * Copy
    * @since 21
    */
    CURSOR_COPY = 14,

    /**
    * Forbid
    * @since 21
    */
    CURSOR_FORBID = 15,

    /**
    * Sucker
    * @since 21
    */
    COLOR_SUCKER = 16,

    /**
    * Grabbing hand
    * @since 21
    */
    HAND_GRABBING = 17,

    /**
    * Opening hand
    * @since 21
    */
    HAND_OPEN = 18,

    /**
    * Hand-shaped pointer
    * @since 21
    */
    HAND_POINTING = 19,

    /**
    * Help
    * @since 21
    */
    HELP = 20,

    /**
    * Move
    * @since 21
    */
    MOVE = 21,

    /**
    * Left and right resizing
    * @since 21
    */
    RESIZE_LEFT_RIGHT = 22,

    /**
    * Up and down resizing
    * @since 21
    */
    RESIZE_UP_DOWN = 23,

    /**
    * Screenshot crosshair
    * @since 21
    */
    SCREENSHOT_CHOOSE = 24,

    /**
    * Screenshot
    * @since 21
    */
    SCREENSHOT_CURSOR = 25,

    /**
    * Text selection
    * @since 21
    */
    TEXT_CURSOR = 26,

    /**
    * Zoom in
    * @since 21
    */
    ZOOM_IN = 27,

    /**
    * Zoom out
    * @since 21
    */
    ZOOM_OUT = 28,

    /**
    * Scrolling east
    * @since 21
    */
    MIDDLE_BTN_EAST = 29,

    /**
    * Scrolling west
    * @since 21
    */
    MIDDLE_BTN_WEST = 30,

    /**
    * Scrolling south
    * @since 21
    */
    MIDDLE_BTN_SOUTH = 31,

    /**
    * Scrolling north
    * @since 21
    */
    MIDDLE_BTN_NORTH = 32,

    /**
    * Scrolling north and south
    * @since 21
    */
    MIDDLE_BTN_NORTH_SOUTH = 33,

    /**
    * Scrolling northeast
    * @since 21
    */
    MIDDLE_BTN_NORTH_EAST = 34,

    /**
    * Scrolling northwest
    * @since 21
    */
    MIDDLE_BTN_NORTH_WEST = 35,

    /**
    * Scrolling southeast
    * @since 21
    */
    MIDDLE_BTN_SOUTH_EAST = 36,

    /**
    * Scrolling southwest
    * @since 21
    */
    MIDDLE_BTN_SOUTH_WEST = 37,

    /**
    * Moving as a cone in four directions
    * @since 21
    */
    MIDDLE_BTN_NORTH_SOUTH_WEST_EAST = 38,

    /**
    * Horizontal text selection
    * @since 21
    */
    HORIZONTAL_TEXT_CURSOR = 39,

    /**
    * Precise selection
    * @since 21
    */
    CURSOR_CROSS = 40,

    /**
    * Cursor with circle style
    * @since 21
    */
    CURSOR_CIRCLE = 41,

    /**
    * Loading state with dynamic cursor
    * @since 21
    */
    LOADING = 42,

    /**
    * Running state with dynamic cursor
    * @since 21
    */
    RUNNING = 43,

    /**
    * Scrolling east and west
    * @since 21
    */
    MIDDLE_BTN_EAST_WEST = 44;
    
    /**
    * Screen Recording
    * @since 21
    */
    SCREENRECORDER_CURSOR = 48;
} Input_PointerStyle;

#ifdef __cplusplus
}
#endif
/** @} */

#endif /* OH_POINTER_H */