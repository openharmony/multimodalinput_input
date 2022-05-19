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

#ifndef DISPLAY_INFO_H
#define DISPLAY_INFO_H

#include <vector>
#include <string>

namespace OHOS {
namespace MMI {
enum Direction {
    /**
     * Rotating the display clockwise by 0 degree
     *
     * @since 9
    */
    Direction0,

    /**
     * Rotating the display clockwise by 90 degrees
     *
     * @since 9
    */
    Direction90,

    /**
     * Rotating the display clockwise by 180 degrees
     *
     * @since 9
    */
    Direction180,

    /**
     * Rotating the display clockwise by 270 degrees
     *
     * @since 9
    */
    
    Direction270
};

struct WindowInfo {
    /**
     * Untouchable window
     *
     * @since 9
    */
    static constexpr uint32_t FLAG_BIT_UNTOUCHABLE = 1;

    /**
     * Globally unique identifier of the window
     *
     * @since 9
    */
    int32_t id;

    /**
     * ID of the process where the window is located
     *
     * @since 9
    */
    int32_t pid;

    /**
     * UID of the process where the window is located
     *
     * @since 9
    */
    int32_t uid;

    /**
     * X coordinate of the upper left corner of the hot zone window
     *
     * @since 9
    */
    int32_t hotZoneTopLeftX;

    /**
     * Y coordinate of the upper left corner of the hot zone window
     *
     * @since 9
    */
    int32_t hotZoneTopLeftY;

    /**
     * Width of the hot zone window
     *
     * @since 9
    */
    int32_t hotZoneWidth;

    /**
     * Height of the hot zone window
     *
     * @since 9
    */
    int32_t hotZoneHeight;

    /**
     * Logical display ID
     *
     * @since 9
    */
    int32_t displayId;

    /**
     * Agent window ID
     *
     * @since 9
    */
    int32_t agentWindowId;

    /**
     * X coordinate of the upper left corner of the window
     *
     * @since 9
    */
    int32_t winTopLeftX;

    /**
     * Y coordinate of the upper left corner of the window
     *
     * @since 9
    */
    int32_t winTopLeftY;

    /**
     * A 32-bit flag that represents the window status. If the 0th bit is 1,
     * the window is untouchable; if the 0th bit is 0, the window is touchable.
     *
     * @since 9
    */
    uint32_t flags;
};

struct PhysicalDisplayInfo {
    /**
     * Unique ID of the physical display
     *
     * @since 9
    */
    int32_t id;

    /**
     * ID of the left physical display
     *
     * @since 9
    */
    int32_t leftDisplayId;

    /**
     * ID of the upper physical display
     *
     * @since 9
    */
    int32_t upDisplayId;

    /**
     * X coordinate of the upper left corner of the display
     *
     * @since 9
    */
    int32_t topLeftX;

    /**
     * Y coordinate of the upper left corner of the display
     *
     * @since 9
    */
    int32_t topLeftY;

    /**
     * Display width
     *
     * @since 9
    */
    int32_t width;

    /**
     * Display height
     *
     * @since 9
    */
    int32_t height;

    /**
     * Name of the physical display, which is used for debugging
     *
     * @since 9
    */
    std::string name;

    /**
     * Seat ID of the physical display, which is used for matching the touchscreen and display
     *
     * @since 9
    */
    std::string seatId;

    /**
     * Seat name of the physical display, which is used for matching the touchscreen and display
     *
     * @since 9
    */
    std::string seatName;

    /**
     * Logical width of the physical display
     *
     * @since 9
    */
    int32_t logicWidth;

    /**
     * Logical height of the physical display
     *
     * @since 9
    */
    int32_t logicHeight;

    /**
     * Orientation of the physical display
     *
     * @since 9
    */
    Direction direction;
};

struct LogicalDisplayInfo {
    /**
     * Unique ID of the logical display
     *
     * @since 9
    */
    int32_t id;

    /**
     * X coordinate of the upper left corner of the logical display
     *
     * @since 9
    */
    int32_t topLeftX;

    /**
     * Y coordinate of the upper left corner of the logical display
     *
     * @since 9
    */
    int32_t topLeftY;

    /**
     * Width of the logical display
     *
     * @since 9
    */
    int32_t width;

    /**
     * Height of the logical display
     *
     * @since 9
    */
    int32_t height;

    /**
     * Name of the logical display, which is used for debugging
     *
     * @since 9
    */
    std::string name;

    /**
     * Seat ID of the logical display, which is used for matching the touchscreen
     *
     * @since 9
    */
    std::string seatId;

    /**
     * Seat name of the logical display, which is used for matching the touchscreen
     *
     * @since 9
    */
    std::string seatName;

    /**
     * ID of the focus window
     *
     * @since 9
    */
    int32_t focusWindowId;

    /**
     * List of window information of the logical display arranged in Z order, with the top window at the top
     *
     * @since 9
    */
    std::vector<WindowInfo> windowsInfo;
};
} // namespace MMI
} // namespace OHOS
#endif // DISPLAY_INFO_H