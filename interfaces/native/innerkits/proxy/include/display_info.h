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

struct Rect {
    /**
     * X coordinate of the upper left corner
     *
     * @since 9
     */
    int32_t x;

    /**
     * Y coordinate of the upper left corner
     *
     * @since 9
     */
    int32_t y;

    /**
     * Width
     *
     * @since 9
     */
    int32_t width;

    /**
     * Height
     *
     * @since 9
     */
    int32_t height;
};


struct WindowInfo {
    /**
     * Maximum number of hot areas
     *
     * @since 9
     */
    static constexpr int32_t MAX_HOTAREA_COUNT = 10;

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
     * Window display area
     *
     * @since 9
     */
    Rect area;

    /**
     * Number of touch response areas (excluding the mouse response areas) in the window.
     * The value cannot exceed the value of MAX_HOTAREA_COUNT.
     *
     * @since 9
     */
    std::vector<Rect> defaultHotAreas;

    /**
     * Number of mouse response areas in the window. The value cannot exceed the value of MAX_HOTAREA_COUNT.
     *
     * @since 9
     */
    std::vector<Rect> pointerHotAreas;

    /**
     * Agent window ID
     *
     * @since 9
     */
    int32_t agentWindowId;

    /**
     * A 32-bit flag that represents the window status. If the 0th bit is 1,
     * the window is untouchable; if the 0th bit is 0, the window is touchable.
     *
     * @since 9
     */
    uint32_t flags;
};

/**
 * Physical screen information
 *
 * @since 9
 */
struct DisplayInfo {
    /**
     * Unique ID of the physical display
     *
     * @since 9
     */
    int32_t id;

    /**
     * X coordinate of the upper left corner on the logical screen
     *
     * @since 9
     */
    int32_t x;

    /**
     * Y coordinate of the upper left corner on the logical screen
     *
     * @since 9
     */
    int32_t y;

    /**
     * Display width, which is the logical width of the original screen when the rotation angle is 0.
     * The value remains unchanged even if the display screen is rotated.
     *
     * @since 9
     */
    int32_t width;

    /**
     * Display height, which is the logical height of the original screen when the rotation angle is 0.
     * The value remains unchanged even if the display screen is rotated.
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
     * Unique screen ID, which is used to associate the corresponding touchscreen. The default value is default0.
     *
     * @since 9
     */
    std::string uniq;

    /**
     * Orientation of the physical display
     *
     * @since 9
     */
    Direction direction;
};

/**
 * Logical screen information
 *
 * @since 9
 */
struct DisplayGroupInfo {
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

    /**
     * Physical screen information list
     *
     * @since 9
     */
    std::vector<DisplayInfo> displaysInfo;
};
} // namespace MMI
} // namespace OHOS
#endif // DISPLAY_INFO_H