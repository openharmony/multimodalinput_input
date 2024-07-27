/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef DISPLAY_INFO_H
#define DISPLAY_INFO_H

#include <string>
#include <vector>

namespace OHOS {
namespace MMI {
inline constexpr int32_t GLOBAL_WINDOW_ID = -1;

inline constexpr int32_t DEFAULT_DISPLAY_ID = -1;

enum SecureFlag {
    DEFAULT_MODE = 0,
    PRIVACY_MODE = 1,
};

/**
 * @brief Enumerates the fold display mode.
 */
enum class DisplayMode: uint32_t {
    /**
     * The default display mode
     *
     * @since 9
     */
    UNKNOWN = 0,

    /**
     * The full display mode
     *
     * @since 9
     */
    FULL = 1,

    /**
     * The main display mode
     *
     * @since 9
     */
    MAIN = 2,

    /**
     * The sub display mode
     *
     * @since 9
     */
    SUB = 3,

    /**
     * The coordination display mode
     *
     * @since 9
     */
    COORDINATION = 4,
};

enum class WINDOW_UPDATE_ACTION: uint32_t {
    /**
     * The default window update action
     *
     * @since 9
     */
    UNKNOWN = 0,

    /**
     * Add the window action
     *
     * @since 9
     */
    ADD = 1,

    /**
     * Delete the window action
     *
     * @since 9
     */
    DEL = 2,

     /**
     * Change the window action
     *
     * @since 9
     */
    CHANGE = 3,

    /**
     * Add the window action end
     *
     * @since 9
     */
    ADD_END = 4,
};

enum Direction {
    /**
     * Rotating the display clockwise by 0 degree
     *
     * @since 9
     */
    DIRECTION0,

    /**
     * Rotating the display clockwise by 90 degrees
     *
     * @since 9
     */
    DIRECTION90,

    /**
     * Rotating the display clockwise by 180 degrees
     *
     * @since 9
     */
    DIRECTION180,

    /**
     * Rotating the display clockwise by 270 degrees
     *
     * @since 9
     */
    DIRECTION270
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

enum class WindowInputType : uint8_t {
    NORMAL = 0,
    TRANSMIT_ALL = 1,
    TRANSMIT_EXCEPT_MOVE = 2,
    ANTI_MISTAKE_TOUCH = 3,
    TRANSMIT_AXIS_MOVE = 4,
    TRANSMIT_MOUSE_MOVE = 5,
    TRANSMIT_LEFT_RIGHT = 6,
    TRANSMIT_BUTTOM = 7,
    MIX_LEFT_RIGHT_ANTI_AXIS_MOVE = 18,
    MIX_BUTTOM_ANTI_AXIS_MOVE = 19
};

struct WindowInfo {
    /**
     * Maximum number of hot areas
     *
     * @since 9
     */
    static constexpr int32_t MAX_HOTAREA_COUNT = 50;

    static constexpr int32_t DEFAULT_HOTAREA_COUNT = 10;

    /**
     * The number of pointer change areas
     *
     * @since 9
     */
    static constexpr int32_t POINTER_CHANGEAREA_COUNT = 8;

    /**
     * The size of window transform, which create a 3*3 matrix
     *
     * @since 9
     */
    static constexpr int32_t WINDOW_TRANSFORM_SIZE = 9;

    /**
     * Untouchable window
     *
     * @since 9
     */
    static constexpr uint32_t FLAG_BIT_UNTOUCHABLE = 1;

    /**
     * Only handwriting window
     *
     * @since 12
     */
    static constexpr uint32_t FLAG_BIT_HANDWRITING = 2;

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

    /**
     * Agent window ID
     *
     * @since 9
     */
    WINDOW_UPDATE_ACTION action { WINDOW_UPDATE_ACTION::UNKNOWN };

    /**
     * Window display ID
     *
     * @since 9
     */
    int32_t displayId { DEFAULT_DISPLAY_ID };

    /**
     * Window order in Z-index
     *
     * @since 9
     */
    float zOrder { 0.0f };

    /**
     * Number of mouse style change areas in the window. The value must be POINTER_CHANGEAREA_COUNT.
     *
     * @since 9
     */
    std::vector<int32_t> pointerChangeAreas;

    /**
     * Number of transform in the window which is used to calculate the window x and window y by logic x and window y.
     * The value must be POINTER_CHANGEAREA_COUNT.
     *
     * @since 9
     */
    std::vector<float> transform;

    /**
     * pixelMap Indicates the special-shaped window. Its actual type must be OHOS::Media::PixelMap*,
     * which is used to determine whether an event is dispatched to the current window.
     *
     * @since 12
     */
    void* pixelMap { nullptr };

    WindowInputType windowInputType { WindowInputType::NORMAL };

    SecureFlag privacyMode { SecureFlag::DEFAULT_MODE };

    int32_t windowType;

    bool privacyUIFlag { false };

    std::vector<WindowInfo> uiExtentionWindowInfo;
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
     * Pixel density, which indicates the number of pixels in an inch
     *
     * @since 10
     */
    int32_t dpi;

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

    Direction displayDirection;

    /**
     * DisplayMode of the display
     *
     * @since 9
     */
    DisplayMode displayMode { DisplayMode::UNKNOWN };

    /**
     * Number of transform in the screen which is used to calculate the display x and display y by logic x and logic y.
     * The value must be POINTER_CHANGEAREA_COUNT.
     *
     * @since 12
     */
    std::vector<float> transform;
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

    int32_t currentUserId { -1 };

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

struct WindowGroupInfo {
    /**
     * ID of the focus window
     *
     * @since 9
     */
    int32_t focusWindowId { GLOBAL_WINDOW_ID };

    /**
     * Window display ID
     *
     * @since 9
     */
    int32_t displayId { DEFAULT_DISPLAY_ID };

    /**
     * List of window information of the logical display arranged in Z order, with the top window at the top
     *
     * @since 9
     */
    std::vector<WindowInfo> windowsInfo;
};

struct DisplayBindInfo {
    int32_t inputDeviceId { -1 };
    std::string inputDeviceName;
    int32_t displayId { -1 };
    std::string displayName;
};
enum class WindowArea: int32_t {
    ENTER = 0,
    EXIT,
    FOCUS_ON_INNER,
    FOCUS_ON_TOP,
    FOCUS_ON_BOTTOM,
    FOCUS_ON_LEFT,
    FOCUS_ON_RIGHT,
    FOCUS_ON_TOP_LEFT,
    FOCUS_ON_TOP_RIGHT,
    FOCUS_ON_BOTTOM_LEFT,
    FOCUS_ON_BOTTOM_RIGHT,
    TOP_LEFT_LIMIT,
    TOP_RIGHT_LIMIT,
    TOP_LIMIT,
    LEFT_LIMIT,
    RIGHT_LIMIT,
    BOTTOM_LEFT_LIMIT,
    BOTTOM_LIMIT,
    BOTTOM_RIGHT_LIMIT
};

using DisplayBindInfos = std::vector<DisplayBindInfo>;
} // namespace MMI
} // namespace OHOS
#endif // DISPLAY_INFO_H
