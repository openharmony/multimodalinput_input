/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "parcel.h"
#include <string>

namespace OHOS {
namespace MMI {
inline constexpr int32_t GLOBAL_WINDOW_ID = -1;

inline constexpr int32_t DEFAULT_DISPLAY_ID = -1;
inline constexpr int32_t DEFAULT_GROUP_ID = 0;
constexpr uint32_t MAX_DISPLAY_GROUP_SIZE = 100;
constexpr uint32_t MAX_DISPLAY_SIZE = 1000;
constexpr uint32_t MAX_SCREEN_SIZE = 1000;
constexpr uint32_t MAX_WINDOWS_SIZE = 1000;
constexpr uint32_t MAX_UI_EXTENSION_SIZE = 1000;
constexpr uint32_t MAX_WINDOW_GROUP_INFO_SIZE = 1000;

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
    MIX_BUTTOM_ANTI_AXIS_MOVE = 19,
    SLID_TOUCH_WINDOW = 40,
    TRANSMIT_ANTI_AXIS_MOVE = 50,
    DUALTRIGGER_TOUCH = 60
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
    static constexpr uint32_t FLAG_BIT_HANDWRITING = 1 << 1;

    /**
     * Disable user action window
     *
     * @since 21
     */
    static constexpr uint32_t FLAG_BIT_DISABLE_USER_ACTION = 1 << 2;

    /**
     * pointer locked window
     *
     * @since 22
     */
    static constexpr uint32_t FLAG_BIT_POINTER_LOCKED = 1 << 3;

    /**
     * pointer confined window
     *
     * @since 22
     */
    static constexpr uint32_t FLAG_BIT_POINTER_CONFINED = 1 << 4;

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
     * display group ID
     *
     * @since 19
     */
    int32_t groupId { DEFAULT_GROUP_ID };

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

    bool rectChangeBySystem { false };

    bool isDisplayCoord { false };

    bool isSkipSelfWhenShowOnVirtualScreen { false };
	
    int32_t windowNameType;

    /**
     * ID of the agent process where the window is located
     *
     * @since 21
     */
    int32_t agentPid { -1 };
};

/**
 * Physical screen information
 *
 * @since 9
 */
enum class DisplaySourceMode : uint32_t {
    SCREEN_ALONE,
    SCREEN_EXPAND,

    /**
     * mirror screen
     *
     * @since 20
     */
    SCREEN_MIRROR,

    /**
     * different source screen
     *
     * @since 20
     */
    SCREEN_UNIQUE,

    /**
     * extend screen
     *
     * @since 20
     */
    SCREEN_EXTEND,

    /**
     * main screen
     *
     * @since 20
     */
    SCREEN_MAIN
};

/**
* The area of ​​the logical screen on the physical screen
* Based on screen 0°, not affected by display rotation angle
* @since 20
*/
struct ScreenArea {
    /**
     * The unique ID of the physical screen.
     *
     * @since 20
     */
    int32_t id;

    /**
     * The area of ​​the logical screen on the physical screen
     * The upper left corner of the screen is the origin
     * Based on screen 0°, not affected by display rotation angle
     * @since 20
     */
    Rect area;
};

struct DisplayInfo {
    /**
     * Unique ID of the logical display, this value is greater than or equal to 0 and is unique in user space.
     *
     * @since 9 20
     */
    int32_t id;

    /**
     * The x offset of the upper left corner of the current rotation angle of the screen relative to the upper
     * left corner of the main screen, in px, changes with the rotation
     * @since 9 20
     */
    int32_t x;

    /**
     * The y offset of the upper left corner of the current rotation angle of the screen relative to the upper
     * left corner of the main screen, changes with the rotation. in px.
     *
     * @since 9 20
     */
    int32_t y;

    /**
     * Display width, which is the logical width of the original screen when the rotation angle is 0.
     * The value remains unchanged even if the display screen is rotated. in px.
     *
     * @since 9 20
     */
    int32_t width;

    /**
     * Display height, which is the logical height of the original screen when the rotation angle is 0.
     * The value changed if the display screen is rotated. in px.
     *
     * @since 9
     */
    int32_t height;

    /**
     * Pixel density, which indicates the number of pixels in an inch,changes with resolution adjustment
     *
     * @since 10
     */
    int32_t dpi;

    /**
     * Name of the logical display, which is used for debugging
     *
     * @since 9
     */
    std::string name;

    /**
     * The angle increment from the logical screen orientation of 0° clockwise to the current screen orientation.
     *
     * @since 9 20
     */
    Direction direction;

    /**
     * The angle increment from the current rotation angle of the logical screen to the rotation angle of
     * its window content display clockwise.
     * @since 20
     */
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

    /**
     * Scale percent of oneHand rect to display rect.
     * If 'scalePercent < 100', it means one hand mode.
     * If 'scalePercent == 100', it means not in one hand mode.
     */
    int32_t scalePercent = 100;

    /**
     * Expand height from bottom.
     */
    int32_t expandHeight = 0;

    /**
     * Use for off screen policy
     *
     * @since 12
     */
    bool isCurrentOffScreenRendering = false;

    /**
     * logical screen mode
     *
     * @since 12 20
     */
    DisplaySourceMode displaySourceMode = DisplaySourceMode::SCREEN_MAIN;

    /**
     * Coordinate of the upper left corner of the virtual screen in one-hand mode.
     * If oneHandX is 0, the virtual screen is in the lower left corner.
     * If oneHandX is greater than 0, the virtual screen is in the lower right corner.
     */
    int32_t oneHandX = 0;
    int32_t oneHandY = 0;

    /**
    * The area of ​​the logical screen on the physical screen
    * Based on screen 0°, not affected by display rotation angle
    * @since 20
    */
    ScreenArea screenArea;

    /**
     * rs id.
     *
     * @since 20
     */
    uint64_t rsId;

    /**
     * The x coordinate of the valid area relative to the entire logical screen
     *
     * @since 20
     */
    int32_t offsetX = 0;
    /**
     * The y coordinate of the valid area relative to the entire logical screen
     *
     * @since 12
     */
    int32_t offsetY = 0;
    /**
     * The Pointer Active Width
     *
     * @since 12
     */
    int32_t pointerActiveWidth { 0 };

    /**
     * The Pointer Active Height
     *
     * @since 12
     */
    int32_t pointerActiveHeight { 0 };

    /**
     * The angle of the screen content relative to the sensor 0 degrees.
     *
     * @since 21
     */
    Direction deviceRotation;

    /**
     * The angle of the rotation correction.
     *
     * @since 21
     */
    Direction rotationCorrection;
};
/**
* Screen type.
*
* @since 20
*/
enum class ScreenType : uint32_t {
    UNDEFINED,
    /**
     * real screen.
     *
     * @since 20
     */
    REAL,

    /**
     * virtual screen.
     *
     * @since 20
     */
    VIRTUAL
};

/**
* The angle of the physical screen relative to the sensor 0 degrees.
*
* @since 20
*/
enum class Rotation : uint32_t {
    ROTATION_0,
    ROTATION_90,
    ROTATION_180,
    ROTATION_270,
};

/**
 * physical screen information
 *
 * @since 20
 */
struct ScreenInfo {
    /**
     * The unique ID of the physical screen.
     *
     * @since 20
     */
    int32_t id;

    /**
     * Unique screen ID, which is used to associate the corresponding touchscreen.
     * The default value is default0.
     *
     * @since 20
     */
    std::string uniqueId;

    /**
     * Screen type.
     *
     * @since 20
     */
    ScreenType screenType { ScreenType::REAL };

    /**
     * The width of the physical screen, in px. Does not follow rotation. Does not change for
     * the same physical screen.
     *
     * @since 20
     */
    int32_t width;

    /**
     * The height of the physical screen, in px. Does not follow rotation. Does not change for
     * the same physical screen.
     *
     * @since 20
     */
    int32_t height;

    /**
     * The width of the physical screen, in mm. Does not follow the rotation. Does not change for
     * the same physical screen.
     *
     * @since 20
     */
    int32_t physicalWidth;
    /**
     * The width of the physical height, in mm. Does not follow the rotation. Does not change for
     *  the same physical screen.
     *
     * @since 20
     */
    int32_t physicalHeight;

    /**
     * The angle from the screen default origin to the TP origin clockwise.
     *
     * @since 20
     */
    Direction tpDirection;

    /**
     * Physical pixel density does not change with resolution.
     *
     * @since 20
     */
    int32_t dpi;

    /**
     * The number of pixels per inch is a physical property and does not change.
     *
     * @since 20
     */
    int32_t ppi;

    /**
     * The angle of the physical screen relative to the sensor 0 degrees.
     *
     * @since 20
     */
    Rotation rotation;
};

/**
 * Logical screen group type
 *
 * @since 20
 */
enum GroupType {
    /**
    * The default group, the group that receives input events. This group can only have one
    *
    * @since 20
    */
    GROUP_DEFAULT = 0,

    /**
    * The special group, the group can have multiple.
    *
    * @since 20
    */
    GROUP_SPECIAL = 1,
};
/**
 * Logical screen information
 *
 * @since 9 20
 */
struct DisplayGroupInfo {
    /**
     * Logical screen group id, at least the user space level guarantees uniqueness.
     * The range is greater than or equal to 0
     *
     * @since 20
     */
    int32_t id;

    /**
     * Logical screen group name
     *
     * @since 20
     */
    std::string name;

    /**
     * Logical screen group type
     *
     * @since 20
     */
    GroupType type;

    /**
     * The main logical screen ID. The logical screen with this ID must be in the displaysInfo.
     *
     * @since 20
     */
    int32_t mainDisplayId;

    /**
     * ID of the focus window, The value -1 indicates that there is no focused window in the current screen group.
     * The default screen group must have a focused window.
     *
     * @since 9 20
     */
    int32_t focusWindowId;

    /**
     * List of window information of the logical display arranged in Z order, with the top window at the top
     *
     * @since 9
     */
    std::vector<WindowInfo> windowsInfo;

    /**
     * logical screen information list
     *
     * @since 9 20
     */
    std::vector<DisplayInfo> displaysInfo;
};

/**
 * user state
 *
 * @since 21
 */
enum UserState {
    /**
    * user active
    *
    * @since 21
    */
    USER_ACTIVE = 0,

    /**
    * user inactive.
    *
    * @since 21
    */
    USER_INACTIVE = 1,
};

/**
 * user's screen information
 *
 * @since 20
 */
struct UserScreenInfo {
    /**
     * user id.
     *
     * @since 20
     */
    int32_t userId;

    /**
     * user state.
     *
     * @since 21
     */
    UserState userState { USER_ACTIVE};

    /**
     * Physical screen information.
     *
     * @since 20
     */
    std::vector<ScreenInfo> screens;

    /**
     * Logical screen information.
     *
     * @since 20
     */
    std::vector<DisplayGroupInfo> displayGroups;
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

struct DisplayBindInfo : public Parcelable {
    int32_t inputDeviceId { -1 };
    std::string inputDeviceName;
    int32_t displayId { -1 };
    std::string displayName;

    bool Marshalling(Parcel &parcel) const
    {
        if (!parcel.WriteInt32(inputDeviceId)) {
            return false;
        }
        if (!parcel.WriteString(inputDeviceName)) {
            return false;
        }
        if (!parcel.WriteInt32(displayId)) {
            return false;
        }
        if (!parcel.WriteString(displayName)) {
            return false;
        }
        return true;
    };

    bool ReadFromParcel(Parcel &parcel)
    {
        return (
            parcel.ReadInt32(inputDeviceId) &&
            parcel.ReadString(inputDeviceName) &&
            parcel.ReadInt32(displayId) &&
            parcel.ReadString(displayName)
        );
    }

    static DisplayBindInfo* Unmarshalling(Parcel &parcel)
    {
        auto obj = new (std::nothrow) DisplayBindInfo();
        if (obj && !obj->ReadFromParcel(parcel)) {
            delete obj;
            obj = nullptr;
        }
        return obj;
    };
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
