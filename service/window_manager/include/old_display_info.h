/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#ifndef OLD_DISPLAY_INFO_H
#define OLD_DISPLAY_INFO_H
#include "window_info.h"
namespace OHOS {
namespace MMI {
namespace OLD {
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
    OHOS::MMI::Direction direction;

    OHOS::MMI::Direction displayDirection;

    /**
     * DisplayMode of the display
     *
     * @since 9
     */
    OHOS::MMI::DisplayMode displayMode { OHOS::MMI::DisplayMode::UNKNOWN };

    /**
     * Number of transform in the screen which is used to calculate the display x and display y by logic x and logic y.
     * The value must be POINTER_CHANGEAREA_COUNT.
     *
     * @since 12
     */
    std::vector<float> transform;

    /**
     * Orientation of the physical display
     *
     * @since 12
     */
    int32_t offsetX = 0;
    int32_t offsetY = 0;
    float ppi;

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
    int32_t screenRealWidth = 0;
    int32_t screenRealHeight = 0;
    int32_t screenRealDPI = 0;
    /**
     * logical screen mode
     *
     * @since 12 20
     */
    OHOS::MMI::DisplaySourceMode displaySourceMode = OHOS::MMI::DisplaySourceMode::SCREEN_MAIN;
    /**
     * Coordinate of the upper left corner of the virtual screen in one-hand mode.
     * If oneHandX is 0, the virtual screen is in the lower left corner.
     * If oneHandX is greater than 0, the virtual screen is in the lower right corner.
     */
    int32_t oneHandX = 0;
    int32_t oneHandY = 0;

    /**
     * Width of the effective area of the screen. When the screen is rotated, the value changes accordingly.
     *
     * @since 12
     */
    int32_t validWidth = 0;

    /**
     * Height of the effective area of the screen. When the screen is rotated, the value changes accordingly.
     *
     * @since 12
     */
    int32_t validHeight = 0;

    /**
     * Rotation angle of the TP patch offset correction.
     *
     * @since 12
     */
    OHOS::MMI::Direction fixedDirection;
    
    /**
     * The physical width of the screen, in millimeters.
     *
     * @since 12
     */
    int32_t physicalWidth { 0 };

    /**
     * The physical height of the screen, in millimeters.
     *
     * @since 12
     */
    int32_t physicalHeight { 0 };

    /**
     * The Pointer Active Width
     *
     * @since 18
     */
    int32_t pointerActiveWidth { 0 };

    /**
     * The Pointer Active Height
     *
     * @since 18
     */
    int32_t pointerActiveHeight { 0 };

    /** Unique ID of the physical display
     *
     * @since 18
     */
    uint64_t rsId { 0 };

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

struct DisplayGroupInfo {
    /**
     * index of group. default=-1
     *
     * @since 19
     */
    int32_t groupId { DEFAULT_GROUP_ID };
    /**
     * Logical screen group type
     *
     * @since 20
     */
    OHOS::MMI::GroupType type;
    /**
     * The main logical screen ID. The logical screen with this ID must be in the displaysInfo.
     *
     * @since 20
     */
    int32_t mainDisplayId;

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
    std::vector<OHOS::MMI::WindowInfo> windowsInfo;

    /**
     * Physical screen information list
     *
     * @since 9
     */
    std::vector<DisplayInfo> displaysInfo;
};
} // namespace OLD
} // namespace MMI
} // namespace OHOS
#endif // DISPLAY_INFO_H