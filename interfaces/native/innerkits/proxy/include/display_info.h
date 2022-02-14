/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include <vector>
#include <string>

namespace OHOS {
namespace MMI {
enum Direction {
    // The display rotated 0 degrees clockwise
    Direction0,

    // The display rotated 90 degrees clockwise
    Direction90,

    // The display rotated 180 degrees clockwise
    Direction180,

    // The display rotated 270 degrees clockwise
    Direction270
};

struct WindowInfo {
    // The globally unique identifier of the window
    int32_t id;

    // The id of the process where the window is located
    int32_t pid;

    // The uid of the process where the window is located
    int32_t uid;

    // The x coordinate of the upper left corner of the window in the logical display
    int32_t topLeftX;

    // The y coordinate of the upper left corner of the window in the logical display
    int32_t topLeftY;

    // Logical width of the window
    int32_t width;

    // Logical height of the window
    int32_t height;

    // The logical display id to which the window belongs
    int32_t displayId;

    // The input events sent to this window will be sent to the agentwindowid window for processing
    int32_t agentWindowId;

    // The x coordinate of the upper left corner of the window in the logical display
    int32_t winTopLeftX;

    // The y coordinate of the upper left corner of the window in the logical display
    int32_t winTopLeftY;
};

struct PhysicalDisplayInfo {
    // The globally unique id of the physical display
    int32_t id;

    // Globally unique id of the physical display on the left
    int32_t leftDisplayId;

    // The globally unique id of the upper physical display
    int32_t upDisplayId;

    // The x coordinate of the upper left corner of the display
    int32_t topLeftX;

    // The y coordinate of the upper left corner of the display
    int32_t topLeftY;

    // Display width
    int32_t width;

    // Display height
    int32_t height;

    // Display name, for debugging
    std::string name;

    // Display seatId, The display associated with the touch screen must be configured with a non-empty seatid
    std::string seatId;

    std::string seatName;

    // Display logic width
    int32_t logicWidth;

    // Display logic width
    int32_t logicHeight;

    // Display orientation
    Direction direction;
};

struct LogicalDisplayInfo {
    // The globally unique id of the logic display
    int32_t id;

    // The x coordinate of the upper left corner of the logical display
    int32_t topLeftX;

    // The y coordinate of the upper left corner of the logical display
    int32_t topLeftY;

    // Logical display width
    int32_t width;

    // Logical display height
    int32_t height;

    // Logical display name, for debugging
    std::string name;

    // Logical display seatId, Displays that are not touch screen-independent use this attribute to associate with input
    // devices Keep it empty unless you are sure of what you are doing
    std::string seatId;

    std::string seatName;

    int32_t focusWindowId;

    // List of window information arranged in Z order, with the top window at the top
    std::vector<WindowInfo> windowsInfo_;
};
}
} // namespace OHOS::MMI

#endif // DISPLAY_INFO_H