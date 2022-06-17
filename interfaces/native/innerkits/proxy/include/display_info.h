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
    // 左上角x坐标
    int32_t x;

    // 左上角y坐标
    int32_t y;

    // 宽度
    int32_t width;

    // 高度
    int32_t height;
};


struct WindowInfo {
    // 热区最大数量
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

    // 窗口的显示区域
    Rect area;

    // 窗口的触摸响应区域(除鼠标之外的), 数量不能超过MAX_HOTAREA_COUNT
    std::vector<Rect> defaultHotAreas;

    // 窗口的鼠标响应区域，数量不能超过MAX_HOTAREA_COUNT
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

// 物理屏显示信息
struct DisplayInfo {
    /**
     * Unique ID of the physical display
     *
     * @since 9
    */
    int32_t id;

    /**
     * 在逻辑屏幕中，屏幕左上角的x坐标
     *
     * @since 9
    */
    int32_t x;

    /**
     * 在逻辑屏幕中，屏幕左上角的y坐标
     *
     * @since 9
    */
    int32_t y;

    /**
     * Display width，原始显示屏的旋转角度为0的逻辑宽度，旋转后，此值依然保持旋转角度为0的值
     *
     * @since 9
    */
    int32_t width;

    /**
     * Display height，原始显示屏的旋转角度为0的逻辑高度，旋转后，此值依然保持旋转角度为0的值
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
     * 屏幕唯一标识符号，用于关联对应的触摸屏，默认为default0
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

// 逻辑屏显示信息
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
    
    // 物理屏信息列表
    std::vector<DisplayInfo> displaysInfo;
};
} // namespace MMI
} // namespace OHOS
#endif // DISPLAY_INFO_H