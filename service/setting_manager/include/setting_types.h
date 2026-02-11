/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef SETTING_TYPES_H
#define SETTING_TYPES_H

#include <set>

namespace OHOS {
namespace MMI {
const std::string MOUSE_KEY_SETTING = "settings.input.mouse";
const std::string TOUCHPAD_KEY_SETTING = "settings.input.touchpad";
const std::string KEYBOARD_KEY_SETTING = "settings.input.keyboard";

// 键盘相关的设置项
const std::string FIELD_KEYBOARD_REPEAT_RATE = "keyboardRepeatRate";
const std::string FIELD_KEYBOARD_REPEAT_RATE_DELAY = "keyboardRepeatDelay";
// 鼠标相关的设置项
const std::string FIELD_MOUSE_SCROLL_ROWS  = "rows";
const std::string FIELD_MOUSE_PRIMARY_BUTTON = "primaryButton";
const std::string FIELD_MOUSE_POINTER_SPEED = "speed";
const std::string FIELD_MOUSE_HOVER_SCROLL_STATE = "isEnableHoverScroll";
const std::string FIELD_MOUSE_POINTER_COLOR = "pointerColor";
const std::string FIELD_MOUSE_POINTER_SIZE = "pointerSize";
const std::string FIELD_MOUSE_POINTER_STYLE = "pointerStyle";
const std::string FIELD_MAGIC_POINTER_COLOR = "magicPointerColor";
const std::string FIELD_MAGIC_POINTER_SIZE = "magicPointerSize";
// 触控板相关的设置项
const std::string FIELD_TOUCHPAD_SCROLL_ROWS = "touchpadScrollRows";
const std::string FIELD_TOUCHPAD_THREE_FINGERTAP_SWITCH = "touchpadThreeFingerTap";
const std::string FIELD_TOUCHPAD_DOUBLE_TAP_AND_DRAG = "touchpadDoubleTapAndDrag";
const std::string FIELD_TOUCHPAD_RIGHT_CLICK_TYPE = "rightMenuSwitch";
const std::string FIELD_TOUCHPAD_POINTER_SPEED = "touchPadPointerSpeed";
const std::string FIELD_TOUCHPAD_TAP_SWITCH = "touchpadTap";
const std::string FIELD_TOUCHPAD_SCROLL_DIRECTION = "scrollDirection";
const std::string FIELD_TOUCHPAD_SCROLL_SWITCH = "scrollSwitch";
const std::string FIELD_TOUCHPAD_PINCH_SWITCH = "touchpadPinch";
const std::string FIELD_TOUCHPAD_SWIPE_SWITCH = "touchpadSwipe";
const std::string FIELD_TOUCHPAD_ROTATE_SWITCH = "touchpadRotate";
constexpr int32_t DEFAULT_USER_ID { 100 };

// 鼠标配置支持的键值白名单
const std::set<std::string> MOUSE_SETTING_FIELDS = {
    FIELD_MOUSE_SCROLL_ROWS,
    FIELD_MOUSE_PRIMARY_BUTTON,
    FIELD_MOUSE_POINTER_SPEED,
    FIELD_MOUSE_HOVER_SCROLL_STATE,
    FIELD_MOUSE_POINTER_COLOR,
    FIELD_MOUSE_POINTER_SIZE,
    FIELD_MOUSE_POINTER_STYLE
};

// 触摸板配置支持的键值白名单
const std::set<std::string> TOUCHPAD_SETTING_FIELDS = {
    FIELD_TOUCHPAD_SCROLL_ROWS,
    FIELD_TOUCHPAD_THREE_FINGERTAP_SWITCH,
    FIELD_TOUCHPAD_DOUBLE_TAP_AND_DRAG,
    FIELD_TOUCHPAD_RIGHT_CLICK_TYPE,
    FIELD_TOUCHPAD_POINTER_SPEED,
    FIELD_TOUCHPAD_TAP_SWITCH,
    FIELD_TOUCHPAD_SCROLL_DIRECTION,
    FIELD_TOUCHPAD_SCROLL_SWITCH,
    FIELD_TOUCHPAD_PINCH_SWITCH,
    FIELD_TOUCHPAD_SWIPE_SWITCH
};

// 键盘配置支持的键值白名单
const std::set<std::string> KEYBOARD_SETTING_FIELDS = {
    FIELD_KEYBOARD_REPEAT_RATE,
    FIELD_KEYBOARD_REPEAT_RATE_DELAY
};

const std::set<std::string> SETTING_KEYS = {
    MOUSE_KEY_SETTING,
    TOUCHPAD_KEY_SETTING,
    KEYBOARD_KEY_SETTING
};
} // namespace MMI
} // namespace OHOS

#endif // SETTING_TYPES_H