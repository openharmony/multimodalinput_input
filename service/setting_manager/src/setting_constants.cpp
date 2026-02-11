/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "setting_constants.h"
#include "setting_types.h"

namespace OHOS {
namespace MMI {
namespace SettingConstants {
    // Version numbers
    const std::string VERSION_NUMBERS_LATEST = "1.0";
    const std::string VERSION_NUMBERS_INITIAL = "0.0";
    const std::string FIELD_VERSION = "version";

    // File paths (internal use only)
    const std::string GLOBAL_CONFIG_PATH = "/data/service/el1/public/multimodalinput/";
    const std::string GLOBAL_MOUSE_FILE_PATH = GLOBAL_CONFIG_PATH + "mouse_settings.xml";
    const std::string GLOBAL_KEYBOARD_FILE_PATH = GLOBAL_CONFIG_PATH + "keyboard_settings.xml";
    const std::string GLOBAL_TOUCHPAD_FILE_PATH = GLOBAL_CONFIG_PATH + "touchpad_settings.xml";

    // Field type sets for migration
    const std::vector<std::string> SETTING_FIELDS_BOOL = {
        FIELD_MOUSE_HOVER_SCROLL_STATE,
        FIELD_TOUCHPAD_THREE_FINGERTAP_SWITCH,
        FIELD_TOUCHPAD_DOUBLE_TAP_AND_DRAG,
        FIELD_TOUCHPAD_TAP_SWITCH,
        FIELD_TOUCHPAD_SCROLL_DIRECTION,
        FIELD_TOUCHPAD_SCROLL_SWITCH,
        FIELD_TOUCHPAD_PINCH_SWITCH,
        FIELD_TOUCHPAD_SWIPE_SWITCH
    };

    const std::vector<std::string> SETTING_FIELDS_NUM = {
        FIELD_MOUSE_SCROLL_ROWS,
        FIELD_MOUSE_PRIMARY_BUTTON,
        FIELD_MOUSE_POINTER_SPEED,
        FIELD_MOUSE_POINTER_COLOR,
        FIELD_MOUSE_POINTER_SIZE,
        FIELD_MOUSE_POINTER_STYLE,
        FIELD_TOUCHPAD_SCROLL_ROWS,
        FIELD_TOUCHPAD_POINTER_SPEED,
        FIELD_KEYBOARD_REPEAT_RATE,
        FIELD_KEYBOARD_REPEAT_RATE_DELAY,
        FIELD_TOUCHPAD_RIGHT_CLICK_TYPE
    };
}  // namespace SettingConstants
}  // namespace MMI
}  // namespace OHOS
