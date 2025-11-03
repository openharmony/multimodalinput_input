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

#ifndef OHOS_MULTIMODALINPUT_POINTER_IMPL_H
#define OHOS_MULTIMODALINPUT_POINTER_IMPL_H

#include <map>
#include <stdexcept>

#include "ani_common.h"
#include "define_multimodal.h"
#include "input_manager.h"
#include "ohos.multimodalInput.pointer.proj.hpp"
#include "ohos.multimodalInput.pointer.impl.hpp"
#include "taihe/runtime.hpp"

enum PointerStyleCode {
    DEFAULT_IMPL,
    EAST_IMPL,
    WEST_IMPL,
    SOUTH_IMPL,
    NORTH_IMPL,
    WEST_EAST_IMPL,
    NORTH_SOUTH_IMPL,
    NORTH_EAST_IMPL,
    NORTH_WEST_IMPL,
    SOUTH_EAST_IMPL,
    SOUTH_WEST_IMPL,
    NORTH_EAST_SOUTH_WEST_IMPL,
    NORTH_WEST_SOUTH_EAST_IMPL,
    CROSS_IMPL,
    CURSOR_COPY_IMPL,
    CURSOR_FORBID_IMPL,
    COLOR_SUCKER_IMPL,
    HAND_GRABBING_IMPL,
    HAND_OPEN_IMPL,
    HAND_POINTING_IMPL,
    HELP_IMPL,
    MOVE_IMPL,
    RESIZE_LEFT_RIGHT_IMPL,
    RESIZE_UP_DOWN_IMPL,
    SCREENSHOT_CHOOSE_IMPL,
    SCREENSHOT_CURSOR_IMPL,
    TEXT_CURSOR_IMPL,
    ZOOM_IN_IMPL,
    ZOOM_OUT_IMPL,
    MIDDLE_BTN_EAST_IMPL,
    MIDDLE_BTN_WEST_IMPL,
    MIDDLE_BTN_SOUTH_IMPL,
    MIDDLE_BTN_NORTH_IMPL,
    MIDDLE_BTN_NORTH_SOUTH_IMPL,
    MIDDLE_BTN_NORTH_EAST_IMPL,
    MIDDLE_BTN_NORTH_WEST_IMPL,
    MIDDLE_BTN_SOUTH_EAST_IMPL,
    MIDDLE_BTN_SOUTH_WEST_IMPL,
    MIDDLE_BTN_NORTH_SOUTH_WEST_EAST_IMPL,
    HORIZONTAL_TEXT_CURSOR_IMPL,
    CURSOR_CROSS_IMPL,
    CURSOR_CIRCLE_IMPL,
    LOADING_IMPL,
    RUNNING_IMPL,
    MIDDLE_BTN_EAST_WEST_IMPL,
    SCREENRECORDER_CURSOR_IMPL = 48
};
#endif // OHOS_MULTIMODALINPUT_POINTER_IMPL_H
