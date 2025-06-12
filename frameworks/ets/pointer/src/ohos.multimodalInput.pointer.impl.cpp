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

#include "ohos.multimodalInput.pointer.impl.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "ohos.multimodalInput.pointer"

using namespace taihe;
using namespace ohos::multimodalInput::pointer;

namespace {
std::map<int32_t, PointerStyle> POINTER_STYLE_TRANSFORMATION = {
    { DEFAULT_IMPL,                                 PointerStyle::key_t::DEFAULT },
    { EAST_IMPL,                                    PointerStyle::key_t::EAST },
    { WEST_IMPL,                                    PointerStyle::key_t::WEST },
    { SOUTH_IMPL,                                   PointerStyle::key_t::SOUTH },
    { NORTH_IMPL,                                   PointerStyle::key_t::NORTH },
    { WEST_EAST_IMPL,                               PointerStyle::key_t::WEST_EAST },
    { NORTH_SOUTH_IMPL,                             PointerStyle::key_t::NORTH_SOUTH },
    { NORTH_EAST_IMPL,                              PointerStyle::key_t::NORTH_EAST },
    { SOUTH_EAST_IMPL,                              PointerStyle::key_t::SOUTH_EAST },
    { SOUTH_WEST_IMPL,                              PointerStyle::key_t::SOUTH_WEST },
    { NORTH_EAST_SOUTH_WEST_IMPL,                   PointerStyle::key_t::NORTH_EAST_SOUTH_WEST },
    { NORTH_WEST_SOUTH_EAST_IMPL,                   PointerStyle::key_t::NORTH_WEST_SOUTH_EAST },
    { CROSS_IMPL,                                   PointerStyle::key_t::CROSS },
    { CURSOR_COPY_IMPL,                             PointerStyle::key_t::CURSOR_COPY },
    { CURSOR_FORBID_IMPL,                           PointerStyle::key_t::CURSOR_FORBID },
    { COLOR_SUCKER_IMPL,                            PointerStyle::key_t::COLOR_SUCKER },
    { HAND_GRABBING_IMPL,                           PointerStyle::key_t::HAND_GRABBING },
    { HAND_OPEN_IMPL,                               PointerStyle::key_t::HAND_OPEN },
    { HAND_POINTING_IMPL,                           PointerStyle::key_t::HAND_POINTING },
    { HELP_IMPL,                                    PointerStyle::key_t::HELP },
    { MOVE_IMPL,                                    PointerStyle::key_t::MOVE },
    { RESIZE_LEFT_RIGHT_IMPL,                       PointerStyle::key_t::RESIZE_LEFT_RIGHT },
    { RESIZE_UP_DOWN_IMPL,                          PointerStyle::key_t::RESIZE_UP_DOWN },
    { SCREENSHOT_CHOOSE_IMPL,                       PointerStyle::key_t::SCREENSHOT_CHOOSE },
    { SCREENSHOT_CURSOR_IMPL,                       PointerStyle::key_t::SCREENSHOT_CURSOR },
    { TEXT_CURSOR_IMPL,                             PointerStyle::key_t::TEXT_CURSOR },
    { ZOOM_IN_IMPL,                                 PointerStyle::key_t::ZOOM_IN },
    { ZOOM_OUT_IMPL,                                PointerStyle::key_t::ZOOM_OUT },
    { MOVE_IMPL,                                    PointerStyle::key_t::MOVE },
    { MIDDLE_BTN_EAST_IMPL,                         PointerStyle::key_t::MIDDLE_BTN_EAST },
    { MIDDLE_BTN_WEST_IMPL,                         PointerStyle::key_t::MIDDLE_BTN_WEST },
    { MIDDLE_BTN_SOUTH_IMPL,                        PointerStyle::key_t::MIDDLE_BTN_SOUTH },
    { MIDDLE_BTN_NORTH_IMPL,                        PointerStyle::key_t::MIDDLE_BTN_NORTH },
    { MIDDLE_BTN_NORTH_SOUTH_IMPL,                  PointerStyle::key_t::MIDDLE_BTN_NORTH_SOUTH },
    { MIDDLE_BTN_NORTH_EAST_IMPL,                   PointerStyle::key_t::MIDDLE_BTN_NORTH_EAST },
    { MIDDLE_BTN_NORTH_WEST_IMPL,                   PointerStyle::key_t::MIDDLE_BTN_NORTH_WEST },
    { MIDDLE_BTN_SOUTH_EAST_IMPL,                   PointerStyle::key_t::MIDDLE_BTN_SOUTH_EAST },
    { MIDDLE_BTN_SOUTH_WEST_IMPL,                   PointerStyle::key_t::MIDDLE_BTN_SOUTH_WEST },
    { MIDDLE_BTN_NORTH_SOUTH_WEST_EAST_IMPL,        PointerStyle::key_t::MIDDLE_BTN_NORTH_SOUTH_WEST_EAST },
    { HORIZONTAL_TEXT_CURSOR_IMPL,                  PointerStyle::key_t::HORIZONTAL_TEXT_CURSOR },
    { CURSOR_CROSS_IMPL,                            PointerStyle::key_t::CURSOR_CROSS },
    { CURSOR_CIRCLE_IMPL,                           PointerStyle::key_t::CURSOR_CIRCLE },
    { LOADING_IMPL,                                 PointerStyle::key_t::LOADING },
    { RUNNING_IMPL,                                 PointerStyle::key_t::RUNNING },
    { MIDDLE_BTN_EAST_WEST_IMPL,                    PointerStyle::key_t::MIDDLE_BTN_EAST_WEST },
};

PointerStyle ConvertPointerStyle(int32_t pointerStyle)
{
    auto iter = POINTER_STYLE_TRANSFORMATION.find(pointerStyle);
    if (iter == POINTER_STYLE_TRANSFORMATION.end()) {
        MMI_HILOGE("Find failed, pointerStyle:%{public}d", pointerStyle);
        return PointerStyle::key_t::DEFAULT;
    }
    return iter->second;
}

void SetPointerStyleAsync(int32_t windowId, PointerStyle pointerStyle)
{
    OHOS::MMI::PointerStyle style;
    style.id = pointerStyle;
    int32_t ret = OHOS::MMI::InputManager::GetInstance()->SetPointerStyle(windowId, style);
    if (ret == COMMON_PARAMETER_ERROR) {
        taihe::set_business_error(ret, "failed to get default SetPointerStyle!");
        MMI_HILOGE("failed to get default SetPointerStyle!");
    }
}

void SetPointerVisibleSync(bool visible)
{
    int32_t ret = OHOS::MMI::InputManager::GetInstance()->SetPointerVisible(visible);
    if (ret == COMMON_PARAMETER_ERROR) {
        taihe::set_business_error(ret, "failed to get default SetPointerVisible!");
        MMI_HILOGE("failed to get default SetPointerVisible!");
    }
}

PointerStyle GetPointerStyleSync(int32_t windowId)
{
    OHOS::MMI::PointerStyle pointerStyle;
    int32_t ret = OHOS::MMI::InputManager::GetInstance()->GetPointerStyle(windowId, pointerStyle);
    if (ret == COMMON_PARAMETER_ERROR) {
        taihe::set_business_error(ret, "failed to get default GetPointerStyle!");
        MMI_HILOGE("failed to get default GetPointerStyle!");
            return PointerStyle::key_t::DEFAULT;
    }
        return ConvertPointerStyle(pointerStyle.id);
}

void SetPointerStyleSync(int32_t windowId, PointerStyle pointerStyle)
{
    OHOS::MMI::PointerStyle style;
    style.id = pointerStyle;
    int32_t ret = OHOS::MMI::InputManager::GetInstance()->GetInstance()->SetPointerStyle(windowId, style);
    if (ret == COMMON_PARAMETER_ERROR) {
        taihe::set_business_error(ret, "failed to get default SetPointerStyle!");
        MMI_HILOGE("failed to get default SetPointerStyle!");
    }
}
} // namespace

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_SetPointerStyleAsync(SetPointerStyleAsync);
TH_EXPORT_CPP_API_SetPointerVisibleSync(SetPointerVisibleSync);
TH_EXPORT_CPP_API_GetPointerStyleSync(GetPointerStyleSync);
TH_EXPORT_CPP_API_SetPointerStyleSync(SetPointerStyleSync);
// NOLINTEND