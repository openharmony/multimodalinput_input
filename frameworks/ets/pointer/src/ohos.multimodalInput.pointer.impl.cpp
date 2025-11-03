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
#include "mmi_log.h"

#include "taihe_pointer_utils.h"
#include "input_manager.h"
#include "struct_multimodal.h"
#include "pixel_map_taihe_ani.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "ohos.multimodalInput.pointer"

using namespace taihe;
using namespace OHOS::MMI;
using namespace ohos::multimodalInput::pointer;
using TaihePointerStyle = ohos::multimodalInput::pointer::PointerStyle;

namespace {
constexpr int32_t MAX_SPEED { 20 };
constexpr int32_t MIN_SPEED { 1 };
constexpr int32_t MIN_POINTER_SIZE { 1 };
constexpr int32_t MAX_POINTER_SIZE { 7 };
constexpr int32_t MIN_ROWS { 1 };
constexpr int32_t MAX_ROWS { 100 };
constexpr int32_t INVALID_VALUE { -2 };
constexpr int32_t MAX_PIXELMAP_SIZE { 256 };

const static std::map<int32_t, TaihePointerStyle> POINTER_STYLE_TRANSFORMATION = {
    { DEFAULT_IMPL,                                 TaihePointerStyle::key_t::DEFAULT },
    { EAST_IMPL,                                    TaihePointerStyle::key_t::EAST },
    { WEST_IMPL,                                    TaihePointerStyle::key_t::WEST },
    { SOUTH_IMPL,                                   TaihePointerStyle::key_t::SOUTH },
    { NORTH_IMPL,                                   TaihePointerStyle::key_t::NORTH },
    { WEST_EAST_IMPL,                               TaihePointerStyle::key_t::WEST_EAST },
    { NORTH_SOUTH_IMPL,                             TaihePointerStyle::key_t::NORTH_SOUTH },
    { NORTH_EAST_IMPL,                              TaihePointerStyle::key_t::NORTH_EAST },
    { SOUTH_EAST_IMPL,                              TaihePointerStyle::key_t::SOUTH_EAST },
    { SOUTH_WEST_IMPL,                              TaihePointerStyle::key_t::SOUTH_WEST },
    { NORTH_EAST_SOUTH_WEST_IMPL,                   TaihePointerStyle::key_t::NORTH_EAST_SOUTH_WEST },
    { NORTH_WEST_SOUTH_EAST_IMPL,                   TaihePointerStyle::key_t::NORTH_WEST_SOUTH_EAST },
    { CROSS_IMPL,                                   TaihePointerStyle::key_t::CROSS },
    { CURSOR_COPY_IMPL,                             TaihePointerStyle::key_t::CURSOR_COPY },
    { CURSOR_FORBID_IMPL,                           TaihePointerStyle::key_t::CURSOR_FORBID },
    { COLOR_SUCKER_IMPL,                            TaihePointerStyle::key_t::COLOR_SUCKER },
    { HAND_GRABBING_IMPL,                           TaihePointerStyle::key_t::HAND_GRABBING },
    { HAND_OPEN_IMPL,                               TaihePointerStyle::key_t::HAND_OPEN },
    { HAND_POINTING_IMPL,                           TaihePointerStyle::key_t::HAND_POINTING },
    { HELP_IMPL,                                    TaihePointerStyle::key_t::HELP },
    { MOVE_IMPL,                                    TaihePointerStyle::key_t::MOVE },
    { RESIZE_LEFT_RIGHT_IMPL,                       TaihePointerStyle::key_t::RESIZE_LEFT_RIGHT },
    { RESIZE_UP_DOWN_IMPL,                          TaihePointerStyle::key_t::RESIZE_UP_DOWN },
    { SCREENSHOT_CHOOSE_IMPL,                       TaihePointerStyle::key_t::SCREENSHOT_CHOOSE },
    { SCREENSHOT_CURSOR_IMPL,                       TaihePointerStyle::key_t::SCREENSHOT_CURSOR },
    { TEXT_CURSOR_IMPL,                             TaihePointerStyle::key_t::TEXT_CURSOR },
    { ZOOM_IN_IMPL,                                 TaihePointerStyle::key_t::ZOOM_IN },
    { ZOOM_OUT_IMPL,                                TaihePointerStyle::key_t::ZOOM_OUT },
    { MIDDLE_BTN_EAST_IMPL,                         TaihePointerStyle::key_t::MIDDLE_BTN_EAST },
    { MIDDLE_BTN_WEST_IMPL,                         TaihePointerStyle::key_t::MIDDLE_BTN_WEST },
    { MIDDLE_BTN_SOUTH_IMPL,                        TaihePointerStyle::key_t::MIDDLE_BTN_SOUTH },
    { MIDDLE_BTN_NORTH_IMPL,                        TaihePointerStyle::key_t::MIDDLE_BTN_NORTH },
    { MIDDLE_BTN_NORTH_SOUTH_IMPL,                  TaihePointerStyle::key_t::MIDDLE_BTN_NORTH_SOUTH },
    { MIDDLE_BTN_NORTH_EAST_IMPL,                   TaihePointerStyle::key_t::MIDDLE_BTN_NORTH_EAST },
    { MIDDLE_BTN_NORTH_WEST_IMPL,                   TaihePointerStyle::key_t::MIDDLE_BTN_NORTH_WEST },
    { MIDDLE_BTN_SOUTH_EAST_IMPL,                   TaihePointerStyle::key_t::MIDDLE_BTN_SOUTH_EAST },
    { MIDDLE_BTN_SOUTH_WEST_IMPL,                   TaihePointerStyle::key_t::MIDDLE_BTN_SOUTH_WEST },
    { MIDDLE_BTN_NORTH_SOUTH_WEST_EAST_IMPL,        TaihePointerStyle::key_t::MIDDLE_BTN_NORTH_SOUTH_WEST_EAST },
    { HORIZONTAL_TEXT_CURSOR_IMPL,                  TaihePointerStyle::key_t::HORIZONTAL_TEXT_CURSOR },
    { CURSOR_CROSS_IMPL,                            TaihePointerStyle::key_t::CURSOR_CROSS },
    { CURSOR_CIRCLE_IMPL,                           TaihePointerStyle::key_t::CURSOR_CIRCLE },
    { LOADING_IMPL,                                 TaihePointerStyle::key_t::LOADING },
    { RUNNING_IMPL,                                 TaihePointerStyle::key_t::RUNNING },
    { MIDDLE_BTN_EAST_WEST_IMPL,                    TaihePointerStyle::key_t::MIDDLE_BTN_EAST_WEST },
};

bool CheckCustomCursor(OHOS::MMI::CustomCursor &cursor)
{
    if (cursor.pixelMap == nullptr) {
        MMI_HILOGE("pixelMap is invalid");
        return false;
    }
    OHOS::Media::PixelMap* newPixelMap = static_cast<OHOS::Media::PixelMap*>(cursor.pixelMap);
    if (newPixelMap == nullptr) {
        MMI_HILOGE("newPixelMap is invalid");
        return false;
    }
    if (newPixelMap->GetWidth() > MAX_PIXELMAP_SIZE || newPixelMap->GetHeight() > MAX_PIXELMAP_SIZE) {
        return false;
    }
    if (cursor.focusX < 0 || cursor.focusX > newPixelMap->GetWidth()) {
        return false;
    }
    if (cursor.focusY < 0 || cursor.focusY > newPixelMap->GetHeight()) {
        return false;
    }
    return true;
}

TaihePointerStyle ConvertPointerStyle(int32_t pointerStyle)
{
    auto iter = POINTER_STYLE_TRANSFORMATION.find(pointerStyle);
    if (iter == POINTER_STYLE_TRANSFORMATION.end()) {
        MMI_HILOGE("Find failed, pointerStyle:%{public}d", pointerStyle);
        return TaihePointerStyle::key_t::DEFAULT;
    }
    return iter->second;
}

void SetPointerStyleAsync(int32_t windowId, TaihePointerStyle pointerStyle)
{
    OHOS::MMI::PointerStyle style;
    style.id = pointerStyle;
    int32_t ret = OHOS::MMI::InputManager::GetInstance()->SetPointerStyle(windowId, style);
    if (ret == COMMON_PARAMETER_ERROR) {
        taihe::set_business_error(ret, "failed to get default SetPointerStyle!");
        MMI_HILOGE("failed to get default SetPointerStyle!");
    } else if (ret != RET_OK) {
        MMI_HILOGE("SetPointerStyleAsync failed");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error.");
    }
}

void SetPointerVisibleSync(bool visible)
{
    int32_t ret = OHOS::MMI::InputManager::GetInstance()->SetPointerVisible(visible);
    if (ret == COMMON_PARAMETER_ERROR) {
        taihe::set_business_error(ret, "failed to get default SetPointerVisible!");
        MMI_HILOGE("failed to get default SetPointerVisible!");
    } else if (ret != RET_OK) {
        MMI_HILOGE("SetPointerVisible failed");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error.");
    }
}

TaihePointerStyle GetPointerStyleSync(int32_t windowId)
{
    OHOS::MMI::PointerStyle pointerStyle;
    if (windowId < 0 && windowId != OHOS::MMI::GLOBAL_WINDOW_ID) {
        MMI_HILOGE("Invalid windowId");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "windowId is invalid");
        return TaihePointerStyle::key_t::DEFAULT;
    }
    int32_t ret = OHOS::MMI::InputManager::GetInstance()->GetPointerStyle(windowId, pointerStyle);
    if (ret == COMMON_PARAMETER_ERROR) {
        taihe::set_business_error(ret, "failed to get default GetPointerStyle!");
        MMI_HILOGE("failed to get default GetPointerStyle!");
        return TaihePointerStyle::key_t::DEFAULT;
    } else if (ret != RET_OK) {
        MMI_HILOGE("GetPointerStyle failed");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error.");
        return TaihePointerStyle::key_t::DEFAULT;
    }
    return ConvertPointerStyle(pointerStyle.id);
}

void SetPointerStyleSync(int32_t windowId, TaihePointerStyle pointerStyle)
{
    OHOS::MMI::PointerStyle style;
    style.id = pointerStyle;
    int32_t ret = OHOS::MMI::InputManager::GetInstance()->SetPointerStyle(windowId, style);
    if (ret == COMMON_PARAMETER_ERROR) {
        taihe::set_business_error(ret, "failed to get default SetPointerStyle!");
        MMI_HILOGE("failed to get default SetPointerStyle!");
    } else if (ret != RET_OK) {
        MMI_HILOGE("SetPointerStyle failed");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error.");
    }
}

void SetPointerVisibleAsync(bool visible)
{
    CALL_DEBUG_ENTER;
    auto errorCode = InputManager::GetInstance()->SetPointerVisible(visible);
    if (errorCode == COMMON_PARAMETER_ERROR) {
        MMI_HILOGE("failed to SetPointerVisible!");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "failed to SetPointerVisible!");
    } else if (errorCode != RET_OK) {
        MMI_HILOGE("SetPointerVisible failed");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error.");
    }
}

void SetPointerSpeedAsync(int32_t speed)
{
    CALL_DEBUG_ENTER;
    if (speed < MIN_SPEED) {
        speed = MIN_SPEED;
    } else if (speed > MAX_SPEED) {
        speed = MAX_SPEED;
    }
    auto errorCode = InputManager::GetInstance()->SetPointerSpeed(speed);
    if (errorCode == COMMON_PARAMETER_ERROR) {
        MMI_HILOGE("failed to SetPointerSpeed!");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "failed to SetPointerSpeed!");
    } else if (errorCode != RET_OK) {
        MMI_HILOGE("SetPointerSpeed failed");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error.");
    }
}

int32_t GetPointerSpeedAsync()
{
    CALL_DEBUG_ENTER;
    int32_t pointerSpeed = 0;
    auto errorCode = InputManager::GetInstance()->GetPointerSpeed(pointerSpeed);
    if (errorCode == COMMON_PARAMETER_ERROR) {
        MMI_HILOGE("failed to GetPointerSpeed!");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "failed to GetPointerSpeed!");
    } else if (errorCode != RET_OK) {
        MMI_HILOGE("GetPointerSpeed failed");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error.");
    }
    return pointerSpeed;
}

bool IsPointerVisibleAsync()
{
    CALL_DEBUG_ENTER;
    bool visible = InputManager::GetInstance()->IsPointerVisible();
    return visible;
}

TaihePointerStyle GetPointerStyleAsync(int32_t windowId)
{
    CALL_DEBUG_ENTER;
    if (windowId < 0 && windowId != OHOS::MMI::GLOBAL_WINDOW_ID) {
        MMI_HILOGE("Invalid windowid");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Windowid is invalid");
        return TaihePointerStyle::key_t::DEFAULT;
    }
    OHOS::MMI::PointerStyle pointerStyle;
    auto errorCode = InputManager::GetInstance()->GetPointerStyle(windowId, pointerStyle);
    if (errorCode == COMMON_USE_SYSAPI_ERROR) {
        MMI_HILOGE("WindowId is negative number and no system applications use system API");
        taihe::set_business_error(COMMON_USE_SYSAPI_ERROR,
            "WindowId is negative number and no system applications use system API");
        return TaihePointerStyle::key_t::DEFAULT;
    } else if (errorCode != RET_OK) {
        MMI_HILOGE("GetPointerStyle failed");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error.");
        return TaihePointerStyle::key_t::DEFAULT;
    }
    return ConvertPointerStyle(pointerStyle.id);
}

bool GetTouchpadDoubleTapAndDragStateAsync()
{
    CALL_DEBUG_ENTER;
    bool switchFlag = true;
    auto errorCode = InputManager::GetInstance()->GetTouchpadDoubleTapAndDragState(switchFlag);
    if (errorCode == COMMON_USE_SYSAPI_ERROR) {
        MMI_HILOGE("Non system applications use system API");
        taihe::set_business_error(COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
    } else if (errorCode != RET_OK) {
        MMI_HILOGE("GetTouchpadDoubleTapAndDragState failed");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error.");
    }
    return switchFlag;
}

void SetTouchpadDoubleTapAndDragStateAsync(bool isOpen)
{
    CALL_DEBUG_ENTER;
    auto errorCode = InputManager::GetInstance()->SetTouchpadDoubleTapAndDragState(isOpen);
    if (errorCode == COMMON_USE_SYSAPI_ERROR) {
        MMI_HILOGE("Non system applications use system API");
        taihe::set_business_error(COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
    } else if (errorCode != RET_OK) {
        MMI_HILOGE("SetTouchpadDoubleTapAndDragState failed");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error.");
    }
}

void SetCustomCursorSync(int32_t windowId, uintptr_t pixelMap,
    ::taihe::optional_view<int32_t> focusX, ::taihe::optional_view<int32_t> focusY)
{
    CALL_DEBUG_ENTER;
    if (windowId < 0) {
        MMI_HILOGE("Invalid windowsId");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "windowId is invalid");
        return;
    }
    ani_object object = reinterpret_cast<ani_object>(pixelMap);
    auto newPixelMap = OHOS::Media::PixelMapTaiheAni::GetNativePixelMap(taihe::get_env(), object);
    if (newPixelMap == nullptr) {
        MMI_HILOGE("Get pixelMap failed");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "pixelMap is invalid");
        return;
    }
    CursorFocus cursorFocus;
    cursorFocus.x = focusX.has_value() ? focusX.value() : 0;
    cursorFocus.y = focusY.has_value() ? focusY.value() : 0;
    if ((cursorFocus.x == INVALID_VALUE) || (cursorFocus.y == INVALID_VALUE)) {
        MMI_HILOGE("focusX or focusY is invalid");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "focusX or focusY is invalid");
        return;
    }
    InputManager::GetInstance()->SetCustomCursor(windowId,
        (void *)newPixelMap.get(), cursorFocus.x, cursorFocus.y);
}

void SetCustomCursorPixelMapAsync(int32_t windowId, uintptr_t pixelMap,
    ::taihe::optional_view<int32_t> focusX, ::taihe::optional_view<int32_t> focusY)
{
    CALL_DEBUG_ENTER;
    if (windowId < 0) {
        MMI_HILOGE("Invalid windowsId");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "windowId is invalid");
        return;
    }
    ani_object object = reinterpret_cast<ani_object>(pixelMap);
    auto newPixelMap = OHOS::Media::PixelMapTaiheAni::GetNativePixelMap(taihe::get_env(), object);
    if (newPixelMap == nullptr) {
        MMI_HILOGE("Get pixelMap failed");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "pixelMap is invalid");
        return;
    }
    CursorFocus cursorFocus;
    cursorFocus.x = focusX.has_value() ? focusX.value() : 0;
    cursorFocus.y = focusY.has_value() ? focusY.value() : 0;
    if ((cursorFocus.x == INVALID_VALUE) || (cursorFocus.y == INVALID_VALUE)) {
        MMI_HILOGE("focusX or focusY is invalid");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "focusX or focusY is invalid");
        return;
    }
    auto errorCode = InputManager::GetInstance()->SetCustomCursor(windowId,
        (void *)newPixelMap.get(), cursorFocus.x, cursorFocus.y);
    if (errorCode == COMMON_USE_SYSAPI_ERROR) {
        MMI_HILOGE("SetCustomCursor is failed");
        taihe::set_business_error(COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
    } else if (errorCode != RET_OK) {
        MMI_HILOGE("SetCustomCursor failed");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error.");
    }
}

void SetCustomCursorAsync(int32_t windowId, ::ohos::multimodalInput::pointer::CustomCursor const& cursor,
    ::ohos::multimodalInput::pointer::CursorConfig const& config)
{
    CALL_DEBUG_ENTER;
    if (windowId < 0) {
        MMI_HILOGE("Invalid windowsId");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "windowId is invalid");
        return;
    }
    auto newCursor = TaihePointerUtils::ConverterToCustomCursor(cursor);
    if (!CheckCustomCursor(newCursor)) {
        MMI_HILOGE("cursor is invalid");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "cursor is invalid");
        return;
    }
    auto options = TaihePointerUtils::ConverterToCursorConfig(config);
    auto errorCode = InputManager::GetInstance()->SetCustomCursor(windowId, newCursor, options);
    if (errorCode != RET_OK) {
        TaiheError codeMsg;
        if (!TaiheConverter::GetApiError(errorCode, codeMsg)) {
            MMI_HILOGE("Error code %{public}d not found", errorCode);
            return;
        }
        taihe::set_business_error(errorCode, codeMsg.msg);
    }
}

int32_t GetPointerSpeedSync()
{
    CALL_DEBUG_ENTER;
    int32_t pointerSpeed = 0;
    InputManager::GetInstance()->GetPointerSpeed(pointerSpeed);
    return pointerSpeed;
}

::ohos::multimodalInput::pointer::RightClickType GetTouchpadRightClickTypeAsync()
{
    CALL_DEBUG_ENTER;
    int32_t type = 1;
    auto errorCode = InputManager::GetInstance()->GetTouchpadRightClickType(type);
    ohos::multimodalInput::pointer::RightClickType clickType =
        static_cast<ohos::multimodalInput::pointer::RightClickType::key_t>(type);
    if (errorCode == COMMON_USE_SYSAPI_ERROR) {
        MMI_HILOGE("Non system applications use system API");
        taihe::set_business_error(COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
    } else if (errorCode != RET_OK) {
        MMI_HILOGE("GetTouchpadRightClickType failed");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error.");
    }
    return clickType;
}

void SetTouchpadRightClickTypeAsync(::ohos::multimodalInput::pointer::RightClickType type)
{
    CALL_DEBUG_ENTER;
    int32_t clickType = static_cast<int32_t>(type);
    auto errorCode = InputManager::GetInstance()->SetTouchpadRightClickType(clickType);
    if (errorCode == COMMON_USE_SYSAPI_ERROR) {
        MMI_HILOGE("Non system applications use system API");
        taihe::set_business_error(COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
    } else if (errorCode != RET_OK) {
        MMI_HILOGE("SetTouchpadRightClickType failed");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error.");
    }
}

bool GetTouchpadSwipeSwitchAsync()
{
    CALL_DEBUG_ENTER;
    bool switchFlag = true;
    auto errorCode = InputManager::GetInstance()->GetTouchpadSwipeSwitch(switchFlag);
    if (errorCode == COMMON_USE_SYSAPI_ERROR) {
        MMI_HILOGE("Non system applications use system API");
        taihe::set_business_error(COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
    } else if (errorCode != RET_OK) {
        MMI_HILOGE("GetTouchpadSwipeSwitch failed");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error.");
    }
    return switchFlag;
}

void SetTouchpadSwipeSwitchAsync(bool state)
{
    CALL_DEBUG_ENTER;
    auto errorCode = InputManager::GetInstance()->SetTouchpadSwipeSwitch(state);
    if (errorCode == COMMON_USE_SYSAPI_ERROR) {
        MMI_HILOGE("Non system applications use system API");
        taihe::set_business_error(COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
    } else if (errorCode != RET_OK) {
        MMI_HILOGE("SetTouchpadSwipeSwitch failed");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error.");
    }
}

bool GetTouchpadPinchSwitchAsync()
{
    CALL_DEBUG_ENTER;
    bool switchFlag = true;
    auto errorCode = InputManager::GetInstance()->GetTouchpadPinchSwitch(switchFlag);
    if (errorCode == COMMON_USE_SYSAPI_ERROR) {
        MMI_HILOGE("Non system applications use system API");
        taihe::set_business_error(COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
    } else if (errorCode != RET_OK) {
        MMI_HILOGE("GetTouchpadPinchSwitch failed");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error.");
    }
    return switchFlag;
}

void SetTouchpadPinchSwitchAsync(bool state)
{
    CALL_DEBUG_ENTER;
    auto errorCode = InputManager::GetInstance()->SetTouchpadPinchSwitch(state);
    if (errorCode == COMMON_USE_SYSAPI_ERROR) {
        MMI_HILOGE("Non system applications use system API");
        taihe::set_business_error(COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
    } else if (errorCode != RET_OK) {
        MMI_HILOGE("SetTouchpadPinchSwitch failed");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error.");
    }
}

int32_t GetTouchpadPointerSpeedAsync()
{
    CALL_DEBUG_ENTER;
    int32_t speed = 0;
    auto errorCode = InputManager::GetInstance()->GetTouchpadPointerSpeed(speed);
    if (errorCode == COMMON_USE_SYSAPI_ERROR) {
        MMI_HILOGE("Non system applications use system API");
        taihe::set_business_error(COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
    } else if (errorCode != RET_OK) {
        MMI_HILOGE("GetTouchpadPointerSpeed failed");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error.");
    }
    return speed;
}

void SetTouchpadPointerSpeedAsync(int32_t speed)
{
    CALL_DEBUG_ENTER;
    auto errorCode = InputManager::GetInstance()->SetTouchpadPointerSpeed(speed);
    if (errorCode == COMMON_USE_SYSAPI_ERROR) {
        MMI_HILOGE("Non system applications use system API");
        taihe::set_business_error(COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
    } else if (errorCode != RET_OK) {
        MMI_HILOGE("SetTouchpadPointerSpeed failed");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error.");
    }
}

bool GetTouchpadTapSwitchAsync()
{
    CALL_DEBUG_ENTER;
    bool switchFlag = true;
    auto errorCode = InputManager::GetInstance()->GetTouchpadTapSwitch(switchFlag);
    if (errorCode == COMMON_USE_SYSAPI_ERROR) {
        MMI_HILOGE("Non system applications use system API");
        taihe::set_business_error(COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
    } else if (errorCode != RET_OK) {
        MMI_HILOGE("GetTouchpadTapSwitch failed");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error.");
    }
    return switchFlag;
}

void SetTouchpadTapSwitchAsync(bool state)
{
    CALL_DEBUG_ENTER;
    auto errorCode = InputManager::GetInstance()->SetTouchpadTapSwitch(state);
    if (errorCode == COMMON_USE_SYSAPI_ERROR) {
        MMI_HILOGE("Non system applications use system API");
        taihe::set_business_error(COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
    } else if (errorCode != RET_OK) {
        MMI_HILOGE("SetTouchpadTapSwitch failed");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error.");
    }
}

bool GetTouchpadScrollDirectionAsync()
{
    CALL_DEBUG_ENTER;
    bool state = true;
    auto errorCode = InputManager::GetInstance()->GetTouchpadScrollDirection(state);
    if (errorCode == COMMON_USE_SYSAPI_ERROR) {
        MMI_HILOGE("Non system applications use system API");
        taihe::set_business_error(COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
    } else if (errorCode != RET_OK) {
        MMI_HILOGE("GetTouchpadScrollDirection failed");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error.");
    }
    return state;
}

void SetTouchpadScrollDirectionAsync(bool state)
{
    CALL_DEBUG_ENTER;
    auto errorCode = InputManager::GetInstance()->SetTouchpadScrollDirection(state);
    if (errorCode == COMMON_USE_SYSAPI_ERROR) {
        MMI_HILOGE("Non system applications use system API");
        taihe::set_business_error(COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
    } else if (errorCode != RET_OK) {
        MMI_HILOGE("SetTouchpadScrollDirection failed");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error.");
    }
}

bool GetTouchpadScrollSwitchAsync()
{
    CALL_DEBUG_ENTER;
    bool switchFlag = true;
    auto errorCode = InputManager::GetInstance()->GetTouchpadScrollSwitch(switchFlag);
    if (errorCode == COMMON_USE_SYSAPI_ERROR) {
        MMI_HILOGE("Non system applications use system API");
        taihe::set_business_error(COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
    } else if (errorCode != RET_OK) {
        MMI_HILOGE("GetTouchpadScrollSwitch failed");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error.");
    }
    return switchFlag;
}

void SetTouchpadScrollSwitchAsync(bool state)
{
    CALL_DEBUG_ENTER;
    auto errorCode = InputManager::GetInstance()->SetTouchpadScrollSwitch(state);
    if (errorCode == COMMON_USE_SYSAPI_ERROR) {
        MMI_HILOGE("Non system applications use system API");
        taihe::set_business_error(COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
    } else if (errorCode != RET_OK) {
        MMI_HILOGE("SetTouchpadScrollSwitch failed");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error.");
    }
}

int32_t GetMouseScrollRowsAsync()
{
    CALL_DEBUG_ENTER;
    int32_t rows = 3;
    auto errorCode = InputManager::GetInstance()->GetMouseScrollRows(rows);
    if (errorCode == COMMON_USE_SYSAPI_ERROR) {
        MMI_HILOGE("Non system applications use system API");
        taihe::set_business_error(COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
    } else if (errorCode != RET_OK) {
        MMI_HILOGE("GetMouseScrollRows failed");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error.");
    }
    return rows;
}

void SetMouseScrollRowsAsync(int32_t rows)
{
    CALL_DEBUG_ENTER;
    if (rows < MIN_ROWS) {
        rows = MIN_ROWS;
    } else if (rows > MAX_ROWS) {
        rows = MAX_ROWS;
    }
    auto errorCode = InputManager::GetInstance()->SetMouseScrollRows(rows);
    if (errorCode == COMMON_USE_SYSAPI_ERROR) {
        MMI_HILOGE("Non system applications use system API");
        taihe::set_business_error(COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
    } else if (errorCode != RET_OK) {
        MMI_HILOGE("SetMouseScrollRows failed");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error.");
    }
}

bool GetHoverScrollStateAsync()
{
    CALL_DEBUG_ENTER;
    bool state = false;
    auto errorCode = InputManager::GetInstance()->GetHoverScrollState(state);
    if (errorCode == COMMON_USE_SYSAPI_ERROR) {
        MMI_HILOGE("Non system applications use system API");
        taihe::set_business_error(COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
    } else if (errorCode != RET_OK) {
        MMI_HILOGE("GetHoverScrollState failed");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error.");
    }
    return state;
}

void SetHoverScrollStateAsync(bool state)
{
    CALL_DEBUG_ENTER;
    auto errorCode = InputManager::GetInstance()->SetHoverScrollState(state);
    if (errorCode == COMMON_USE_SYSAPI_ERROR) {
        MMI_HILOGE("Non system applications use system API");
        taihe::set_business_error(COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
    } else if (errorCode != RET_OK) {
        MMI_HILOGE("SetHoverScrollState failed");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error.");
    }
}

::ohos::multimodalInput::pointer::PrimaryButton GetMousePrimaryButtonAsync()
{
    CALL_DEBUG_ENTER;
    int32_t primaryButton = 0;
    auto errorCode = InputManager::GetInstance()->GetMousePrimaryButton(primaryButton);
    ohos::multimodalInput::pointer::PrimaryButton button =
        static_cast<ohos::multimodalInput::pointer::PrimaryButton::key_t>(primaryButton);
    if (errorCode == COMMON_USE_SYSAPI_ERROR) {
        MMI_HILOGE("Non system applications use system API");
        taihe::set_business_error(COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
    } else if (errorCode != RET_OK) {
        MMI_HILOGE("GetMousePrimaryButton failed");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error.");
    }
    return button;
}

void SetMousePrimaryButtonAsync(::ohos::multimodalInput::pointer::PrimaryButton primary)
{
    CALL_DEBUG_ENTER;
    int32_t primaryButton = static_cast<int32_t>(primary);
    if (primaryButton < LEFT_BUTTON || primaryButton > RIGHT_BUTTON) {
        MMI_HILOGE("Undefined mouse primary button");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Mouse primary button does not exist");
        return;
    }
    auto errorCode = InputManager::GetInstance()->SetMousePrimaryButton(primaryButton);
    if (errorCode == COMMON_USE_SYSAPI_ERROR) {
        MMI_HILOGE("Non system applications use system API");
        taihe::set_business_error(COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
    } else if (errorCode != RET_OK) {
        MMI_HILOGE("SetMousePrimaryButton failed");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error.");
    }
}

int32_t GetPointerSizeAsync()
{
    CALL_DEBUG_ENTER;
    int32_t size = 1;
    auto errorCode = InputManager::GetInstance()->GetPointerSize(size);
    if (errorCode == COMMON_USE_SYSAPI_ERROR) {
        MMI_HILOGE("Non system applications use system API");
        taihe::set_business_error(COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
    } else if (errorCode != RET_OK) {
        MMI_HILOGE("GetPointerSize failed");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error.");
    }
    return size;
}

void SetPointerSizeSync(int32_t size)
{
    CALL_DEBUG_ENTER;
    if (size < MIN_POINTER_SIZE) {
        size = MIN_POINTER_SIZE;
    } else if (size > MAX_POINTER_SIZE) {
        size = MAX_POINTER_SIZE;
    }
    auto errorCode = InputManager::GetInstance()->SetPointerSize(size);
    if (errorCode == COMMON_USE_SYSAPI_ERROR) {
        MMI_HILOGE("Non system applications use system API");
        taihe::set_business_error(COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
    } else if (errorCode != RET_OK) {
        MMI_HILOGE("SetPointerSizeSync failed");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error.");
    }
}

void SetPointerSizeAsync(int32_t size)
{
    CALL_DEBUG_ENTER;
    if (size < MIN_POINTER_SIZE) {
        size = MIN_POINTER_SIZE;
    } else if (size > MAX_POINTER_SIZE) {
        size = MAX_POINTER_SIZE;
    }
    auto errorCode = InputManager::GetInstance()->SetPointerSize(size);
    if (errorCode == COMMON_USE_SYSAPI_ERROR) {
        MMI_HILOGE("Non system applications use system API");
        taihe::set_business_error(COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
    } else if (errorCode != RET_OK) {
        MMI_HILOGE("SetPointerSize failed");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error.");
    }
}

int32_t GetPointerColorAsync()
{
    CALL_DEBUG_ENTER;
    int32_t color = 1;
    auto errorCode = InputManager::GetInstance()->GetPointerColor(color);
    if (errorCode == COMMON_USE_SYSAPI_ERROR) {
        MMI_HILOGE("Non system applications use system API");
        taihe::set_business_error(COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
    } else if (errorCode != RET_OK) {
        MMI_HILOGE("GetPointerColor failed");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error.");
    }
    return color;
}

void SetPointerColorSync(int32_t color)
{
    CALL_DEBUG_ENTER;
    auto errorCode = InputManager::GetInstance()->SetPointerColor(color);
    if (errorCode == COMMON_USE_SYSAPI_ERROR) {
        MMI_HILOGE("Non system applications use system API");
        taihe::set_business_error(COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
    } else if (errorCode != RET_OK) {
        MMI_HILOGE("SetPointerColorSync failed");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error.");
    }
}

void SetPointerColorAsync(int32_t color)
{
    CALL_DEBUG_ENTER;
    auto errorCode = InputManager::GetInstance()->SetPointerColor(color);
    if (errorCode == COMMON_USE_SYSAPI_ERROR) {
        MMI_HILOGE("Non system applications use system API");
        taihe::set_business_error(COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
    } else if (errorCode != RET_OK) {
        MMI_HILOGE("SetPointerColor failed");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error.");
    }
}

void SetPointerSpeedSync(int32_t speed)
{
    CALL_DEBUG_ENTER;
    if (speed < MIN_SPEED) {
        speed = MIN_SPEED;
    } else if (speed > MAX_SPEED) {
        speed = MAX_SPEED;
    }
    auto errorCode = InputManager::GetInstance()->SetPointerSpeed(speed);
    if (errorCode != RET_OK) {
        MMI_HILOGE("Non system applications use system API");
        TaiheError codeMsg;
        if (!TaiheConverter::GetApiError(errorCode, codeMsg)) {
            MMI_HILOGE("Error code %{public}d not found", errorCode);
        }
        taihe::set_business_error(errorCode, codeMsg.msg);
    }
}

bool IsPointerVisibleSync()
{
    CALL_DEBUG_ENTER;
    bool visible = InputManager::GetInstance()->IsPointerVisible();
    return visible;
}

int32_t GetPointerColorSync()
{
    CALL_DEBUG_ENTER;
    int32_t color = 1;
    auto errorCode = InputManager::GetInstance()->GetPointerColor(color);
    if (errorCode == COMMON_USE_SYSAPI_ERROR) {
        MMI_HILOGE("Non system applications use system API");
        taihe::set_business_error(COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
    } else if (errorCode != RET_OK) {
        MMI_HILOGE("GetPointerColor failed");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error.");
    }
    return color;
}

int32_t GetPointerSizeSync()
{
    CALL_DEBUG_ENTER;
    int32_t size = 1;
    auto errorCode = InputManager::GetInstance()->GetPointerSize(size);
    if (errorCode == COMMON_USE_SYSAPI_ERROR) {
        MMI_HILOGE("Non system applications use system API");
        taihe::set_business_error(COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
    } else if (errorCode != RET_OK) {
        MMI_HILOGE("GetPointerSize failed");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error.");
    }
    return size;
}
} // namespace

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_SetPointerStyleAsync(SetPointerStyleAsync);
TH_EXPORT_CPP_API_SetPointerVisibleSync(SetPointerVisibleSync);
TH_EXPORT_CPP_API_GetPointerStyleSync(GetPointerStyleSync);
TH_EXPORT_CPP_API_SetPointerStyleSync(SetPointerStyleSync);
TH_EXPORT_CPP_API_SetPointerVisibleAsync(SetPointerVisibleAsync);
TH_EXPORT_CPP_API_SetPointerSpeedAsync(SetPointerSpeedAsync);
TH_EXPORT_CPP_API_GetPointerSpeedAsync(GetPointerSpeedAsync);
TH_EXPORT_CPP_API_IsPointerVisibleAsync(IsPointerVisibleAsync);
TH_EXPORT_CPP_API_GetPointerStyleAsync(GetPointerStyleAsync);
TH_EXPORT_CPP_API_GetTouchpadDoubleTapAndDragStateAsync(GetTouchpadDoubleTapAndDragStateAsync);
TH_EXPORT_CPP_API_SetTouchpadDoubleTapAndDragStateAsync(SetTouchpadDoubleTapAndDragStateAsync);
TH_EXPORT_CPP_API_SetCustomCursorSync(SetCustomCursorSync);
TH_EXPORT_CPP_API_SetCustomCursorPixelMapAsync(SetCustomCursorPixelMapAsync);
TH_EXPORT_CPP_API_SetCustomCursorAsync(SetCustomCursorAsync);
TH_EXPORT_CPP_API_GetPointerSpeedSync(GetPointerSpeedSync);
TH_EXPORT_CPP_API_GetTouchpadRightClickTypeAsync(GetTouchpadRightClickTypeAsync);
TH_EXPORT_CPP_API_SetTouchpadRightClickTypeAsync(SetTouchpadRightClickTypeAsync);
TH_EXPORT_CPP_API_GetTouchpadSwipeSwitchAsync(GetTouchpadSwipeSwitchAsync);
TH_EXPORT_CPP_API_SetTouchpadSwipeSwitchAsync(SetTouchpadSwipeSwitchAsync);
TH_EXPORT_CPP_API_GetTouchpadPinchSwitchAsync(GetTouchpadPinchSwitchAsync);
TH_EXPORT_CPP_API_SetTouchpadPinchSwitchAsync(SetTouchpadPinchSwitchAsync);
TH_EXPORT_CPP_API_GetTouchpadPointerSpeedAsync(GetTouchpadPointerSpeedAsync);
TH_EXPORT_CPP_API_SetTouchpadPointerSpeedAsync(SetTouchpadPointerSpeedAsync);
TH_EXPORT_CPP_API_GetTouchpadTapSwitchAsync(GetTouchpadTapSwitchAsync);
TH_EXPORT_CPP_API_SetTouchpadTapSwitchAsync(SetTouchpadTapSwitchAsync);
TH_EXPORT_CPP_API_GetTouchpadScrollDirectionAsync(GetTouchpadScrollDirectionAsync);
TH_EXPORT_CPP_API_SetTouchpadScrollDirectionAsync(SetTouchpadScrollDirectionAsync);
TH_EXPORT_CPP_API_GetTouchpadScrollSwitchAsync(GetTouchpadScrollSwitchAsync);
TH_EXPORT_CPP_API_SetTouchpadScrollSwitchAsync(SetTouchpadScrollSwitchAsync);
TH_EXPORT_CPP_API_GetMouseScrollRowsAsync(GetMouseScrollRowsAsync);
TH_EXPORT_CPP_API_SetMouseScrollRowsAsync(SetMouseScrollRowsAsync);
TH_EXPORT_CPP_API_GetHoverScrollStateAsync(GetHoverScrollStateAsync);
TH_EXPORT_CPP_API_SetHoverScrollStateAsync(SetHoverScrollStateAsync);
TH_EXPORT_CPP_API_GetMousePrimaryButtonAsync(GetMousePrimaryButtonAsync);
TH_EXPORT_CPP_API_SetMousePrimaryButtonAsync(SetMousePrimaryButtonAsync);
TH_EXPORT_CPP_API_GetPointerSizeAsync(GetPointerSizeAsync);
TH_EXPORT_CPP_API_SetPointerSizeSync(SetPointerSizeSync);
TH_EXPORT_CPP_API_SetPointerSizeAsync(SetPointerSizeAsync);
TH_EXPORT_CPP_API_GetPointerColorAsync(GetPointerColorAsync);
TH_EXPORT_CPP_API_SetPointerColorSync(SetPointerColorSync);
TH_EXPORT_CPP_API_SetPointerColorAsync(SetPointerColorAsync);
TH_EXPORT_CPP_API_SetPointerSpeedSync(SetPointerSpeedSync);
TH_EXPORT_CPP_API_IsPointerVisibleSync(IsPointerVisibleSync);
TH_EXPORT_CPP_API_GetPointerColorSync(GetPointerColorSync);
TH_EXPORT_CPP_API_GetPointerSizeSync(GetPointerSizeSync);
// NOLINTEND