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

#include "mouse_preference_accessor.h"

#include "define_multimodal.h"
#include "i_input_windows_manager.h"
#include "i_preference_manager.h"
#include "setting_types.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "MousePreferenceAccessor"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t MIN_SPEED { 1 };
constexpr int32_t MAX_SPEED { 20 };
constexpr int32_t DEFAULT_SPEED { 10 };
constexpr int32_t MAX_TOUCHPAD_SPEED { 11 };
constexpr int32_t DEFAULT_TOUCHPAD_SPEED { 6 };
constexpr int32_t DEFAULT_ROWS { 3 };
constexpr int32_t MIN_ROWS { 1 };
constexpr int32_t MAX_ROWS { 100 };
constexpr int32_t RIGHT_CLICK_TYPE_MIN { 1 };
constexpr int32_t RIGHT_CLICK_TYPE_MAX { 5 };
} // namespace

int32_t MousePreferenceAccessor::SetMouseScrollRows(IInputServiceContext &env, int32_t userId, int32_t rows)
{
    CALL_DEBUG_ENTER;
    if (rows < MIN_ROWS) {
        rows = MIN_ROWS;
    } else if (rows > MAX_ROWS) {
        rows = MAX_ROWS;
    }
    if (PutConfigDataToDatabase(env, userId, MOUSE_KEY_SETTING, FIELD_MOUSE_SCROLL_ROWS, rows) != RET_OK) {
        MMI_HILOGE("Set mouse scroll rows failed, rows:%{public}d", rows);
        return RET_ERR;
    }
    return RET_OK;
}

int32_t MousePreferenceAccessor::GetMouseScrollRows(IInputServiceContext &env, int32_t userId)
{
    CALL_DEBUG_ENTER;
    int32_t rows = DEFAULT_ROWS;
    GetConfigDataFromDatabase(env, userId, MOUSE_KEY_SETTING, FIELD_MOUSE_SCROLL_ROWS, rows);
    return rows;
}

int32_t MousePreferenceAccessor::SetMousePrimaryButton(IInputServiceContext &env, int32_t userId, int32_t primaryButton)
{
    CALL_DEBUG_ENTER;
    MMI_HILOGD("Set mouse primary button:%{public}d", primaryButton);
    if (PutConfigDataToDatabase(env, userId, MOUSE_KEY_SETTING, FIELD_MOUSE_PRIMARY_BUTTON, primaryButton) != RET_OK) {
        MMI_HILOGE("Set mouse primary button failed, primaryButton:%{public}d", primaryButton);
        return RET_ERR;
    }
    return RET_OK;
}

int32_t MousePreferenceAccessor::GetMousePrimaryButton(IInputServiceContext &env, int32_t userId)
{
    CALL_DEBUG_ENTER;
    int32_t primaryButton = 0;
    GetConfigDataFromDatabase(env, userId, MOUSE_KEY_SETTING, FIELD_MOUSE_PRIMARY_BUTTON, primaryButton);
    return primaryButton;
}

int32_t MousePreferenceAccessor::SetPointerSpeed(IInputServiceContext &env, int32_t userId, int32_t speed)
{
    CALL_DEBUG_ENTER;
    if (speed < MIN_SPEED) {
        speed = MIN_SPEED;
    } else if (speed > MAX_SPEED) {
        speed = MAX_SPEED;
    }
    if (PutConfigDataToDatabase(env, userId, MOUSE_KEY_SETTING, FIELD_MOUSE_POINTER_SPEED, speed) != RET_OK) {
        MMI_HILOGE("SetPointerSpeed failed, speed:%{public}d", speed);
        return RET_ERR;
    }
    MMI_HILOGD("SetPointerSpeed success, speed:%{public}d", speed);
    return RET_OK;
}

int32_t MousePreferenceAccessor::GetPointerSpeed(IInputServiceContext &env, int32_t userId)
{
    CALL_DEBUG_ENTER;
    int32_t speed = DEFAULT_SPEED;
    GetConfigDataFromDatabase(env, userId, MOUSE_KEY_SETTING, FIELD_MOUSE_POINTER_SPEED, speed);
    return speed;
}

int32_t MousePreferenceAccessor::GetTouchpadSpeed(IInputServiceContext &env, int32_t userId)
{
    int32_t speed = DEFAULT_TOUCHPAD_SPEED;
    GetTouchpadPointerSpeed(env, userId, speed);
    MMI_HILOGD("TouchPad pointer speed:%{public}d", speed);
    return speed;
}

int32_t MousePreferenceAccessor::SetTouchpadScrollSwitch(IInputServiceContext &env, int32_t userId, int32_t pid, bool switchFlag)
{
    if (PutConfigDataToDatabase(env, userId, TOUCHPAD_KEY_SETTING, FIELD_TOUCHPAD_SCROLL_SWITCH, switchFlag) != RET_OK) {
        MMI_HILOGE("Failed to set scroll switch flag, switchFlag:%{public}d", switchFlag);
        return RET_ERR;
    }
    return RET_OK;
}

void MousePreferenceAccessor::GetTouchpadScrollSwitch(IInputServiceContext &env, int32_t userId, bool &switchFlag)
{
    GetConfigDataFromDatabase(env, userId, TOUCHPAD_KEY_SETTING, FIELD_TOUCHPAD_SCROLL_SWITCH, switchFlag);
}

int32_t MousePreferenceAccessor::SetTouchpadScrollDirection(IInputServiceContext &env, int32_t userId, bool state)
{
    if (PutConfigDataToDatabase(env, userId, TOUCHPAD_KEY_SETTING, FIELD_TOUCHPAD_SCROLL_DIRECTION, state) != RET_OK) {
        MMI_HILOGE("Failed to set scroll direction flag");
        return RET_ERR;
    }
    return RET_OK;
}

void MousePreferenceAccessor::GetTouchpadScrollDirection(IInputServiceContext &env, int32_t userId, bool &state)
{
    GetConfigDataFromDatabase(env, userId, TOUCHPAD_KEY_SETTING, FIELD_TOUCHPAD_SCROLL_DIRECTION, state);
}

int32_t MousePreferenceAccessor::SetTouchpadTapSwitch(IInputServiceContext &env, int32_t userId, bool switchFlag)
{
    if (PutConfigDataToDatabase(env, userId, TOUCHPAD_KEY_SETTING, FIELD_TOUCHPAD_TAP_SWITCH, switchFlag) != RET_OK) {
        MMI_HILOGE("Failed to set touchpad tap switch");
        return RET_ERR;
    }
    return RET_OK;
}

void MousePreferenceAccessor::GetTouchpadTapSwitch(IInputServiceContext &env, int32_t userId, bool &switchFlag)
{
    GetConfigDataFromDatabase(env, userId, TOUCHPAD_KEY_SETTING, FIELD_TOUCHPAD_TAP_SWITCH, switchFlag);
}

int32_t MousePreferenceAccessor::SetTouchpadRightClickType(IInputServiceContext &env, int32_t userId, int32_t type)
{
    if (PutConfigDataToDatabase(env, userId, TOUCHPAD_KEY_SETTING, FIELD_TOUCHPAD_RIGHT_CLICK_TYPE, type) != RET_OK) {
        MMI_HILOGE("Failed to set touchpad right click type");
        return RET_ERR;
    }
    return RET_OK;
}

void MousePreferenceAccessor::GetTouchpadRightClickType(IInputServiceContext &env, int32_t userId, int32_t &type)
{
    GetConfigDataFromDatabase(env, userId, TOUCHPAD_KEY_SETTING, FIELD_TOUCHPAD_RIGHT_CLICK_TYPE, type);
    if (type < RIGHT_CLICK_TYPE_MIN || type > RIGHT_CLICK_TYPE_MAX) {
        type = RIGHT_CLICK_TYPE_MIN;
    }
}

int32_t MousePreferenceAccessor::SetTouchpadPointerSpeed(IInputServiceContext &env, int32_t userId, int32_t speed)
{
    if (PutConfigDataToDatabase(env, userId, TOUCHPAD_KEY_SETTING, FIELD_TOUCHPAD_POINTER_SPEED, speed) != RET_OK) {
        MMI_HILOGE("Failed to set touchpad pointer speed");
        return RET_ERR;
    }
    return RET_OK;
}

void MousePreferenceAccessor::GetTouchpadPointerSpeed(IInputServiceContext &env, int32_t userId, int32_t &speed)
{
    GetConfigDataFromDatabase(env, userId, TOUCHPAD_KEY_SETTING, FIELD_TOUCHPAD_POINTER_SPEED, speed);
    speed = speed == 0 ? DEFAULT_TOUCHPAD_SPEED : speed;
    speed = speed < MIN_SPEED ? MIN_SPEED : speed;
    speed = speed > MAX_TOUCHPAD_SPEED ? MAX_TOUCHPAD_SPEED : speed;
}

int32_t MousePreferenceAccessor::GetTouchpadScrollRows(IInputServiceContext &env, int32_t userId)
{
    CALL_DEBUG_ENTER;
    int32_t rows = DEFAULT_ROWS;
    GetConfigDataFromDatabase(env, userId, TOUCHPAD_KEY_SETTING, FIELD_TOUCHPAD_SCROLL_ROWS, rows);
    MMI_HILOGD("Get touchpad scroll rows successfully, rows:%{public}d", rows);
    return rows;
}

int32_t MousePreferenceAccessor::PutConfigDataToDatabase(IInputServiceContext &env, int32_t userId,
    const std::string &key, const std::string &field, bool value)
{
    auto settingManager = env.GetSettingManager();
    if (settingManager == nullptr) {
        MMI_HILOGE("settingManager is nullptr");
        return RET_ERR;
    }
    if (!settingManager->SetBoolValue(userId, key, field, value)) {
        MMI_HILOGE("SetBoolValue failed, key:%{public}s, value:%{public}d", key.c_str(), int32_t(value));
        return RET_ERR;
    }
    return RET_OK;
}

void MousePreferenceAccessor::GetConfigDataFromDatabase(IInputServiceContext &env, int32_t userId,
    const std::string &key, const std::string &field, bool &value)
{
    auto settingManager = env.GetSettingManager();
    if (settingManager == nullptr) {
        MMI_HILOGE("settingManager is nullptr");
        return;
    }
    bool defaultVal = true;
    settingManager->GetBoolValue(userId, key, field, defaultVal);
    value = defaultVal;
}

int32_t MousePreferenceAccessor::PutConfigDataToDatabase(IInputServiceContext &env, int32_t userId, const std::string &key,
    const std::string &field, int32_t value)
{
    auto settingManager = env.GetSettingManager();
    if (settingManager == nullptr) {
        MMI_HILOGE("settingManager is nullptr");
        return RET_ERR;
    }
    if (!settingManager->SetIntValue(userId, key, field, value)) {
        MMI_HILOGE("SetBoolValue failed, key:%{public}s, value:%{public}d", key.c_str(), value);
        return RET_ERR;
    }
    return RET_OK;
}

void MousePreferenceAccessor::GetConfigDataFromDatabase(IInputServiceContext &env, int32_t userId,
    const std::string &key, const std::string &field, int32_t &value)
{
    auto settingManager = env.GetSettingManager();
    if (settingManager == nullptr) {
        MMI_HILOGE("settingManager is nullptr");
        return;
    }
    settingManager->GetIntValue(userId, key, field, value);
}
} // namespace MMI
} // namespace OHOS