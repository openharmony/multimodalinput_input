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
const std::string MOUSE_FILE_NAME { "mouse_settings.xml" };
const std::string TOUCHPAD_FILE_NAME { "touchpad_settings.xml" };
constexpr int32_t RIGHT_MENU_TYPE_INDEX_V2 { 1 };
} // namespace

int32_t MousePreferenceAccessor::SetMouseScrollRows(IInputServiceContext &env, int32_t rows)
{
    CALL_DEBUG_ENTER;
    if (rows < MIN_ROWS) {
        rows = MIN_ROWS;
    } else if (rows > MAX_ROWS) {
        rows = MAX_ROWS;
    }
    if (int32_t ret = PutConfigDataToDatabase(env, "rows", MOUSE_FILE_NAME, rows); ret != RET_OK) {
        MMI_HILOGE("Set mouse scroll rows failed, code:%{public}d", ret);
        return ret;
    } else {
        MMI_HILOGD("Set mouse scroll rows successfully, rows:%{public}d", rows);
    }
    return RET_OK;
}

int32_t MousePreferenceAccessor::GetMouseScrollRows(IInputServiceContext &env)
{
    CALL_DEBUG_ENTER;
    int32_t rows = DEFAULT_ROWS;
    GetConfigDataFromDatabase(env, "rows", rows);
    return rows;
}

int32_t MousePreferenceAccessor::SetMousePrimaryButton(IInputServiceContext &env, int32_t primaryButton)
{
    CALL_DEBUG_ENTER;
    MMI_HILOGD("Set mouse primary button:%{public}d", primaryButton);
    std::string name = "primaryButton";
    if (int32_t ret = PutConfigDataToDatabase(env, "primaryButton", MOUSE_FILE_NAME, primaryButton); ret != RET_OK) {
        MMI_HILOGE("Set mouse primary button failed, code:%{public}d", ret);
        return ret;
    } else {
        MMI_HILOGD("Set mouse primary button success, primaryButton:%{public}d", primaryButton);
    }
    return RET_OK;
}

int32_t MousePreferenceAccessor::GetMousePrimaryButton(IInputServiceContext &env)
{
    CALL_DEBUG_ENTER;
    int32_t primaryButton = 0;
    GetConfigDataFromDatabase(env, "primaryButton", primaryButton);
    return primaryButton;
}

int32_t MousePreferenceAccessor::SetPointerSpeed(IInputServiceContext &env, int32_t speed)
{
    CALL_DEBUG_ENTER;
    if (speed < MIN_SPEED) {
        speed = MIN_SPEED;
    } else if (speed > MAX_SPEED) {
        speed = MAX_SPEED;
    }
    if (int32_t ret = PutConfigDataToDatabase(env, "speed", MOUSE_FILE_NAME, speed); ret != RET_OK) {
        MMI_HILOGE("SetPointerSpeed, code:%{public}d", ret);
        return ret;
    } else {
        MMI_HILOGD("SetPointerSpeed success, speed:%{public}d", speed);
    }
    return RET_OK;
}

int32_t MousePreferenceAccessor::GetPointerSpeed(IInputServiceContext &env)
{
    CALL_DEBUG_ENTER;
    int32_t speed = DEFAULT_SPEED;
    GetConfigDataFromDatabase(env, "speed", speed);
    return speed;
}

int32_t MousePreferenceAccessor::GetTouchpadSpeed(IInputServiceContext &env)
{
    int32_t speed = DEFAULT_TOUCHPAD_SPEED;
    GetTouchpadPointerSpeed(env, speed);
    MMI_HILOGD("TouchPad pointer speed:%{public}d", speed);
    return speed;
}

int32_t MousePreferenceAccessor::SetTouchpadScrollSwitch(IInputServiceContext &env, int32_t pid, bool switchFlag)
{
    std::string name = "scrollSwitch";
    if (PutConfigDataToDatabase(env, name, MOUSE_FILE_NAME, switchFlag) != RET_OK) {
        MMI_HILOGE("Failed to set scroll switch flag to mem, name:%s, switchFlag:%{public}d", name.c_str(), switchFlag);
        return RET_ERR;
    }
    return RET_OK;
}

void MousePreferenceAccessor::GetTouchpadScrollSwitch(IInputServiceContext &env, bool &switchFlag)
{
    std::string name = "scrollSwitch";
    GetConfigDataFromDatabase(env, name, switchFlag);
}

int32_t MousePreferenceAccessor::SetTouchpadScrollDirection(IInputServiceContext &env, bool state)
{
    std::string name = "scrollDirection";
    if (PutConfigDataToDatabase(env, name, MOUSE_FILE_NAME, state) != RET_OK) {
        MMI_HILOGE("Failed to set scroll direct switch flag to mem");
        return RET_ERR;
    }
    return RET_OK;
}

void MousePreferenceAccessor::GetTouchpadScrollDirection(IInputServiceContext &env, bool &state)
{
    std::string name = "scrollDirection";
    GetConfigDataFromDatabase(env, name, state);
}

int32_t MousePreferenceAccessor::SetTouchpadTapSwitch(IInputServiceContext &env, bool switchFlag)
{
    std::string name = "touchpadTap";
    if (PutConfigDataToDatabase(env, name, MOUSE_FILE_NAME, switchFlag) != RET_OK) {
        MMI_HILOGE("Failed to set scroll direct switch flag to mem");
        return RET_ERR;
    }
    return RET_OK;
}

void MousePreferenceAccessor::GetTouchpadTapSwitch(IInputServiceContext &env, bool &switchFlag)
{
    std::string name = "touchpadTap";
    GetConfigDataFromDatabase(env, name, switchFlag);
}

int32_t MousePreferenceAccessor::SetTouchpadRightClickType(IInputServiceContext &env, int32_t type)
{
    auto preferenceMgr = env.GetPreferenceManager();
    if (preferenceMgr == nullptr) {
        MMI_HILOGE("PreferenceMgr is nullptr");
        return RET_ERR;
    }
    std::string name = "rightMenuSwitch";
    std::vector<uint8_t> switchType {TOUCHPAD_RIGHT_BUTTON, type}; // index0: v1.0, index1: v2.0
    std::string filePath = "";
    preferenceMgr->UpdatePreferencesMap(name, TOUCHPAD_FILE_NAME, type, filePath);
    switchType = static_cast<std::vector<uint8_t>>(preferenceMgr->GetPreValue(name, switchType));
    switchType[RIGHT_MENU_TYPE_INDEX_V2] = type;
    if (preferenceMgr->SetPreValue(name, filePath, switchType) != RET_OK) {
        MMI_HILOGE("Failed to set touch pad right click type to mem");
        return RET_ERR;
    }
    return RET_OK;
}

void MousePreferenceAccessor::GetTouchpadRightClickType(IInputServiceContext &env, int32_t &type)
{
    std::string name = "rightMenuSwitch";
    GetConfigDataFromDatabase(env, name, type);
    if (type < RIGHT_CLICK_TYPE_MIN || type > RIGHT_CLICK_TYPE_MAX) {
        type = RIGHT_CLICK_TYPE_MIN;
    }
}

int32_t MousePreferenceAccessor::SetTouchpadPointerSpeed(IInputServiceContext &env, int32_t speed)
{
    std::string name = "touchPadPointerSpeed";
    if (PutConfigDataToDatabase(env, name, MOUSE_FILE_NAME, speed) != RET_OK) {
        MMI_HILOGE("Failed to set touch pad pointer speed to mem");
        return RET_ERR;
    }
    return RET_OK;
}

void MousePreferenceAccessor::GetTouchpadPointerSpeed(IInputServiceContext &env, int32_t &speed)
{
    std::string name = "touchPadPointerSpeed";
    GetConfigDataFromDatabase(env, name, speed);
    speed = speed == 0 ? DEFAULT_TOUCHPAD_SPEED : speed;
    speed = speed < MIN_SPEED ? MIN_SPEED : speed;
    speed = speed > MAX_TOUCHPAD_SPEED ? MAX_TOUCHPAD_SPEED : speed;
}

int32_t MousePreferenceAccessor::GetTouchpadScrollRows(IInputServiceContext &env)
{
    CALL_DEBUG_ENTER;
    std::string name = "touchpadScrollRows";
    int32_t rows = DEFAULT_ROWS;
    GetConfigDataFromDatabase(env, name, rows);
    MMI_HILOGD("Get touchpad scroll rows successfully, rows:%{public}d", rows);
    return rows;
}

int32_t MousePreferenceAccessor::PutConfigDataToDatabase(IInputServiceContext &env, const std::string &key,
    const std::string &setFile, bool value)
{
    auto preferenceMgr = env.GetPreferenceManager();
    if (preferenceMgr == nullptr) {
        MMI_HILOGE("PreferenceMgr is nullptr");
        return RET_ERR;
    }
    return preferenceMgr->SetBoolValue(key, setFile, value);
}

void MousePreferenceAccessor::GetConfigDataFromDatabase(IInputServiceContext &env, const std::string &key, bool &value)
{
    auto preferenceMgr = env.GetPreferenceManager();
    if (preferenceMgr == nullptr) {
        MMI_HILOGE("PreferenceMgr is nullptr");
        return;
    }
    bool defaultValue = true;
    value = preferenceMgr->GetBoolValue(key, defaultValue);
}

int32_t MousePreferenceAccessor::PutConfigDataToDatabase(IInputServiceContext &env, const std::string &key,
    const std::string &setFile, int32_t value)
{
    auto preferenceMgr = env.GetPreferenceManager();
    if (preferenceMgr == nullptr) {
        MMI_HILOGE("PreferenceMgr is nullptr");
        return RET_ERR;
    }
    return preferenceMgr->SetIntValue(key, setFile, value);
}

void MousePreferenceAccessor::GetConfigDataFromDatabase(IInputServiceContext &env, const std::string &key,
    int32_t &value)
{
    auto preferenceMgr = env.GetPreferenceManager();
    if (preferenceMgr == nullptr) {
        MMI_HILOGE("PreferenceMgr is nullptr");
        return;
    }
    int32_t defaultValue = value;
    value = preferenceMgr->GetIntValue(key, defaultValue);
}
} // namespace MMI
} // namespace OHOS