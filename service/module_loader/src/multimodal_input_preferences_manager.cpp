/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
 
#include "multimodal_input_preferences_manager.h"

#include "mmi_log.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_SERVER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "MultiModalInputPreferencesManager"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t KEYBOARD_REPEATRATE = 50;
constexpr int32_t KEYBOARD_REPEATDELAY = 500;
constexpr int32_t MOUSE_SCROLL_ROWS = 3;
constexpr int32_t PRIMARY_BUTTON = 0;
constexpr int32_t POINTER_SPEED = 7;
constexpr int32_t TOUCHPAD_POINTER_SPEED = 9;
constexpr int32_t RIGHT_CLICK_TYPE = 1;
constexpr int32_t POINTER_COLOR = -1;
constexpr int32_t POINTER_SIZE = 1;
constexpr int32_t MAGIC_POINTER_SIZE = 3;
constexpr int32_t POINTER_STYLE = 0;
constexpr int32_t ERROR_DELAY_VALUE = -1000;
constexpr bool BOOL_DEFAULT = true;
const std::string path = "/data/service/el1/public/multimodalinput/";
const std::string shortKeyFileName = "Settings.xml";
const std::string mouseFileName = "mouse_settings.xml";
const std::string keyboarFileName = "keyboard_settings.xml";
const std::string touchpadFileName = "touchpad_settings.xml";
} // namespace

MultiModalInputPreferencesManager::MultiModalInputPreferencesManager() {}

MultiModalInputPreferencesManager::~MultiModalInputPreferencesManager() {}

int32_t MultiModalInputPreferencesManager::InitPreferences()
{
    CALL_DEBUG_ENTER;
    int32_t ret = GetPreferencesSettings();
    if (ret != RET_OK) {
        MMI_HILOGE("Get multimodal input preferences settings failed");
        return RET_ERR;
    }
    ret = InitPreferencesMap();
    if (ret != RET_OK) {
        MMI_HILOGE("Init multimodal input preferences map failed");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t MultiModalInputPreferencesManager::GetPreferencesSettings()
{
    int32_t errCode = RET_OK;
    std::shared_ptr<NativePreferences::Preferences> mousePref =
        NativePreferences::PreferencesHelper::GetPreferences(path + mouseFileName, errCode);
    CHKPR(mousePref, errno);
    std::shared_ptr<NativePreferences::Preferences> keyboardPref =
        NativePreferences::PreferencesHelper::GetPreferences(path + keyboarFileName, errCode);
    CHKPR(keyboardPref, errno);
    std::shared_ptr<NativePreferences::Preferences> touchpadPref =
        NativePreferences::PreferencesHelper::GetPreferences(path + touchpadFileName, errCode);
    CHKPR(touchpadPref, errno);
    g_pointerSize = mousePref->GetInt(pointerSize, POINTER_SIZE);
    g_pointerSpeed = mousePref->GetInt(pointerSpeed, POINTER_SPEED);
    g_pointerColor = mousePref->GetInt(pointerColor, POINTER_COLOR);
    g_pointerStyle = mousePref->GetInt(pointerStyle, POINTER_STYLE);
    g_mouseScrollRows = mousePref->GetInt(mouseScrollRows, MOUSE_SCROLL_ROWS);
    g_hoverScrollState = mousePref->GetBool(hoverScrollState, BOOL_DEFAULT);
    g_mousePrimaryButton = mousePref->GetInt(mousePrimaryButton, PRIMARY_BUTTON);
    g_touchpadTapSwitch = touchpadPref->GetBool(touchpadTapSwitch, BOOL_DEFAULT);
    g_keyboardRepeatRate = keyboardPref->GetInt(keyboardRepeatRate, KEYBOARD_REPEATRATE);
    g_keyboardRepeatDelay = keyboardPref->GetInt(keyboardRepeatDelay, KEYBOARD_REPEATDELAY);
    g_touchpadPinchSwitch = touchpadPref->GetBool(touchpadPinchSwitch, BOOL_DEFAULT);
    g_touchpadSwipeSwitch = touchpadPref->GetBool(touchpadSwipeSwitch, BOOL_DEFAULT);
    g_touchpadPointerSpeed = touchpadPref->GetInt(touchpadPointerSpeed, TOUCHPAD_POINTER_SPEED);
    g_touchpadScrollSwitch = touchpadPref->GetBool(touchpadScrollSwitch, BOOL_DEFAULT);
    g_touchpadRightClickType = touchpadPref->GetInt(touchpadRightClickType, RIGHT_CLICK_TYPE);
    g_touchpadScrollDirection = touchpadPref->GetBool(touchpadScrollDirection, BOOL_DEFAULT);
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    g_magicPointerSize = mousePref->GetInt(magicPointerSize, MAGIC_POINTER_SIZE);
    g_magicPointerColor = mousePref->GetInt(magicPointerColor, POINTER_COLOR);
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
    NativePreferences::PreferencesHelper::RemovePreferencesFromCache(path + mouseFileName);
    NativePreferences::PreferencesHelper::RemovePreferencesFromCache(path + keyboarFileName);
    NativePreferences::PreferencesHelper::RemovePreferencesFromCache(path + touchpadFileName);
    return RET_OK;
}

int32_t MultiModalInputPreferencesManager::InitPreferencesMap()
{
    preferencesMap[pointerSize] = {mouseFileName, g_pointerSize};
    preferencesMap[pointerSpeed] = {mouseFileName, g_pointerSpeed};
    preferencesMap[pointerColor] = {mouseFileName, g_pointerColor};
    preferencesMap[pointerStyle] = {mouseFileName, g_pointerStyle};
    preferencesMap[mouseScrollRows] = {mouseFileName, g_mouseScrollRows};
    preferencesMap[hoverScrollState] = {mouseFileName, static_cast<int32_t>(g_hoverScrollState)};
    preferencesMap[mousePrimaryButton] = {mouseFileName, g_mousePrimaryButton};
    preferencesMap[touchpadTapSwitch] = {touchpadFileName, static_cast<int32_t>(g_touchpadTapSwitch)};
    preferencesMap[keyboardRepeatRate] = {keyboarFileName, g_keyboardRepeatRate};
    preferencesMap[keyboardRepeatDelay] = {keyboarFileName, g_keyboardRepeatDelay};
    preferencesMap[touchpadPinchSwitch] = {touchpadFileName, static_cast<int32_t>(g_touchpadPinchSwitch)};
    preferencesMap[touchpadSwipeSwitch] = {touchpadFileName, static_cast<int32_t>(g_touchpadSwipeSwitch)};
    preferencesMap[touchpadPointerSpeed] = {touchpadFileName, g_touchpadPointerSpeed};
    preferencesMap[touchpadScrollSwitch] = {touchpadFileName, static_cast<int32_t>(g_touchpadScrollSwitch)};
    preferencesMap[touchpadRightClickType] = {touchpadFileName, g_touchpadRightClickType};
    preferencesMap[touchpadScrollDirection] = {touchpadFileName, static_cast<int32_t>(g_touchpadScrollDirection)};
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    preferencesMap[magicPointerSize] = {mouseFileName, g_magicPointerSize};
    preferencesMap[magicPointerColor] = {mouseFileName, g_magicPointerColor};
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
    return RET_OK;
}

int32_t MultiModalInputPreferencesManager::GetIntValue(const std::string &key, int32_t defaultValue)
{
    auto iter = preferencesMap.find(key);
    if (iter == preferencesMap.end()) {
        return defaultValue;
    }
    auto [fileName, value] = iter->second;
    return value;
}

bool MultiModalInputPreferencesManager::GetBoolValue(const std::string &key, bool defaultValue)
{
    auto iter = preferencesMap.find(key);
    if (iter == preferencesMap.end()) {
        return defaultValue;
    }
    auto [fileName, value] = iter->second;
    return static_cast<bool>(value);
}

int32_t MultiModalInputPreferencesManager::SetIntValue(const std::string &key, const std::string &setFile,
    int32_t setValue)
{
    auto iter = preferencesMap.find(key);
    std::string filePath = "";
    if (iter == preferencesMap.end()) {
        preferencesMap[key] = {setFile, setValue};
        filePath = path + setFile;
    } else {
        auto [fileName, value] = iter->second;
        if (value == setValue) {
            MMI_HILOGD("The set value is same");
            return RET_OK;
        }
        filePath = path + fileName;
        preferencesMap[key].second = setValue;
    }

    int32_t errCode = RET_OK;
    std::shared_ptr<NativePreferences::Preferences> pref =
        NativePreferences::PreferencesHelper::GetPreferences(filePath, errCode);
    CHKPR(pref, errno);
    int32_t ret = pref->PutInt(key, setValue);
    if (ret != RET_OK) {
        MMI_HILOGE("Put value is failed, ret:%{public}d", ret);
        return RET_ERR;
    }
    ret = pref->FlushSync();
    if (ret != RET_OK) {
        MMI_HILOGE("Flush sync is failed, ret:%{public}d", ret);
        return RET_ERR;
    }
    NativePreferences::PreferencesHelper::RemovePreferencesFromCache(filePath);
    return RET_OK;
}

int32_t MultiModalInputPreferencesManager::SetBoolValue(const std::string &key, const std::string &setFile,
    bool setValue)
{
    auto iter = preferencesMap.find(key);
    std::string filePath = "";
    if (iter == preferencesMap.end()) {
        preferencesMap[key] = {setFile, static_cast<int32_t>(setValue)};
        filePath = path + setFile;
    } else {
        auto [fileName, value] = iter->second;
        if (static_cast<bool>(value) == setValue) {
            MMI_HILOGD("The set value is same");
            return RET_OK;
        }
        filePath = path + fileName;
        preferencesMap[key].second = setValue;
    }

    int32_t errCode = RET_OK;
    std::shared_ptr<NativePreferences::Preferences> pref =
        NativePreferences::PreferencesHelper::GetPreferences(filePath, errCode);
    CHKPR(pref, errno);
    int32_t ret = pref->PutBool(key, setValue);
    if (ret != RET_OK) {
        MMI_HILOGE("Put value is failed, ret:%{public}d", ret);
        return RET_ERR;
    }
    ret = pref->FlushSync();
    if (ret != RET_OK) {
        MMI_HILOGE("Flush sync is failed, ret:%{public}d", ret);
        return RET_ERR;
    }
    NativePreferences::PreferencesHelper::RemovePreferencesFromCache(filePath);
    return RET_OK;
}

int32_t MultiModalInputPreferencesManager::GetShortKeyDuration(const std::string &key)
{
    int32_t errCode = RET_OK;
    if (g_shortcutKeyMap.empty() || g_shortcutKeyMap.find(key) == g_shortcutKeyMap.end()) {
        std::shared_ptr<NativePreferences::Preferences> pref =
            NativePreferences::PreferencesHelper::GetPreferences(path + shortKeyFileName, errCode);
        CHKPR(pref, errno);
        int32_t duration = pref->GetInt(key, ERROR_DELAY_VALUE);
        NativePreferences::PreferencesHelper::RemovePreferencesFromCache(path + shortKeyFileName);
        g_shortcutKeyMap.emplace(key, duration);
        return duration;
    }
    return g_shortcutKeyMap[key];
}

int32_t MultiModalInputPreferencesManager::SetShortKeyDuration(const std::string &key, int32_t setValue)
{
    auto iter = g_shortcutKeyMap.find(key);
    if (iter != g_shortcutKeyMap.end() && iter->second == setValue) {
        MMI_HILOGD("The set value is same");
        return RET_OK;
    }

    g_shortcutKeyMap[key] = setValue;
    int32_t errCode = RET_OK;
    std::shared_ptr<NativePreferences::Preferences> pref =
        NativePreferences::PreferencesHelper::GetPreferences(path + shortKeyFileName, errCode);
    CHKPR(pref, errno);
    int32_t ret = pref->PutInt(key, setValue);
    if (ret != RET_OK) {
        MMI_HILOGE("Put value is failed, ret:%{public}d", ret);
        return RET_ERR;
    }
    ret = pref->FlushSync();
    if (ret != RET_OK) {
        MMI_HILOGE("Flush sync is failed, ret:%{public}d", ret);
        return RET_ERR;
    }
    NativePreferences::PreferencesHelper::RemovePreferencesFromCache(path + shortKeyFileName);
    return RET_OK;
}
} // namespace MMI
} // namespace OHOS