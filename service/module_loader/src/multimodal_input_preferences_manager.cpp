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
constexpr int32_t KEYBOARD_REPEATRATE { 50 };
constexpr int32_t KEYBOARD_REPEATDELAY { 500 };
constexpr int32_t MOUSE_SCROLL_ROWS { 3 };
constexpr int32_t PRIMARY_BUTTON { 0 };
constexpr int32_t POINTER_SPEED { 7 };
constexpr int32_t TOUCHPAD_POINTER_SPEED { 6 };
constexpr int32_t TOUCHPAD_SCROLL_ROWS { 3 };
constexpr int32_t RIGHT_CLICK_TYPE { 1 };
constexpr int32_t POINTER_COLOR { -1 };
constexpr int32_t POINTER_SIZE { 1 };
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
constexpr int32_t MAGIC_POINTER_SIZE { 1 };
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
constexpr int32_t POINTER_STYLE { 0 };
constexpr int32_t ERROR_DELAY_VALUE { -1000 };
constexpr bool BOOL_DEFAULT { true };
const std::string PATH { "/data/service/el1/public/multimodalinput/" };
const std::string SHORT_KEY_FILE_NAME { "Settings.xml" };
const std::string MOUSE_FILE_NAME { "mouse_settings.xml" };
const std::string KEYBOARD_FILE_NAME { "keyboard_settings.xml" };
const std::string TOUCHPAD_FILE_NAME { "touchpad_settings.xml" };
} // namespace

std::shared_ptr<IPreferenceManager> IPreferenceManager::instance_;
std::mutex IPreferenceManager::mutex_;

std::shared_ptr<IPreferenceManager> IPreferenceManager::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (instance_ == nullptr) {
            instance_ = std::make_shared<MultiModalInputPreferencesManager>();
        }
    }
    return instance_;
}

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
        NativePreferences::PreferencesHelper::GetPreferences(PATH + MOUSE_FILE_NAME, errCode);
    CHKPR(mousePref, errno);
    std::shared_ptr<NativePreferences::Preferences> keyboardPref =
        NativePreferences::PreferencesHelper::GetPreferences(PATH + KEYBOARD_FILE_NAME, errCode);
    CHKPR(keyboardPref, errno);
    std::shared_ptr<NativePreferences::Preferences> touchpadPref =
        NativePreferences::PreferencesHelper::GetPreferences(PATH + TOUCHPAD_FILE_NAME, errCode);
    CHKPR(touchpadPref, errno);
    pointerSize_ = mousePref->GetInt(strPointerSize_, POINTER_SIZE);
    pointerSpeed_ = mousePref->GetInt(strPointerSpeed_, POINTER_SPEED);
    pointerColor_ = mousePref->GetInt(strPointerColor_, POINTER_COLOR);
    pointerStyle_ = mousePref->GetInt(strPointerStyle_, POINTER_STYLE);
    mouseScrollRows_ = mousePref->GetInt(strMouseScrollRows_, MOUSE_SCROLL_ROWS);
    hoverScrollState_ = mousePref->GetBool(strHoverScrollState_, BOOL_DEFAULT);
    mousePrimaryButton_ = mousePref->GetInt(strMousePrimaryButton_, PRIMARY_BUTTON);
    touchpadTapSwitch_ = touchpadPref->GetBool(strTouchpadTapSwitch_, BOOL_DEFAULT);
    keyboardRepeatRate_ = keyboardPref->GetInt(strKeyboardRepeatRate_, KEYBOARD_REPEATRATE);
    keyboardRepeatDelay_ = keyboardPref->GetInt(strKeyboardRepeatDelay_, KEYBOARD_REPEATDELAY);
    touchpadPinchSwitch_ = touchpadPref->GetBool(strTouchpadPinchSwitch_, BOOL_DEFAULT);
    touchpadSwipeSwitch_ = touchpadPref->GetBool(strTouchpadSwipeSwitch_, BOOL_DEFAULT);
    touchpadPointerSpeed_ = touchpadPref->GetInt(strTouchpadPointerSpeed_, TOUCHPAD_POINTER_SPEED);
    touchpadScrollSwitch_ = touchpadPref->GetBool(strTouchpadScrollSwitch_, BOOL_DEFAULT);
    touchpadRightClickType_ = touchpadPref->GetInt(strTouchpadRightClickType_, RIGHT_CLICK_TYPE);
    touchpadScrollDirection_ = touchpadPref->GetBool(strTouchpadScrollDirection_, BOOL_DEFAULT);
    touchpadThreeFingerTapSwitch_ = touchpadPref->GetBool(strTouchpadThreeFingerTapSwitch_, BOOL_DEFAULT);
    touchpadScrollRows_ = touchpadPref->GetInt(strTouchpadScrollRows_, TOUCHPAD_SCROLL_ROWS);
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    magicPointerSize_ = mousePref->GetInt(strMagicPointerSize_, MAGIC_POINTER_SIZE);
    magicPointerColor_ = mousePref->GetInt(strMagicPointerColor_, POINTER_COLOR);
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
#ifdef OHOS_BUILD_ENABLE_MOVE_EVENT_FILTERS
    moveEventFilterFlag_ = mousePref->GetBool(strMoveEventFilterFlag_, BOOL_DEFAULT);
#endif // OHOS_BUILD_ENABLE_MOVE_EVENT_FILTERS
    NativePreferences::PreferencesHelper::RemovePreferencesFromCache(PATH + MOUSE_FILE_NAME);
    NativePreferences::PreferencesHelper::RemovePreferencesFromCache(PATH + KEYBOARD_FILE_NAME);
    NativePreferences::PreferencesHelper::RemovePreferencesFromCache(PATH + TOUCHPAD_FILE_NAME);
    return RET_OK;
}

int32_t MultiModalInputPreferencesManager::InitPreferencesMap()
{
    preferencesMap_[strPointerSize_] = {MOUSE_FILE_NAME, pointerSize_};
    preferencesMap_[strPointerSpeed_] = {MOUSE_FILE_NAME, pointerSpeed_};
    preferencesMap_[strPointerColor_] = {MOUSE_FILE_NAME, pointerColor_};
    preferencesMap_[strPointerStyle_] = {MOUSE_FILE_NAME, pointerStyle_};
    preferencesMap_[strMouseScrollRows_] = {MOUSE_FILE_NAME, mouseScrollRows_};
    preferencesMap_[strHoverScrollState_] = {MOUSE_FILE_NAME, static_cast<int32_t>(hoverScrollState_)};
    preferencesMap_[strMousePrimaryButton_] = {MOUSE_FILE_NAME, mousePrimaryButton_};
    preferencesMap_[strTouchpadTapSwitch_] = {TOUCHPAD_FILE_NAME, static_cast<int32_t>(touchpadTapSwitch_)};
    preferencesMap_[strKeyboardRepeatRate_] = {KEYBOARD_FILE_NAME, keyboardRepeatRate_};
    preferencesMap_[strKeyboardRepeatDelay_] = {KEYBOARD_FILE_NAME, keyboardRepeatDelay_};
    preferencesMap_[strTouchpadPinchSwitch_] = {TOUCHPAD_FILE_NAME, static_cast<int32_t>(touchpadPinchSwitch_)};
    preferencesMap_[strTouchpadSwipeSwitch_] = {TOUCHPAD_FILE_NAME, static_cast<int32_t>(touchpadSwipeSwitch_)};
    preferencesMap_[strTouchpadPointerSpeed_] = {TOUCHPAD_FILE_NAME, touchpadPointerSpeed_};
    preferencesMap_[strTouchpadScrollSwitch_] = {TOUCHPAD_FILE_NAME, static_cast<int32_t>(touchpadScrollSwitch_)};
    preferencesMap_[strTouchpadRightClickType_] = {TOUCHPAD_FILE_NAME, touchpadRightClickType_};
    preferencesMap_[strTouchpadScrollDirection_] = {TOUCHPAD_FILE_NAME, static_cast<int32_t>(touchpadScrollDirection_)};
    preferencesMap_[strTouchpadThreeFingerTapSwitch_] = {TOUCHPAD_FILE_NAME,
                                                    static_cast<int32_t>(touchpadThreeFingerTapSwitch_)};
    preferencesMap_[strTouchpadScrollRows_] = {TOUCHPAD_FILE_NAME, touchpadScrollRows_};
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    preferencesMap_[strMagicPointerSize_] = {MOUSE_FILE_NAME, magicPointerSize_};
    preferencesMap_[strMagicPointerColor_] = {MOUSE_FILE_NAME, magicPointerColor_};
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
#ifdef OHOS_BUILD_ENABLE_MOVE_EVENT_FILTERS
    preferencesMap_[strMoveEventFilterFlag_] = {MOUSE_FILE_NAME, static_cast<int32_t>(moveEventFilterFlag_)};
#endif // OHOS_BUILD_ENABLE_MOVE_EVENT_FILTERS
    return RET_OK;
}

int32_t MultiModalInputPreferencesManager::GetIntValue(const std::string &key, int32_t defaultValue)
{
    auto iter = preferencesMap_.find(key);
    if (iter == preferencesMap_.end()) {
        return defaultValue;
    }
    auto [fileName, value] = iter->second;
    return value;
}

bool MultiModalInputPreferencesManager::GetBoolValue(const std::string &key, bool defaultValue)
{
    auto iter = preferencesMap_.find(key);
    if (iter == preferencesMap_.end()) {
        return defaultValue;
    }
    auto [fileName, value] = iter->second;
    return static_cast<bool>(value);
}

int32_t MultiModalInputPreferencesManager::SetIntValue(const std::string &key, const std::string &setFile,
    int32_t setValue)
{
    auto iter = preferencesMap_.find(key);
    std::string filePath = "";
    if (iter == preferencesMap_.end()) {
        preferencesMap_[key] = {setFile, setValue};
        filePath = PATH + setFile;
    } else {
        auto [fileName, value] = iter->second;
        if (value == setValue) {
            MMI_HILOGD("The set value is same");
            return RET_OK;
        }
        filePath = PATH + fileName;
        preferencesMap_[key].second = setValue;
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
    auto iter = preferencesMap_.find(key);
    std::string filePath = "";
    if (iter == preferencesMap_.end()) {
        preferencesMap_[key] = {setFile, static_cast<int32_t>(setValue)};
        filePath = PATH + setFile;
    } else {
        auto [fileName, value] = iter->second;
        if (static_cast<bool>(value) == setValue) {
            MMI_HILOGD("The set value is same");
            return RET_OK;
        }
        filePath = PATH + fileName;
        preferencesMap_[key].second = setValue;
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
    if (shortcutKeyMap_.empty() || shortcutKeyMap_.find(key) == shortcutKeyMap_.end()) {
        std::shared_ptr<NativePreferences::Preferences> pref =
            NativePreferences::PreferencesHelper::GetPreferences(PATH + SHORT_KEY_FILE_NAME, errCode);
        CHKPR(pref, errno);
        int32_t duration = pref->GetInt(key, ERROR_DELAY_VALUE);
        NativePreferences::PreferencesHelper::RemovePreferencesFromCache(PATH + SHORT_KEY_FILE_NAME);
        shortcutKeyMap_.emplace(key, duration);
        return duration;
    }
    return shortcutKeyMap_[key];
}

int32_t MultiModalInputPreferencesManager::SetShortKeyDuration(const std::string &key, int32_t setValue)
{
    auto iter = shortcutKeyMap_.find(key);
    if (iter != shortcutKeyMap_.end() && iter->second == setValue) {
        MMI_HILOGD("The set value is same");
        return RET_OK;
    }

    shortcutKeyMap_[key] = setValue;
    int32_t errCode = RET_OK;
    std::shared_ptr<NativePreferences::Preferences> pref =
        NativePreferences::PreferencesHelper::GetPreferences(PATH + SHORT_KEY_FILE_NAME, errCode);
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
    NativePreferences::PreferencesHelper::RemovePreferencesFromCache(PATH + SHORT_KEY_FILE_NAME);
    return RET_OK;
}
} // namespace MMI
} // namespace OHOS