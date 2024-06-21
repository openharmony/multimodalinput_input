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

#ifndef MULTIMODAL_INPUT_PREFERENCES_MANAGER_H
#define MULTIMODAL_INPUT_PREFERENCES_MANAGER_H

#include "nocopyable.h"
#include "preferences.h"
#include "preferences_errno.h"
#include "preferences_helper.h"

#include "i_preference_manager.h"

namespace OHOS {
namespace MMI {
class MultiModalInputPreferencesManager : public IPreferenceManager {
public:
    MultiModalInputPreferencesManager() = default;
    ~MultiModalInputPreferencesManager() = default;
    DISALLOW_COPY_AND_MOVE(MultiModalInputPreferencesManager);

    int32_t InitPreferences();
    int32_t GetPreferencesSettings();
    int32_t InitPreferencesMap();
    int32_t GetIntValue(const std::string &key, int32_t defaultValue);
    bool GetBoolValue(const std::string &key, bool defaultValue);
    int32_t SetIntValue(const std::string &key, const std::string &setFile, int32_t setValue);
    int32_t SetBoolValue(const std::string &key, const std::string &setFile, bool setValue);
    int32_t GetShortKeyDuration(const std::string &key);
    int32_t SetShortKeyDuration(const std::string &key, int32_t setValue);

private:
    std::map<std::string, std::pair<std::string, int32_t>> preferencesMap_;
    std::map<std::string, int32_t> shortcutKeyMap_;
    int32_t keyboardRepeatRate_ { 50 };
    int32_t keyboardRepeatDelay_ { 500 };
    int32_t mouseScrollRows_ { 3 };
    int32_t mousePrimaryButton_ { 0 };
    int32_t pointerSpeed_ { 7 };
    int32_t touchpadRightClickType_ { 1 };
    int32_t touchpadPointerSpeed_ { 9 };
    bool touchpadTapSwitch_ { true };
    bool touchpadScrollDirection_ { true };
    bool touchpadScrollSwitch_ { true };
    bool touchpadPinchSwitch_ { true };
    bool touchpadSwipeSwitch_ { true };
    bool hoverScrollState_ { true };
    bool touchpadThreeFingerTapSwitch_ {false};
    int32_t pointerColor_ { -1 };
    int32_t pointerSize_ { 1 };
    int32_t pointerStyle_ { 0 };
    const std::string strKeyboardRepeatRate_ = "keyboardRepeatRate";
    const std::string strKeyboardRepeatDelay_ = "keyboardRepeatDelay";
    const std::string strMouseScrollRows_ = "rows";
    const std::string strMousePrimaryButton_ = "primaryButton";
    const std::string strPointerSpeed_ = "speed";
    const std::string strTouchpadRightClickType_ = "rightMenuSwitch";
    const std::string strTouchpadPointerSpeed_ = "touchPadPointerSpeed";
    const std::string strTouchpadTapSwitch_ = "touchpadTap";
    const std::string strTouchpadScrollDirection_ = "scrollDirection";
    const std::string strTouchpadScrollSwitch_ = "scrollSwitch";
    const std::string strTouchpadPinchSwitch_ = "touchpadPinch";
    const std::string strTouchpadSwipeSwitch_ = "touchpadSwipe";
    const std::string strHoverScrollState_ = "isEnableHoverScroll";
    const std::string strPointerColor_ = "pointerColor";
    const std::string strPointerSize_ = "pointerSize";
    const std::string strPointerStyle_ = "pointerStyle";
    const std::string strTouchpadThreeFingerTapSwitch_ = "touchpadThreeFingerTap";
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    int32_t magicPointerColor_ { -1 };
    int32_t magicPointerSize_ { 3 };
    const std::string strMagicPointerColor_ = "magicPointerColor";
    const std::string strMagicPointerSize_ = "magicPointerSize";
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
};
} // namespace MMI
} // namespace OHOS
#endif // MULTIMODAL_INPUT_PREFERENCES_MANAGER_H