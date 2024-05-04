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

#include "preferences.h"
#include "preferences_impl.h"
#include "preferences_errno.h"
#include "preferences_helper.h"
#include "preferences_xml_utils.h"

#include "singleton.h"

namespace OHOS {
namespace MMI {
class MultiModalInputPreferencesManager {
    DECLARE_DELAYED_SINGLETON(MultiModalInputPreferencesManager);

public:
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
    std::map<std::string, std::pair<std::string, int32_t>> preferencesMap;
    std::map<std::string, int32_t> g_shortcutKeyMap;
    int32_t g_keyboardRepeatRate { 50 };
    int32_t g_keyboardRepeatDelay { 500 };
    int32_t g_mouseScrollRows { 3 };
    int32_t g_mousePrimaryButton { 0 };
    int32_t g_pointerSpeed { 5 };
    int32_t g_touchpadRightClickType { 1 };
    int32_t g_touchpadPointerSpeed { 9 };
    bool g_touchpadTapSwitch { true };
    bool g_touchpadScrollDirection { true };
    bool g_touchpadScrollSwitch { true };
    bool g_touchpadPinchSwitch { true };
    bool g_touchpadSwipeSwitch { true };
    bool g_hoverScrollState { true };
    int32_t g_pointerColor { -1 };
    int32_t g_pointerSize { 1 };
    int32_t g_pointerStyle { 0 };
    const std::string keyboardRepeatRate = "keyboardRepeatRate";
    const std::string keyboardRepeatDelay = "keyboardRepeatDelay";
    const std::string mouseScrollRows = "rows";
    const std::string mousePrimaryButton = "primaryButton";
    const std::string pointerSpeed = "speed";
    const std::string touchpadRightClickType = "rightMenuSwitch";
    const std::string touchpadPointerSpeed = "touchPadPointerSpeed";
    const std::string touchpadTapSwitch = "touchpadTap";
    const std::string touchpadScrollDirection = "scrollDirection";
    const std::string touchpadScrollSwitch = "scrollSwitch";
    const std::string touchpadPinchSwitch = "touchpadPinch";
    const std::string touchpadSwipeSwitch = "touchpadSwipe";
    const std::string hoverScrollState = "isEnableHoverScroll";
    const std::string pointerColor = "pointerColor";
    const std::string pointerSize = "pointerSize";
    const std::string pointerStyle = "pointerStyle";
};

#define PREFERENCES_MGR ::OHOS::DelayedSingleton<MultiModalInputPreferencesManager>::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // MULTIMODAL_INPUT_PREFERENCES_MANAGER_H