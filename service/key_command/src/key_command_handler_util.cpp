/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "key_command_handler_util.h"
#include "json_parser.h"

#ifdef SHORTCUT_KEY_MANAGER_ENABLED
#include "key_shortcut_manager.h"
#endif // SHORTCUT_KEY_MANAGER_ENABLED

namespace OHOS {
namespace MMI {
bool IsSpecialType(int32_t keyCode, SpecialType type)
{
    auto it = SPECIAL_KEYS.find(keyCode);
    if (it == SPECIAL_KEYS.end()) {
        return false;
    }
    return (it->second == SpecialType::SPECIAL_ALL || it->second == type);
}

bool GetAbilityStartDelay(const cJSON* jsonData, int64_t &abilityStartDelayInt)
{
    if (!cJSON_IsObject(jsonData)) {
        MMI_HILOGE("The json Data is not object");
        return false;
    }
    cJSON *abilityStartDelay = cJSON_GetObjectItemCaseSensitive(jsonData, "abilityStartDelay");
    if (abilityStartDelay == nullptr) {
        MMI_HILOGE("The ability start delay init failed");
        return false;
    }
    if (!cJSON_IsNumber(abilityStartDelay)) {
        MMI_HILOGE("The ability start delay is not number");
        return false;
    }
    if ((abilityStartDelay->valueint < 0) || (abilityStartDelay->valueint > MAX_ABILITYSTARTDELAY_TIME)) {
        MMI_HILOGE("The ability start delay must be number and bigger and equal zero and less than max delay time");
        return false;
    }
    abilityStartDelayInt = abilityStartDelay->valueint;
    return true;
}

#ifdef SHORTCUT_KEY_MANAGER_ENABLED
static int32_t RegisterSystemKey(const ShortcutKey &shortcutKey,
    std::function<void(std::shared_ptr<KeyEvent>)> callback)
{
    KeyShortcutManager::SystemShortcutKey sysKey {
        .modifiers = shortcutKey.preKeys,
        .finalKey = shortcutKey.finalKey,
        .longPressTime = shortcutKey.keyDownDuration,
        .triggerType = (shortcutKey.triggerType == KeyEvent::KEY_ACTION_DOWN ?
            KeyShortcutManager::SHORTCUT_TRIGGER_TYPE_DOWN : KeyShortcutManager::SHORTCUT_TRIGGER_TYPE_UP),
        .callback = callback,
    };
    return KEY_SHORTCUT_MGR->RegisterSystemKey(sysKey);
}
#endif // SHORTCUT_KEY_MANAGER_ENABLED


char* GetProFileAbsPath(const char* fileName, char* buf, int32_t length)
{
    return ::GetOneCfgFile(fileName, buf, length);
}
} // namespace MMI
} // namespace OHOS