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

void GetKeyVal(const cJSON* json, const std::string &key, std::string &value)
{
    if (!cJSON_IsObject(json)) {
        MMI_HILOGE("The json is not object");
        return;
    }
    cJSON *valueJson = cJSON_GetObjectItemCaseSensitive(json, key.c_str());
    if (valueJson == nullptr) {
        MMI_HILOGE("The value json init failed");
        return;
    }
    if (cJSON_IsString(valueJson)) {
        value = valueJson->valuestring;
    }
}

bool GetEntities(const cJSON* jsonAbility, Ability &ability)
{
    if (!cJSON_IsObject(jsonAbility)) {
        MMI_HILOGE("The json ability is not object");
        return false;
    }
    cJSON *entities = cJSON_GetObjectItemCaseSensitive(jsonAbility, "entities");
    if (entities == nullptr) {
        return true;
    }
    if (!cJSON_IsArray(entities)) {
        MMI_HILOGE("The entities must be array");
        return false;
    }
    int32_t entitySize = cJSON_GetArraySize(entities);
    for (int32_t i = 0; i < entitySize; i++) {
        cJSON* entity = cJSON_GetArrayItem(entities, i);
        if (entity == nullptr) {
            MMI_HILOGE("The entity init failed");
            continue;
        }
        if (!cJSON_IsString(entity)) {
            MMI_HILOGE("The entity is not string");
            return false;
        }
        ability.entities.push_back(entity->valuestring);
    }
    return true;
}

bool GetParams(const cJSON* jsonAbility, Ability &ability)
{
    if (!cJSON_IsObject(jsonAbility)) {
        MMI_HILOGE("The json ability is not object");
        return false;
    }
    cJSON *params = cJSON_GetObjectItemCaseSensitive(jsonAbility, "params");
    if (params == nullptr) {
        return true;
    }
    if (!cJSON_IsArray(params)) {
        MMI_HILOGE("The params must be array");
        return false;
    }
    int32_t paramsSize = cJSON_GetArraySize(params);
    for (int32_t i = 0; i < paramsSize; ++i) {
        cJSON* param = cJSON_GetArrayItem(params, i);
        if (!cJSON_IsObject(param)) {
            MMI_HILOGE("The param must be object");
            return false;
        }
        cJSON* key = cJSON_GetObjectItemCaseSensitive(param, "key");
        if (!cJSON_IsString(key)) {
            MMI_HILOGE("The key is not string");
            return false;
        }
        cJSON* value = cJSON_GetObjectItemCaseSensitive(param, "value");
        if (!cJSON_IsString(value)) {
            MMI_HILOGE("The value is not string");
            return false;
        }
        auto ret = ability.params.emplace(key->valuestring, value->valuestring);
        if (!ret.second) {
            MMI_HILOGW("The key is duplicated");
        }
    }
    return true;
}

bool PackageAbility(const cJSON* jsonAbility, Ability &ability)
{
    if (!cJSON_IsObject(jsonAbility)) {
        MMI_HILOGE("The json ability is not object");
        return false;
    }
    GetKeyVal(jsonAbility, "bundleName", ability.bundleName);
    GetKeyVal(jsonAbility, "abilityName", ability.abilityName);
    GetKeyVal(jsonAbility, "action", ability.action);
    GetKeyVal(jsonAbility, "type", ability.type);
    GetKeyVal(jsonAbility, "deviceId", ability.deviceId);
    GetKeyVal(jsonAbility, "uri", ability.uri);
    GetKeyVal(jsonAbility, "abilityType", ability.abilityType);
    if (!GetEntities(jsonAbility, ability)) {
        MMI_HILOGE("Get centities failed");
        return false;
    }
    if (!GetParams(jsonAbility, ability)) {
        MMI_HILOGE("Get params failed");
        return false;
    }
    return true;
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

bool IsPackageKnuckleGesture(const cJSON* jsonData, const std::string knuckleGesture, Ability &launchAbility)
{
    if (!cJSON_IsObject(jsonData)) {
        MMI_HILOGE("The jsonData is not object");
        return false;
    }
    cJSON *knuckleGestureData = cJSON_GetObjectItemCaseSensitive(jsonData, knuckleGesture.c_str());
    if (!cJSON_IsObject(knuckleGestureData)) {
        MMI_HILOGE("Knuckle gesture data is not object");
        return false;
    }
    if (!cJSON_IsObject(knuckleGestureData)) {
        MMI_HILOGE("The knuckleGestureData is not object");
        return false;
    }
    cJSON *ability = cJSON_GetObjectItemCaseSensitive(knuckleGestureData, "ability");
    if (!cJSON_IsObject(ability)) {
        MMI_HILOGE("Ability is not object");
        return false;
    }
    if (!PackageAbility(ability, launchAbility)) {
        MMI_HILOGE("Package ability failed");
        return false;
    }
    return true;
}

bool IsParseKnuckleGesture(const JsonParser &parser, const std::string ability, KnuckleGesture &knuckleGesture)
{
    if (!cJSON_IsObject(parser.Get())) {
        MMI_HILOGE("The parser is not object");
        return false;
    }
    cJSON *jsonData = cJSON_GetObjectItemCaseSensitive(parser.Get(), "KnuckleGesture");
    if (!cJSON_IsObject(jsonData)) {
        MMI_HILOGE("Knuckle gesture is not object");
        return false;
    }
    if (!IsPackageKnuckleGesture(jsonData, ability, knuckleGesture.ability)) {
        MMI_HILOGE("Package knuckle gesture failed");
        return false;
    }
    return true;
}

float AbsDiff(KnuckleGesture knuckleGesture, const std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPR(pointerEvent, -1);
    auto id = pointerEvent->GetPointerId();
    PointerEvent::PointerItem item;
    pointerEvent->GetPointerItem(id, item);
    return static_cast<float>(sqrt(pow(knuckleGesture.lastDownPointer.x - item.GetDisplayX(), POW_SQUARE) +
        pow(knuckleGesture.lastDownPointer.y - item.GetDisplayY(), POW_SQUARE)));
}

bool IsEqual(float f1, float f2)
{
    return (std::fabs(f1 - f2) <= std::numeric_limits<double>::epsilon());
}

bool ParseMultiFingersTap(const JsonParser &parser, const std::string ability, MultiFingersTap &mulFingersTap)
{
    if (!cJSON_IsObject(parser.Get())) {
        MMI_HILOGE("The parser is not object");
        return false;
    }
    cJSON *jsonData = cJSON_GetObjectItemCaseSensitive(parser.Get(), "TouchPadMultiFingersTap");
    if (!cJSON_IsObject(jsonData)) {
        MMI_HILOGE("Multi fingers tap is not object");
        return false;
    }
    if (!IsPackageKnuckleGesture(jsonData, ability, mulFingersTap.ability)) {
        MMI_HILOGE("Package mulFingersTap gesture failed");
        return false;
    }
    return true;
}

char* GetProFileAbsPath(const char* fileName, char* buf, int32_t length)
{
    return ::GetOneCfgFile(fileName, buf, length);
}
} // namespace MMI
} // namespace OHOS