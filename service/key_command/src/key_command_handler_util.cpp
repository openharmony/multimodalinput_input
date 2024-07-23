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

bool GetBusinessId(const cJSON* jsonData, std::string &businessIdValue, std::vector<std::string> &businessIds)
{
    if (!cJSON_IsObject(jsonData)) {
        MMI_HILOGE("jsonData is not object");
        return false;
    }
    cJSON *businessId = cJSON_GetObjectItemCaseSensitive(jsonData, "businessId");
    if (!cJSON_IsString(businessId)) {
        MMI_HILOGE("businessId is not string");
        return false;
    }
    businessIdValue = businessId->valuestring;
    businessIds.push_back(businessIdValue);
    return true;
}

bool GetPreKeys(const cJSON* jsonData, ShortcutKey &shortcutKey)
{
    if (!cJSON_IsObject(jsonData)) {
        MMI_HILOGE("jsonData is not object");
        return false;
    }
    cJSON* preKey = cJSON_GetObjectItemCaseSensitive(jsonData, "preKey");
    if (!cJSON_IsArray(preKey)) {
        MMI_HILOGE("preKey number must be array");
        return false;
    }
    int32_t preKeySize = cJSON_GetArraySize(preKey);
    if (preKeySize > MAX_PREKEYS_NUM) {
        MMI_HILOGE("preKeySize number must less and equal four");
        return false;
    }
    for (int32_t i = 0; i < preKeySize; ++i) {
        cJSON *preKeyJson = cJSON_GetArrayItem(preKey, i);
        if (!cJSON_IsNumber(preKeyJson)) {
            MMI_HILOGE("preKeyJson is not number");
            return false;
        }
        if (preKeyJson->valueint < 0) {
            MMI_HILOGE("preKeyJson must be number and bigger or equal than 0");
            return false;
        }
        if (!shortcutKey.preKeys.emplace(preKeyJson->valueint).second) {
            MMI_HILOGE("preKeyJson must be unduplicated");
            return false;
        }
    }
    return true;
}

bool GetTrigger(const cJSON* jsonData, int32_t &triggerType)
{
    if (!cJSON_IsObject(jsonData)) {
        MMI_HILOGE("jsonData is not object");
        return false;
    }
    cJSON *trigger = cJSON_GetObjectItemCaseSensitive(jsonData, "trigger");
    if (!cJSON_IsString(trigger)) {
        MMI_HILOGE("trigger is not string");
        return false;
    }
    if (((std::strcmp(trigger->valuestring, "key_up") != 0)
        && (std::strcmp(trigger->valuestring, "key_down") != 0))) {
        MMI_HILOGE("trigger must be one of [key_up, key_down]");
        return false;
    }
    if (std::strcmp(trigger->valuestring, "key_up") == 0) {
        triggerType = KeyEvent::KEY_ACTION_UP;
    } else {
        triggerType = KeyEvent::KEY_ACTION_DOWN;
    }
    return true;
}

bool GetKeyDownDuration(const cJSON* jsonData, int32_t &keyDownDurationInt)
{
    if (!cJSON_IsObject(jsonData)) {
        MMI_HILOGE("jsonData is not object");
        return false;
    }
    cJSON *keyDownDuration = cJSON_GetObjectItemCaseSensitive(jsonData, "keyDownDuration");
    if (!cJSON_IsNumber(keyDownDuration)) {
        MMI_HILOGE("keyDownDuration is not number");
        return false;
    }
    if (keyDownDuration->valueint < 0) {
        MMI_HILOGE("keyDownDuration must be number and bigger and equal zero");
        return false;
    }
    keyDownDurationInt = keyDownDuration->valueint;
    return true;
}

bool GetKeyFinalKey(const cJSON* jsonData, int32_t &finalKeyInt)
{
    if (!cJSON_IsObject(jsonData)) {
        MMI_HILOGE("jsonData is not object");
        return false;
    }
    cJSON *finalKey = cJSON_GetObjectItemCaseSensitive(jsonData, "finalKey");
    if (!cJSON_IsNumber(finalKey)) {
        MMI_HILOGE("finalKey must be number");
        return false;
    }
    finalKeyInt = finalKey->valueint;
    return true;
}

void GetKeyVal(const cJSON* json, const std::string &key, std::string &value)
{
    if (!cJSON_IsObject(json)) {
        MMI_HILOGE("json is not object");
        return;
    }
    cJSON *valueJson = cJSON_GetObjectItemCaseSensitive(json, key.c_str());
    if (cJSON_IsString(valueJson)) {
        value = valueJson->valuestring;
    }
}

bool GetEntities(const cJSON* jsonAbility, Ability &ability)
{
    if (!cJSON_IsObject(jsonAbility)) {
        MMI_HILOGE("jsonAbility is not object");
        return false;
    }
    cJSON *entities = cJSON_GetObjectItemCaseSensitive(jsonAbility, "entities");
    if (entities == nullptr) {
        return true;
    }
    if (!cJSON_IsArray(entities)) {
        MMI_HILOGE("entities must be array");
        return false;
    }
    int32_t entitySize = cJSON_GetArraySize(entities);
    for (int32_t i = 0; i < entitySize; i++) {
        cJSON* entity = cJSON_GetArrayItem(entities, i);
        if (!cJSON_IsString(entity)) {
            MMI_HILOGE("entity is not string");
            return false;
        }
        ability.entities.push_back(entity->valuestring);
    }
    return true;
}

bool GetParams(const cJSON* jsonAbility, Ability &ability)
{
    if (!cJSON_IsObject(jsonAbility)) {
        MMI_HILOGE("jsonAbility is not object");
        return false;
    }
    cJSON *params = cJSON_GetObjectItemCaseSensitive(jsonAbility, "params");
    if (params == nullptr) {
        return true;
    }
    if (!cJSON_IsArray(params)) {
        MMI_HILOGE("params must be array");
        return false;
    }
    int32_t paramsSize = cJSON_GetArraySize(params);
    for (int32_t i = 0; i < paramsSize; ++i) {
        cJSON* param = cJSON_GetArrayItem(params, i);
        if (!cJSON_IsObject(param)) {
            MMI_HILOGE("param must be object");
            return false;
        }
        cJSON* key = cJSON_GetObjectItemCaseSensitive(param, "key");
        if (!cJSON_IsString(key)) {
            MMI_HILOGE("key is not string");
            return false;
        }
        cJSON* value = cJSON_GetObjectItemCaseSensitive(param, "value");
        if (!cJSON_IsString(value)) {
            MMI_HILOGE("value is not string");
            return false;
        }
        auto ret = ability.params.emplace(key->valuestring, value->valuestring);
        if (!ret.second) {
            MMI_HILOGW("key is duplicated");
        }
    }
    return true;
}

bool PackageAbility(const cJSON* jsonAbility, Ability &ability)
{
    if (!cJSON_IsObject(jsonAbility)) {
        MMI_HILOGE("JsonAbility is not object");
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

bool ConvertToShortcutKey(const cJSON* jsonData, ShortcutKey &shortcutKey, std::vector<std::string> &businessIds)
{
    if (!cJSON_IsObject(jsonData)) {
        MMI_HILOGE("jsonData is not object");
        return false;
    }
    if (!GetBusinessId(jsonData, shortcutKey.businessId, businessIds)) {
        MMI_HILOGW("Get abilityKey failed");
    }
    if (!GetPreKeys(jsonData, shortcutKey)) {
        MMI_HILOGE("Get preKeys failed");
        return false;
    }
    if (!GetKeyFinalKey(jsonData, shortcutKey.finalKey)) {
        MMI_HILOGE("Get finalKey failed");
        return false;
    }
    if (!GetTrigger(jsonData, shortcutKey.triggerType)) {
        MMI_HILOGE("Get trigger failed");
        return false;
    }
    if (!GetKeyDownDuration(jsonData, shortcutKey.keyDownDuration)) {
        MMI_HILOGE("Get downDuration failed");
        return false;
    }

    GetKeyVal(jsonData, "statusConfig", shortcutKey.statusConfig);

    cJSON *ability = cJSON_GetObjectItemCaseSensitive(jsonData, "ability");
    if (!cJSON_IsObject(ability)) {
        MMI_HILOGE("ability is not object");
        return false;
    }
    if (!PackageAbility(ability, shortcutKey.ability)) {
        MMI_HILOGE("Package ability failed");
        return false;
    }
    return true;
}

bool GetKeyCode(const cJSON* jsonData, int32_t &keyCodeInt)
{
    if (!cJSON_IsObject(jsonData)) {
        MMI_HILOGE("jsonData is not object");
        return false;
    }
    cJSON *keyCode = cJSON_GetObjectItemCaseSensitive(jsonData, "keyCode");
    if (!cJSON_IsNumber(keyCode)) {
        MMI_HILOGE("keyCode is not number");
        return false;
    }
    if (keyCode->valueint < 0) {
        MMI_HILOGE("keyCode must be number and bigger and equal zero");
        return false;
    }
    keyCodeInt = keyCode->valueint;
    return true;
}

bool GetKeyAction(const cJSON* jsonData, int32_t &keyActionInt)
{
    if (!cJSON_IsObject(jsonData)) {
        MMI_HILOGE("jsonData is not object");
        return false;
    }
    cJSON *keyAction = cJSON_GetObjectItemCaseSensitive(jsonData, "keyAction");
    if (!cJSON_IsNumber(keyAction)) {
        MMI_HILOGE("keyAction is not number");
        return false;
    }
    if ((keyAction->valueint != KeyEvent::KEY_ACTION_DOWN) && (keyAction->valueint != KeyEvent::KEY_ACTION_UP)) {
        MMI_HILOGE("keyAction must be down or up");
        return false;
    }
    keyActionInt = keyAction->valueint;
    return true;
}

bool GetDelay(const cJSON* jsonData, int64_t &delayInt)
{
    if (!cJSON_IsObject(jsonData)) {
        MMI_HILOGE("jsonData is not object");
        return false;
    }
    cJSON *delay = cJSON_GetObjectItemCaseSensitive(jsonData, "delay");
    if (!cJSON_IsNumber(delay)) {
        MMI_HILOGE("delay is not number");
        return false;
    }
    if ((delay->valueint < 0) || (delay->valueint > MAX_DELAY_TIME)) {
        MMI_HILOGE("delay must be number and bigger and equal zero and less than max delay");
        return false;
    }
    delayInt = delay->valueint * SECONDS_SYSTEM;
    return true;
}

bool GetRepeatTimes(const cJSON* jsonData, int32_t &repeatTimesInt)
{
    if (!cJSON_IsObject(jsonData)) {
        MMI_HILOGE("GetRepeatTimes jsonData is not object");
        return false;
    }
    cJSON *repeatTimes = cJSON_GetObjectItemCaseSensitive(jsonData, "times");
    if (!cJSON_IsNumber(repeatTimes)) {
        MMI_HILOGE("repeatTimes is not number");
        return false;
    }
    if (repeatTimes->valueint < 0) {
        MMI_HILOGE("repeatTimes must be number and bigger and equal zero");
        return false;
    }
    repeatTimesInt = repeatTimes->valueint;
    return true;
}

bool GetAbilityStartDelay(const cJSON* jsonData, int64_t &abilityStartDelayInt)
{
    if (!cJSON_IsObject(jsonData)) {
        MMI_HILOGE("jsonData is not object");
        return false;
    }
    cJSON *abilityStartDelay = cJSON_GetObjectItemCaseSensitive(jsonData, "abilityStartDelay");
    if (!cJSON_IsNumber(abilityStartDelay)) {
        MMI_HILOGE("abilityStartDelay is not number");
        return false;
    }
    if ((abilityStartDelay->valueint < 0) || (abilityStartDelay->valueint > MAX_DELAY_TIME)) {
        MMI_HILOGE("abilityStartDelay must be number and bigger and equal zero and less than max delay time");
        return false;
    }
    abilityStartDelayInt = abilityStartDelay->valueint;
    return true;
}

bool PackageSequenceKey(const cJSON* sequenceKeysJson, SequenceKey &sequenceKey)
{
    if (!cJSON_IsObject(sequenceKeysJson)) {
        MMI_HILOGE("sequenceKeysJson is not object");
        return false;
    }
    if (!GetKeyCode(sequenceKeysJson, sequenceKey.keyCode)) {
        MMI_HILOGE("Get keyCode failed");
        return false;
    }
    if (!GetKeyAction(sequenceKeysJson, sequenceKey.keyAction)) {
        MMI_HILOGE("Get keyAction failed");
        return false;
    }
    if (!GetDelay(sequenceKeysJson, sequenceKey.delay)) {
        MMI_HILOGE("Get delay failed");
        return false;
    }
    return true;
}

bool GetSequenceKeys(const cJSON* jsonData, Sequence &sequence)
{
    if (!cJSON_IsObject(jsonData)) {
        MMI_HILOGE("jsonData is not object");
        return false;
    }
    cJSON* sequenceKeys = cJSON_GetObjectItemCaseSensitive(jsonData, "sequenceKeys");
    if (!cJSON_IsArray(sequenceKeys)) {
        MMI_HILOGE("sequenceKeys number must be array");
        return false;
    }
    int32_t sequenceKeysSize = cJSON_GetArraySize(sequenceKeys);
    if (sequenceKeysSize > MAX_SEQUENCEKEYS_NUM) {
        MMI_HILOGE("sequenceKeysSize number must less and equal %{public}d", MAX_SEQUENCEKEYS_NUM);
        return false;
    }
    for (int32_t i = 0; i < sequenceKeysSize; ++i) {
        cJSON *sequenceKeysJson = cJSON_GetArrayItem(sequenceKeys, i);
        if (!cJSON_IsObject(sequenceKeysJson)) {
            MMI_HILOGE("sequenceKeysJson is not object");
            return false;
        }
        SequenceKey sequenceKey;
        if (!PackageSequenceKey(sequenceKeysJson, sequenceKey)) {
            MMI_HILOGE("Packege sequenceKey failed");
            return false;
        }
        sequence.sequenceKeys.push_back(sequenceKey);
    }
    return true;
}

bool IsSequenceKeysValid(const Sequence &sequence)
{
    if (sequence.sequenceKeys.empty()) {
        MMI_HILOGE("sequenceKeys can not be empty");
        return false;
    }

    if (sequence.sequenceKeys.size() > MAX_SEQUENCEKEYS_NUM) {
        MMI_HILOGE("sequenceKeys size must less or equal to %{public}d", MAX_SEQUENCEKEYS_NUM);
        return false;
    }

    std::map<int32_t, SequenceKey> sequenceKeys;
    for (const SequenceKey& item : sequence.sequenceKeys) {
        if (sequenceKeys.find(item.keyCode) == sequenceKeys.end()) {
            auto it = sequenceKeys.emplace(item.keyCode, item);
            if (!it.second) {
                MMI_HILOGE("keyCode is duplicated");
                return false;
            }
        } else {
            if (sequenceKeys[item.keyCode].keyAction == item.keyAction) {
                MMI_HILOGE("sequenceKeys illegal");
                return false;
            }
            sequenceKeys[item.keyCode].keyAction = item.keyAction;
            sequenceKeys[item.keyCode].delay = item.delay;
        }
    }
    return true;
}

bool ConvertToKeySequence(const cJSON* jsonData, Sequence &sequence)
{
    if (!cJSON_IsObject(jsonData)) {
        MMI_HILOGE("jsonData is not object");
        return false;
    }
    if (!GetSequenceKeys(jsonData, sequence)) {
        MMI_HILOGE("Get sequenceKeys failed");
        return false;
    }
    if (!IsSequenceKeysValid(sequence)) {
        MMI_HILOGE("Sequence invalid");
        return false;
    }
    if (!GetAbilityStartDelay(jsonData, sequence.abilityStartDelay)) {
        MMI_HILOGE("Get abilityStartDelay failed");
        return false;
    }

    GetKeyVal(jsonData, "statusConfig", sequence.statusConfig);

    cJSON *ability = cJSON_GetObjectItemCaseSensitive(jsonData, "ability");
    if (!cJSON_IsObject(ability)) {
        MMI_HILOGE("ability is not object");
        return false;
    }
    if (!PackageAbility(ability, sequence.ability)) {
        MMI_HILOGE("Package ability failed");
        return false;
    }
    return true;
}

bool ConvertToExcludeKey(const cJSON* jsonData, ExcludeKey &exKey)
{
    cJSON *keyCodeJson = cJSON_GetObjectItemCaseSensitive(jsonData, "keyCode");
    if (!cJSON_IsNumber(keyCodeJson)) {
        MMI_HILOGE("keyCodeJson is not number");
        return false;
    }
    exKey.keyCode = keyCodeJson->valueint;

    cJSON *keyActionJson = cJSON_GetObjectItemCaseSensitive(jsonData, "keyAction");
    if (!cJSON_IsNumber(keyActionJson)) {
        MMI_HILOGE("keyActionJson is not number");
        return false;
    }
    exKey.keyAction = keyActionJson->valueint;

    cJSON *delayJson = cJSON_GetObjectItemCaseSensitive(jsonData, "delay");
    if (!cJSON_IsNumber(delayJson)) {
        MMI_HILOGE("delayJson is not number");
        return false;
    }
    exKey.delay = delayJson->valueint;

    return true;
}

bool ConvertToKeyRepeat(const cJSON* jsonData, RepeatKey &repeatKey)
{
    if (!cJSON_IsObject(jsonData)) {
        MMI_HILOGE("jsonData is not object");
        return false;
    }

    if (!GetKeyCode(jsonData, repeatKey.keyCode)) {
        MMI_HILOGE("Get keyCode failed");
        return false;
    }

    if (!GetRepeatTimes(jsonData, repeatKey.times)) {
        MMI_HILOGE("Get repeatTimes failed");
        return false;
    }

    if (!GetDelay(jsonData, repeatKey.delay)) {
        MMI_HILOGE("Get delay failed");
        return false;
    }

    GetKeyVal(jsonData, "statusConfig", repeatKey.statusConfig);

    cJSON *ability = cJSON_GetObjectItemCaseSensitive(jsonData, "ability");
    if (!cJSON_IsObject(ability)) {
        MMI_HILOGE("ability is not object");
        return false;
    }
    if (!PackageAbility(ability, repeatKey.ability)) {
        MMI_HILOGE("Package ability failed");
        return false;
    }
    return true;
}

std::string GenerateKey(const ShortcutKey& key)
{
    std::set<int32_t> preKeys = key.preKeys;
    std::stringstream ss;
    for (const auto& preKey : preKeys) {
        ss << preKey << ",";
    }
    ss << key.finalKey << ",";
    ss << key.triggerType << ",";
    ss << key.keyDownDuration;
    return std::string(ss.str());
}

bool ParseShortcutKeys(const JsonParser& parser, std::map<std::string, ShortcutKey>& shortcutKeyMap,
    std::vector<std::string>& businessIds)
{
    cJSON* shortkeys = cJSON_GetObjectItemCaseSensitive(parser.json_, "Shortkeys");
    if (!cJSON_IsArray(shortkeys)) {
        MMI_HILOGE("shortkeys is not array");
        return false;
    }
    int32_t shortkeysSize = cJSON_GetArraySize(shortkeys);
    for (int32_t i = 0; i < shortkeysSize; ++i) {
        ShortcutKey shortcutKey;
        cJSON *shortkey = cJSON_GetArrayItem(shortkeys, i);
        if (!cJSON_IsObject(shortkey)) {
            continue;
        }
        if (!ConvertToShortcutKey(shortkey, shortcutKey, businessIds)) {
            continue;
        }
        std::string key = GenerateKey(shortcutKey);
        if (shortcutKeyMap.find(key) == shortcutKeyMap.end()) {
            if (!shortcutKeyMap.emplace(key, shortcutKey).second) {
                MMI_HILOGW("Duplicate shortcutKey:%{private}s", key.c_str());
            }
        }
    }
    return true;
}

bool ParseSequences(const JsonParser& parser, std::vector<Sequence>& sequenceVec)
{
    cJSON* sequences = cJSON_GetObjectItemCaseSensitive(parser.json_, "Sequences");
    if (!cJSON_IsArray(sequences)) {
        MMI_HILOGE("sequences is not array");
        return false;
    }
    int32_t sequencesSize = cJSON_GetArraySize(sequences);
    for (int32_t i = 0; i < sequencesSize; ++i) {
        Sequence seq;
        cJSON *sequence = cJSON_GetArrayItem(sequences, i);
        if (!cJSON_IsObject(sequence)) {
            continue;
        }
        if (!ConvertToKeySequence(sequence, seq)) {
            continue;
        }
        sequenceVec.push_back(seq);
    }
    return true;
}

bool ParseExcludeKeys(const JsonParser& parser, std::vector<ExcludeKey>& excludeKeyVec)
{
    cJSON* excludeKeys = cJSON_GetObjectItemCaseSensitive(parser.json_, "excludeKeys");
    if (!cJSON_IsArray(excludeKeys)) {
        MMI_HILOGE("excludeKeys is not array");
        return false;
    }
    int32_t excludeKeysSize = cJSON_GetArraySize(excludeKeys);
    for (int32_t i = 0; i < excludeKeysSize; ++i) {
        ExcludeKey exKey;
        cJSON *keyJson = cJSON_GetArrayItem(excludeKeys, i);
        if (!cJSON_IsObject(keyJson)) {
            continue;
        }
        if (!ConvertToExcludeKey(keyJson, exKey)) {
            continue;
        }
        excludeKeyVec.push_back(exKey);
    }
    return true;
}

bool ParseRepeatKeys(const JsonParser& parser, std::vector<RepeatKey>& repeatKeyVec)
{
    cJSON* repeatKeys = cJSON_GetObjectItemCaseSensitive(parser.json_, "RepeatKeys");
    if (!cJSON_IsArray(repeatKeys)) {
        MMI_HILOGE("repeatKeys is not array");
        return false;
    }
    int32_t repeatKeysSize = cJSON_GetArraySize(repeatKeys);
    for (int32_t i = 0; i < repeatKeysSize; i++) {
        cJSON *repeatKey = cJSON_GetArrayItem(repeatKeys, i);
        if (!cJSON_IsObject(repeatKey)) {
            continue;
        }
        RepeatKey rep;
        if (!ConvertToKeyRepeat(repeatKey, rep)) {
            continue;
        }
        repeatKeyVec.push_back(rep);
    }

    return true;
}

bool ParseTwoFingerGesture(const JsonParser& parser, TwoFingerGesture& gesture)
{
    cJSON *jsonData = cJSON_GetObjectItemCaseSensitive(parser.json_, "TwoFingerGesture");
    if (!cJSON_IsObject(jsonData)) {
        MMI_HILOGE("TwoFingerGesture is not object");
        return false;
    }
    if (!GetAbilityStartDelay(jsonData, gesture.abilityStartDelay)) {
        MMI_HILOGE("Get abilityStartDelay failed");
        return false;
    }
    cJSON *ability = cJSON_GetObjectItemCaseSensitive(jsonData, "ability");
    if (!cJSON_IsObject(ability)) {
        MMI_HILOGE("ability is not object");
        return false;
    }
    if (!PackageAbility(ability, gesture.ability)) {
        MMI_HILOGE("Package ability failed");
        return false;
    }
    gesture.active = true;
    return true;
}

bool IsPackageKnuckleGesture(const cJSON* jsonData, const std::string knuckleGesture, Ability &launchAbility)
{
    cJSON *knuckleGestureData = cJSON_GetObjectItemCaseSensitive(jsonData, knuckleGesture.c_str());
    if (!cJSON_IsObject(knuckleGestureData)) {
        MMI_HILOGE("KnuckleGestureData is not object");
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
    cJSON *jsonData = cJSON_GetObjectItemCaseSensitive(parser.json_, "KnuckleGesture");
    if (!cJSON_IsObject(jsonData)) {
        MMI_HILOGE("KnuckleGesture is not object");
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
        pow(knuckleGesture.lastDownPointer.y  - item.GetDisplayY(), POW_SQUARE)));
}

bool IsEqual(float f1, float f2)
{
    return (std::fabs(f1 - f2) <= std::numeric_limits<double>::epsilon());
}

bool ParseMultiFingersTap(const JsonParser &parser, const std::string ability, MultiFingersTap &mulFingersTap)
{
    cJSON *jsonData = cJSON_GetObjectItemCaseSensitive(parser.json_, "TouchPadMultiFingersTap");
    if (!cJSON_IsObject(jsonData)) {
        MMI_HILOGE("MultiFingersTap is not object");
        return false;
    }
    if (!IsPackageKnuckleGesture(jsonData, ability, mulFingersTap.ability)) {
        MMI_HILOGE("Package mulFingersTap gesture failed");
        return false;
    }
    return true;
}
} // namespace MMI
} // namespace OHOS