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

#include "key_command_handler.h"

#include "ability_manager_client.h"
#include "bytrace_adapter.h"
#include "cJSON.h"
#include "config_policy_utils.h"
#include "file_ex.h"
#include "setting_datashare.h"
#include "system_ability_definition.h"

#include "define_multimodal.h"
#include "dfx_hisysevent.h"
#include "error_multimodal.h"
#include "input_event_data_transformation.h"
#include "input_event_handler.h"
#include "input_windows_manager.h"
#include "mmi_log.h"
#include "multimodal_input_preferences_manager.h"
#include "nap_process.h"
#include "net_packet.h"
#include "proto.h"
#include "stylus_key_handler.h"
#include "timer_manager.h"
#include "util_ex.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyCommandHandler"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t MAX_PREKEYS_NUM = 4;
constexpr int32_t MAX_SEQUENCEKEYS_NUM = 10;
constexpr int64_t MAX_DELAY_TIME = 1000000;
constexpr int64_t SECONDS_SYSTEM = 1000;
constexpr int32_t SPECIAL_KEY_DOWN_DELAY = 150;
constexpr int32_t MAX_SHORT_KEY_DOWN_DURATION = 4000;
constexpr int32_t MIN_SHORT_KEY_DOWN_DURATION = 0;
constexpr int32_t TOUCH_MAX_THRESHOLD = 20;
constexpr int32_t TWO_FINGERS_DISTANCE_LIMIT = 16;
constexpr int32_t TWO_FINGERS_TIME_LIMIT = 150000;
constexpr int32_t TOUCH_LIFT_LIMIT = 24;
constexpr int32_t TOUCH_RIGHT_LIMIT = 24;
constexpr int32_t TOUCH_TOP_LIMIT = 80;
constexpr int32_t TOUCH_BOTTOM_LIMIT = 41;
constexpr int32_t COMMON_PARAMETER_ERROR = 401;
constexpr int32_t KNUCKLE_KNOCKS = 1;
constexpr size_t SINGLE_KNUCKLE_SIZE = 1;
constexpr size_t DOUBLE_KNUCKLE_SIZE = 2;
constexpr int32_t MAX_TIME_FOR_ADJUST_CONFIG = 5;
constexpr int32_t POW_SQUARE = 2;
constexpr int64_t DOUBLE_CLICK_INTERVAL_TIME_DEFAULT = 250000;
constexpr int64_t DOUBLE_CLICK_INTERVAL_TIME_SLOW = 450000;
constexpr float DOUBLE_CLICK_DISTANCE_DEFAULT_CONFIG = 64.0f;
constexpr float DOUBLE_CLICK_DISTANCE_LONG_CONFIG = 96.0f;
constexpr float VPR_CONFIG = 3.25f;
constexpr int32_t REMOVE_OBSERVER = -2;
constexpr int32_t ACTIVE_EVENT = 2;
const std::string EXTENSION_ABILITY = "extensionAbility";
const std::string SINGLE_KNUCKLE_ABILITY = "SingleKnuckleDoubleClickGesture";
const std::string DOUBLE_KNUCKLE_ABILITY = "DoubleKnuckleDoubleClickGesture";
const std::string TOUCHPAD_TRIP_TAP_ABILITY = "ThreeFingersTap";
enum SpecialType {
    SPECIAL_ALL = 0,
    SUBSCRIBER_BEFORE_DELAY = 1,
    KEY_DOWN_ACTION = 2
};
const std::map<int32_t, SpecialType> SPECIAL_KEYS = {
    { KeyEvent::KEYCODE_POWER, SpecialType::KEY_DOWN_ACTION },
    { KeyEvent::KEYCODE_VOLUME_DOWN, SpecialType::SPECIAL_ALL },
    { KeyEvent::KEYCODE_VOLUME_UP, SpecialType::SPECIAL_ALL }
};
struct JsonParser {
    JsonParser() = default;
    ~JsonParser()
    {
        if (json_ != nullptr) {
            cJSON_Delete(json_);
        }
    }
    operator cJSON *()
    {
        return json_;
    }
    cJSON *json_ { nullptr };
};

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
    return;
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
            MMI_HILOGW("Emplace to failed");
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
                MMI_HILOGE("Emplace duplicated");
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
    ss << key.triggerType;
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
                MMI_HILOGW("Duplicate shortcutKey:%{public}s", key.c_str());
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

bool ParseRepeatKeys(const JsonParser& parser, std::vector<RepeatKey>& repeatKeyVec)
{
    cJSON* repeatKeys = cJSON_GetObjectItemCaseSensitive(parser.json_, "RepeatKeys");
    if (!cJSON_IsArray(repeatKeys)) {
        MMI_HILOGE("repeatKeys is not array");
        return false;
    }
    int32_t repeatKeysSize = cJSON_GetArraySize(repeatKeys);
    for (int32_t i = 0; i < repeatKeysSize; i++) {
        RepeatKey rep;
        cJSON *repeatKey = cJSON_GetArrayItem(repeatKeys, i);
        if (!cJSON_IsObject(repeatKey)) {
            continue;
        }
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
    return (float) sqrt(pow(knuckleGesture.lastDownPointer.x - item.GetDisplayX(), POW_SQUARE) +
        pow(knuckleGesture.lastDownPointer.y - item.GetDisplayY(), POW_SQUARE));
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
} // namespace

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
void KeyCommandHandler::HandleKeyEvent(const std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPV(keyEvent);
    if (OnHandleEvent(keyEvent)) {
        MMI_HILOGD("The keyEvent start launch an ability, keyCode:%{public}d", keyEvent->GetKeyCode());
        BytraceAdapter::StartBytrace(keyEvent, BytraceAdapter::KEY_LAUNCH_EVENT);
        return;
    }
    CHKPV(nextHandler_);
    nextHandler_->HandleKeyEvent(keyEvent);
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

#ifdef OHOS_BUILD_ENABLE_POINTER
void KeyCommandHandler::HandlePointerEvent(const std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPV(pointerEvent);
    if (OnHandleEvent(pointerEvent)) {
        MMI_HILOGD("The pointerEvent start launch an ability, pointAction:%{public}s",
            pointerEvent->DumpPointerAction());
    }
    CHKPV(nextHandler_);
    nextHandler_->HandlePointerEvent(pointerEvent);
}
#endif // OHOS_BUILD_ENABLE_POINTER

#ifdef OHOS_BUILD_ENABLE_TOUCH
void KeyCommandHandler::HandleTouchEvent(const std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPV(pointerEvent);
    CHKPV(nextHandler_);
    OnHandleTouchEvent(pointerEvent);
    if (isKnuckleState_) {
        MMI_HILOGD("current pointer event is knuckle");
        return;
    }
    nextHandler_->HandleTouchEvent(pointerEvent);
}

void KeyCommandHandler::OnHandleTouchEvent(const std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);
#ifdef OHOS_BUILD_ENABLE_FINGERSENSE_WRAPPER
    STYLUS_HANDLER->SetLastEventState(false);
#endif // OHOS_BUILD_ENABLE_FINGERSENSE_WRAPPER
    if (!isParseConfig_) {
        if (!ParseConfig()) {
            MMI_HILOGE("Parse configFile failed");
            return;
        }
        isParseConfig_ = true;
    }
    if (!isTimeConfig_) {
        SetKnuckleDoubleTapIntervalTime(DOUBLE_CLICK_INTERVAL_TIME_DEFAULT);
        isTimeConfig_ = true;
    }
    if (!isDistanceConfig_) {
        distanceDefaultConfig_ = DOUBLE_CLICK_DISTANCE_DEFAULT_CONFIG * VPR_CONFIG;
        distanceLongConfig_ = DOUBLE_CLICK_DISTANCE_LONG_CONFIG * VPR_CONFIG;
        SetKnuckleDoubleTapDistance(distanceDefaultConfig_);
        isDistanceConfig_ = true;
    }

    switch (touchEvent->GetPointerAction()) {
        case PointerEvent::POINTER_ACTION_CANCEL:
        case PointerEvent::POINTER_ACTION_UP: {
            HandlePointerActionUpEvent(touchEvent);
            break;
        }
        case PointerEvent::POINTER_ACTION_MOVE: {
            HandlePointerActionMoveEvent(touchEvent);
            break;
        }
        case PointerEvent::POINTER_ACTION_DOWN: {
            HandlePointerActionDownEvent(touchEvent);
            break;
        }
        default:
            // Don't care about other actions
            MMI_HILOGD("other action not match.");
            break;
    }
}

void KeyCommandHandler::HandlePointerActionDownEvent(const std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);
    auto id = touchEvent->GetPointerId();
    PointerEvent::PointerItem item;
    touchEvent->GetPointerItem(id, item);
    int32_t toolType = item.GetToolType();
    MMI_HILOGD("Pointer tool type:%{public}d", toolType);
    singleKnuckleGesture_.state = false;
    doubleKnuckleGesture_.state = false;
    switch (toolType) {
        case PointerEvent::TOOL_TYPE_FINGER: {
            isKnuckleState_ = false;
            HandleFingerGestureDownEvent(touchEvent);
            break;
        }
        case PointerEvent::TOOL_TYPE_KNUCKLE: {
            DfxHisysevent::ReportKnuckleClickEvent();
            HandleKnuckleGestureDownEvent(touchEvent);
            break;
        }
        default: {
            // other tool type are not processed
            isKnuckleState_ = false;
            MMI_HILOGD("Current touch event tool type:%{public}d", toolType);
            break;
        }
    }
}

void KeyCommandHandler::HandlePointerActionMoveEvent(const std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    if (!twoFingerGesture_.active) {
        return;
    }
    if (twoFingerGesture_.timerId == -1) {
        MMI_HILOGD("Two finger gesture timer id is -1.");
        return;
    }
    auto id = touchEvent->GetPointerId();
    auto pos = std::find_if(std::begin(twoFingerGesture_.touches), std::end(twoFingerGesture_.touches),
        [id](const auto& item) { return item.id == id; });
    if (pos == std::end(twoFingerGesture_.touches)) {
        return;
    }
    PointerEvent::PointerItem item;
    touchEvent->GetPointerItem(id, item);
    auto dx = std::abs(pos->x - item.GetDisplayX());
    auto dy = std::abs(pos->y - item.GetDisplayY());
    auto moveDistance = sqrt(pow(dx, 2) + pow(dy, 2));
    if (moveDistance > ConvertVPToPX(TOUCH_MAX_THRESHOLD)) {
        StopTwoFingerGesture();
    }
}

void KeyCommandHandler::HandlePointerActionUpEvent(const std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);
    auto id = touchEvent->GetPointerId();
    PointerEvent::PointerItem item;
    touchEvent->GetPointerItem(id, item);
    int32_t toolType = item.GetToolType();
    switch (toolType) {
        case PointerEvent::TOOL_TYPE_FINGER: {
            HandleFingerGestureUpEvent(touchEvent);
            break;
        }
        case PointerEvent::TOOL_TYPE_KNUCKLE: {
            HandleKnuckleGestureUpEvent(touchEvent);
            break;
        }
        default: {
            // other tool type are not processed
            MMI_HILOGW("Current touch event tool type:%{public}d", toolType);
            break;
        }
    }
}

void KeyCommandHandler::HandleFingerGestureDownEvent(const std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    if (!twoFingerGesture_.active) {
        MMI_HILOGD("Two finger gesture is not active");
        return;
    }
    auto num = touchEvent->GetPointerIds().size();
    if (num == TwoFingerGesture::MAX_TOUCH_NUM) {
        StartTwoFingerGesture();
    } else {
        StopTwoFingerGesture();
    }
    if (num > 0 && num <= TwoFingerGesture::MAX_TOUCH_NUM) {
        auto id = touchEvent->GetPointerId();
        PointerEvent::PointerItem item;
        touchEvent->GetPointerItem(id, item);
        twoFingerGesture_.touches[num - 1].id = id;
        twoFingerGesture_.touches[num - 1].x = item.GetDisplayX();
        twoFingerGesture_.touches[num - 1].y = item.GetDisplayY();
        twoFingerGesture_.touches[num - 1].downTime = item.GetDownTime();
    }
}

void KeyCommandHandler::HandleFingerGestureUpEvent(const std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);
    if (!twoFingerGesture_.active) {
        MMI_HILOGD("Two finger gesture is not active");
        return;
    }
    StopTwoFingerGesture();
}

void KeyCommandHandler::HandleKnuckleGestureDownEvent(const std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);

    auto id = touchEvent->GetPointerId();
    PointerEvent::PointerItem item;
    touchEvent->GetPointerItem(id, item);
    if (item.GetToolType() != PointerEvent::TOOL_TYPE_KNUCKLE) {
        MMI_HILOGW("Touch event tool type:%{public}d not knuckle", item.GetToolType());
        return;
    }
    size_t size = touchEvent->GetPointerIds().size();
    if (size == SINGLE_KNUCKLE_SIZE) {
        SingleKnuckleGestureProcesser(touchEvent);
        isDoubleClick_ = false;
        knuckleCount_++;
    } else if (size == DOUBLE_KNUCKLE_SIZE) {
        DoubleKnuckleGestureProcesser(touchEvent);
        isDoubleClick_ = true;
    } else {
        MMI_HILOGW("Other kunckle size not process, size:%{public}zu", size);
    }
}

void KeyCommandHandler::HandleKnuckleGestureUpEvent(const std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);
    size_t size = touchEvent->GetPointerIds().size();
    if ((size == SINGLE_KNUCKLE_SIZE) && (!isDoubleClick_)) {
        singleKnuckleGesture_.lastPointerUpTime = touchEvent->GetActionTime();
    } else if (size == DOUBLE_KNUCKLE_SIZE) {
        doubleKnuckleGesture_.lastPointerUpTime = touchEvent->GetActionTime();
    } else {
        MMI_HILOGW("Other kunckle size not process, size:%{public}zu", size);
    }
}

void KeyCommandHandler::SingleKnuckleGestureProcesser(const std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);
    singleKnuckleGesture_.state = false;
    KnuckleGestureProcessor(touchEvent, singleKnuckleGesture_);
}

void KeyCommandHandler::DoubleKnuckleGestureProcesser(const std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);
    doubleKnuckleGesture_.state = false;
    KnuckleGestureProcessor(touchEvent, doubleKnuckleGesture_);
}

void KeyCommandHandler::KnuckleGestureProcessor(const std::shared_ptr<PointerEvent> touchEvent,
    KnuckleGesture &knuckleGesture)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);
    isKnuckleState_ = true;
    if (knuckleGesture.lastPointerDownEvent == nullptr) {
        MMI_HILOGI("knuckle gesture first down Event");
        knuckleGesture.lastPointerDownEvent = touchEvent;
        UpdateKnuckleGestureInfo(touchEvent, knuckleGesture);
        return;
    }
    int64_t intervalTime = touchEvent->GetActionTime() - knuckleGesture.lastPointerUpTime;
    bool isTimeIntervalReady = intervalTime > 0 && intervalTime <= downToPrevUpTimeConfig_;
    float downToPrevDownDistance = AbsDiff(knuckleGesture, touchEvent);
    bool isDistanceReady = downToPrevDownDistance < downToPrevDownDistanceConfig_;
    knuckleGesture.downToPrevUpTime = intervalTime;
    knuckleGesture.doubleClickDistance = downToPrevDownDistance;
    UpdateKnuckleGestureInfo(touchEvent, knuckleGesture);
    if (isTimeIntervalReady && isDistanceReady) {
        MMI_HILOGI("knuckle gesture start launch ability");
        knuckleCount_ = 0;
        DfxHisysevent::ReportSingleKnuckleDoubleClickEvent(intervalTime);
        LaunchAbility(knuckleGesture.ability, 0);
        knuckleGesture.state = true;
        ReportKnuckleScreenCapture(touchEvent);
    } else {
        if (knuckleCount_ > KNUCKLE_KNOCKS) {
            knuckleCount_ = 0;
            MMI_HILOGW("time ready:%{public}d, distance ready:%{public}d", isTimeIntervalReady, isDistanceReady);
            if (!isTimeIntervalReady) {
                DfxHisysevent::ReportFailIfInvalidTime(touchEvent, intervalTime);
            }
            if (!isDistanceReady) {
                DfxHisysevent::ReportFailIfInvalidDistance(touchEvent, downToPrevDownDistance);
            }
        }
    }
    AdjustTimeIntervalConfigIfNeed(intervalTime);
    AdjustDistanceConfigIfNeed(downToPrevDownDistance);
}

void KeyCommandHandler::UpdateKnuckleGestureInfo(const std::shared_ptr<PointerEvent> touchEvent,
    KnuckleGesture &knuckleGesture)
{
    auto id = touchEvent->GetPointerId();
    PointerEvent::PointerItem item;
    touchEvent->GetPointerItem(id, item);
    knuckleGesture.lastDownPointer.x = item.GetDisplayX();
    knuckleGesture.lastDownPointer.y = item.GetDisplayY();
    knuckleGesture.lastDownPointer.id = touchEvent->GetId();
}

void KeyCommandHandler::AdjustTimeIntervalConfigIfNeed(int64_t intervalTime)
{
    CALL_DEBUG_ENTER;
    int64_t newTimeConfig;
    MMI_HILOGI("down to prev up interval time:%{public}" PRId64 ",config time:%{public}" PRId64"",
        intervalTime, downToPrevUpTimeConfig_);
    if (downToPrevUpTimeConfig_ == DOUBLE_CLICK_INTERVAL_TIME_DEFAULT) {
        if (intervalTime < DOUBLE_CLICK_INTERVAL_TIME_DEFAULT || intervalTime > DOUBLE_CLICK_INTERVAL_TIME_SLOW) {
            return;
        }
        newTimeConfig = DOUBLE_CLICK_INTERVAL_TIME_SLOW;
    } else if (downToPrevUpTimeConfig_ == DOUBLE_CLICK_INTERVAL_TIME_SLOW) {
        if (intervalTime > DOUBLE_CLICK_INTERVAL_TIME_DEFAULT) {
            return;
        }
        newTimeConfig = DOUBLE_CLICK_INTERVAL_TIME_DEFAULT;
    } else {
        return;
    }
    checkAdjustIntervalTimeCount_++;
    if (checkAdjustIntervalTimeCount_ < MAX_TIME_FOR_ADJUST_CONFIG) {
        return;
    }
    MMI_HILOGI("adjust new double click interval time:%{public}" PRId64 "", newTimeConfig);
    downToPrevUpTimeConfig_ = newTimeConfig;
    checkAdjustIntervalTimeCount_ = 0;
}

void KeyCommandHandler::AdjustDistanceConfigIfNeed(float distance)
{
    CALL_DEBUG_ENTER;
    float newDistanceConfig;
    MMI_HILOGI("down to prev down distance:%{public}f, config distance:%{public}f",
        distance, downToPrevDownDistanceConfig_);
    if (IsEqual(downToPrevDownDistanceConfig_, distanceDefaultConfig_)) {
        if (distance < distanceDefaultConfig_ || distance > distanceLongConfig_) {
            return;
        }
        newDistanceConfig = distanceLongConfig_;
    } else if (IsEqual(downToPrevDownDistanceConfig_, distanceLongConfig_)) {
        if (distance > distanceDefaultConfig_) {
            return;
        }
        newDistanceConfig = distanceDefaultConfig_;
    } else {
        return;
    }
    checkAdjustDistanceCount_++;
    if (checkAdjustDistanceCount_ < MAX_TIME_FOR_ADJUST_CONFIG) {
        return;
    }
    MMI_HILOGI("adjust new double click distance:%{public}f", newDistanceConfig);
    downToPrevDownDistanceConfig_ = newDistanceConfig;
    checkAdjustDistanceCount_ = 0;
}

void KeyCommandHandler::ReportKnuckleDoubleClickEvent(const std::shared_ptr<PointerEvent> touchEvent,
    KnuckleGesture &knuckleGesture)
{
    CHKPV(touchEvent);
    size_t size = touchEvent->GetPointerIds().size();
    if (size == SINGLE_KNUCKLE_SIZE) {
        DfxHisysevent::ReportSingleKnuckleDoubleClickEvent(knuckleGesture.downToPrevUpTime);
        return;
    }
    MMI_HILOGW("current touch event size:%{public}zu", size);
}

void KeyCommandHandler::ReportKnuckleScreenCapture(const std::shared_ptr<PointerEvent> touchEvent)
{
    CHKPV(touchEvent);
    size_t size = touchEvent->GetPointerIds().size();
    if (size == SINGLE_KNUCKLE_SIZE) {
        DfxHisysevent::ReportScreenCaptureGesture();
        return;
    }
    MMI_HILOGW("current touch event size:%{public}zu", size);
}

void KeyCommandHandler::StartTwoFingerGesture()
{
    CALL_DEBUG_ENTER;
    twoFingerGesture_.timerId = TimerMgr->AddTimer(twoFingerGesture_.abilityStartDelay, 1, [this]() {
        twoFingerGesture_.timerId = -1;
        if (!CheckTwoFingerGestureAction()) {
            return;
        }
        twoFingerGesture_.ability.params.emplace("displayX1", std::to_string(twoFingerGesture_.touches[0].x));
        twoFingerGesture_.ability.params.emplace("displayY1", std::to_string(twoFingerGesture_.touches[0].y));
        twoFingerGesture_.ability.params.emplace("displayX2", std::to_string(twoFingerGesture_.touches[1].x));
        twoFingerGesture_.ability.params.emplace("displayY2", std::to_string(twoFingerGesture_.touches[1].y));
        MMI_HILOGI("Start launch ability immediately");
        LaunchAbility(twoFingerGesture_.ability, twoFingerGesture_.abilityStartDelay);
    });
}

void KeyCommandHandler::StopTwoFingerGesture()
{
    CALL_DEBUG_ENTER;
    if (twoFingerGesture_.timerId != -1) {
        TimerMgr->RemoveTimer(twoFingerGesture_.timerId);
        twoFingerGesture_.timerId = -1;
    }
}

bool KeyCommandHandler::CheckTwoFingerGestureAction() const
{
    if (!twoFingerGesture_.active) {
        return false;
    }

    auto firstFinger = twoFingerGesture_.touches[0];
    auto secondFinger = twoFingerGesture_.touches[1];

    auto pressTimeInterval = fabs(firstFinger.downTime - secondFinger.downTime);
    if (pressTimeInterval > TWO_FINGERS_TIME_LIMIT) {
        return false;
    }

    auto devX = firstFinger.x - secondFinger.x;
    auto devY = firstFinger.y - secondFinger.y;
    auto distance = sqrt(pow(devX, 2) + pow(devY, 2));
    if (distance < ConvertVPToPX(TWO_FINGERS_DISTANCE_LIMIT)) {
        MMI_HILOGI("two fingers distance:%{public}f too small", distance);
        return false;
    }

    auto displayInfo = WinMgr->GetDefaultDisplayInfo();
    CHKPR(displayInfo, false);
    auto leftLimit = ConvertVPToPX(TOUCH_LIFT_LIMIT);
    auto rightLimit = displayInfo->width - ConvertVPToPX(TOUCH_RIGHT_LIMIT);
    auto topLimit = ConvertVPToPX(TOUCH_TOP_LIMIT);
    auto bottomLimit = displayInfo->height - ConvertVPToPX(TOUCH_BOTTOM_LIMIT);
    if (firstFinger.x <= leftLimit || firstFinger.x >= rightLimit ||
        firstFinger.y <= topLimit || firstFinger.y >= bottomLimit ||
        secondFinger.x <= leftLimit || secondFinger.x >= rightLimit ||
        secondFinger.y <= topLimit || secondFinger.y >= bottomLimit) {
        MMI_HILOGI("any finger out of region");
        return false;
    }

    return true;
}

int32_t KeyCommandHandler::ConvertVPToPX(int32_t vp) const
{
    if (vp <= 0) {
        return 0;
    }
    auto displayInfo = WinMgr->GetDefaultDisplayInfo();
    CHKPR(displayInfo, 0);
    int32_t dpi = displayInfo->dpi;
    if (dpi <= 0) {
        return 0;
    }
    const int32_t base = 160;
    return vp * (dpi / base);
}

#endif // OHOS_BUILD_ENABLE_TOUCH

bool KeyCommandHandler::ParseConfig()
{
#ifndef UNIT_TEST
    const char *testPathSuffix = "/etc/multimodalinput/ability_launch_config.json";
#else
    const char *testPathSuffix = "/data/test/test.json";
#endif // UNIT_TEST
    char buf[MAX_PATH_LEN] = { 0 };
    char *filePath = GetOneCfgFile(testPathSuffix, buf, MAX_PATH_LEN);
#ifndef UNIT_TEST
    std::string defaultConfig = "/system/etc/multimodalinput/ability_launch_config.json";
#else
    std::string defaultConfig = "/data/test/test.json";
#endif // UNIT_TEST
    if (filePath == nullptr || filePath[0] == '\0' || strlen(filePath) > MAX_PATH_LEN) {
        MMI_HILOGD("Can not get customization config file");
        return ParseJson(defaultConfig);
    }
    std::string customConfig = filePath;
    MMI_HILOGD("The configuration file path is :%{public}s", customConfig.c_str());
    return ParseJson(customConfig) || ParseJson(defaultConfig);
}

void KeyCommandHandler::ParseRepeatKeyMaxCount()
{
    if (repeatKeys_.empty()) {
        maxCount_ = 0;
    }
    int32_t tempCount = 0;
    for (RepeatKey& item : repeatKeys_) {
        if (item.times > tempCount) {
            tempCount = item.times;
        }
    }
    maxCount_ = tempCount;
}

bool KeyCommandHandler::ParseJson(const std::string &configFile)
{
    CALL_DEBUG_ENTER;
    std::string jsonStr = ReadJsonFile(configFile);
    if (jsonStr.empty()) {
        MMI_HILOGE("Read configFile failed");
        return false;
    }
    JsonParser parser;
    parser.json_ = cJSON_Parse(jsonStr.c_str());
    if (!cJSON_IsObject(parser.json_)) {
        MMI_HILOGE("Parser.json_ is not object");
        return false;
    }

    bool isParseShortKeys = ParseShortcutKeys(parser, shortcutKeys_, businessIds_);
    bool isParseSequences = ParseSequences(parser, sequences_);
    bool isParseTwoFingerGesture = ParseTwoFingerGesture(parser, twoFingerGesture_);
    bool isParseSingleKnuckleGesture = IsParseKnuckleGesture(parser, SINGLE_KNUCKLE_ABILITY, singleKnuckleGesture_);
    bool isParseDoubleKnuckleGesture = IsParseKnuckleGesture(parser, DOUBLE_KNUCKLE_ABILITY, doubleKnuckleGesture_);
    bool isParseMultiFingersTap = ParseMultiFingersTap(parser, TOUCHPAD_TRIP_TAP_ABILITY, threeFingersTap_);
    bool isParseRepeatKeys = ParseRepeatKeys(parser, repeatKeys_);
    if (!isParseShortKeys && !isParseSequences && !isParseTwoFingerGesture && !isParseSingleKnuckleGesture &&
        !isParseDoubleKnuckleGesture && !isParseMultiFingersTap && !isParseRepeatKeys) {
        MMI_HILOGE("Parse configFile failed");
        return false;
    }

    Print();
    PrintSeq();
    return true;
}

void KeyCommandHandler::Print()
{
    MMI_HILOGI("shortcutKey count:%{public}zu", shortcutKeys_.size());
    int32_t row = 0;
    for (const auto &item : shortcutKeys_) {
        MMI_HILOGI("row:%{public}d", row++);
        auto &shortcutKey = item.second;
        for (const auto &prekey : shortcutKey.preKeys) {
            MMI_HILOGI("preKey:%{public}d", prekey);
        }
        MMI_HILOGI("finalKey:%{public}d, keyDownDuration:%{public}d, triggerType:%{public}d,"
                   " bundleName:%{public}s, abilityName:%{public}s", shortcutKey.finalKey,
                   shortcutKey.keyDownDuration, shortcutKey.triggerType,
                   shortcutKey.ability.bundleName.c_str(), shortcutKey.ability.abilityName.c_str());
    }
}

void KeyCommandHandler::PrintSeq()
{
    MMI_HILOGI("sequences count:%{public}zu", sequences_.size());
    int32_t row = 0;
    for (const auto &item : sequences_) {
        MMI_HILOGI("row:%{public}d", row++);
        for (const auto& sequenceKey : item.sequenceKeys) {
            MMI_HILOGI("keyCode:%{public}d, keyAction:%{public}d, delay:%{public}" PRId64,
                       sequenceKey.keyCode, sequenceKey.keyAction, sequenceKey.delay);
        }
        MMI_HILOGI("bundleName:%{public}s, abilityName:%{public}s",
                   item.ability.bundleName.c_str(), item.ability.abilityName.c_str());
    }
}

bool KeyCommandHandler::IsEnableCombineKey(const std::shared_ptr<KeyEvent> key)
{
    CHKPF(key);
    if (enableCombineKey_) {
        return true;
    }
    if (key->GetKeyCode() == KeyEvent::KEYCODE_POWER && key->GetKeyAction() == KeyEvent::KEY_ACTION_UP) {
        auto items = key->GetKeyItems();
        if (items.size() != 1) {
            return enableCombineKey_;
        }
        return true;
    }
    if (key->GetKeyCode() == KeyEvent::KEYCODE_L) {
        for (const auto &item : key->GetKeyItems()) {
            int32_t keyCode = item.GetKeyCode();
            if (keyCode != KeyEvent::KEYCODE_L && keyCode != KeyEvent::KEYCODE_META_LEFT &&
                keyCode != KeyEvent::KEYCODE_META_RIGHT) {
                return enableCombineKey_;
            }
        }
        return true;
    }
    return enableCombineKey_;
}

int32_t KeyCommandHandler::EnableCombineKey(bool enable)
{
    enableCombineKey_ = enable;
    MMI_HILOGI("Enable combineKey is successful in keyCommand handler, enable:%{public}d", enable);
    return RET_OK;
}

void KeyCommandHandler::ParseStatusConfigObserver()
{
    CALL_DEBUG_ENTER;
    for (Sequence& item : sequences_) {
        if (item.statusConfig.empty()) {
            continue;
        }
        CreateStatusConfigObserver<Sequence>(item);
    }

    for (auto& item : shortcutKeys_) {
        ShortcutKey &shortcutKey = item.second;
        if (shortcutKey.statusConfig.empty()) {
            continue;
        }
        CreateStatusConfigObserver<ShortcutKey>(shortcutKey);
    }
}

template <class T>
void KeyCommandHandler::CreateStatusConfigObserver(T& item)
{
    CALL_DEBUG_ENTER;
    SettingObserver::UpdateFunc updateFunc = [&item](const std::string& key) {
        bool statusValue = true;
        auto ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
            .GetBoolValue(key, statusValue);
        if (ret != RET_OK) {
            MMI_HILOGE("Get value from setting date fail");
            return;
        }
        item.statusConfigValue = statusValue;
    };
    sptr<SettingObserver> statusObserver = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
        .CreateObserver(item.statusConfig, updateFunc);
    ErrCode ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID).RegisterObserver(statusObserver);
    if (ret != ERR_OK) {
        MMI_HILOGE("register setting observer failed, ret=%{public}d", ret);
        statusObserver = nullptr;
    }
}

std::shared_ptr<KeyEvent> KeyCommandHandler::CreateKeyEvent(int32_t keyCode, int32_t keyAction, bool isPressed)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    CHKPP(keyEvent);
    KeyEvent::KeyItem item;
    item.SetKeyCode(keyCode);
    item.SetPressed(isPressed);
    keyEvent->SetKeyCode(keyCode);
    keyEvent->SetKeyAction(keyAction);
    keyEvent->AddPressedKeyItems(item);
    return keyEvent;
}

bool KeyCommandHandler::PreHandleEvent(const std::shared_ptr<KeyEvent> key)
{
    CHKPF(key);
    if (!IsEnableCombineKey(key)) {
        MMI_HILOGI("Combine key is taken over in key command");
        return false;
    }
    if (!isParseConfig_) {
        if (!ParseConfig()) {
            MMI_HILOGE("Parse configFile failed");
            return false;
        }
        isParseConfig_ = true;
    }

    if (!isParseMaxCount_) {
        ParseRepeatKeyMaxCount();
        isParseMaxCount_ = true;
        if (repeatKeys_.size() > 0) {
            intervalTime_ = repeatKeys_[0].delay;
        }
    }

    if (!isParseStatusConfig_) {
        ParseStatusConfigObserver();
        isParseStatusConfig_ = true;
    }

    return true;
}

bool KeyCommandHandler::HandleEvent(const std::shared_ptr<KeyEvent> key)
{
    CALL_DEBUG_ENTER;
    CHKPF(key);
    if (!PreHandleEvent(key)) {
        return false;
    }

#ifdef OHOS_BUILD_ENABLE_FINGERSENSE_WRAPPER
    if (STYLUS_HANDLER->HandleStylusKey(keyEvent)) {
        return true;
    }
#endif // OHOS_BUILD_ENABLE_FINGERSENSE_WRAPPER

    bool isHandled = HandleShortKeys(key);
    isHandled = HandleSequences(key) || isHandled;
    if (isHandled) {
        if (isKeyCancel_) {
            isHandleSequence_ = false;
            isKeyCancel_ = false;
        } else {
            isHandleSequence_ = true;
        }
        return true;
    }

    if (!isDownStart_) {
        HandleRepeatKeys(key);
        return false;
    } else {
        bool isRepeatKeyHandle = HandleRepeatKeys(key);
        if (isRepeatKeyHandle) {
            return true;
        }
    }

    count_ = 0;
    isDownStart_ = false;
    return false;
}

bool KeyCommandHandler::OnHandleEvent(const std::shared_ptr<KeyEvent> key)
{
    CALL_DEBUG_ENTER;
    CHKPF(key);

    bool handleEventStatus = HandleEvent(key);
    if (handleEventStatus) {
        return true;
    }

    if (!specialKeys_.empty() && specialKeys_.find(key->GetKeyCode()) != specialKeys_.end()) {
        HandleSpecialKeys(key->GetKeyCode(), key->GetAction());
        return true;
    }

    if (IsSpecialType(key->GetKeyCode(), SpecialType::SUBSCRIBER_BEFORE_DELAY)) {
        auto tmpKey = KeyEvent::Clone(key);
        int32_t timerId = TimerMgr->AddTimer(SPECIAL_KEY_DOWN_DELAY, 1, [this, tmpKey] () {
            MMI_HILOGD("Timer callback");
            auto it = specialTimers_.find(tmpKey->GetKeyCode());
            if (it != specialTimers_.end() && !it->second.empty()) {
                it->second.pop_front();
            }
            InputHandler->GetSubscriberHandler()->HandleKeyEvent(tmpKey);
        });
        if (timerId < 0) {
            MMI_HILOGE("Add timer failed");
            return false;
        }

        auto it = specialTimers_.find(key->GetKeyCode());
        if (it == specialTimers_.end()) {
            std::list<int32_t> timerIds;
            timerIds.push_back(timerId);
            auto it = specialTimers_.emplace(key->GetKeyCode(), timerIds);
            if (!it.second) {
                MMI_HILOGE("Keycode duplicated");
                return false;
            }
        } else {
            it->second.push_back(timerId);
        }
        MMI_HILOGD("Add timer success");
        return true;
    }
    return false;
}

bool KeyCommandHandler::OnHandleEvent(const std::shared_ptr<PointerEvent> pointer)
{
    CALL_DEBUG_ENTER;
    CHKPF(pointer);
#ifdef OHOS_BUILD_ENABLE_FINGERSENSE_WRAPPER
    STYLUS_HANDLER->SetLastEventState(false);
#endif // OHOS_BUILD_ENABLE_FINGERSENSE_WRAPPER
    if (!isParseConfig_) {
        if (!ParseConfig()) {
            MMI_HILOGE("Parse configFile failed");
            return false;
        }
        isParseConfig_ = true;
    }
    bool isHandled = HandleMulFingersTap(pointer);
    if (isHandled) {
        return true;
    }
    return false;
}

bool KeyCommandHandler::HandleRepeatKeys(const std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPF(keyEvent);
    if (repeatKeys_.empty()) {
        MMI_HILOGD("No sequences configuration data");
        return false;
    }

    if (count_ > maxCount_) {
        return false;
    }

    bool isLaunched = false;
    bool waitRepeatKey = false;

    for (RepeatKey& item : repeatKeys_) {
        if (HandleKeyUpCancel(item, keyEvent)) {
            return false;
        }
        if (HandleRepeatKeyCount(item, keyEvent)) {
            break;
        }
    }

    for (RepeatKey& item : repeatKeys_) {
        bool isRepeatKey = HandleRepeatKey(item, isLaunched, keyEvent);
        if (isRepeatKey) {
            waitRepeatKey = true;
        }
    }

    return isLaunched || waitRepeatKey;
}

bool KeyCommandHandler::HandleRepeatKey(const RepeatKey &item, bool &isLaunched,
    const std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPF(keyEvent);

    if (keyEvent->GetKeyCode() != item.keyCode) {
        return false;
    }
    if (count_ == item.times) {
        bool statusValue = true;
        auto ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
            .GetBoolValue(item.statusConfig, statusValue);
        if (ret != RET_OK) {
            MMI_HILOGE("Get value from setting date fail");
            return false;
        }
        if (!statusValue) {
            return false;
        }
        LaunchAbility(item.ability);
        launchAbilityCount_ = count_;
        isLaunched = true;
        isDownStart_ = false;
        auto keyEventCancel = std::make_shared<KeyEvent>(*keyEvent);
        keyEventCancel->SetKeyAction(KeyEvent::KEY_ACTION_CANCEL);
        InputHandler->GetSubscriberHandler()->HandleKeyEvent(keyEventCancel);
    }
    return true;
}

bool KeyCommandHandler::HandleKeyUpCancel(const RepeatKey &item, const std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPF(keyEvent);
    if (keyEvent->GetKeyCode() == item.keyCode && keyEvent->GetKeyAction() == KeyEvent::KEY_ACTION_CANCEL) {
        isKeyCancel_ = true;
        isDownStart_ = false;
        return true;
    }
    return false;
}

bool KeyCommandHandler::HandleRepeatKeyCount(const RepeatKey &item, const std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPF(keyEvent);

    if (keyEvent->GetKeyCode() == item.keyCode && keyEvent->GetKeyAction() == KeyEvent::KEY_ACTION_UP) {
        if (repeatKey_.keyCode != item.keyCode) {
            std::vector<int32_t> pressedKeys = keyEvent->GetPressedKeys();

            if (pressedKeys.size() == 0) {
                count_ = 1;
            } else {
                count_ = 0;
            }
            repeatKey_.keyCode = item.keyCode;
        } else {
            count_++;
        }

        upActionTime_ = keyEvent->GetActionTime();
        repeatTimerId_ = TimerMgr->AddTimer(intervalTime_ / SECONDS_SYSTEM, 1, [this] () {
            SendKeyEvent();
        });
        if (repeatTimerId_ < 0) {
            return false;
        }
        repeatKey_.keyCode = item.keyCode;
        return true;
    }

    if (keyEvent->GetKeyCode() == item.keyCode && keyEvent->GetKeyAction() == KeyEvent::KEY_ACTION_DOWN) {
        repeatKey_.keyCode = item.keyCode;
        isDownStart_ = true;

        downActionTime_ = keyEvent->GetActionTime();
        if ((downActionTime_ - upActionTime_) < intervalTime_) {
            if (repeatTimerId_ >= 0) {
                TimerMgr->RemoveTimer(repeatTimerId_);
            }
        }
        return true;
    }
    return false;
}

void KeyCommandHandler::SendKeyEvent()
{
    CALL_DEBUG_ENTER;
    if (!isHandleSequence_) {
        for (int32_t i = launchAbilityCount_; i < count_; i++) {
            int32_t keycode = repeatKey_.keyCode;
            if (IsSpecialType(keycode, SpecialType::KEY_DOWN_ACTION)) {
                HandleSpecialKeys(keycode, KeyEvent::KEY_ACTION_UP);
            }
            if (i != 0) {
                auto keyEventDown = CreateKeyEvent(keycode, KeyEvent::KEY_ACTION_DOWN, true);
                CHKPV(keyEventDown);
                InputHandler->GetSubscriberHandler()->HandleKeyEvent(keyEventDown);
            }

            auto keyEventUp = CreateKeyEvent(keycode, KeyEvent::KEY_ACTION_UP, false);
            CHKPV(keyEventUp);
            InputHandler->GetSubscriberHandler()->HandleKeyEvent(keyEventUp);
        }
    }
    count_ = 0;
    isDownStart_ = false;
    isHandleSequence_ = false;
    launchAbilityCount_ = 0;
}

bool KeyCommandHandler::HandleShortKeys(const std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPF(keyEvent);
    if (shortcutKeys_.empty()) {
        MMI_HILOGD("No shortkeys configuration data");
        return false;
    }
    if (IsKeyMatch(lastMatchedKey_, keyEvent)) {
        MMI_HILOGD("The same key is waiting timeout, skip");
        return true;
    }
    if (currentLaunchAbilityKey_.timerId >= 0 && IsKeyMatch(currentLaunchAbilityKey_, keyEvent)) {
        MMI_HILOGD("repeat, current key %{public}d has launched ability", currentLaunchAbilityKey_.finalKey);
        return true;
    }
    DfxHisysevent::GetComboStartTime();
    if (lastMatchedKey_.timerId >= 0) {
        MMI_HILOGD("Remove timer:%{public}d", lastMatchedKey_.timerId);
        TimerMgr->RemoveTimer(lastMatchedKey_.timerId);
    }
    ResetLastMatchedKey();
    for (auto &item : shortcutKeys_) {
        ShortcutKey &shortcutKey = item.second;
        if (!shortcutKey.statusConfigValue) {
            continue;
        }
        if (!IsKeyMatch(shortcutKey, keyEvent)) {
            MMI_HILOGD("Not key matched, next");
            continue;
        }
        int32_t delay = GetKeyDownDurationFromXml(shortcutKey.businessId);
        if (delay >= MIN_SHORT_KEY_DOWN_DURATION && delay <= MAX_SHORT_KEY_DOWN_DURATION) {
            MMI_HILOGD("User defined new short key down duration:%{public}d", delay);
            shortcutKey.keyDownDuration = delay;
        }
        shortcutKey.Print();
        if (shortcutKey.triggerType == KeyEvent::KEY_ACTION_DOWN) {
            return HandleKeyDown(shortcutKey);
        } else if (shortcutKey.triggerType == KeyEvent::KEY_ACTION_UP) {
            return HandleKeyUp(keyEvent, shortcutKey);
        } else {
            return HandleKeyCancel(shortcutKey);
        }
    }
    return HandleConsumedKeyEvent(keyEvent);
}

bool KeyCommandHandler::HandleConsumedKeyEvent(const std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPF(keyEvent);
    if (currentLaunchAbilityKey_.finalKey == keyEvent->GetKeyCode()
        && keyEvent->GetKeyAction() == KeyEvent::KEY_ACTION_UP) {
        MMI_HILOGI("Handle consumed key event, cancel opration");
        ResetCurrentLaunchAbilityKey();
        auto keyEventCancel = std::make_shared<KeyEvent>(*keyEvent);
        keyEventCancel->SetKeyAction(KeyEvent::KEY_ACTION_CANCEL);
        auto inputEventNormalizeHandler = InputHandler->GetEventNormalizeHandler();
        CHKPF(inputEventNormalizeHandler);
        inputEventNormalizeHandler->HandleKeyEvent(keyEventCancel);
        return true;
    }
    return false;
}

bool KeyCommandHandler::IsRepeatKeyEvent(const SequenceKey &sequenceKey)
{
    for (size_t i = keys_.size(); i > 0; --i) {
        if (keys_[i-1].keyCode == sequenceKey.keyCode) {
            if (keys_[i-1].keyAction == sequenceKey.keyAction) {
                MMI_HILOGI("Is repeat key, keyCode:%{public}d", sequenceKey.keyCode);
                return true;
            }
            MMI_HILOGI("Is not repeat key");
            return false;
        }
    }
    return false;
}

bool KeyCommandHandler::HandleSequences(const std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPF(keyEvent);
    if (sequences_.empty()) {
        MMI_HILOGD("No sequences configuration data");
        return false;
    }

    if (!AddSequenceKey(keyEvent)) {
        MMI_HILOGD("Add new sequence key failed");
        return false;
    }

    if (filterSequences_.empty()) {
        filterSequences_ = sequences_;
    }

    bool isLaunchAbility = false;
    for (auto iter = filterSequences_.begin(); iter != filterSequences_.end();) {
        if (!HandleSequence((*iter), isLaunchAbility)) {
            filterSequences_.erase(iter);
            continue;
        }
        ++iter;
    }

    if (filterSequences_.empty()) {
        MMI_HILOGW("no sequences matched");
        keys_.clear();
        return false;
    }

    if (isLaunchAbility) {
        for (const auto& item : keys_) {
            if (IsSpecialType(item.keyCode, SpecialType::KEY_DOWN_ACTION)) {
                HandleSpecialKeys(item.keyCode, item.keyAction);
            }
            InputHandler->GetSubscriberHandler()->RemoveSubscriberKeyUpTimer(item.keyCode);
            RemoveSubscribedTimer(item.keyCode);
        }
    }
    return isLaunchAbility;
}

bool KeyCommandHandler::AddSequenceKey(const std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPF(keyEvent);
    SequenceKey sequenceKey;
    sequenceKey.keyCode = keyEvent->GetKeyCode();
    sequenceKey.keyAction = keyEvent->GetKeyAction();
    sequenceKey.actionTime = keyEvent->GetActionTime();
    size_t size = keys_.size();
    if (size > 0) {
        if (keys_[size - 1].actionTime > sequenceKey.actionTime) {
            MMI_HILOGE("The current event time is greater than the last event time");
            ResetSequenceKeys();
            return false;
        }
        if ((sequenceKey.actionTime - keys_[size - 1].actionTime) > MAX_DELAY_TIME) {
            MMI_HILOGD("The delay time is greater than the maximum delay time");
            ResetSequenceKeys();
        } else {
            if (IsRepeatKeyEvent(sequenceKey)) {
                MMI_HILOGD("This is a repeat key event, don't add");
                return false;
            }
            keys_[size - 1].delay = sequenceKey.actionTime - keys_[size - 1].actionTime;
            InterruptTimers();
        }
    }
    if (size > MAX_SEQUENCEKEYS_NUM) {
        MMI_HILOGD("The save key size more than the max size");
        return false;
    }
    keys_.push_back(sequenceKey);
    return true;
}

bool KeyCommandHandler::HandleSequence(Sequence &sequence, bool &isLaunchAbility)
{
    CALL_DEBUG_ENTER;
    size_t keysSize = keys_.size();
    size_t sequenceKeysSize = sequence.sequenceKeys.size();

    if (!sequence.statusConfigValue) {
        return false;
    }

    if (keysSize > sequenceKeysSize) {
        MMI_HILOGI("The save sequence not matching ability sequence");
        return false;
    }

    for (size_t i = 0; i < keysSize; ++i) {
        if (keys_[i] != sequence.sequenceKeys[i]) {
            MMI_HILOGI("The keyCode or keyAction not matching");
            return false;
        }
        int64_t delay = sequence.sequenceKeys[i].delay;
        if (((i + 1) != keysSize) && (delay != 0) && (keys_[i].delay >= delay)) {
            MMI_HILOGI("Delay is not matching");
            return false;
        }
    }

    if (keysSize == sequenceKeysSize) {
        if (sequence.abilityStartDelay == 0) {
            MMI_HILOGI("Start launch ability immediately");
            LaunchAbility(sequence);
            isLaunchAbility = true;
            return true;
        }
        sequence.timerId = TimerMgr->AddTimer(sequence.abilityStartDelay, 1, [this, sequence] () {
            MMI_HILOGI("Timer callback");
            LaunchAbility(sequence);
        });
        if (sequence.timerId < 0) {
            MMI_HILOGE("Add Timer failed");
            return false;
        }
        MMI_HILOGI("Add timer success");
        isLaunchAbility = true;
    }
    return true;
}

bool KeyCommandHandler::HandleMulFingersTap(const std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_TRIPTAP) {
        MMI_HILOGI("The touchpad trip tap will launch ability");
        LaunchAbility(threeFingersTap_.ability, 0);
        return true;
    }
    return false;
}

bool KeyCommandHandler::IsKeyMatch(const ShortcutKey &shortcutKey, const std::shared_ptr<KeyEvent> &key)
{
    CALL_DEBUG_ENTER;
    CHKPF(key);
    if ((key->GetKeyCode() != shortcutKey.finalKey) || (shortcutKey.triggerType != key->GetKeyAction())) {
        return false;
    }
    if ((shortcutKey.preKeys.size() + 1) != key->GetKeyItems().size()) {
        return false;
    }
    for (const auto &item : key->GetKeyItems()) {
        int32_t keyCode = item.GetKeyCode();
        if (SkipFinalKey(keyCode, key)) {
            continue;
        }
        if (shortcutKey.preKeys.find(keyCode) == shortcutKey.preKeys.end()) {
            return false;
        }
    }
    MMI_HILOGD("Leave, key matched");
    return true;
}

bool KeyCommandHandler::SkipFinalKey(const int32_t keyCode, const std::shared_ptr<KeyEvent> &key)
{
    CHKPF(key);
    return keyCode == key->GetKeyCode();
}

bool KeyCommandHandler::HandleKeyDown(ShortcutKey &shortcutKey)
{
    CALL_DEBUG_ENTER;
    if (shortcutKey.keyDownDuration == 0) {
        MMI_HILOGI("Start launch ability immediately");
        LaunchAbility(shortcutKey);
        return true;
    }
    shortcutKey.timerId = TimerMgr->AddTimer(shortcutKey.keyDownDuration, 1, [this, shortcutKey] () {
        MMI_HILOGI("Timer callback");
        currentLaunchAbilityKey_ = shortcutKey;
        LaunchAbility(shortcutKey);
    });
    if (shortcutKey.timerId < 0) {
        MMI_HILOGE("Add Timer failed");
        return false;
    }
    MMI_HILOGI("Add timer success");
    lastMatchedKey_ = shortcutKey;
    if (InputHandler->GetSubscriberHandler()->IsKeyEventSubscribed(shortcutKey.finalKey, shortcutKey.triggerType)) {
        MMI_HILOGI("current shortcutKey %{public}d is subSubcribed", shortcutKey.finalKey);
        return false;
    }
    return true;
}

int32_t KeyCommandHandler::GetKeyDownDurationFromXml(const std::string &businessId)
{
    CALL_DEBUG_ENTER;
    return PREFERENCES_MGR->GetShortKeyDuration(businessId);
}

bool KeyCommandHandler::HandleKeyUp(const std::shared_ptr<KeyEvent> &keyEvent, const ShortcutKey &shortcutKey)
{
    CALL_DEBUG_ENTER;
    CHKPF(keyEvent);
    if (shortcutKey.keyDownDuration == 0) {
        MMI_HILOGI("Start launch ability immediately");
        LaunchAbility(shortcutKey);
        return true;
    }
    std::optional<KeyEvent::KeyItem> keyItem = keyEvent->GetKeyItem();
    if (!keyItem) {
        MMI_HILOGE("The keyItem is nullopt");
        return false;
    }
    auto upTime = keyEvent->GetActionTime();
    auto downTime = keyItem->GetDownTime();
    MMI_HILOGI("upTime:%{public}" PRId64 ",downTime:%{public}" PRId64 ",keyDownDuration:%{public}d",
        upTime, downTime, shortcutKey.keyDownDuration);
    if (upTime - downTime >= static_cast<int64_t>(shortcutKey.keyDownDuration) * 1000) {
        MMI_HILOGI("Skip, upTime - downTime >= duration");
        return false;
    }
    MMI_HILOGI("Start launch ability immediately");
    LaunchAbility(shortcutKey);
    return true;
}

bool KeyCommandHandler::HandleKeyCancel(ShortcutKey &shortcutKey)
{
    CALL_DEBUG_ENTER;
    if (shortcutKey.timerId < 0) {
        MMI_HILOGE("Skip, timerid less than 0");
    }
    auto timerId = shortcutKey.timerId;
    shortcutKey.timerId = -1;
    TimerMgr->RemoveTimer(timerId);
    MMI_HILOGI("timerId:%{public}d", timerId);
    return false;
}

void KeyCommandHandler::LaunchAbility(const Ability &ability, int64_t delay)
{
    CALL_DEBUG_ENTER;
    if (ability.bundleName.empty()) {
        MMI_HILOGW("BundleName is empty");
        return;
    }
    AAFwk::Want want;
    want.SetElementName(ability.deviceId, ability.bundleName, ability.abilityName);
    want.SetAction(ability.action);
    want.SetUri(ability.uri);
    want.SetType(ability.type);
    for (const auto &entity : ability.entities) {
        want.AddEntity(entity);
    }
    for (const auto &item : ability.params) {
        want.SetParam(item.first, item.second);
    }
    DfxHisysevent::CalcComboStartTimes(delay);
    DfxHisysevent::ReportComboStartTimes();
    MMI_HILOGI("Start launch ability, bundleName:%{public}s", ability.bundleName.c_str());
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want);
    if (err != ERR_OK) {
        MMI_HILOGE("LaunchAbility failed, bundleName:%{public}s, err:%{public}d", ability.bundleName.c_str(), err);
    }
    int32_t state = NapProcess::GetInstance()->GetNapClientPid();
    if (state == REMOVE_OBSERVER) {
        MMI_HILOGW("nap client status:%{public}d", state);
        return;
    }
    OHOS::MMI::NapProcess::NapStatusData napData;
    napData.pid = -1;
    napData.uid = -1;
    napData.bundleName = ability.bundleName;
    int32_t syncState = ACTIVE_EVENT;
    NapProcess::GetInstance()->AddMmiSubscribedEventData(napData, syncState);
    NapProcess::GetInstance()->NotifyBundleName(napData, syncState);
    MMI_HILOGI("End launch ability, bundleName:%{public}s", ability.bundleName.c_str());
}

void KeyCommandHandler::LaunchAbility(const Ability &ability)
{
    CALL_DEBUG_ENTER;
    AAFwk::Want want;
    want.SetElementName(ability.deviceId, ability.bundleName, ability.abilityName);
    want.SetAction(ability.action);
    want.SetUri(ability.uri);
    want.SetType(ability.uri);
    for (const auto &entity : ability.entities) {
        want.AddEntity(entity);
    }
    for (const auto &item : ability.params) {
        want.SetParam(item.first, item.second);
    }

    MMI_HILOGI("Start launch ability, bundleName:%{public}s", ability.bundleName.c_str());
    if (ability.abilityType == EXTENSION_ABILITY) {
        ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->StartExtensionAbility(want, nullptr);
        if (err != ERR_OK) {
            MMI_HILOGE("LaunchAbility failed, bundleName:%{public}s, err:%{public}d", ability.bundleName.c_str(), err);
        }
    } else {
        ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want);
        if (err != ERR_OK) {
            MMI_HILOGE("LaunchAbility failed, bundleName:%{public}s, err:%{public}d", ability.bundleName.c_str(), err);
        }
    }

    MMI_HILOGI("End launch ability, bundleName:%{public}s", ability.bundleName.c_str());
}

void KeyCommandHandler::LaunchAbility(const ShortcutKey &key)
{
    CALL_INFO_TRACE;
    LaunchAbility(key.ability, lastMatchedKey_.keyDownDuration);
    ResetLastMatchedKey();
}

void KeyCommandHandler::LaunchAbility(const Sequence &sequence)
{
    CALL_INFO_TRACE;
    LaunchAbility(sequence.ability, sequence.abilityStartDelay);
}

void ShortcutKey::Print() const
{
    for (const auto &prekey: preKeys) {
        MMI_HILOGI("Eventkey matched, preKey:%{public}d", prekey);
    }
    MMI_HILOGI("Eventkey matched, finalKey:%{public}d, bundleName:%{public}s",
        finalKey, ability.bundleName.c_str());
}

void KeyCommandHandler::RemoveSubscribedTimer(int32_t keyCode)
{
    CALL_DEBUG_ENTER;
    auto iter = specialTimers_.find(keyCode);
    if (iter != specialTimers_.end()) {
        for (auto& item : iter->second) {
            TimerMgr->RemoveTimer(item);
        }
        specialTimers_.erase(keyCode);
        MMI_HILOGI("Remove timer success");
    }
}

void KeyCommandHandler::HandleSpecialKeys(int32_t keyCode, int32_t keyAction)
{
    CALL_DEBUG_ENTER;
    auto iter = specialKeys_.find(keyCode);
    if (keyAction == KeyEvent::KEY_ACTION_UP) {
        if (iter != specialKeys_.end()) {
            specialKeys_.erase(iter);
            return;
        }
    }

    if (keyAction == KeyEvent::KEY_ACTION_DOWN) {
        if (iter == specialKeys_.end()) {
            auto it = specialKeys_.emplace(keyCode, keyAction);
            if (!it.second) {
                MMI_HILOGD("KeyCode duplicated");
                return;
            }
        }
    }
}

void KeyCommandHandler::InterruptTimers()
{
    for (Sequence& item : filterSequences_) {
        if (item.timerId >= 0) {
            MMI_HILOGD("The key sequence change, close the timer");
            TimerMgr->RemoveTimer(item.timerId);
            item.timerId = -1;
        }
    }
}

int32_t KeyCommandHandler::UpdateSettingsXml(const std::string &businessId, int32_t delay)
{
    CALL_DEBUG_ENTER;
    if (businessId.empty() || businessIds_.empty()) {
        MMI_HILOGE("businessId or businessIds_ is empty");
        return COMMON_PARAMETER_ERROR;
    }
    if (std::find(businessIds_.begin(), businessIds_.end(), businessId) == businessIds_.end()) {
        MMI_HILOGE("%{public}s not in the config file", businessId.c_str());
        return COMMON_PARAMETER_ERROR;
    }
    if (delay < MIN_SHORT_KEY_DOWN_DURATION || delay > MAX_SHORT_KEY_DOWN_DURATION) {
        MMI_HILOGE("delay is not in valid range.");
        return COMMON_PARAMETER_ERROR;
    }
    return PREFERENCES_MGR->SetShortKeyDuration(businessId, delay);
}

KnuckleGesture KeyCommandHandler::GetSingleKnuckleGesture()
{
    return singleKnuckleGesture_;
}
KnuckleGesture KeyCommandHandler::GetDoubleKnuckleGesture()
{
    return doubleKnuckleGesture_;
}
void KeyCommandHandler::SetKnuckleDoubleTapIntervalTime(int64_t interval)
{
    CALL_DEBUG_ENTER;
    if (interval < 0) {
        MMI_HILOGE("invalid interval time:%{public}" PRId64 "", interval);
        return;
    }
    downToPrevUpTimeConfig_ = interval;
}
void KeyCommandHandler::SetKnuckleDoubleTapDistance(float distance)
{
    CALL_DEBUG_ENTER;
    if (distance <= std::numeric_limits<float>::epsilon()) {
        MMI_HILOGE("invalid distance:%{public}f", distance);
        return;
    }
    downToPrevDownDistanceConfig_ = distance;
}
} // namespace MMI
} // namespace OHOS