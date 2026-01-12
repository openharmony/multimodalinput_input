/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "key_config_parser.h"

#include <memory>

#include "key_command_handler_util.h"
#ifdef SHORTCUT_KEY_MANAGER_ENABLED
#include "key_shortcut_manager.h"
#endif // SHORTCUT_KEY_MANAGER_ENABLED

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyConfigParser"

namespace OHOS {
namespace MMI {
namespace {
const std::string TOUCHPAD_TRIP_TAP_ABILITY = "ThreeFingersTap";
}
bool KeyConfigParser::ParseConfig()
{
    const std::string defaultConfig { "/system/etc/multimodalinput/ability_launch_config.json" };
    const char configName[] { "/etc/multimodalinput/ability_launch_config.json" };
    char buf[MAX_PATH_LEN] {};

    char *filePath = ::GetOneCfgFile(configName, buf, sizeof(buf));
    if (filePath == nullptr || filePath[0] == '\0' || strlen(filePath) > MAX_PATH_LEN) {
        MMI_HILOGD("Can not get customization config file");
        return ParseJson(defaultConfig);
    }
    std::string customConfig = filePath;
    MMI_HILOGD("The configuration file path:%{private}s", customConfig.c_str());
    return ParseJson(customConfig) || ParseJson(defaultConfig);
}

bool KeyConfigParser::ParseJson(const std::string &configFile)
{
    CALL_DEBUG_ENTER;
    std::string jsonStr = ReadJsonFile(configFile);
    if (jsonStr.empty()) {
        MMI_HILOGE("Read configFile failed");
        return false;
    }
    JsonParser parser(jsonStr.c_str());
    if (parser.Get() == nullptr) {
        MMI_HILOGE("parser is nullptr");
        return false;
    }
    if (!cJSON_IsObject(parser.Get())) {
        MMI_HILOGE("Parser.Get() is not object");
        return false;
    }

    bool isParseShortKeys = ParseShortcutKeys(parser, *context_.shortcutKeys_, context_.businessIds_);
    bool isParseSequences = ParseSequences(parser, *context_.sequences_);
    bool isParseTwoFingerGesture = ParseTwoFingerGesture(parser, context_.twoFingerGesture_);
    bool isParseRepeatKeys = ParseRepeatKeys(parser, *context_.repeatKeys_, context_.repeatKeyMaxTimes_);
    bool isParseMultiFingersTap = ParseMultiFingersTap(parser, TOUCHPAD_TRIP_TAP_ABILITY, context_.threeFingersTap_);
    if (!isParseShortKeys && !isParseSequences && !isParseRepeatKeys && !isParseTwoFingerGesture &&
        !isParseMultiFingersTap) {
        MMI_HILOGE("Parse configFile failed");
        return false;
    }
    Print();
    PrintSeq();
    return true;
}

bool KeyConfigParser::ParseExcludeConfig()
{
    const std::string defaultConfig { "/system/etc/multimodalinput/exclude_keys_config.json" };
    const char configName[] { "/etc/multimodalinput/exclude_keys_config.json" };
    char buf[MAX_PATH_LEN] {};

    char *filePath = ::GetOneCfgFile(configName, buf, sizeof(buf));
    if (filePath == nullptr || filePath[0] == '\0' || strlen(filePath) > MAX_PATH_LEN) {
        MMI_HILOGD("Can not get customization exclude_keys_config.json file");
        return ParseExcludeJson(defaultConfig);
    }
    std::string customConfig = filePath;
    MMI_HILOGD("The exclude_keys_config.json file path:%s", customConfig.c_str());
    return ParseExcludeJson(customConfig) || ParseExcludeJson(defaultConfig);
}

bool KeyConfigParser::ParseExcludeJson(const std::string &configFile)
{
    CALL_DEBUG_ENTER;
    std::string jsonStr = ReadJsonFile(configFile);
    if (jsonStr.empty()) {
        MMI_HILOGE("Read excludeKey configFile failed");
        return false;
    }
    JsonParser parser(jsonStr.c_str());
    if (parser.Get() == nullptr) {
        MMI_HILOGE("parser is nullptr");
        return false;
    }
    if (!cJSON_IsObject(parser.Get())) {
        MMI_HILOGE("Parser.Get() of excludeKey is not object");
        return false;
    }
    bool ret = ParseExcludeKeys(parser, *context_.excludeKeys_);
    if (!ret) {
        MMI_HILOGE("Parse ExcludeKeys configFile failed");
        return false;
    }
    PrintExcludeKeys();
    return true;
}

bool KeyConfigParser::ParseShortcutKeys(const JsonParser &parser,
    std::map<std::string, ShortcutKey> &shortcutKeyMap, std::vector<std::string> &businessIds)
{
    if (!cJSON_IsObject(parser.Get())) {
        MMI_HILOGE("The parser is not object");
        return false;
    }
    cJSON* shortkeys = cJSON_GetObjectItemCaseSensitive(parser.Get(), "Shortkeys");
    if (!cJSON_IsArray(shortkeys)) {
        MMI_HILOGE("The short keys is not array");
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
#ifdef SHORTCUT_KEY_MANAGER_ENABLED
        shortcutKey.shortcutId = RegisterSystemKey(shortcutKey,
            [shortcutKey](std::shared_ptr<KeyEvent> keyEvent) {});
        if (shortcutKey.shortcutId < 0) {
            MMI_HILOGE("Register system key fail, error:%{public}d", shortcutKey.shortcutId);
            continue;
        }
#endif // SHORTCUT_KEY_MANAGER_ENABLED
        std::string key = GenerateKey(shortcutKey);
        shortcutKey.key = key;
        if (shortcutKeyMap.find(key) == shortcutKeyMap.end()) {
            if (!shortcutKeyMap.emplace(key, shortcutKey).second) {
                MMI_HILOGW("Duplicate shortcutKey:%s", key.c_str());
            }
        }
    }
    return true;
}

bool KeyConfigParser::ParseSequences(const JsonParser &parser, std::vector<Sequence> &sequenceVec)
{
    if (!cJSON_IsObject(parser.Get())) {
        MMI_HILOGE("The parser is not object");
        return false;
    }
    cJSON* sequences = cJSON_GetObjectItemCaseSensitive(parser.Get(), "Sequences");
    if (!cJSON_IsArray(sequences)) {
        MMI_HILOGE("The sequences is not array");
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

bool KeyConfigParser::ParseRepeatKeys(const JsonParser &parser, std::vector<RepeatKey> &repeatKeyVec,
                                      std::map<int32_t, int32_t> &repeatKeyMaxTimes)
{
    if (!cJSON_IsObject(parser.Get())) {
        MMI_HILOGE("The parser is not object");
        return false;
    }
    cJSON *repeatKeys = cJSON_GetObjectItemCaseSensitive(parser.Get(), "RepeatKeys");
    if (!cJSON_IsArray(repeatKeys)) {
        MMI_HILOGE("The repeat keys is not array");
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
        if (repeatKeyMaxTimes.find(rep.keyCode) == repeatKeyMaxTimes.end()) {
            repeatKeyMaxTimes.insert(std::make_pair(rep.keyCode, rep.times));
        }
        if (repeatKeyMaxTimes[rep.keyCode] < rep.times) {
            repeatKeyMaxTimes[rep.keyCode] = rep.times;
        }
    }

    return !repeatKeyVec.empty();
}

bool KeyConfigParser::ParseTwoFingerGesture(const JsonParser& parser, TwoFingerGesture& gesture)
{
    if (!cJSON_IsObject(parser.Get())) {
        MMI_HILOGE("The parser is not object");
        return false;
    }
    cJSON *jsonData = cJSON_GetObjectItemCaseSensitive(parser.Get(), "TwoFingerGesture");
    if (!cJSON_IsObject(jsonData)) {
        MMI_HILOGE("Two finger gesture is not object");
        return false;
    }
    if (!GetAbilityStartDelay(jsonData, gesture.abilityStartDelay)) {
        MMI_HILOGE("Get ability start delay failed");
        return false;
    }
    cJSON *ability = cJSON_GetObjectItemCaseSensitive(jsonData, "ability");
    if (!cJSON_IsObject(ability)) {
        MMI_HILOGE("The ability is not object");
        return false;
    }
    if (!PackageAbility(ability, gesture.ability)) {
        MMI_HILOGE("Package ability failed");
        return false;
    }
    gesture.active = true;
    return true;
}

bool KeyConfigParser::ParseExcludeKeys(const JsonParser& parser, std::vector<ExcludeKey>& excludeKeyVec)
{
    if (!cJSON_IsObject(parser.Get())) {
        MMI_HILOGE("The parser is not object");
        return false;
    }
    cJSON* excludeKeys = cJSON_GetObjectItemCaseSensitive(parser.Get(), "excludeKeys");
    if (!cJSON_IsArray(excludeKeys)) {
        MMI_HILOGE("The exclude keys is not array");
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

bool KeyConfigParser::ParseMultiFingersTap(const JsonParser &parser, const std::string ability,
    MultiFingersTap &mulFingersTap)
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

void KeyConfigParser::Print()
{
    MMI_HILOGI("ShortcutKey count:%{public}zu", context_.shortcutKeys_->size());
    int32_t row = 0;
    for (const auto &item : *context_.shortcutKeys_) {
        MMI_HILOGI("The row:%{public}d", row++);
        auto &shortcutKey = item.second;
        for (const auto &prekey : shortcutKey.preKeys) {
            MMI_HILOGI("The preKey:%d", prekey);
        }
        MMI_HILOGI("The finalKey:%d, keyDownDuration:%{public}d, triggerType:%{public}d,"
                   " bundleName:%{public}s, abilityName:%{public}s", shortcutKey.finalKey,
                   shortcutKey.keyDownDuration, shortcutKey.triggerType,
                   shortcutKey.ability.bundleName.c_str(), shortcutKey.ability.abilityName.c_str());
    }
}

void KeyConfigParser::PrintSeq()
{
    MMI_HILOGI("Sequences count:%{public}zu", context_.sequences_->size());
    int32_t row = 0;
    for (const auto &item : *context_.sequences_) {
        MMI_HILOGI("The row:%{public}d", row++);
        for (const auto& sequenceKey : item.sequenceKeys) {
            MMI_HILOGI("code:%{private}d, keyAction:%{public}d, delay:%{public}" PRId64,
                       sequenceKey.keyCode, sequenceKey.keyAction, sequenceKey.delay);
        }
        MMI_HILOGI("Ability bundleName:%{public}s, abilityName:%{public}s",
                   item.ability.bundleName.c_str(), item.ability.abilityName.c_str());
    }
}

void KeyConfigParser::PrintExcludeKeys()
{
    size_t keysSize = context_.excludeKeys_->size();
    for (size_t i = 0; i < keysSize; i++) {
        MMI_HILOGD("code:%{private}d, keyAction:%{public}d, delay:%{public}" PRId64,
                    (*context_.excludeKeys_)[i].keyCode, (*context_.excludeKeys_)[i].keyAction,
                    (*context_.excludeKeys_)[i].delay);
    }
}

bool KeyConfigParser::ConvertToExcludeKey(const cJSON* jsonData, ExcludeKey &exKey)
{
    if (!cJSON_IsObject(jsonData)) {
        MMI_HILOGE("The json data is not object");
        return false;
    }
    cJSON *keyCodeJson = cJSON_GetObjectItemCaseSensitive(jsonData, "keyCode");
    if (!cJSON_IsNumber(keyCodeJson)) {
        MMI_HILOGE("The keyCode json is not number");
        return false;
    }
    exKey.keyCode = keyCodeJson->valueint;

    cJSON *keyActionJson = cJSON_GetObjectItemCaseSensitive(jsonData, "keyAction");
    if (!cJSON_IsNumber(keyActionJson)) {
        MMI_HILOGE("THe keyAction json is not number");
        return false;
    }
    exKey.keyAction = keyActionJson->valueint;

    cJSON *delayJson = cJSON_GetObjectItemCaseSensitive(jsonData, "delay");
    if (!cJSON_IsNumber(delayJson)) {
        MMI_HILOGE("The delay json is not number");
        return false;
    }
    exKey.delay = delayJson->valueint;
    return true;
}

bool KeyConfigParser::ConvertToShortcutKey(const cJSON* jsonData, ShortcutKey &shortcutKey,
    std::vector<std::string> &businessIds)
{
    if (!cJSON_IsObject(jsonData)) {
        MMI_HILOGE("The json data is not object");
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
        MMI_HILOGE("The ability is not object");
        return false;
    }
    if (!PackageAbility(ability, shortcutKey.ability)) {
        MMI_HILOGE("Package ability failed");
        return false;
    }
    return true;
}

bool KeyConfigParser::ConvertToKeySequence(const cJSON* jsonData, Sequence &sequence)
{
    if (!cJSON_IsObject(jsonData)) {
        MMI_HILOGE("The json data is not object");
        return false;
    }
    if (!GetSequenceKeys(jsonData, sequence)) {
        MMI_HILOGE("Get sequence keys failed");
        return false;
    }
    if (!IsSequenceKeysValid(sequence)) {
        MMI_HILOGE("Sequence invalid");
        return false;
    }
    if (!GetAbilityStartDelay(jsonData, sequence.abilityStartDelay)) {
        MMI_HILOGE("Get ability start delay failed");
        return false;
    }

    GetKeyVal(jsonData, "statusConfig", sequence.statusConfig);

    cJSON *ability = cJSON_GetObjectItemCaseSensitive(jsonData, "ability");
    if (!cJSON_IsObject(ability)) {
        MMI_HILOGE("The ability is not object");
        return false;
    }
    if (!PackageAbility(ability, sequence.ability)) {
        MMI_HILOGE("Package ability failed");
        return false;
    }
    return true;
}

bool KeyConfigParser::ConvertToKeyRepeat(const cJSON* jsonData, RepeatKey &repeatKey)
{
    if (!cJSON_IsObject(jsonData)) {
        MMI_HILOGE("The json data is not object");
        return false;
    }

    if (!GetKeyCode(jsonData, repeatKey.keyCode)) {
        MMI_HILOGE("Get keyCode failed");
        return false;
    }

    if (!GetRepeatTimes(jsonData, repeatKey.times)) {
        MMI_HILOGE("Get repeat times failed");
        return false;
    }

    if (!GetRepeatKeyDelay(jsonData, repeatKey.delay)) {
        MMI_HILOGE("Get delay failed");
        return false;
    }

    GetKeyVal(jsonData, "statusConfig", repeatKey.statusConfig);

    cJSON *ability = cJSON_GetObjectItemCaseSensitive(jsonData, "ability");
    if (!cJSON_IsObject(ability)) {
        MMI_HILOGE("The ability is not object");
        return false;
    }
    if (!PackageAbility(ability, repeatKey.ability)) {
        MMI_HILOGE("Package ability failed");
        return false;
    }

    cJSON *preNotifyAbility = cJSON_GetObjectItemCaseSensitive(jsonData, "preNotifyAbility");
    if (preNotifyAbility != nullptr) {
        if (!PackageAbility(preNotifyAbility, repeatKey.preNotifyAbility)) {
            return false;
        }
    }
    return true;
}

bool KeyConfigParser::GetRepeatTimes(const cJSON* jsonData, int32_t &repeatTimesInt)
{
    if (!cJSON_IsObject(jsonData)) {
        MMI_HILOGE("Get repeat times jsonData is not object");
        return false;
    }
    cJSON *repeatTimes = cJSON_GetObjectItemCaseSensitive(jsonData, "times");
    if (repeatTimes == nullptr) {
        MMI_HILOGE("The repeat times init failed");
        return false;
    }
    if (!cJSON_IsNumber(repeatTimes)) {
        MMI_HILOGE("The repeat times is not number");
        return false;
    }
    if (repeatTimes->valueint < 0) {
        MMI_HILOGE("The repeat times must be number and bigger and equal zero");
        return false;
    }
    repeatTimesInt = repeatTimes->valueint;
    return true;
}

bool KeyConfigParser::GetRepeatKeyDelay(const cJSON* jsonData, int64_t &delayInt)
{
    if (!cJSON_IsObject(jsonData)) {
        MMI_HILOGE("The json data is not object");
        return false;
    }
    cJSON *delay = cJSON_GetObjectItemCaseSensitive(jsonData, "delay");
    if (delay == nullptr) {
        MMI_HILOGE("The delay init failed");
        return false;
    }
    if (!cJSON_IsNumber(delay)) {
        MMI_HILOGE("The delay is not number");
        return false;
    }
    if ((delay->valueint < 0) || (delay->valueint > MAX_REPEATKEY_DELAY_TIME)) {
        MMI_HILOGE("The delay must be number and bigger and equal zero and less than max delay");
        return false;
    }
    delayInt = delay->valueint * SECONDS_SYSTEM;
    return true;
}

bool KeyConfigParser::GetSequenceKeys(const cJSON* jsonData, Sequence &sequence)
{
    if (!cJSON_IsObject(jsonData)) {
        MMI_HILOGE("The json data is not object");
        return false;
    }
    cJSON* sequenceKeys = cJSON_GetObjectItemCaseSensitive(jsonData, "sequenceKeys");
    if (!cJSON_IsArray(sequenceKeys)) {
        MMI_HILOGE("The sequence keys number must be array");
        return false;
    }
    int32_t sequenceKeysSize = cJSON_GetArraySize(sequenceKeys);
    if (sequenceKeysSize > MAX_SEQUENCEKEYS_NUM) {
        MMI_HILOGE("The sequence keys size number must less and equal %{public}d", MAX_SEQUENCEKEYS_NUM);
        return false;
    }
    for (int32_t i = 0; i < sequenceKeysSize; ++i) {
        cJSON *sequenceKeysJson = cJSON_GetArrayItem(sequenceKeys, i);
        if (!cJSON_IsObject(sequenceKeysJson)) {
            MMI_HILOGE("The sequence keys json is not object");
            return false;
        }
        SequenceKey sequenceKey;
        if (!PackageSequenceKey(sequenceKeysJson, sequenceKey)) {
            MMI_HILOGE("Packege sequence key failed");
            return false;
        }
        sequence.sequenceKeys.push_back(sequenceKey);
    }
    return true;
}

bool KeyConfigParser::IsSequenceKeysValid(const Sequence &sequence)
{
    if (sequence.sequenceKeys.empty()) {
        MMI_HILOGE("The sequence keys can not be empty");
        return false;
    }

    if (sequence.sequenceKeys.size() > MAX_SEQUENCEKEYS_NUM) {
        MMI_HILOGE("The sequence keys size must less or equal to %{public}d", MAX_SEQUENCEKEYS_NUM);
        return false;
    }

    std::map<int32_t, SequenceKey> sequenceKeys;
    for (const SequenceKey& item : sequence.sequenceKeys) {
        if (sequenceKeys.find(item.keyCode) == sequenceKeys.end()) {
            auto it = sequenceKeys.emplace(item.keyCode, item);
            if (!it.second) {
                MMI_HILOGE("The key code is duplicated");
                return false;
            }
        } else {
            if (sequenceKeys[item.keyCode].keyAction == item.keyAction) {
                MMI_HILOGE("The sequence keys illegal");
                return false;
            }
            sequenceKeys[item.keyCode].keyAction = item.keyAction;
            sequenceKeys[item.keyCode].delay = item.delay;
        }
    }
    return true;
}

bool KeyConfigParser::GetBusinessId(const cJSON* jsonData, std::string &businessIdValue,
    std::vector<std::string> &businessIds)
{
    if (!cJSON_IsObject(jsonData)) {
        MMI_HILOGE("The json data is not object");
        return false;
    }
    cJSON *businessId = cJSON_GetObjectItemCaseSensitive(jsonData, "businessId");
    if (!cJSON_IsString(businessId)) {
        MMI_HILOGE("The business id is not string");
        return false;
    }
    businessIdValue = businessId->valuestring;
    businessIds.push_back(businessIdValue);
    return true;
}

bool KeyConfigParser::GetPreKeys(const cJSON* jsonData, ShortcutKey &shortcutKey)
{
    if (!cJSON_IsObject(jsonData)) {
        MMI_HILOGE("The json data is not object");
        return false;
    }
    cJSON* preKey = cJSON_GetObjectItemCaseSensitive(jsonData, "preKey");
    if (!cJSON_IsArray(preKey)) {
        MMI_HILOGE("The pre-key number must be array");
        return false;
    }
    int32_t preKeySize = cJSON_GetArraySize(preKey);
    if (preKeySize > MAX_PREKEYS_NUM) {
        MMI_HILOGE("The pre-key size number must less and equal four");
        return false;
    }
    for (int32_t i = 0; i < preKeySize; ++i) {
        cJSON *preKeyJson = cJSON_GetArrayItem(preKey, i);
        if (!cJSON_IsNumber(preKeyJson)) {
            MMI_HILOGE("The pre-key json is not number");
            return false;
        }
        if (preKeyJson->valueint < 0) {
            MMI_HILOGE("The pre-key json must be number and bigger or equal than 0");
            return false;
        }
        if (!shortcutKey.preKeys.emplace(preKeyJson->valueint).second) {
            MMI_HILOGE("The pre-key json must be unduplicated");
            return false;
        }
    }
    return true;
}

bool KeyConfigParser::GetKeyFinalKey(const cJSON* jsonData, int32_t &finalKeyInt)
{
    if (!cJSON_IsObject(jsonData)) {
        MMI_HILOGE("The json data is not object");
        return false;
    }
    cJSON *finalKey = cJSON_GetObjectItemCaseSensitive(jsonData, "finalKey");
    if (!cJSON_IsNumber(finalKey)) {
        MMI_HILOGE("The final key must be number");
        return false;
    }
    finalKeyInt = finalKey->valueint;
    return true;
}

bool KeyConfigParser::GetTrigger(const cJSON* jsonData, int32_t &triggerType)
{
    if (!cJSON_IsObject(jsonData)) {
        MMI_HILOGE("The json data is not object");
        return false;
    }
    cJSON *trigger = cJSON_GetObjectItemCaseSensitive(jsonData, "trigger");
    if (!cJSON_IsString(trigger)) {
        MMI_HILOGE("The trigger is not string");
        return false;
    }
    if (((std::strcmp(trigger->valuestring, "key_up") != 0)
        && (std::strcmp(trigger->valuestring, "key_down") != 0))) {
        MMI_HILOGE("The trigger must be one of [key_up, key_down]");
        return false;
    }
    if (std::strcmp(trigger->valuestring, "key_up") == 0) {
        triggerType = KeyEvent::KEY_ACTION_UP;
    } else {
        triggerType = KeyEvent::KEY_ACTION_DOWN;
    }
    return true;
}

bool KeyConfigParser::GetKeyDownDuration(const cJSON* jsonData, int32_t &keyDownDurationInt)
{
    if (!cJSON_IsObject(jsonData)) {
        MMI_HILOGE("The json data is not object");
        return false;
    }
    cJSON *keyDownDuration = cJSON_GetObjectItemCaseSensitive(jsonData, "keyDownDuration");
    if (!cJSON_IsNumber(keyDownDuration)) {
        MMI_HILOGE("The key-down duration is not number");
        return false;
    }
    if (keyDownDuration->valueint < 0 || keyDownDuration->valueint > MAX_KEYDOWNDURATION_TIME) {
        MMI_HILOGE("The key-down duration must be number and bigger and equal zero");
        return false;
    }
    keyDownDurationInt = keyDownDuration->valueint;
    return true;
}

bool KeyConfigParser::PackageSequenceKey(const cJSON* sequenceKeysJson, SequenceKey &sequenceKey)
{
    if (!cJSON_IsObject(sequenceKeysJson)) {
        MMI_HILOGE("The sequence keys json is not object");
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

bool KeyConfigParser::GetKeyCode(const cJSON* jsonData, int32_t &keyCodeInt)
{
    if (!cJSON_IsObject(jsonData)) {
        MMI_HILOGE("The json data is not object");
        return false;
    }
    cJSON *keyCode = cJSON_GetObjectItemCaseSensitive(jsonData, "keyCode");
    if (keyCode == nullptr) {
        MMI_HILOGE("The keyCode init failed");
        return false;
    }
    if (!cJSON_IsNumber(keyCode)) {
        MMI_HILOGE("The keyCode is not number");
        return false;
    }
    if (keyCode->valueint < 0) {
        MMI_HILOGE("The keyCode must be number and bigger and equal zero");
        return false;
    }
    keyCodeInt = keyCode->valueint;
    return true;
}

bool KeyConfigParser::GetKeyAction(const cJSON* jsonData, int32_t &keyActionInt)
{
    if (!cJSON_IsObject(jsonData)) {
        MMI_HILOGE("The json data is not object");
        return false;
    }
    cJSON *keyAction = cJSON_GetObjectItemCaseSensitive(jsonData, "keyAction");
    if (keyAction == nullptr) {
        MMI_HILOGE("THe key action Init failed");
        return false;
    }
    if (!cJSON_IsNumber(keyAction)) {
        MMI_HILOGE("THe key action is not number");
        return false;
    }
    if ((keyAction->valueint != KeyEvent::KEY_ACTION_DOWN) && (keyAction->valueint != KeyEvent::KEY_ACTION_UP)) {
        MMI_HILOGE("THe key action must be down or up");
        return false;
    }
    keyActionInt = keyAction->valueint;
    return true;
}

bool KeyConfigParser::GetDelay(const cJSON* jsonData, int64_t &delayInt)
{
    if (!cJSON_IsObject(jsonData)) {
        MMI_HILOGE("The json data is not object");
        return false;
    }
    cJSON *delay = cJSON_GetObjectItemCaseSensitive(jsonData, "delay");
    if (delay == nullptr) {
        MMI_HILOGE("The delay init failed");
        return false;
    }
    if (!cJSON_IsNumber(delay)) {
        MMI_HILOGE("The delay is not number");
        return false;
    }
    if ((delay->valueint < 0) || (delay->valueint > MAX_DELAY_TIME)) {
        MMI_HILOGE("The delay must be number and bigger and equal zero and less than max delay");
        return false;
    }
    delayInt = delay->valueint * SECONDS_SYSTEM;
    return true;
}

#ifdef SHORTCUT_KEY_MANAGER_ENABLED
int32_t KeyConfigParser::RegisterSystemKey(const ShortcutKey &shortcutKey,
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

std::string KeyConfigParser::GenerateKey(const ShortcutKey& key)
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

bool KeyConfigParser::IsPackageKnuckleGesture(const cJSON* jsonData, const std::string knuckleGesture,
    Ability &launchAbility)
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

bool KeyConfigParser::PackageAbility(const cJSON* jsonAbility, Ability &ability)
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

void KeyConfigParser::GetKeyVal(const cJSON* json, const std::string &key, std::string &value)
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

bool KeyConfigParser::GetEntities(const cJSON* jsonAbility, Ability &ability)
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

bool KeyConfigParser::GetParams(const cJSON* jsonAbility, Ability &ability)
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
}  // namespace MMI
}  // namespace OHOS