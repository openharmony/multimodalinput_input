/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "key_command_handler.h"

#include "dfx_hisysevent.h"
#include "ability_manager_client.h"
#include "bytrace_adapter.h"
#include "cJSON.h"
#include "config_policy_utils.h"
#include "define_multimodal.h"
#include "error_multimodal.h"
#include "file_ex.h"
#include "input_event_data_transformation.h"
#include "input_event_handler.h"
#include "mmi_log.h"
#include "net_packet.h"
#include "proto.h"
#include "timer_manager.h"
#include "util_ex.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t MAX_PREKEYS_NUM = 4;
constexpr int32_t MAX_SEQUENCEKEYS_NUM = 10;
constexpr int64_t MAX_DELAY_TIME = 1000000;
constexpr int64_t SECONDS_SYSTEM = 1000;
constexpr int32_t SPECIAL_KEY_DOWN_DELAY = 150;
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "KeyCommandHandler" };
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

bool ConvertToShortcutKey(const cJSON* jsonData, ShortcutKey &shortcutKey)
{
    if (!cJSON_IsObject(jsonData)) {
        MMI_HILOGE("jsonData is not object");
        return false;
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

bool GetAlibityStartDelay(const cJSON* jsonData, int64_t &abilityStartDelayInt)
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
    abilityStartDelayInt = abilityStartDelay->valueint * SECONDS_SYSTEM;
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
    if (!GetAlibityStartDelay(jsonData, sequence.abilityStartDelay)) {
        MMI_HILOGE("Get abilityStartDelay failed");
        return false;
    }
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

bool ParseShortcutKeys(const JsonParser& parser, std::map<std::string, ShortcutKey>& shortcutKeyMap)
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
        if (!ConvertToShortcutKey(shortkey, shortcutKey)) {
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
    CHKPV(nextHandler_);
    nextHandler_->HandlePointerEvent(pointerEvent);
}
#endif // OHOS_BUILD_ENABLE_POINTER

#ifdef OHOS_BUILD_ENABLE_TOUCH
void KeyCommandHandler::HandleTouchEvent(const std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPV(pointerEvent);
    CHKPV(nextHandler_);
    nextHandler_->HandleTouchEvent(pointerEvent);
}
#endif // OHOS_BUILD_ENABLE_TOUCH

bool KeyCommandHandler::ParseConfig()
{
    const char *testPathSuffix = "/etc/multimodalinput/ability_launch_config.json";
    char buf[MAX_PATH_LEN] = { 0 };
    char *filePath = GetOneCfgFile(testPathSuffix, buf, MAX_PATH_LEN);
    std::string defaultConfig = "/system/etc/multimodalinput/ability_launch_config.json";
    if (filePath == NULL || filePath[0] == '\0' || strlen(filePath) > MAX_PATH_LEN) {
        MMI_HILOGD("Can not get customization config file");
        return ParseJson(defaultConfig);
    }
    std::string customConfig = filePath;
    MMI_HILOGD("The configuration file path is :%{public}s", customConfig.c_str());
    return ParseJson(customConfig) || ParseJson(defaultConfig);
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

    bool isParseShortKeys = ParseShortcutKeys(parser, shortcutKeys_);
    bool isParseSequences = ParseSequences(parser, sequences_);
    if (!isParseShortKeys && !isParseSequences) {
        MMI_HILOGE("Parse configFile failed");
        return false;
    }

    Print();
    PrintSeq();
    return true;
}

void KeyCommandHandler::Print()
{
    MMI_HILOGD("shortcutKey count:%{public}zu", shortcutKeys_.size());
    int32_t row = 0;
    for (const auto &item : shortcutKeys_) {
        MMI_HILOGD("row:%{public}d", row++);
        auto &shortcutKey = item.second;
        for (const auto &prekey : shortcutKey.preKeys) {
            MMI_HILOGD("preKey:%{public}d", prekey);
        }
        MMI_HILOGD("finalKey:%{public}d, keyDownDuration:%{public}d, triggerType:%{public}d,"
                   " bundleName:%{public}s, abilityName:%{public}s", shortcutKey.finalKey,
                   shortcutKey.keyDownDuration, shortcutKey.triggerType,
                   shortcutKey.ability.bundleName.c_str(), shortcutKey.ability.abilityName.c_str());
    }
}

void KeyCommandHandler::PrintSeq()
{
    MMI_HILOGD("sequences count:%{public}zu", sequences_.size());
    int32_t row = 0;
    for (const auto &item : sequences_) {
        MMI_HILOGD("row:%{public}d", row++);
        for (const auto& sequenceKey : item.sequenceKeys) {
            MMI_HILOGD("keyCode:%{public}d, keyAction:%{public}d, delay:%{public}" PRId64,
                       sequenceKey.keyCode, sequenceKey.keyAction, sequenceKey.delay);
        }
        MMI_HILOGD("bundleName:%{public}s, abilityName:%{public}s",
                   item.ability.bundleName.c_str(), item.ability.abilityName.c_str());
    }
}

bool KeyCommandHandler::OnHandleEvent(const std::shared_ptr<KeyEvent> key)
{
    CALL_DEBUG_ENTER;
    CHKPF(key);
    if (!isParseConfig_) {
        if (!ParseConfig()) {
            MMI_HILOGE("Parse configFile failed");
            return false;
        }
        isParseConfig_ = true;
    }

    bool isHandled = HandleShortKeys(key);
    isHandled = HandleSequences(key) || isHandled;
    if (isHandled) {
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
    DfxHisysevent::GetComboStartTime();
    if (lastMatchedKey_.timerId >= 0) {
        MMI_HILOGD("Remove timer:%{public}d", lastMatchedKey_.timerId);
        TimerMgr->RemoveTimer(lastMatchedKey_.timerId);
    }
    ResetLastMatchedKey();
    for (auto &item : shortcutKeys_) {
        ShortcutKey &shortcutKey = item.second;
        if (!IsKeyMatch(shortcutKey, keyEvent)) {
            MMI_HILOGD("Not key matched, next");
            continue;
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
    return false;
}

bool KeyCommandHandler::IsRepeatKeyEvent(const SequenceKey &sequenceKey)
{
    for (size_t i = keys_.size(); i > 0; --i) {
        if (keys_[i-1].keyCode == sequenceKey.keyCode) {
            if (keys_[i-1].keyAction == sequenceKey.keyAction) {
                MMI_HILOGD("Is repeat key, keyCode:%{public}d", sequenceKey.keyCode);
                return true;
            }
            MMI_HILOGD("Is not repeat key");
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
        MMI_HILOGW("Add new sequence key failed");
        return false;
    }

    if (filterSequences_.empty()) {
        filterSequences_ = sequences_;
    }

    bool isLaunchAbility = false;
    std::vector<Sequence> tempSeqs;
    for (Sequence& item : filterSequences_) {
        if (HandleSequence(item, isLaunchAbility)) {
            tempSeqs.push_back(item);
        }
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

    if (tempSeqs.empty()) {
        MMI_HILOGD("No matching sequence found");
    } else {
        filterSequences_ = tempSeqs;
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
    if (keysSize > sequenceKeysSize) {
        MMI_HILOGD("The save sequence not matching ability sequence");
        return false;
    }

    for (size_t i = 0; i < keysSize; ++i) {
        if (keys_[i] != sequence.sequenceKeys[i]) {
            MMI_HILOGD("The keyCode or keyAction not matching");
            return false;
        }
        int64_t delay = sequence.sequenceKeys[i].delay;
        if (((i + 1) != keysSize) && (delay != 0) && (keys_[i].delay >= delay)) {
            MMI_HILOGD("Delay is not matching");
            return false;
        }
    }

    if (keysSize == sequenceKeysSize) {
        if (sequence.abilityStartDelay == 0) {
            MMI_HILOGD("Start launch ability immediately");
            LaunchAbility(sequence);
            isLaunchAbility = true;
            return true;
        }
        sequence.timerId = TimerMgr->AddTimer(sequence.abilityStartDelay/SECONDS_SYSTEM, 1, [this, sequence] () {
            MMI_HILOGD("Timer callback");
            LaunchAbility(sequence);
        });
        if (sequence.timerId < 0) {
            MMI_HILOGE("Add Timer failed");
            return false;
        }
        MMI_HILOGD("Add timer success");
        isLaunchAbility = true;
    }
    return true;
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
        MMI_HILOGD("Start launch ability immediately");
        LaunchAbility(shortcutKey);
        return true;
    }
    shortcutKey.timerId = TimerMgr->AddTimer(shortcutKey.keyDownDuration, 1, [this, shortcutKey] () {
        MMI_HILOGD("Timer callback");
        LaunchAbility(shortcutKey);
    });
    if (shortcutKey.timerId < 0) {
        MMI_HILOGE("Add Timer failed");
        return false;
    }
    MMI_HILOGD("Add timer success");
    lastMatchedKey_ = shortcutKey;
    return true;
}

bool KeyCommandHandler::HandleKeyUp(const std::shared_ptr<KeyEvent> &keyEvent, const ShortcutKey &shortcutKey)
{
    CALL_DEBUG_ENTER;
    CHKPF(keyEvent);
    if (shortcutKey.keyDownDuration == 0) {
        MMI_HILOGD("Start launch ability immediately");
        LaunchAbility(shortcutKey);
        return true;
    }
    const KeyEvent::KeyItem* keyItem = keyEvent->GetKeyItem();
    CHKPF(keyItem);
    auto upTime = keyEvent->GetActionTime();
    auto downTime = keyItem->GetDownTime();
    MMI_HILOGD("upTime:%{public}" PRId64 ",downTime:%{public}" PRId64 ",keyDownDuration:%{public}d",
        upTime, downTime, shortcutKey.keyDownDuration);
    if (upTime - downTime >= static_cast<int64_t>(shortcutKey.keyDownDuration) * 1000) {
        MMI_HILOGD("Skip, upTime - downTime >= duration");
        return false;
    }
    MMI_HILOGD("Start launch ability immediately");
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
    MMI_HILOGD("timerId:%{public}d", timerId);
    return false;
}

void KeyCommandHandler::LaunchAbility(const ShortcutKey &key)
{
    AAFwk::Want want;
    want.SetElementName(key.ability.deviceId, key.ability.bundleName, key.ability.abilityName);
    want.SetAction(key.ability.action);
    want.SetUri(key.ability.uri);
    want.SetType(key.ability.uri);
    for (const auto &entity : key.ability.entities) {
        want.AddEntity(entity);
    }
    for (const auto &item : key.ability.params) {
        want.SetParam(item.first, item.second);
    }
    DfxHisysevent::CalcComboStartTimes(lastMatchedKey_.keyDownDuration);
    DfxHisysevent::ReportComboStartTimes();
    MMI_HILOGD("Start launch ability, bundleName:%{public}s", key.ability.bundleName.c_str());
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want);
    if (err != ERR_OK) {
        MMI_HILOGE("LaunchAbility failed, bundleName:%{public}s, err:%{public}d", key.ability.bundleName.c_str(), err);
    }
    ResetLastMatchedKey();
    MMI_HILOGD("End launch ability, bundleName:%{public}s", key.ability.bundleName.c_str());
}

void KeyCommandHandler::LaunchAbility(const Sequence &sequence)
{
    AAFwk::Want want;
    want.SetElementName(sequence.ability.deviceId, sequence.ability.bundleName, sequence.ability.abilityName);
    want.SetAction(sequence.ability.action);
    want.SetUri(sequence.ability.uri);
    want.SetType(sequence.ability.uri);
    for (const auto &entity : sequence.ability.entities) {
        want.AddEntity(entity);
    }
    for (const auto &item : sequence.ability.params) {
        want.SetParam(item.first, item.second);
    }
    DfxHisysevent::CalcComboStartTimes(sequence.abilityStartDelay);
    DfxHisysevent::ReportComboStartTimes();
    ResetSequenceKeys();
    MMI_HILOGD("Start launch ability, bundleName:%{public}s", sequence.ability.bundleName.c_str());
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want);
    if (err != ERR_OK) {
        MMI_HILOGE("LaunchAbility failed, bundleName:%{public}s, err:%{public}d",
                   sequence.ability.bundleName.c_str(), err);
    }
    MMI_HILOGD("End launch ability, bundleName:%{public}s", sequence.ability.bundleName.c_str());
}

void ShortcutKey::Print() const
{
    for (const auto &prekey: preKeys) {
        MMI_HILOGI("Eventkey matched, preKey:%{public}d", prekey);
    }
    MMI_HILOGD("Eventkey matched, finalKey:%{public}d, bundleName:%{public}s",
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
        MMI_HILOGD("Remove timer success");
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
} // namespace MMI
} // namespace OHOS