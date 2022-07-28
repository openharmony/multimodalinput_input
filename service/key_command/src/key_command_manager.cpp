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

#include "key_command_manager.h"

#include "ability_manager_client.h"
#include "cJSON.h"
#include "file_ex.h"
#include "mmi_log.h"
#include "string_wrapper.h"
#include "timer_manager.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t MAX_PREKEYS_NUM = 4;
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "KeyCommandManager" };
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
    cJSON *json_ = nullptr;
};

bool GetPreKeys(cJSON* jsonData, ShortcutKey &shortcutKey)
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

bool GetTrigger(cJSON* jsonData, int32_t &triggerType)
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

bool GetKeyDownDuration(cJSON* jsonData, int32_t &keyDownDurationInt)
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

bool GetKeyFinalKey(cJSON* jsonData, int32_t &finalKeyInt)
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

void GetKeyVal(cJSON* json, const std::string &key, std::string &value)
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

bool GetEntities(cJSON* jsonAbility, Ability &ability)
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

bool GetParams(cJSON* jsonAbility, Ability &ability)
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

bool PackageAbility(cJSON* jsonAbility, Ability &ability)
{
    if (!cJSON_IsObject(jsonAbility)) {
        MMI_HILOGE("jsonAbility is not object");
        return false;
    }
    GetKeyVal(jsonAbility, "bundleName", ability.bundleName);
    GetKeyVal(jsonAbility, "abilityName", ability.abilityName);
    GetKeyVal(jsonAbility, "action", ability.action);
    GetKeyVal(jsonAbility, "type", ability.type);
    GetKeyVal(jsonAbility, "deviceId", ability.deviceId);
    GetKeyVal(jsonAbility, "uri", ability.uri);
    if (!GetEntities(jsonAbility, ability)) {
        MMI_HILOGE("entities to failed");
        return false;
    }
    if (!GetParams(jsonAbility, ability)) {
        MMI_HILOGE("Params to failed");
        return false;
    }
    return true;
}

bool ConvertToShortcutKey(cJSON* jsonData, ShortcutKey &shortcutKey)
{
    if (!cJSON_IsObject(jsonData)) {
        MMI_HILOGE("jsonData is not object");
        return false;
    }
    if (!GetPreKeys(jsonData, shortcutKey)) {
        MMI_HILOGE("preKeys to failed");
        return false;
    }
    if (!GetKeyFinalKey(jsonData, shortcutKey.finalKey)) {
        MMI_HILOGE("finalKey to failed");
        return false;
    }
    if (!GetTrigger(jsonData, shortcutKey.triggerType)) {
        MMI_HILOGE("trigger to failed");
        return false;
    }
    if (!GetKeyDownDuration(jsonData, shortcutKey.keyDownDuration)) {
        MMI_HILOGE("downDuration to failed");
        return false;
    }
    cJSON *ability = cJSON_GetObjectItemCaseSensitive(jsonData, "ability");
    if (!cJSON_IsObject(ability)) {
        MMI_HILOGE("ability is not object");
        return false;
    }
    if (!PackageAbility(ability, shortcutKey.ability)) {
        MMI_HILOGE("package ability failed");
        return false;
    }
    return true;
}
} // namespace

std::string KeyCommandManager::GenerateKey(const ShortcutKey& key)
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

bool KeyCommandManager::ParseConfig()
{
    std::string vendorConfig = "/vendor/etc/ability_launch_config.json";
    std::string defaultConfig = "/system/etc/multimodalinput/ability_launch_config.json";
    return ParseJson(vendorConfig) || ParseJson(defaultConfig);
}

bool KeyCommandManager::ParseJson(const std::string configFile)
{
    CALL_LOG_ENTER;
    std::string jsonStr = ReadJsonFile(configFile);
    if (jsonStr.empty()) {
        MMI_HILOGE("configFile read failed");
        return false;
    }
    JsonParser parser;
    parser.json_ = cJSON_Parse(jsonStr.c_str());
    if (!cJSON_IsObject(parser.json_)) {
        MMI_HILOGE("parser is not object");
        return false;
    }
    cJSON* shortkeys = cJSON_GetObjectItemCaseSensitive(parser.json_, "Shortkeys");
    if (!cJSON_IsArray(shortkeys)) {
        MMI_HILOGE("shortkeys in config file is empty");
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
        if (shortcutKeys_.find(GenerateKey(shortcutKey)) == shortcutKeys_.end()) {
            if (!shortcutKeys_.emplace(GenerateKey(shortcutKey), shortcutKey).second) {
                MMI_HILOGW("Duplicate shortcutKey:%{public}s", GenerateKey(shortcutKey).c_str());
            }
        }
    }
    return true;
}

void KeyCommandManager::Print()
{
    uint32_t count = shortcutKeys_.size();
    MMI_HILOGD("shortcutKey count:%{public}u", count);
    for (const auto &item : shortcutKeys_) {
        auto &shortcutKey = item.second;
        for (auto prekey: shortcutKey.preKeys) {
            MMI_HILOGD("preKey:%{public}d", prekey);
        }
        MMI_HILOGD("finalKey:%{public}d,keyDownDuration:%{public}d,triggerType:%{public}d,"
            " bundleName:%{public}s,abilityName:%{public}s", shortcutKey.finalKey,
            shortcutKey.keyDownDuration, shortcutKey.triggerType,
            shortcutKey.ability.bundleName.c_str(), shortcutKey.ability.abilityName.c_str());
    }
}

bool KeyCommandManager::HandleEvent(const std::shared_ptr<KeyEvent> key)
{
    CALL_LOG_ENTER;
    if (IsKeyMatch(lastMatchedKey_, key)) {
        MMI_HILOGE("The same key is waiting timeout, skip");
        return true;
    }
    if (lastMatchedKey_.timerId >= 0) {
        MMI_HILOGE("remove timer:%{public}d", lastMatchedKey_.timerId);
        TimerMgr->RemoveTimer(lastMatchedKey_.timerId);
    }
    ResetLastMatchedKey();
    if (shortcutKeys_.empty()) {
        if (!ParseConfig()) {
            MMI_HILOGE("Parse configFile failed");
            return false;
        }
        Print();
    }
    for (auto& item : shortcutKeys_) {
        ShortcutKey &shortcutKey = item.second;
        if (!IsKeyMatch(shortcutKey, key)) {
            MMI_HILOGD("not key matched, next");
            continue;
        }
        shortcutKey.Print();
        if (shortcutKey.triggerType == KeyEvent::KEY_ACTION_DOWN) {
            return HandleKeyDown(shortcutKey);
        } else if (shortcutKey.triggerType == KeyEvent::KEY_ACTION_UP) {
            return HandleKeyUp(key, shortcutKey);
        } else {
            return HandleKeyCancel(shortcutKey);
        }
    }
    return false;
}

bool KeyCommandManager::IsKeyMatch(const ShortcutKey &shortcutKey, const std::shared_ptr<KeyEvent> &key)
{
    CALL_LOG_ENTER;
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
    MMI_HILOGD("leave, key matched");
    return true;
}

bool KeyCommandManager::SkipFinalKey(const int32_t keyCode, const std::shared_ptr<KeyEvent> &key)
{
    return keyCode == key->GetKeyCode();
}

bool KeyCommandManager::HandleKeyDown(ShortcutKey &shortcutKey)
{
    CALL_LOG_ENTER;
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
        MMI_HILOGE("Timer add failed");
        return false;
    }
    MMI_HILOGD("add timer success");
    lastMatchedKey_ = shortcutKey;
    return true;
}

bool KeyCommandManager::HandleKeyUp(const std::shared_ptr<KeyEvent> &keyEvent, const ShortcutKey &shortcutKey)
{
    CALL_LOG_ENTER;
    if (shortcutKey.keyDownDuration == 0) {
        MMI_HILOGD("Start launch ability immediately");
        LaunchAbility(shortcutKey);
        return true;
    }
    const KeyEvent::KeyItem* keyItem = keyEvent->GetKeyItem();
    CHKPF(keyItem);
    auto upTime = keyEvent->GetActionTime();
    auto downTime = keyItem->GetDownTime();
    MMI_HILOGD("UpTime:%{public}" PRId64 ",downTime:%{public}" PRId64 ",keyDownDuration:%{public}d",
        upTime, downTime, shortcutKey.keyDownDuration);
    if (upTime - downTime >= static_cast<int64_t>(shortcutKey.keyDownDuration) * 1000) {
        MMI_HILOGD("Skip, upTime - downTime >= duration");
        return false;
    }
    MMI_HILOGD("Start launch ability immediately");
    LaunchAbility(shortcutKey);
    return true;
}

bool KeyCommandManager::HandleKeyCancel(ShortcutKey &shortcutKey)
{
    CALL_LOG_ENTER;
    if (shortcutKey.timerId < 0) {
        MMI_HILOGE("Skip, timerid less than 0");
    }
    auto timerId = shortcutKey.timerId;
    shortcutKey.timerId = -1;
    TimerMgr->RemoveTimer(timerId);
    MMI_HILOGD("timerId: %{public}d", timerId);
    return false;
}

void KeyCommandManager::LaunchAbility(ShortcutKey key)
{
    AAFwk::Want want;
    want.SetElementName(key.ability.deviceId, key.ability.bundleName, key.ability.abilityName);
    want.SetAction(key.ability.action);
    want.SetUri(key.ability.uri);
    want.SetType(key.ability.uri);
    for (const auto &entity : key.ability.entities) {
        want.AddEntity(entity);
    }
    AAFwk::WantParams wParams;
    for (const auto &item : key.ability.params) {
        wParams.SetParam(item.first, AAFwk::String::Box(item.second));
    }
    want.SetParams(wParams);
    MMI_HILOGD("Start launch ability, bundleName:%{public}s", key.ability.bundleName.c_str());
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want);
    if (err != ERR_OK) {
        MMI_HILOGE("LaunchAbility failed, bundleName:%{public}s,err:%{public}d", key.ability.bundleName.c_str(), err);
    }
    ResetLastMatchedKey();
    MMI_HILOGD("End launch ability, bundleName:%{public}s", key.ability.bundleName.c_str());
}

void ShortcutKey::Print() const
{
    for (const auto &prekey: preKeys) {
        MMI_HILOGI("eventkey matched, preKey:%{public}d", prekey);
    }
    MMI_HILOGD("eventkey matched, finalKey:%{public}d,bundleName:%{public}s",
        finalKey, ability.bundleName.c_str());
}

std::shared_ptr<IKeyCommandManager> IKeyCommandManager::GetInstance()
{
    if (keyCommand_ == nullptr) {
        keyCommand_ = std::make_shared<KeyCommandManager>();
    }
    return keyCommand_;
}
} // namespace MMI
} // namespace OHOS