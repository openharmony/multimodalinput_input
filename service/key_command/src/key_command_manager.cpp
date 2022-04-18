/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "key_command_manager.h"

#include "ability_manager_client.h"
#include "file_ex.h"
#include "ohos/aafwk/base/string_wrapper.h"

#include "mmi_log.h"
#include "timer_manager.h"

#include "cJSON.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t MAX_PREKEYS_NUM = 4;
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "KeyCommandManager" };
} // namespace

KeyCommandManager::KeyCommandManager()
{
    std::string configFile = GetConfigFilePath();
    ResolveConfig(configFile);
    Print();
}

std::string KeyCommandManager::GenerateKey(const ShortcutKey& key)
{
    std::set<int32_t> preKeys = key.preKeys;
    std::stringstream oss;
    for (const auto& preKey : preKeys) {
        oss << preKey << ",";
    }
    oss << key.finalKey << ",";
    oss << key.triggerType;
    return std::string(oss.str());
}

std::string KeyCommandManager::GetConfigFilePath() const
{
    std::string defaultConfig = "/product/multimodalinput/ability_launch_config.json";
    return FileExists(defaultConfig) ? defaultConfig : "/system/etc/multimodalinput/ability_launch_config.json";
}

bool KeyCommandManager::ResolveJson(const std::string &configFile)
{
    FILE* fp = fopen(configFile.c_str(), "r");
    CHKPF(fp);
    char buf[256] = {};
    std::string jsonBuf;
    while (fgets(buf, sizeof(buf), fp) != nullptr) {
        jsonBuf += buf;
    }
    if (fclose(fp) < 0) {
        MMI_HILOGE("close file failed,error:%{public}d", errno);
    }
    cJSON* configJson = cJSON_Parse(jsonBuf.c_str());
    CHKPF(configJson);
    cJSON* shortkeys = cJSON_GetObjectItemCaseSensitive(configJson, "Shortkeys");
    if (shortkeys == nullptr) {
        MMI_HILOGE("shortkeys is nullptr");
        cJSON_Delete(configJson);
        return false;
    }
    if (!cJSON_IsArray(shortkeys)) {
        MMI_HILOGE("shortkeys in config file is empty");
        cJSON_Delete(configJson);
        return false;
    }
    int32_t shortkeysSize = cJSON_GetArraySize(shortkeys);
    for (int32_t i = 0; i < shortkeysSize; ++i) {
        ShortcutKey shortcutKey;
        cJSON *shortkey = cJSON_GetArrayItem(shortkeys, i);
        if (shortkey == nullptr) {
            continue;
        }
        std::string shortkeyStr = cJSON_Print(shortkey);
        if (shortkeyStr.empty()) {
            continue;
        }
        if (!ConvertToShortcutKey(shortkeyStr, shortcutKey)) {
            continue;
        }
        if (shortcutKeys_.find(GenerateKey(shortcutKey)) == shortcutKeys_.end()) {
            if (!shortcutKeys_.emplace(GenerateKey(shortcutKey), shortcutKey).second) {
                MMI_HILOGE("Duplicate shortcutKey:%{public}s", GenerateKey(shortcutKey).c_str());
            }
        }
    }
    cJSON_Delete(configJson);
    return true;
}

void KeyCommandManager::ResolveConfig(const std::string configFile)
{
    if (!FileExists(configFile)) {
        MMI_HILOGE("config file %{public}s not exist", configFile.c_str());
        return;
    }
    MMI_HILOGD("config file path:%{public}s", configFile.c_str());
    if (!ResolveJson(configFile)) {
        MMI_HILOGE("ResolveJson failed");
    }
    return;
}

bool KeyCommandManager::GetPreKeys(const std::string &objStr, ShortcutKey &shortcutKey)
{
    cJSON* jsonData = cJSON_Parse(objStr.c_str());
    CHKPF(jsonData);
    cJSON* preKey = cJSON_GetObjectItemCaseSensitive(jsonData, "preKey");
    if (preKey == nullptr) {
        MMI_HILOGE("preKey is nullptr");
        cJSON_Delete(jsonData);
        return false;
    }
    if (!cJSON_IsArray(preKey)) {
        MMI_HILOGE("preKey number must be array");
        cJSON_Delete(jsonData);
        return false;
    }
    int32_t preKeySize = cJSON_GetArraySize(preKey);
    if (preKeySize > MAX_PREKEYS_NUM) {
        MMI_HILOGE("preKey number must less and equal four");
        cJSON_Delete(jsonData);
        return false;
    }
    for (int32_t i = 0; i < preKeySize; ++i) {
        cJSON *preKeyJson = cJSON_GetArrayItem(preKey, i);
        if (!cJSON_IsNumber(preKeyJson)) {
            MMI_HILOGE("preKey must be number and bigger or equal to 0");
            cJSON_Delete(jsonData);
            return false;
        }
        if (preKeyJson->valueint < 0) {
            MMI_HILOGE("preKey must be number and bigger or equal to 0");
            cJSON_Delete(jsonData);
            return false;
        }
        auto ret = shortcutKey.preKeys.emplace(preKeyJson->valueint);
        if (!ret.second) {
            MMI_HILOGE("preKey must be unduplicated");
            cJSON_Delete(jsonData);
            return false;
        }
    }
    cJSON_Delete(jsonData);
    return true;
}

bool KeyCommandManager::GetTrigger(const std::string &objStr, int32_t &triggerType)
{
    cJSON* jsonData = cJSON_Parse(objStr.c_str());
    CHKPF(jsonData);
    cJSON *trigger = cJSON_GetObjectItemCaseSensitive(jsonData, "trigger");
    if (trigger == nullptr) {
        MMI_HILOGE("trigger is nullptr");
        cJSON_Delete(jsonData);
        return false;
    }
    if (!cJSON_IsString(trigger)) {
        MMI_HILOGE("trigger must be one of [key_up, key_down]");
        cJSON_Delete(jsonData);
        return false;
    }
    if (((std::strcmp(trigger->valuestring, "key_up") != 0)
        && (std::strcmp(trigger->valuestring, "key_down") != 0))) {
        MMI_HILOGE("trigger must be one of [key_up, key_down]");
        cJSON_Delete(jsonData);
        return false;
    }
    if (std::strcmp(trigger->valuestring, "key_up") == 0) {
        triggerType = KeyEvent::KEY_ACTION_UP;
    } else {
        triggerType = KeyEvent::KEY_ACTION_DOWN;
    }
    return true;
}

bool KeyCommandManager::GetKeyDownDuration(const std::string &objStr, int32_t &keyDownDurationInt)
{
    cJSON* jsonData = cJSON_Parse(objStr.c_str());
    CHKPF(jsonData);
    cJSON *keyDownDuration = cJSON_GetObjectItemCaseSensitive(jsonData, "keyDownDuration");
    if (keyDownDuration == nullptr) {
        MMI_HILOGE("keyDownDuration is nullptr");
        cJSON_Delete(jsonData);
        return false;
    }
    if (!cJSON_IsNumber(keyDownDuration)) {
        MMI_HILOGE("keyDownDuration must be number and bigger and equal zero");
        cJSON_Delete(jsonData);
        return false;
    }
    if (keyDownDuration->valueint < 0) {
        MMI_HILOGE("keyDownDuration must be number and bigger and equal zero");
        cJSON_Delete(jsonData);
        return false;
    }
    keyDownDurationInt = keyDownDuration->valueint;
    return true;
}

bool KeyCommandManager::GetKeyFinalKey(const std::string &objStr, int32_t &finalKeyInt)
{
    cJSON* jsonData = cJSON_Parse(objStr.c_str());
    CHKPF(jsonData);
    cJSON *finalKey = cJSON_GetObjectItemCaseSensitive(jsonData, "finalKey");
    if (finalKey == nullptr) {
        MMI_HILOGE("finalKey is nullptr");
        cJSON_Delete(jsonData);
        return false;
    }
    if (!cJSON_IsNumber(finalKey)) {
        MMI_HILOGE("finalKey must be number");
        cJSON_Delete(jsonData);
        return false;
    }
    finalKeyInt = finalKey->valueint;
    return true;
}

bool KeyCommandManager::ConvertToShortcutKey(const std::string &jsonDataStr, ShortcutKey &shortcutKey)
{
    if (!GetPreKeys(jsonDataStr, shortcutKey)) {
        MMI_HILOGE("preKeys is nullptr");
        return false;
    }
    if (!GetKeyFinalKey(jsonDataStr, shortcutKey.finalKey)) {
        MMI_HILOGE("GetTrigger return false");
        return false;
    }
    if (!GetTrigger(jsonDataStr, shortcutKey.triggerType)) {
        MMI_HILOGE("GetTrigger return false");
        return false;
    }
    if (!GetKeyDownDuration(jsonDataStr, shortcutKey.keyDownDuration)) {
        MMI_HILOGE("GetKeyDownDuration return false");
        return false;
    }
    cJSON* jsonData = cJSON_Parse(jsonDataStr.c_str());
    CHKPF(jsonData);
    cJSON *ability = cJSON_GetObjectItemCaseSensitive(jsonData, "ability");
    if (ability == nullptr) {
        MMI_HILOGE("ability is nullptr");
        cJSON_Delete(jsonData);
        return false;
    }
    std::string abilityStr = cJSON_Print(ability);
    if (abilityStr.empty()) {
        MMI_HILOGE("abilityStr is null");
        cJSON_Delete(jsonData);
        return false;
    }
    if (!PackageAbility(abilityStr, shortcutKey.ability)) {
        MMI_HILOGE("package ability failed");
        cJSON_Delete(jsonData);
        return false;
    }
    return true;
}

void KeyCommandManager::GetKeyVal(const std::string &objStr, const std::string &key, std::string &value)
{
    cJSON *json = cJSON_Parse(objStr.c_str());
    CHKPV(json);
    cJSON *valueJson = cJSON_GetObjectItemCaseSensitive(json, key.c_str());
    if (valueJson == nullptr) {
        MMI_HILOGE("valueJson is nullptr");
        cJSON_Delete(json);
        return;
    }
    value = valueJson->valuestring;
    cJSON_Delete(json);
    return;
}

bool KeyCommandManager::GetParams(const std::string &objStr, Ability &ability)
{
    cJSON *jsonAbility = cJSON_Parse(objStr.c_str());
    CHKPF(jsonAbility);
    cJSON *params = cJSON_GetObjectItemCaseSensitive(jsonAbility, "params");
    if (params == nullptr) {
        MMI_HILOGE("params is nullptr");
        cJSON_Delete(jsonAbility);
        return false;
    }
    if (!cJSON_IsArray(params)) {
        MMI_HILOGE("params must be array");
        cJSON_Delete(jsonAbility);
        return false;
    }
    int32_t paramsSize = cJSON_GetArraySize(params);
    for (int32_t i = 0; i < paramsSize; ++i) {
        cJSON* param = cJSON_GetArrayItem(params, i);
        if (param == nullptr) {
            MMI_HILOGE("param is nullptr");
            cJSON_Delete(jsonAbility);
            return false;
        }
        if (!cJSON_IsObject(param)) {
            MMI_HILOGE("param must be object");
            cJSON_Delete(jsonAbility);
            return false;
        }
        cJSON* key = cJSON_GetObjectItemCaseSensitive(param, "key");
        if (key == nullptr) {
            MMI_HILOGE("key is nullptr");
            cJSON_Delete(jsonAbility);
            return false;
        }
        cJSON* value = cJSON_GetObjectItemCaseSensitive(param, "value");
        if (value == nullptr) {
            MMI_HILOGE("value is nullptr");
            cJSON_Delete(jsonAbility);
            return false;
        }
        auto ret = ability.params.emplace(key->valuestring, value->valuestring);
        if (!ret.second) {
            MMI_HILOGW("Emplace to failed");
        }
    }
    return true;
}

bool KeyCommandManager::GetEntities(const std::string &objStr, Ability &ability)
{
    cJSON *jsonAbility = cJSON_Parse(objStr.c_str());
    CHKPF(jsonAbility);
    cJSON *entities = cJSON_GetObjectItemCaseSensitive(jsonAbility, "entities");
    if (entities == nullptr) {
        MMI_HILOGE("entities is nullptr");
        cJSON_Delete(jsonAbility);
        return false;
    }
    if (!cJSON_IsArray(entities)) {
        MMI_HILOGE("entities must be array");
        cJSON_Delete(jsonAbility);
        return false;
    }
    int32_t entitiesSize = cJSON_GetArraySize(entities);
    for (int32_t i = 0; i < entitiesSize; i++) {
        cJSON* entitie = cJSON_GetArrayItem(entities, i);
        if (entitie == nullptr) {
            MMI_HILOGE("entitie is nullptr");
            cJSON_Delete(jsonAbility);
            return false;
        }
        ability.entities.push_back(entitie->valuestring);
    }
    return true;
}

bool KeyCommandManager::PackageAbility(const std::string &abilityStr, Ability &ability)
{
    GetKeyVal(abilityStr, "bundleName", ability.bundleName);
    GetKeyVal(abilityStr, "abilityName", ability.abilityName);
    GetKeyVal(abilityStr, "action", ability.action);
    GetKeyVal(abilityStr, "type", ability.type);
    GetKeyVal(abilityStr, "deviceId", ability.deviceId);
    GetKeyVal(abilityStr, "uri", ability.uri);
    if (!GetEntities(abilityStr, ability)) {
        MMI_HILOGE("GetEntities return false");
        return false;
    }
    if (!GetParams(abilityStr, ability)) {
        MMI_HILOGE("GetParams return false");
        return false;
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

bool KeyCommandManager::HandlerEvent(const std::shared_ptr<KeyEvent> key)
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