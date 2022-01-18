/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "ability_launch_manager.h"
#include <fstream>
#include <sstream>
#include <iostream>

#include "log.h"
#include "file_ex.h"
#include "ability_manager_client.h"
#include "ohos/aafwk/base/string_wrapper.h"

namespace OHOS::MMI {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "AbilityLaunchManager" };
using namespace std;
}
}

OHOS::MMI::AbilityLaunchManager::AbilityLaunchManager()
{
    ResolveConfig(GetAbilityFilePath());
    PrintShortcutKey();
}

std::string OHOS::MMI::AbilityLaunchManager::ConvertKey(ShortcutKey key)
{
    std::stringstream oss;
    oss << key.preKey1 << ",";
    oss << key.preKey2 << ",";
    oss << key.preKey3 << ",";
    oss << key.preKey4 << ",";
    oss << key.finalKey << ",";
    oss << key.triggerType;
    return std::string(oss.str());
}

std::string OHOS::MMI::AbilityLaunchManager::GetAbilityFilePath()
{
    std::string abilityFilePath = "/product/multimodalinput/ability_launch_config.json";
    return FileExists(abilityFilePath) ? abilityFilePath : "/system/etc/multimodalinput/ability_launch_config.json";
}

void OHOS::MMI::AbilityLaunchManager::ResolveConfig(std::string configFile)
{
    if (!FileExists(configFile)) {
        MMI_LOGE("ability config file %{public}s not exist!", configFile.c_str());
        return;
    }
    MMI_LOGE("ability config file path %{public}s", configFile.c_str());
    std::ifstream reader(configFile);
    if (!reader.is_open()) {
        MMI_LOGE("json file can not open!");
        return;
    }
    json configJson;
    reader >> configJson;
    reader.close();
    if (configJson.empty()) {
        MMI_LOGE("json file is empty!");
        return;
    }
    json abilityArray = configJson["Shortkeys"];
    if (!abilityArray.is_array() || abilityArray.empty()) {
        MMI_LOGE("shortkeys array is empty!");
        return;
    }
    shortcutKeysMap.clear();
    for (int32_t i = 0; i < static_cast<int32_t>(abilityArray.size()); i++) {
        ShortcutKey shortcutKey;
        if (ConvertJson(shortcutKey, abilityArray[i])) {
            std::string key = ConvertKey(shortcutKey);
            auto result = shortcutKeysMap.find(key);
            if (result == shortcutKeysMap.end()) {
                shortcutKeysMap.emplace(key, shortcutKey);
            }
        }
    }
}

bool OHOS::MMI::AbilityLaunchManager::ConvertJson(ShortcutKey &shortcutKey, json &jsonData)
{
    json preKey = jsonData["preKey"];
    if (!preKey.is_array() || preKey.size() != 4) {
        MMI_LOGE("preKey array length must be four!");
        return false;
    }

    if (!preKey[0].is_number() || !preKey[1].is_number() || !preKey[2].is_number() || !preKey[3].is_number()) {
        MMI_LOGE("preKey type must be number!");
        return false;
    }
    shortcutKey.preKey1 = preKey[0];
    shortcutKey.preKey2 = preKey[1];
    shortcutKey.preKey3 = preKey[2];
    shortcutKey.preKey4 = preKey[3];
    if (!jsonData["finalKey"].is_number()) {
        MMI_LOGE("finalKey type must be number!");
        return false;
    }
    shortcutKey.finalKey = jsonData["finalKey"];
    if (!jsonData["trigger"].is_string() ||
        (jsonData["trigger"].get<std::string>() != "key_up" && jsonData["trigger"].get<std::string>() != "key_down")) {
        MMI_LOGE("trigger must be one of [key_up,key_down]!");
        return false;
    }
    if (jsonData["trigger"].get<std::string>() == "key_up") {
        shortcutKey.triggerType = OHOS::MMI::KeyEvent::KEY_ACTION_UP;
    } else {
        shortcutKey.triggerType = OHOS::MMI::KeyEvent::KEY_ACTION_DOWN;
    }
    if (!jsonData["keyDownDuration"].is_number() || jsonData["keyDownDuration"] < 0) {
        MMI_LOGE("keyDownDuration type must be number and greater than or equal to zero!");
        return false;
    }
    if (shortcutKey.triggerType == OHOS::MMI::KeyEvent::KEY_ACTION_UP && jsonData["keyDownDuration"] != 0) {
        MMI_LOGE("triggerType is key_up, keyDownDuration must equal to zero!");
        return false;
    }
    shortcutKey.keyDownDuration = jsonData["keyDownDuration"];
    if (!UnwrapAbility(shortcutKey.ability, jsonData["ability"])) {
        MMI_LOGE("ability resolve failed!");
        return false;
    }
    return true;
}

bool OHOS::MMI::AbilityLaunchManager::UnwrapAbility(Ability &ability, json &jsonAbility)
{
    if (!jsonAbility.is_object() || !jsonAbility["entities"].is_array()) {
        MMI_LOGE("ability type must be object!");
        return false;
    }
    ability.bundleName = jsonAbility["bundleName"];
    ability.abilityName = jsonAbility["abilityName"];
    ability.action = jsonAbility["action"];
    ability.type = jsonAbility["type"];
    ability.deviceId = jsonAbility["deviceId"];
    ability.uri = jsonAbility["uri"];
    for (int32_t i = 0; i < static_cast<int32_t>(jsonAbility["entities"].size()); i++) {
        ability.entities.push_back(jsonAbility["entities"][i]);
    }
    for (int32_t i = 0; i < static_cast<int32_t>(jsonAbility["params"].size()); i++) {
        ability.params.emplace(jsonAbility["params"][i]["key"], jsonAbility["params"][i]["value"]);
    }
    return true;
}

void OHOS::MMI::AbilityLaunchManager::PrintShortcutKey()
{
    int32_t count = shortcutKeysMap.size();
    MMI_LOGE("shortcutKeysMap size %{public}d", count);
    for (auto it = shortcutKeysMap.begin(); it != shortcutKeysMap.end(); ++it) {
        auto &shortcutKey = it->second;
        MMI_LOGE("preKey1 = %{public}d preKey2 = %{public}d preKey3 = %{public}d preKey4 = %{public}d finalKey = %{public}d "
            "keyDownDuration = %{public}d triggerType = %{public}d bundleName = %{public}s  abilityName = %{public}s",
            shortcutKey.preKey1, shortcutKey.preKey2, shortcutKey.preKey3, shortcutKey.preKey4, shortcutKey.finalKey,
            shortcutKey.keyDownDuration, shortcutKey.triggerType, shortcutKey.ability.bundleName.c_str(),
            shortcutKey.ability.abilityName.c_str());
    }
}

bool OHOS::MMI::AbilityLaunchManager::CheckLaunchAbility(std::shared_ptr<OHOS::MMI::KeyEvent> &key)
{
    if (CheckShortcutkeyMatch(waitTriggerKey, key)) {
        MMI_LOGE("The same shortcutkey is waiting timeout");
        return true;
    }
    timer.Stop();
    ResetWaitTriggerKey(waitTriggerKey);
    for (auto iter = shortcutKeysMap.begin(); iter != shortcutKeysMap.end(); ++iter) {
        ShortcutKey &shortcutKey = iter->second;
        if (!CheckShortcutkeyMatch(shortcutKey, key)) {
            continue;
        }
        if (shortcutKey.triggerType == OHOS::MMI::KeyEvent::KEY_ACTION_DOWN && shortcutKey.keyDownDuration > 0) {
            MMI_LOGE("Key event matched, start Timer, key=%{public}d, keyAction=%{public}d", key->GetKeyCode(), key->GetKeyAction());
            waitTriggerKey = shortcutKey;
            timer.Start(shortcutKey.keyDownDuration,
                std::bind(&AbilityLaunchManager::LaunchAbility, this, std::placeholders::_1), shortcutKey);
        } else {
            MMI_LOGE("Start launch ability");
            LaunchAbility(shortcutKey);
        }
        return true;
    }
    return false;
}

void OHOS::MMI::AbilityLaunchManager::ResetWaitTriggerKey(ShortcutKey &shortcutKey) {
    shortcutKey.preKey1 = 0;
    shortcutKey.preKey2 = 0;
    shortcutKey.preKey3 = 0;
    shortcutKey.preKey4 = 0;
    shortcutKey.finalKey = 0;
}

bool OHOS::MMI::AbilityLaunchManager::CheckShortcutkeyMatch(ShortcutKey &shortcutKey, std::shared_ptr<OHOS::MMI::KeyEvent> &key) {
    if (key->GetKeyCode() != shortcutKey.finalKey || shortcutKey.triggerType != key->GetKeyAction()) {
        return false;
    }
    size_t validCount = 0;
    if (key->GetKeyAction() == OHOS::MMI::KeyEvent::KEY_ACTION_DOWN) {
        validCount++;
    }
    std::vector<OHOS::MMI::KeyEvent::KeyItem> pressedKeys = key->GetKeyItems();
    if (!CheckKeyPressed(shortcutKey.preKey1, pressedKeys, validCount)) {
        return false;
    }
    if (!CheckKeyPressed(shortcutKey.preKey2, pressedKeys, validCount)) {
        return false;
    }
    if (!CheckKeyPressed(shortcutKey.preKey3, pressedKeys, validCount)) {
        return false;
    }
    if (!CheckKeyPressed(shortcutKey.preKey4, pressedKeys, validCount)) {
        return false;
    }
    if (validCount != pressedKeys.size()) {
        return false;
    }
    return true;
}

bool OHOS::MMI::AbilityLaunchManager::CheckKeyPressed(int32_t waitCheckedKey,
    std::vector<OHOS::MMI::KeyEvent::KeyItem> &pressedKeys, size_t &count)
{
    if (waitCheckedKey <= 0) {
        return true;
    }
    for (auto iter = pressedKeys.begin(); iter != pressedKeys.end(); ++iter) {
        if (iter->GetKeyCode() == waitCheckedKey) {
            count++;
            return true;
        }
    }
    return false;
}

void OHOS::MMI::AbilityLaunchManager::LaunchAbility(ShortcutKey key)
{
    AAFwk::Want want;
    want.SetElementName(key.ability.deviceId, key.ability.bundleName, key.ability.abilityName);
    want.SetAction(key.ability.action);
    want.SetUri(key.ability.uri);
    want.SetType(key.ability.uri);
    for (size_t i = 0; i < key.ability.entities.size(); i++) {
        want.AddEntity(key.ability.entities[i]);
    }
    AAFwk::WantParams wParams;
    for (auto it = key.ability.params.begin(); it != key.ability.params.end(); it++) {
        auto key = it->first;
        auto value = it->second;
        wParams.SetParam(key, AAFwk::String::Box(value));
    }
    want.SetParams(wParams);
    MMI_LOGE("Start launch ability, abilityName:%{public}s", key.ability.abilityName.c_str());
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want);
    if (err != ERR_OK) {
        MMI_LOGE("LaunchAbility failed, abilityName:%{public}s, err:%{public}d", key.ability.abilityName.c_str(), err);
    }
    ResetWaitTriggerKey(waitTriggerKey);
    MMI_LOGE("End launch ability, abilityName:%{public}s", key.ability.abilityName.c_str());
}

OHOS::MMI::AbilityLaunchManager::Timer::Timer()
{
    stopFlag = false;
    time = 0;
    checkThread = std::thread(&Timer::CountingTime, this);
}

OHOS::MMI::AbilityLaunchManager::Timer::~Timer()
{
    std::lock_guard<std::mutex> lockGuard(lock);
    stopFlag = true;
    condition.notify_all();
    if (checkThread.joinable()) {
        checkThread.join();
    }
}

void OHOS::MMI::AbilityLaunchManager::Timer::Start(unsigned long millsTime,
    std::function<void(ShortcutKey)> callback, ShortcutKey key)
{
    std::lock_guard<std::mutex> lockGuard(lock);
    time = millsTime;
    callback_ = callback;
    shortcutKey = key;
    condition.notify_all();
}

void OHOS::MMI::AbilityLaunchManager::Timer::Stop()
{
    std::lock_guard<std::mutex> lockGuard(lock);
    condition.notify_all();
}

void OHOS::MMI::AbilityLaunchManager::Timer::CountingTime()
{
    std::unique_lock<std::mutex> lk(lock);
    while (!stopFlag) {
        if (time == 0) {
            condition.wait(lk);
        } else {
            if (condition.wait_for(lk, std::chrono::milliseconds(time)) == std::cv_status::timeout) {
                if (callback_ != nullptr) {
                    MMI_LOGE("timeout, start launch ability abilityName %{public}s", shortcutKey.ability.abilityName.c_str());
                    callback_(shortcutKey);
                }
            }
            time = 0;
        }
    }
}