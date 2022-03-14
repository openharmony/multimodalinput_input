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

#ifndef ABILITY_LAUNCH_MANAGER_H
#define ABILITY_LAUNCH_MANAGER_H

#include <chrono>
#include <condition_variable>
#include <functional>
#include <fstream>
#include <map>
#include <mutex>
#include <set>
#include <thread>
#include <vector>

#include "nocopyable.h"
#include "nlohmann/json.hpp"
#include "singleton.h"

#include "key_event.h"
#include "struct_multimodal.h"

namespace OHOS {
namespace MMI {
using json = nlohmann::json;
struct Ability {
    std::string bundleName;
    std::string abilityName;
    std::string action;
    std::string type;
    std::string deviceId;
    std::string uri;
    std::vector<std::string> entities;
    std::map<std::string, std::string> params;
};

struct ShortcutKey {
    std::set<int32_t> preKeys;
    int32_t finalKey { -1 };
    int32_t keyDownDuration { 0 };
    int32_t triggerType { KeyEvent::KEY_ACTION_DOWN };
    int32_t timerId { -1 };
    Ability ability;
    void Print() const;
};

class AbilityLaunchManager : public DelayedSingleton<AbilityLaunchManager> {
public:
    AbilityLaunchManager();
    DISALLOW_COPY_AND_MOVE(AbilityLaunchManager);
    ~AbilityLaunchManager() = default;
    bool CheckLaunchAbility(const std::shared_ptr<KeyEvent> event);
private:
    void ResolveConfig(std::string configFile);
    bool ConvertToShortcutKey(const json &jsonData, ShortcutKey &shortcutKey);
    std::string GetConfigFilePath() const;
    void LaunchAbility(ShortcutKey key);
    std::string GenerateKey(const ShortcutKey& key);
    bool PackageAbility(const json &jsonStr, Ability &ability);
    void Print();
    bool IsKeyMatch(const ShortcutKey &shortcutKey, const std::shared_ptr<KeyEvent> &key);
    bool HandleKeyUp(const std::shared_ptr<KeyEvent> &keyEvent, const ShortcutKey &shortcutKey);
    bool HandleKeyDown(ShortcutKey &shortcutKey);
    bool HandleKeyCancel(ShortcutKey &shortcutKey);
    void ResetLastMatchedKey()
    {
        lastMatchedKey_.preKeys.clear();
        lastMatchedKey_.finalKey = -1;
        lastMatchedKey_.timerId = -1;
    }
    bool SkipFinalKey(const int32_t keyCode, const std::shared_ptr<KeyEvent> &key);
    ShortcutKey lastMatchedKey_;
    std::map<std::string, ShortcutKey> shortcutKeys_;
};

#define AbilityMgr AbilityLaunchManager::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // ABILITY_LAUNCH_MANAGER_H