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

#ifndef OHOS_ABILITY_LAUNCH_MANAGER_H
#define OHOS_ABILITY_LAUNCH_MANAGER_H

#include <fstream>
#include <map>
#include <condition_variable>
#include <thread>
#include <chrono>
#include <functional>
#include <mutex>
#include <vector>
#include <set>

#include "nlohmann/json.hpp"
#include "c_singleton.h"
#include "struct_multimodal.h"
#include "key_event.h"

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
    int32_t preKey1 { 0 };
    int32_t preKey2 { 0 };
    int32_t preKey3 { 0 };
    int32_t preKey4 { 0 };
    int32_t finalKey { 0 };
    int32_t keyDownDuration { 0 };
    int32_t triggerType { OHOS::MMI::KeyEvent::KEY_ACTION_DOWN };
    Ability ability;
};

class AbilityLaunchManager : public CSingleton<AbilityLaunchManager> {
public:
    AbilityLaunchManager();
    ~AbilityLaunchManager() = default;
    bool CheckLaunchAbility(std::shared_ptr<OHOS::MMI::KeyEvent> &key);

private:
    class Timer {
    public:
        Timer();
        ~Timer();
        void Start(unsigned long millsTime, std::function<void(ShortcutKey)> callback, ShortcutKey key);
        void Stop();

    private:
        void CountingTime();
        std::mutex lock;
        std::condition_variable condition;
        std::thread checkThread;
        bool stopFlag;
        std::function<void(ShortcutKey)> callback_;
        unsigned long time;
        ShortcutKey shortcutKey;
    };
    void ResolveConfig(std::string configFile);
    bool ConvertJson(ShortcutKey &shortcutKey, json &jsonData);
    std::string GetAbilityFilePath();
    void LaunchAbility(ShortcutKey key);
    std::string ConvertKey(ShortcutKey key);
    bool UnwrapAbility(Ability &ability, json &jsonStr);
    void PrintShortcutKey();
    bool CheckKeyPressed(int32_t preKey, std::vector<OHOS::MMI::KeyEvent::KeyItem> &pressedKeys, size_t &count);
    void ResetWaitTriggerKey(ShortcutKey &shortcutKey);
    bool CheckShortcutkeyMatch(ShortcutKey &shortcutKey, std::shared_ptr<OHOS::MMI::KeyEvent> &key);
    Timer timer;
    ShortcutKey waitTriggerKey;
    std::map<std::string, ShortcutKey> shortcutKeysMap;
};
}
}
#define AbilityMgr OHOS::MMI::AbilityLaunchManager::GetInstance()
#endif
