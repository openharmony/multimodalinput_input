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

#ifndef KEY_COMMAND_MANAGER_H
#define KEY_COMMAND_MANAGER_H

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
#include "nocopyable.h"
#include "struct_multimodal.h"
#include "key_event.h"
#include "i_key_command_manager.h"

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
};

class KeyCommandManager : public IKeyCommandManager {
public:
    KeyCommandManager();
    DISALLOW_COPY_AND_MOVE(KeyCommandManager);
    ~KeyCommandManager() = default;
    bool HandlerEvent(const std::shared_ptr<KeyEvent> event);
private:
    void ResolveConfig(std::string configFile);
    bool ConvertToShortcutKey(const json &jsonData, ShortcutKey &shortcutKey);
    std::string GetConfigFilePath();
    void LaunchAbility(ShortcutKey key);
    std::string GenerateKey(const ShortcutKey& key);
    bool PackageAbility(const json &jsonStr, Ability &ability);
    void Print();
    bool IsKeyMatch(const ShortcutKey &shortcutKey, const std::shared_ptr<KeyEvent> &key);
    bool HandleKeyUp(const std::shared_ptr<KeyEvent> &keyEvent, const ShortcutKey &shortcutKey);
    bool HandleKeyDown(ShortcutKey &shortcutKey);
    bool HandleKeyCancel(ShortcutKey &shortcutKey);
    void ResetLastMatchedKey();
    ShortcutKey lastMatchedKey_;
    std::map<std::string, ShortcutKey> shortcutKeys_;
};
} // namespace MMI
} // namespace OHOS
#endif // KEY_COMMAND_MANAGER_H