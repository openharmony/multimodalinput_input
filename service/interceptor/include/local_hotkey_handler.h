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

#ifndef LOCAL_HOTKEY_HANDLER_H
#define LOCAL_HOTKEY_HANDLER_H

#include <map>
#include <memory>
#include <optional>
#include <set>
#include <shared_mutex>
#include <string>
#include <vector>

#include "key_event.h"

namespace OHOS {
namespace MMI {
struct LocalHotKey {
    int32_t keyCode_ { KeyEvent::KEYCODE_UNKNOWN };
    uint32_t modifiers_ { 0U };

    bool operator<(const LocalHotKey &other) const;
};

enum class LocalHotKeyAction {
    INTERCEPT,
    COPY,
    OVER,
};

using LocalHotKeyMap = std::map<LocalHotKey, LocalHotKeyAction>;

class LocalHotKeySteward final {
public:
    LocalHotKeySteward() = default;
    ~LocalHotKeySteward() = default;
    DISALLOW_COPY_AND_MOVE(LocalHotKeySteward);

    void LoadLocalHotKeys();
    void LoadSystemLocalHotKeys();
    LocalHotKeyAction QueryAction(const LocalHotKey &hotKey) const;
    void Dump(int32_t fd, const std::vector<std::string> &args) const;

private:
    mutable std::shared_mutex mutex_;
    LocalHotKeyMap localHotKeys_;
    std::set<int32_t> systemHotKeys_;
};

class LocalHotKeyHandler final {
public:
    LocalHotKeyHandler() = default;
    ~LocalHotKeyHandler() = default;
    DISALLOW_COPY_AND_MOVE(LocalHotKeyHandler);

    bool HandleEvent(std::shared_ptr<KeyEvent> keyEvent,
        std::function<void(std::shared_ptr<KeyEvent>)> intercept);
    void Dump(int32_t fd, const std::vector<std::string> &args) const;

private:
    bool HandleKeyDown(std::shared_ptr<KeyEvent> keyEvent,
        std::function<void(std::shared_ptr<KeyEvent>)> intercept);
    bool HandleKeyUp(std::shared_ptr<KeyEvent> keyEvent,
        std::function<void(std::shared_ptr<KeyEvent>)> intercept);
    std::optional<LocalHotKey> KeyEvent2LocalHotKey(std::shared_ptr<KeyEvent> keyEvent) const;

    static LocalHotKeySteward steward_;
    std::map<int32_t, LocalHotKeyAction> consumedKeys_;
};
} // namespace MMI
} // namespace OHOS
#endif // LOCAL_HOTKEY_HANDLER_H