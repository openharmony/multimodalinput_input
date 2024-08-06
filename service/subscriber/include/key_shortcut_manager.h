/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef KEY_SHORTCUT_MANAGER_H
#define KEY_SHORTCUT_MANAGER_H

#include <functional>
#include <map>
#include <optional>
#include <set>

#include <cJSON.h>
#include <nocopyable.h>

#include "key_command_handler.h"
#include "key_event.h"
#include "key_option.h"

namespace OHOS {
namespace MMI {
enum KeyShortcutError : int32_t {
    KEY_SHORTCUT_ERROR_BASE = -1,
    KEY_SHORTCUT_ERROR_CONFIG = (KEY_SHORTCUT_ERROR_BASE - 1),
    KEY_SHORTCUT_ERROR_COMBINATION_KEY = (KEY_SHORTCUT_ERROR_BASE - 2),
    KEY_SHORTCUT_ERROR_TAKEN = (KEY_SHORTCUT_ERROR_BASE - 3),
};

class KeyShortcutManager final {
public:
    static inline constexpr uint32_t SHORTCUT_MODIFIER_ALT { 0x1 };
    static inline constexpr uint32_t SHORTCUT_MODIFIER_SHIFT { SHORTCUT_MODIFIER_ALT << 1U };
    static inline constexpr uint32_t SHORTCUT_MODIFIER_CTRL { SHORTCUT_MODIFIER_ALT << 2U };
    static inline constexpr uint32_t SHORTCUT_MODIFIER_LOGO { SHORTCUT_MODIFIER_ALT << 3U };
    static inline constexpr uint32_t SHORTCUT_MODIFIER_MASK {
        SHORTCUT_MODIFIER_ALT | SHORTCUT_MODIFIER_SHIFT | SHORTCUT_MODIFIER_CTRL | SHORTCUT_MODIFIER_LOGO };
    static inline constexpr int32_t SHORTCUT_PURE_MODIFIERS { -1 };
    static inline constexpr int32_t MOUSE_BUTTON_LEFT { 25001 };
    static inline constexpr int32_t MOUSE_BUTTON_RIGHT { MOUSE_BUTTON_LEFT + 1 };

    enum ShortcutTriggerType : int32_t {
        SHORTCUT_TRIGGER_TYPE_DOWN = 0,
        SHORTCUT_TRIGGER_TYPE_UP,
    };

    struct SystemShortcutKey {
        std::set<int32_t> modifiers;
        int32_t finalKey;
        int32_t longPressTime; // ms
        ShortcutTriggerType triggerType;
        int32_t session;
        std::function<void(std::shared_ptr<KeyEvent>)> callback;
    };

    struct HotKey {
        std::set<int32_t> modifiers;
        int32_t finalKey;
        int32_t session;
        std::function<void(std::shared_ptr<KeyEvent>)> callback;
    };

    KeyShortcutManager();
    ~KeyShortcutManager() = default;
    DISALLOW_COPY_AND_MOVE(KeyShortcutManager);

    int32_t RegisterSystemKey(const SystemShortcutKey &key);
    void UnregisterSystemKey(int32_t shortcutId);
    int32_t RegisterHotKey(const HotKey &key);
    void UnregisterHotKey(int32_t shortcutId);
    bool HandleEvent(std::shared_ptr<KeyEvent> keyEvent);
    void ResetAll();

    bool HaveShortcutConsumed(std::shared_ptr<KeyEvent> keyEvent);
    void UpdateShortcutConsumed(std::shared_ptr<KeyEvent> keyEvent);
    void MarkShortcutConsumed(const ShortcutKey &shortcut);
    void MarkShortcutConsumed(const KeyOption &shortcut);

    static std::shared_ptr<KeyShortcutManager> GetInstance();

private:
    struct SystemKey {
        uint32_t modifiers;
        int32_t finalKey;

        bool operator<(const SystemKey &other) const;
    };

    struct ExceptionalSystemKey {
        std::set<int32_t> preKeys;
        int32_t finalKey;
        int32_t longPressTime; // ms
        ShortcutTriggerType triggerType;

        bool operator<(const ExceptionalSystemKey &other) const;
    };

    struct KeyShortcut {
        uint32_t modifiers;
        int32_t finalKey;
        int32_t longPressTime; // ms
        ShortcutTriggerType triggerType;
        int32_t session;
        std::function<void(std::shared_ptr<KeyEvent>)> callback;
    };

    void LoadSystemKeys();
    void ReadSystemKeys(const std::string &cfgPath);
    int32_t ReadSystemKey(cJSON *jsonSysKey);
    int32_t AddSystemKey(const std::set<int32_t> &preKeys, int32_t finalKey);
    void LoadExceptionalSystemKeys();
    void ReadExceptionalSystemKeys(const std::string &cfgPath);
    int32_t ReadExceptionalSystemKey(cJSON *jsonSysKey);
    void AddExceptionalSystemKey(const ExceptionalSystemKey &sysKey);
    std::string FormatModifiers(const std::set<int32_t> &modifiers) const;
    int32_t GenerateId() const;
    bool IsExceptionalSystemKey(const ExceptionalSystemKey &sysKey) const;
    bool IsModifier(int32_t keyCode) const;
    bool CheckSystemKey(const SystemShortcutKey &key, KeyShortcut &shortcut) const;
    bool IsValid(const ShortcutTriggerType triggerType) const;
    bool IsReservedSystemKey(const KeyShortcut &shortcut) const;
    bool CheckGlobalKey(const HotKey &key, KeyShortcut &shortcut) const;
    bool HaveRegisteredGlobalKey(const KeyShortcut &key) const;
    std::string FormatPressedKeys(std::shared_ptr<KeyEvent> keyEvent) const;
    std::set<int32_t> GetForegroundPids() const;
    bool HandleKeyDown(std::shared_ptr<KeyEvent> keyEvent);
    bool HandleKeyUp(std::shared_ptr<KeyEvent> keyEvent);
    bool HandleKeyCancel(std::shared_ptr<KeyEvent> keyEvent);
    bool CheckCombination(std::shared_ptr<KeyEvent> keyEvent, const KeyShortcut &shortcut) const;
    bool CheckPureModifiers(std::shared_ptr<KeyEvent> keyEvent, const KeyShortcut &shortcut) const;
    bool CheckModifiers(std::shared_ptr<KeyEvent> keyEvent, const KeyShortcut &shortcut) const;
    void TriggerDown(std::shared_ptr<KeyEvent> keyEvent, int32_t shortcutId, const KeyShortcut &shortcut);
    void RunShortcut(std::shared_ptr<KeyEvent> keyEvent, int32_t shortcutId);
    void TriggerUp(std::shared_ptr<KeyEvent> keyEvent, int32_t shortcutId, const KeyShortcut &shortcut);
    void ResetTriggering(std::shared_ptr<KeyEvent> keyEvent);
    bool WillResetOnKeyDown(int32_t keyCode, const KeyShortcut &shortcut) const;
    bool WillResetOnKeyUp(int32_t keyCode, const KeyShortcut &shortcut) const;
    void ResetTriggering(int32_t shortcutId);

    std::set<int32_t> shortcutConsumed_;
    std::set<SystemKey> systemKeys_;
    std::set<ExceptionalSystemKey> exceptSysKeys_;
    std::map<int32_t, KeyShortcut> shortcuts_;
    std::map<int32_t, int32_t> triggering_;
    static const std::map<int32_t, uint32_t> modifiers_;
    static std::mutex mutex_;
    static std::shared_ptr<KeyShortcutManager> instance_;
};

#define KEY_SHORTCUT_MGR KeyShortcutManager::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // KEY_SHORTCUT_MANAGER_H
