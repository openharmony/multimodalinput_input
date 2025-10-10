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

#ifndef MMI_KEY_SHORTCUT_MANAGER_MOCK_H
#define MMI_KEY_SHORTCUT_MANAGER_MOCK_H
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <set>

#include "key_event.h"

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
    static inline constexpr uint32_t SHORTCUT_MODIFIER_NONE { 0U };
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
        int32_t longPressTime; // ms
        int32_t session;
        std::function<void(std::shared_ptr<KeyEvent>)> callback;
    };

    KeyShortcutManager() = default;
    ~KeyShortcutManager() = default;
    DISALLOW_COPY_AND_MOVE(KeyShortcutManager);

    static std::shared_ptr<KeyShortcutManager> GetInstance();
    static bool IsModifier(int32_t keyCode);
    static uint32_t Key2Modifier(int32_t keyCode);

private:
    static const std::map<int32_t, uint32_t> modifiers_;
};

#define KEY_SHORTCUT_MGR KeyShortcutManager::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // MMI_KEY_SHORTCUT_MANAGER_MOCK_H
