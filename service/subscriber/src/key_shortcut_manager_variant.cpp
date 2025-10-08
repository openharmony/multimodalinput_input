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

#include "key_shortcut_manager.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyShortcutManager"

namespace OHOS {
namespace MMI {

std::mutex KeyShortcutManager::mutex_;
std::shared_ptr<KeyShortcutManager> KeyShortcutManager::instance_;

const std::map<int32_t, uint32_t> KeyShortcutManager::modifiers_ {
    { KeyEvent::KEYCODE_ALT_LEFT, SHORTCUT_MODIFIER_ALT },
    { KeyEvent::KEYCODE_ALT_RIGHT, SHORTCUT_MODIFIER_ALT },
    { KeyEvent::KEYCODE_SHIFT_LEFT, SHORTCUT_MODIFIER_SHIFT },
    { KeyEvent::KEYCODE_SHIFT_RIGHT, SHORTCUT_MODIFIER_SHIFT },
    { KeyEvent::KEYCODE_CTRL_LEFT, SHORTCUT_MODIFIER_CTRL },
    { KeyEvent::KEYCODE_CTRL_RIGHT, SHORTCUT_MODIFIER_CTRL },
    { KeyEvent::KEYCODE_META_LEFT, SHORTCUT_MODIFIER_LOGO },
    { KeyEvent::KEYCODE_META_RIGHT, SHORTCUT_MODIFIER_LOGO }
};

std::shared_ptr<KeyShortcutManager> KeyShortcutManager::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> guard(mutex_);
        if (instance_ == nullptr) {
            instance_ = std::make_shared<KeyShortcutManager>();
        }
    }
    return instance_;
}

KeyShortcutManager::KeyShortcutManager() {}

bool KeyShortcutManager::IsModifier(int32_t keyCode)
{
    return (modifiers_.find(keyCode) != modifiers_.cend());
}

uint32_t KeyShortcutManager::Key2Modifier(int32_t keyCode)
{
    if (auto iter = modifiers_.find(keyCode); iter != modifiers_.cend()) {
        return iter->second;
    }
    return SHORTCUT_MODIFIER_NONE;
}
} // namespace MMI
} // namespace OHOS
