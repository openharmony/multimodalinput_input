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

#include "shortcut_handler.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "ShortcutHandler"

namespace OHOS {
namespace MMI {

bool ShortcutHandler::HaveShortcutConsumed(std::shared_ptr<KeyEvent> keyEvent)
{
    return (shortcutConsumed_.find(keyEvent->GetKeyCode()) != shortcutConsumed_.cend());
}

void ShortcutHandler::UpdateShortcutConsumed(std::shared_ptr<KeyEvent> keyEvent)
{
    if (keyEvent->GetKeyAction() == KeyEvent::KEY_ACTION_UP) {
        shortcutConsumed_.erase(keyEvent->GetKeyCode());
    }
}

void ShortcutHandler::MarkShortcutConsumed(const ShortcutKey &shortcut)
{
    std::for_each(shortcut.preKeys.cbegin(), shortcut.preKeys.cend(),
        [this](auto keyCode) {
            shortcutConsumed_.emplace(keyCode);
        });
    if (shortcut.triggerType == KeyEvent::KEY_ACTION_DOWN) {
        shortcutConsumed_.emplace(shortcut.finalKey);
    }
}

void ShortcutHandler::MarkShortcutConsumed(const KeyOption &shortcut)
{
    auto preKeys = shortcut.GetPreKeys();

    std::for_each(preKeys.cbegin(), preKeys.cend(),
        [this](auto keyCode) {
            shortcutConsumed_.emplace(keyCode);
        });
    if (shortcut.IsFinalKeyDown()) {
        shortcutConsumed_.emplace(shortcut.GetFinalKey());
    }
}
} // namespace MMI
} // namespace OHOS
