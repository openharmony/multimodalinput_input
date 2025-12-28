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

#ifndef SHORT_KEY_HANDLER_H
#define SHORT_KEY_HANDLER_H

#include "i_key_command_service.h"
#include "key_command_context.h"
#include "key_command_types.h"

namespace OHOS {
namespace MMI {
class ShortKeyHandler {
public:
    explicit ShortKeyHandler(KeyCommandContext& context, IKeyCommandService& service)
        : context_(context), service_(service) {}
    ~ShortKeyHandler() = default;
    bool HandleShortKeys(const std::shared_ptr<KeyEvent> keyEvent);

private:
    bool MatchShortcutKeys(const std::shared_ptr<KeyEvent> keyEvent);
    bool MatchShortcutKey(std::shared_ptr<KeyEvent> keyEvent, ShortcutKey &shortcutKey,
                        std::vector<ShortcutKey> &upAbilities);
    bool IsKeyMatch(const ShortcutKey &shortcutKey, const std::shared_ptr<KeyEvent> &key);
    bool SkipFinalKey(const int32_t keyCode, const std::shared_ptr<KeyEvent> &key);
    bool HandleKeyDown(ShortcutKey &shortcutKey);
    bool HandleKeyUp(const std::shared_ptr<KeyEvent> &keyEvent, const ShortcutKey &shortcutKey);
    bool HandleKeyCancel(ShortcutKey &shortcutKey);
    bool HandleConsumedKeyEvent(const std::shared_ptr<KeyEvent> keyEvent);
    void ResetCurrentLaunchAbilityKey();
    int32_t GetKeyDownDurationFromXml(const std::string &businessId);
    void LaunchShortcutKeyAbility(const ShortcutKey &shortcutKey);

private:
    std::set<std::string> lastMatchedKeys_;
    ShortcutKey currentLaunchAbilityKey_;

private:
    KeyCommandContext& context_;
    IKeyCommandService& service_;
};
}  // namespace MMI
}  // namespace OHOS
#endif // SHORT_KEY_HANDLER_H
