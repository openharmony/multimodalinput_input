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

#ifndef SHORTCUT_HANDLER_H
#define SHORTCUT_HANDLER_H

#include <set>

#include "key_command_handler.h"
#include "key_option.h"
#include "nocopyable.h"

namespace OHOS {
namespace MMI {
class ShortcutHandler final {
public:
    ShortcutHandler() = default;
    ~ShortcutHandler() = default;
    DISALLOW_COPY_AND_MOVE(ShortcutHandler);

    bool HaveShortcutConsumed(std::shared_ptr<KeyEvent> keyEvent);
    void UpdateShortcutConsumed(std::shared_ptr<KeyEvent> keyEvent);
    void MarkShortcutConsumed(const ShortcutKey &shortcut);
    void MarkShortcutConsumed(const KeyOption &shortcut);

private:
    std::set<int32_t> shortcutConsumed_;
};
} // namespace MMI
} // namespace OHOS
#endif // SHORTCUT_HANDLER_H
