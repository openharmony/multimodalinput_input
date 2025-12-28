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

#ifndef ABILITY_LAUNCHER_H
#define ABILITY_LAUNCHER_H

#include <memory>

#include "ability_manager_client.h"
#include "singleton.h"

#include "i_key_command_service.h"
#include "input_handler_type.h"
#include "key_command_context.h"
#include "key_command_types.h"


namespace OHOS {
namespace MMI {
class AbilityLauncher final {
public:
    AbilityLauncher() = default;
    AbilityLauncher(const AbilityLauncher&) = delete;
    AbilityLauncher& operator=(const AbilityLauncher&) = delete;
    void LaunchAbility(const Ability &ability);
    void LaunchAbility(const Ability &ability, int64_t delay);
    void LaunchRepeatKeyAbility(const RepeatKey &item, const std::shared_ptr<KeyEvent> keyEvent);
    void SetKeyCommandService(IKeyCommandService* service);
private:
    IKeyCommandService* keyCommandService_ { nullptr };
};
#define LAUNCHER_ABILITY ::OHOS::DelayedSingleton<AbilityLauncher>::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // ABILITY_LAUNCHER_H

