/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef I_KEY_COMMAND_MANAGER_H
#define I_KEY_COMMAND_MANAGER_H

#include "key_event.h"

namespace OHOS {
namespace MMI {
class IKeyCommandManager {
public:
    IKeyCommandManager() = default;
    virtual ~IKeyCommandManager() = default;
    static std::shared_ptr<IKeyCommandManager> GetInstance();
    virtual bool HandlerEvent(const std::shared_ptr<KeyEvent> key)
    {
        return false;
    }
public:
    static inline std::shared_ptr<IKeyCommandManager> keyCommand_ = nullptr;
};
} // namespace MMI
} // namespace OHOS
#endif // I_KEY_COMMAND_MANAGER_H