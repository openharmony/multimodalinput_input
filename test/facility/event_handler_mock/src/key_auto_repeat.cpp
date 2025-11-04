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

#include "key_auto_repeat.h"

namespace OHOS {
namespace MMI {
std::shared_ptr<KeyAutoRepeat> KeyAutoRepeat::instance_ = nullptr;

std::shared_ptr<KeyAutoRepeat> KeyAutoRepeat::GetInstance()
{
    if (instance_ == nullptr) {
        instance_ = std::make_shared<KeyAutoRepeat>();
    }
    return instance_;
}

void KeyAutoRepeat::ReleaseInstance()
{
    instance_.reset();
}
} // namespace MMI
} // namespace OHOS
