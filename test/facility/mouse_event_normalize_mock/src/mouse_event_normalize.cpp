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

#include "mouse_event_normalize.h"

namespace OHOS {
namespace MMI {
std::shared_ptr<MouseEventNormalize> MouseEventNormalize::instance_ = nullptr;

std::shared_ptr<MouseEventNormalize> MouseEventNormalize::GetInstance()
{
    if (instance_ == nullptr) {
        instance_ = std::make_shared<MouseEventNormalize>();
    }
    return instance_;
}

void MouseEventNormalize::ReleaseInstance()
{
    instance_.reset();
}
} // namespace MMI
} // namespace OHOS