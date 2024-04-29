/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "event_filter_service.h"

#include <cstring>

#include <sys/types.h>
#include <unistd.h>

#include "string_ex.h"

#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "EventFilterService"

namespace OHOS {
namespace MMI {
int32_t EventFilterService::GetNextId()
{
    std::lock_guard<std::mutex> guard(mutex_);
    if (filterIdSeed_ == std::numeric_limits<int32_t>::max()) {
        filterIdSeed_ = 0;
    }
    return filterIdSeed_++;
}

bool EventFilterService::HandleKeyEvent(const std::shared_ptr<KeyEvent> event)
{
    if (filter_ == nullptr) {
        MMI_HILOGE("Filter is nullptr");
        return false;
    }
    return filter_->OnInputEvent(event);
}

bool EventFilterService::HandlePointerEvent(const std::shared_ptr<PointerEvent> event)
{
    if (filter_ == nullptr) {
        MMI_HILOGE("Filter is nullptr");
        return false;
    }
    return filter_->OnInputEvent(event);
}
} // namespace MMI
} // namespace OHOS
