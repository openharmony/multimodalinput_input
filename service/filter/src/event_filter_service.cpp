/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "mmi_log.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
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

ErrCode EventFilterService::HandleKeyEvent(const std::shared_ptr<KeyEvent>& event, bool &resultValue)
{
    CHKPF(filter_);
    resultValue =  filter_->OnInputEvent(event);
    return ERR_OK;
}

ErrCode EventFilterService::HandlePointerEvent(const std::shared_ptr<PointerEvent>& event, bool &resultValue)
{
    CHKPF(filter_);
    resultValue = filter_->OnInputEvent(event);
    return ERR_OK;
}
} // namespace MMI
} // namespace OHOS
