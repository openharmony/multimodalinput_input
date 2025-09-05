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

#include "event_dispatch_order_checker.h"

#include "define_multimodal.h"
#include "mmi_log.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "EventDispatchOrderChecker"

namespace OHOS {
namespace MMI {
EventDispatchOrderChecker& EventDispatchOrderChecker::GetInstance()
{
    static EventDispatchOrderChecker instance;
    return instance;
}

int32_t EventDispatchOrderChecker::CheckDispatchOrder(int32_t hookId, int32_t eventId)
{
    CALL_DEBUG_ENTER;
    std::shared_lock<std::shared_mutex> lock(rwMutex_);
    if (dispatchedEventIds_.find(hookId) == dispatchedEventIds_.end()) {
        MMI_HILOGW("No checker of hook:%{public}d existed", hookId);
        return RET_OK;
    }
    return dispatchedEventIds_[hookId] < eventId ? RET_OK : RET_ERR;
}

int32_t EventDispatchOrderChecker::UpdateLastDispatchedId(int32_t hookId, int32_t eventId)
{
    CALL_DEBUG_ENTER;
    std::unique_lock<std::shared_mutex> lock(rwMutex_);
    dispatchedEventIds_[hookId] = eventId;
    return RET_OK;
}

int32_t EventDispatchOrderChecker::RemoveChecker(int32_t hookId)
{
    CALL_INFO_TRACE;
    std::unique_lock<std::shared_mutex> lock(rwMutex_);
    if (dispatchedEventIds_.find(hookId) == dispatchedEventIds_.end()) {
        MMI_HILOGW("No checker of hook:%{public}d existed", hookId);
        return RET_ERR;
    }
    dispatchedEventIds_.erase(hookId);
    return RET_OK;
}
} // namespace MMI
} // namespace OHOS