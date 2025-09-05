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

#include "event_loop_closure_checker.h"

#include "define_multimodal.h"
#include "mmi_log.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "EventLoopClosureChecker"

namespace OHOS {
namespace MMI {

EventLoopClosureChecker& EventLoopClosureChecker::GetInstance()
{
    static EventLoopClosureChecker instance;
    return instance;
}

int32_t EventLoopClosureChecker::CheckLoopClosure(int32_t hookId, int32_t keyCode)
{
    CALL_DEBUG_ENTER;
    std::shared_lock<std::shared_mutex> lock(rwMutex_);
    if (pendingDownKeys_.find(hookId) == pendingDownKeys_.end()) {
        MMI_HILOGW("No checker of hook:%{public}d existed", hookId);
        return RET_ERR;
    }
    if (pendingDownKeys_[hookId].find(keyCode) == pendingDownKeys_[hookId].end()) {
        MMI_HILOGW("No pending down key:%{private}d of hook:%{public}d existed", keyCode, hookId);
        return RET_ERR;
    }
    return RET_OK;
}

int32_t EventLoopClosureChecker::UpdatePendingDownKeys(int32_t hookId, int32_t keyCode)
{
    CALL_DEBUG_ENTER;
    std::unique_lock<std::shared_mutex> lock(rwMutex_);
    pendingDownKeys_[hookId].insert(keyCode);
    return RET_OK;
}

int32_t EventLoopClosureChecker::RemovePendingDownKeys(int32_t hookId, int32_t keyCode)
{
    CALL_DEBUG_ENTER;
    std::unique_lock<std::shared_mutex> lock(rwMutex_);
    if (pendingDownKeys_.find(hookId) == pendingDownKeys_.end()) {
        MMI_HILOGW("No checker of hook:%{public}d existed", hookId);
        return RET_ERR;
    }
    if (pendingDownKeys_[hookId].find(keyCode) == pendingDownKeys_[hookId].end()) {
        MMI_HILOGW("No pending down key:%{private}d of hook:%{public}d existed", keyCode, hookId);
        return RET_ERR;
    }
    pendingDownKeys_[hookId].erase(keyCode);
    return RET_OK;
}

int32_t EventLoopClosureChecker::RemoveChecker(int32_t hookId)
{
    CALL_INFO_TRACE;
    std::unique_lock<std::shared_mutex> lock(rwMutex_);
    if (pendingDownKeys_.find(hookId) == pendingDownKeys_.end()) {
        MMI_HILOGW("No checker of hook:%{public}d existed", hookId);
        return RET_ERR;
    }
    pendingDownKeys_.erase(hookId);
    return RET_OK;
}

} // namespace MMI
} // namespace OHOS