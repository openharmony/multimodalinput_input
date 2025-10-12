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

#include "event_expiration_checker.h"

#include <chrono>
#include "define_multimodal.h"
#include "mmi_log.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "EventExpirationChecker"

namespace OHOS {
namespace MMI {
namespace {
constexpr long long STASH_EVENT_TIMEOUT_MS { 3000 };
}

EventExpirationChecker& EventExpirationChecker::GetInstance()
{
    static EventExpirationChecker instance;
    return instance;
}

int32_t EventExpirationChecker::CheckExpiration(int32_t hookId, int32_t eventId)
{
    CALL_DEBUG_ENTER;
    std::unique_lock<std::shared_mutex> lock(rwMutex_);
    RemoveExpiredStashEventLocked(hookId);
    if (stashEvents_.find(hookId) == stashEvents_.end()) {
        MMI_HILOGW("No checker of hook:%{public}d existed", hookId);
        return RET_ERR;
    }
    auto iter = std::find_if(stashEvents_[hookId].begin(),
        stashEvents_[hookId].end(), [eventId] (const auto &stashEvent) {
            CHKPF(stashEvent.keyEvent);
            return stashEvent.keyEvent->GetId() == eventId;
        }
    );
    return iter != stashEvents_[hookId].end() ? RET_OK : RET_ERR;
}

int32_t EventExpirationChecker::UpdateStashEvent(int32_t hookId, std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    std::unique_lock<std::shared_mutex> lock(rwMutex_);
    RemoveExpiredStashEventLocked(hookId);
    EventExpirationChecker::StashEvent stashEvent {
        .timeStampRcvd = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count(),
        .keyEvent = KeyEvent::Clone(keyEvent)
    };
    stashEvents_[hookId].push_back(stashEvent);
    return RET_OK;
}

std::shared_ptr<KeyEvent> EventExpirationChecker::GetKeyEvent(int32_t hookId, int32_t eventId)
{
    std::shared_lock<std::shared_mutex> lock(rwMutex_);
    if (stashEvents_.find(hookId) == stashEvents_.end()) {
        MMI_HILOGW("No checker of hook:%{public}d existed", hookId);
        return nullptr;
    }
    auto iter = std::find_if(stashEvents_[hookId].begin(),
        stashEvents_[hookId].end(), [eventId] (const auto &stashEvent) {
            CHKPF(stashEvent.keyEvent);
            return stashEvent.keyEvent->GetId() == eventId;
        }
    );
    if (iter == stashEvents_[hookId].end()) {
        return nullptr;
    }
    return iter->keyEvent;
}

void EventExpirationChecker::RemoveExpiredStashEventLocked(int32_t hookId)
{
    if (stashEvents_.find(hookId) == stashEvents_.end()) {
        MMI_HILOGW("No checker of hook:%{public}d existed", hookId);
        return;
    }
    long long now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    while (!stashEvents_[hookId].empty()) {
        if (auto head = stashEvents_[hookId].front();
            now - head.timeStampRcvd >= STASH_EVENT_TIMEOUT_MS) {
            stashEvents_[hookId].pop_front();
            continue;
        }
        break;
    }
}

int32_t EventExpirationChecker::RemoveChecker(int32_t hookId)
{
    CALL_INFO_TRACE;
    std::unique_lock<std::shared_mutex> lock(rwMutex_);
    if (stashEvents_.find(hookId) == stashEvents_.end()) {
        MMI_HILOGW("No checker of hook:%{public}d existed", hookId);
        return RET_ERR;
    }
    stashEvents_.erase(hookId);
    return RET_OK;
}
} // namespace MMI
} // namespace OHOS