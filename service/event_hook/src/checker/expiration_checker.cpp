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

#include "expiration_checker.h"

#include <chrono>
#include "define_multimodal.h"
#include "mmi_log.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "ExpirationChecker"

namespace OHOS {
namespace MMI {
namespace {
constexpr long long STASH_EVENT_TIMEOUT_MS { 3000 };
}

bool ExpirationChecker::CheckExpiration(int32_t eventId)
{
    std::unique_lock<std::shared_mutex> lock(rwMutex_);
    RemoveExpiredEvent();
    auto iter = std::find_if(stashEvents_.begin(), stashEvents_.end(), [eventId] (const auto &event) {
        return event.eventId == eventId;
    });
    return iter != stashEvents_.end();
}

bool ExpirationChecker::CheckValid(const std::shared_ptr<InputEvent> event)
{
    CHKPF(event);
    std::unique_lock<std::shared_mutex> lock(rwMutex_);
    RemoveExpiredEvent();
    auto iter = std::find_if(stashEvents_.begin(), stashEvents_.end(), [&event] (const auto &elem) {
        return elem.hashCode == event->Hash();
    });
    return iter != stashEvents_.end();
}

void ExpirationChecker::UpdateInputEvent(const std::shared_ptr<InputEvent> event)
{
    CALL_DEBUG_ENTER;
    CHKPV(event);
    std::unique_lock<std::shared_mutex> lock(rwMutex_);
    RemoveExpiredEvent();
    ExpirationChecker::StashEvent stashEvent {
        .timeStampRcvd = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count(),
        .eventId = event->GetId(),
        .hashCode = event->Hash()
    };
    stashEvents_.push_back(stashEvent);
}

void ExpirationChecker::RemoveExpiredEvent()
{
    long long now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    stashEvents_.erase(std::remove_if(stashEvents_.begin(), stashEvents_.end(), [now] (const auto &elem) {
        return now - elem.timeStampRcvd >= STASH_EVENT_TIMEOUT_MS; }),
        stashEvents_.end());
}
} // namespace MMI
} // namespace OHOS