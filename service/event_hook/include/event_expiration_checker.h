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

#ifndef EVENT_EXPIRATION_CHECKER_H
#define EVENT_EXPIRATION_CHECKER_H

#include <queue>
#include <shared_mutex>
#include <unordered_set>

#include "key_event.h"

namespace OHOS {
namespace MMI {
class EventExpirationChecker {
public:
    EventExpirationChecker(const EventExpirationChecker&) = delete;
    EventExpirationChecker& operator=(const EventExpirationChecker&) = delete;
    static EventExpirationChecker& GetInstance();
    int32_t CheckExpiration(int32_t hookId, int32_t eventId);
    int32_t UpdateStashEvent(int32_t hookId, std::shared_ptr<KeyEvent> keyEvent);
    std::shared_ptr<KeyEvent> GetKeyEvent(int32_t hookId, int32_t eventId);
    int32_t RemoveChecker(int32_t hookId);

private:
    EventExpirationChecker() = default;
    ~EventExpirationChecker() = default;

    void RemoveExpiredStashEventLocked(int32_t hookId);

private:
    struct StashEvent {
        long long timeStampRcvd { 0 };
        std::shared_ptr<KeyEvent> keyEvent { nullptr };
    };
    std::unordered_map<int32_t, std::deque<StashEvent>> stashEvents_; // hookId -> dispatched eventId
    std::shared_mutex rwMutex_;
};
} // namespace MMI
} // namespace OHOS

#define EVENT_EXPIRATION_CHECKER OHOS::MMI::EventExpirationChecker::GetInstance()
#endif // EVENT_EXPIRATION_CHECKER_H