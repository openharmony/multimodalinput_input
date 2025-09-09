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

#ifndef EVENT_DISPATCH_ORDER_CHECKER_H
#define EVENT_DISPATCH_ORDER_CHECKER_H

#include <shared_mutex>
#include <unordered_set>

namespace OHOS {
namespace MMI {
class EventDispatchOrderChecker {
public:
    EventDispatchOrderChecker(const EventDispatchOrderChecker&) = delete;
    EventDispatchOrderChecker& operator=(const EventDispatchOrderChecker&) = delete;
    static EventDispatchOrderChecker& GetInstance();
    int32_t CheckDispatchOrder(int32_t hookId, int32_t eventId);
    int32_t UpdateLastDispatchedId(int32_t hookId, int32_t eventId);
    int32_t RemoveChecker(int32_t hookId);

private:
    EventDispatchOrderChecker() = default;
    ~EventDispatchOrderChecker() = default;

    std::unordered_map<int32_t, int32_t> dispatchedEventIds_; // hookId -> dispatched eventId
    std::shared_mutex rwMutex_;
};
} // namespace MMI
} // namespace OHOS

#define EVENT_DISPATCH_ORDER_CHECKER OHOS::MMI::EventDispatchOrderChecker::GetInstance()
#endif // EVENT_DISPATCH_ORDER_CHECKER_H