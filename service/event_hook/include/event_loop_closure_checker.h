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

#ifndef EVENT_LOOP_CLOSURE_CHECKER_H
#define EVENT_LOOP_CLOSURE_CHECKER_H

#include <shared_mutex>
#include <unordered_map>
#include <unordered_set>

namespace OHOS {
namespace MMI {
class EventLoopClosureChecker {
public:
    EventLoopClosureChecker(const EventLoopClosureChecker&) = delete;
    EventLoopClosureChecker& operator=(const EventLoopClosureChecker&) = delete;
    static EventLoopClosureChecker& GetInstance();
    int32_t CheckLoopClosure(int32_t hookId, int32_t keyCode);
    int32_t UpdatePendingDownKeys(int32_t hookId, int32_t keyCode);
    int32_t RemovePendingDownKeys(int32_t hookId, int32_t keyCode);
    int32_t RemoveChecker(int32_t hookId);

private:
    EventLoopClosureChecker() = default;
    ~EventLoopClosureChecker() = default;

    std::unordered_map<int32_t, std::unordered_set<int32_t>> pendingDownKeys_; // hookId -> pending keyCode
    std::shared_mutex rwMutex_;
};
} // namespace MMI
} // namespace OHOS

#define EVENT_LOOP_CLOSURE_CHECKER OHOS::MMI::EventLoopClosureChecker::GetInstance()
#endif // EVENT_LOOP_CLOSURE_CHECKER_H