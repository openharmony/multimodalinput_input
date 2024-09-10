/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef TIMER_MANAGER_H
#define TIMER_MANAGER_H

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>

#include <singleton.h>

namespace OHOS {
namespace MMI {
class TimerManager final {
public:
    static std::shared_ptr<TimerManager> GetInstance();

    TimerManager() = default;
    ~TimerManager() = default;
    DISALLOW_COPY_AND_MOVE(TimerManager);

    int32_t AddTimer(int32_t intervalMs, int32_t repeatCount, std::function<void()> callback);
    int32_t RemoveTimer(int32_t timerId);
    int32_t ResetTimer(int32_t timerId);

private:
    std::atomic_bool running_;
    static std::mutex mutex_;
    static std::shared_ptr<TimerManager> instance_;
};

#define TimerMgr TimerManager::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // TIMER_MANAGER_H