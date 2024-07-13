/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef TIMER_MANAGER_H
#define TIMER_MANAGER_H

#include <future>
#include <functional>
#include <list>
#include <memory>

#include "nocopyable.h"

#include "i_context.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class TimerManager final : public ITimerManager {
public:
    TimerManager() = default;
    DISALLOW_COPY_AND_MOVE(TimerManager);
    ~TimerManager() = default;

    int32_t Init(IContext *context);
    int32_t AddTimer(int32_t intervalMs, int32_t repeatCount, std::function<void()> callback) override;
    int32_t ResetTimer(int32_t timerId);
    int32_t RemoveTimer(int32_t timerId) override;
    bool IsExist(int32_t timerId) const;
    void ProcessTimers();
    int32_t GetTimerFd() const;

private:
    struct TimerItem {
        int32_t id { 0 };
        int32_t intervalMs { 0 };
        int32_t callbackCount { 0 };
        int32_t repeatCount { 0 };
        int64_t nextCallTime { 0 };
        std::function<void()> callback { nullptr };
    };

    int32_t OnInit(IContext *context);
    int32_t OnAddTimer(int32_t intervalMs, int32_t repeatCount, std::function<void()> callback);
    int32_t OnProcessTimers();
    int32_t OnResetTimer(int32_t timerId);
    int32_t OnRemoveTimer(int32_t timerId);
    bool OnIsExist(int32_t timerId) const;
    int32_t RunIsExist(std::packaged_task<bool(int32_t)> &task, int32_t timerId) const;
    int32_t TakeNextTimerId();
    int32_t AddTimerInternal(int32_t intervalMs, int32_t repeatCount, std::function<void()> callback);
    int32_t ResetTimerInternal(int32_t timerId);
    int32_t RemoveTimerInternal(int32_t timerId);
    void InsertTimerInternal(std::unique_ptr<TimerItem> &timer);
    void ProcessTimersInternal();
    int64_t CalcNextDelayInternal();
    int32_t ArmTimer();

    int32_t timerFd_ { -1 };
    IContext *context_ { nullptr };
    std::list<std::unique_ptr<TimerItem>> timers_;
};

inline int32_t TimerManager::GetTimerFd() const
{
    return timerFd_;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // TIMER_MANAGER_H