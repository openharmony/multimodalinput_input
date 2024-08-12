/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include <functional>
#include <list>
#include <memory>

#include "singleton.h"

#include "define_multimodal.h"
#include "mmi_log.h"
#include "util.h"

namespace OHOS {
namespace MMI {
class TimerManager final {
    DECLARE_DELAYED_SINGLETON(TimerManager);

public:
    DISALLOW_COPY_AND_MOVE(TimerManager);
    int32_t AddTimer(int32_t intervalMs, int32_t repeatCount, std::function<void()> callback);
    int32_t RemoveTimer(int32_t timerId);
    int32_t ResetTimer(int32_t timerId);
    bool IsExist(int32_t timerId);
    int32_t CalcNextDelay();
    void ProcessTimers();

private:
    struct TimerItem {
        int32_t id { 0 };
        int32_t intervalMs { 0 };
        int32_t repeatCount { 0 };
        int32_t callbackCount { 0 };
        int64_t nextCallTime { 0 };
        std::function<void()> callback;
    };
private:
    int32_t TakeNextTimerId();
    int32_t AddTimerInternal(int32_t intervalMs, int32_t repeatCount, std::function<void()> callback);
    int32_t RemoveTimerInternal(int32_t timerId);
    int32_t ResetTimerInternal(int32_t timerId);
    bool IsExistInternal(int32_t timerId);
    void InsertTimerInternal(std::unique_ptr<TimerItem>& timer);
    int32_t CalcNextDelayInternal();
    void ProcessTimersInternal();

private:
    std::list<std::unique_ptr<TimerItem>> timers_;
    std::recursive_mutex timerMutex_;
};

#define TimerMgr ::OHOS::DelayedSingleton<TimerManager>::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // TIMER_MANAGER_H