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

#include "timer_manager.h"

#include <numeric>

#include <sys/timerfd.h>

#include "devicestatus_define.h"
#include "fi_log.h"
#include "include/util.h"

#undef LOG_TAG
#define LOG_TAG "TimerManager"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
constexpr int32_t MIN_DELAY { -1 };
constexpr int32_t NONEXISTENT_ID { -1 };
constexpr int32_t MIN_INTERVAL { 50 };
constexpr int32_t TIME_CONVERSION { 1000 };
constexpr int32_t MAX_INTERVAL_MS { 10000 };
constexpr size_t MAX_TIMER_COUNT { 64 };
} // namespace

int32_t TimerManager::OnInit(IContext *context)
{
    CHKPR(context, RET_ERR);
    context_ = context;

    timerFd_ = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
    if (timerFd_ < 0) {
        FI_HILOGE("timerfd_create failed");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t TimerManager::Init(IContext *context)
{
    CHKPR(context, RET_ERR);
    return context->GetDelegateTasks().PostSyncTask([this, context] {
        return this->OnInit(context);
    });
}

int32_t TimerManager::OnAddTimer(int32_t intervalMs, int32_t repeatCount, std::function<void()> callback)
{
    int32_t timerId = AddTimerInternal(intervalMs, repeatCount, callback);
    ArmTimer();
    return timerId;
}

int32_t TimerManager::AddTimer(int32_t intervalMs, int32_t repeatCount, std::function<void()> callback)
{
    CALL_DEBUG_ENTER;
    CHKPR(context_, RET_ERR);
    return context_->GetDelegateTasks().PostSyncTask([this, intervalMs, repeatCount, callback] {
        return this->OnAddTimer(intervalMs, repeatCount, callback);
    });
}

int32_t TimerManager::OnRemoveTimer(int32_t timerId)
{
    int32_t ret = RemoveTimerInternal(timerId);
    if (ret == RET_OK) {
        ArmTimer();
    }
    return ret;
}

int32_t TimerManager::RemoveTimer(int32_t timerId)
{
    CALL_DEBUG_ENTER;
    CHKPR(context_, RET_ERR);
    return context_->GetDelegateTasks().PostSyncTask([this, timerId] {
        return this->OnRemoveTimer(timerId);
    });
}

int32_t TimerManager::OnResetTimer(int32_t timerId)
{
    int32_t ret = ResetTimerInternal(timerId);
    ArmTimer();
    return ret;
}

int32_t TimerManager::ResetTimer(int32_t timerId)
{
    CALL_INFO_TRACE;
    CHKPR(context_, RET_ERR);
    return context_->GetDelegateTasks().PostSyncTask([this, timerId] {
        return this->OnResetTimer(timerId);
    });
}

bool TimerManager::OnIsExist(int32_t timerId) const
{
    for (auto iter = timers_.begin(); iter != timers_.end(); ++iter) {
        if ((*iter)->id == timerId) {
            return true;
        }
    }
    return false;
}

bool TimerManager::IsExist(int32_t timerId) const
{
    CHKPR(context_, false);
    std::packaged_task<bool(int32_t)> task { [this](int32_t timerId) {
        return this->OnIsExist(timerId);
    } };
    auto fu = task.get_future();

    int32_t ret = context_->GetDelegateTasks().PostSyncTask([this, &task, timerId] {
        return this->RunIsExist(std::ref(task), timerId);
    });
    if (ret != RET_OK) {
        FI_HILOGE("Post task failed");
        return false;
    }
    return fu.get();
}

int32_t TimerManager::OnProcessTimers()
{
    ProcessTimersInternal();
    ArmTimer();
    return RET_OK;
}

void TimerManager::ProcessTimers()
{
    CALL_DEBUG_ENTER;
    CHKPV(context_);
    context_->GetDelegateTasks().PostAsyncTask([this] {
        return this->OnProcessTimers();
    });
}

int32_t TimerManager::RunIsExist(std::packaged_task<bool(int32_t)> &task, int32_t timerId) const
{
    task(timerId);
    return RET_OK;
}

int32_t TimerManager::TakeNextTimerId()
{
    uint64_t timerSlot = std::accumulate(timers_.cbegin(), timers_.cend(), uint64_t(0U),
        [] (uint64_t s, const auto &timer) {
            return (s |= (uint64_t(1U) << timer->id));
        });
    for (size_t tmpCount = 0; tmpCount < MAX_TIMER_COUNT; ++tmpCount) {
        if ((timerSlot & (uint64_t(1U) << tmpCount)) == 0) {
            return tmpCount;
        }
    }
    return NONEXISTENT_ID;
}

int32_t TimerManager::AddTimerInternal(int32_t intervalMs, int32_t repeatCount, std::function<void()> callback)
{
    CALL_DEBUG_ENTER;
    if (intervalMs < MIN_INTERVAL) {
        intervalMs = MIN_INTERVAL;
    } else if (intervalMs > MAX_INTERVAL_MS) {
        intervalMs = MAX_INTERVAL_MS;
    }
    if (!callback) {
        return NONEXISTENT_ID;
    }
    int32_t nextTimerId = TakeNextTimerId();
    if (nextTimerId < 0) {
        return NONEXISTENT_ID;
    }
    auto timer = std::make_unique<TimerItem>();
    timer->id = nextTimerId;
    timer->repeatCount = repeatCount;
    timer->intervalMs = intervalMs;
    timer->callbackCount = 0;
    int64_t nowTime = GetMillisTime();
    if (!AddInt64(nowTime, timer->intervalMs, timer->nextCallTime)) {
        FI_HILOGE("The addition of nextCallTime in TimerItem overflows");
        return NONEXISTENT_ID;
    }
    timer->callback = callback;
    InsertTimerInternal(timer);
    return nextTimerId;
}

int32_t TimerManager::RemoveTimerInternal(int32_t timerId)
{
    for (auto iter = timers_.begin(); iter != timers_.end(); ++iter) {
        if ((*iter)->id == timerId) {
            timers_.erase(iter);
            return RET_OK;
        }
    }
    return RET_ERR;
}

int32_t TimerManager::ResetTimerInternal(int32_t timerId)
{
    for (auto iter = timers_.begin(); iter!= timers_.end(); ++iter) {
        if ((*iter)->id == timerId) {
            auto timer = std::move(*iter);
            timers_.erase(iter);
            int64_t nowTime = GetMillisTime();
            if (!AddInt64(nowTime, timer->intervalMs, timer->nextCallTime)) {
                FI_HILOGE("The addition of nextCallTime in TimerItem overflows");
                return RET_ERR;
            }
            timer->callbackCount = 0;
            InsertTimerInternal(timer);
            return RET_OK;
        }
    }
    return RET_ERR;
}

void TimerManager::InsertTimerInternal(std::unique_ptr<TimerItem> &timer)
{
    for (auto iter = timers_.begin(); iter != timers_.end(); ++iter) {
        if ((*iter)->nextCallTime > timer->nextCallTime) {
            timers_.insert(iter, std::move(timer));
            return;
        }
    }
    timers_.push_back(std::move(timer));
}

int64_t TimerManager::CalcNextDelayInternal()
{
    int64_t delayTime = MIN_DELAY;
    if (!timers_.empty()) {
        int64_t nowTime = GetMillisTime();
        const auto &items = *timers_.begin();
        if (nowTime >= items->nextCallTime) {
            delayTime = 0;
        } else {
            delayTime = items->nextCallTime - nowTime;
        }
    }
    return delayTime;
}

void TimerManager::ProcessTimersInternal()
{
    if (timers_.empty()) {
        return;
    }
    int64_t presentTime = GetMillisTime();
    for (;;) {
        auto tIter = timers_.begin();
        if (tIter == timers_.end()) {
            break;
        }
        if ((*tIter)->nextCallTime > presentTime) {
            break;
        }
        auto currentTimer = std::move(*tIter);
        timers_.erase(tIter);
        ++currentTimer->callbackCount;
        if ((currentTimer->repeatCount >= 1) && (currentTimer->callbackCount >= currentTimer->repeatCount)) {
            currentTimer->callback();
            continue;
        }
        if (!AddInt64(currentTimer->nextCallTime, currentTimer->intervalMs, currentTimer->nextCallTime)) {
            FI_HILOGE("The addition of nextCallTime in TimerItem overflows");
            return;
        }
        auto callback = currentTimer->callback;
        InsertTimerInternal(currentTimer);
        callback();
    }
}

int32_t TimerManager::ArmTimer()
{
    CALL_DEBUG_ENTER;
    if (timerFd_ < 0) {
        FI_HILOGE("TimerManager is not initialized");
        return RET_ERR;
    }
    struct itimerspec tspec {};
    int64_t expire = CalcNextDelayInternal();
    FI_HILOGI("The next expire %{public}" PRId64, expire);

    if (expire == 0) {
        expire = 1;
    }
    if (expire > 0) {
        tspec.it_value.tv_sec = expire / TIME_CONVERSION;
        tspec.it_value.tv_nsec = (expire % TIME_CONVERSION) * TIME_CONVERSION * TIME_CONVERSION;
    }

    if (timerfd_settime(timerFd_, 0, &tspec, NULL) != 0) {
        FI_HILOGE("Timer: the timerfd_settime is error");
        return RET_ERR;
    }
    return RET_OK;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
