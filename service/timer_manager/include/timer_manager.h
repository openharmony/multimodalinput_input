/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "c_singleton.h"
#include "define_multimodal.h"
#include <functional>
#include "log.h"
#include <list>
#include <memory>
#include "util.h"

namespace OHOS {
namespace MMI {
class TimerManager : public CSingleton<TimerManager> {  
public:
    int32_t AddTimer(int32_t intervalMs, int32_t repeatCount, std::function<void()> callback);
    int32_t RemoveTimer(int32_t timerId);
    int32_t ResetTimer(int32_t timerId);
    bool IsExist(int32_t timerId);
    int32_t CalcNextDelay();
    void ProcessTimers();
        
private:
    static const int32_t MIN_DELAY = 36;
    static const int32_t MIN_INTERVAL = 50;
    static const int32_t MAX_INTERVAL = 4096;
    static const int32_t MAX_TIMER_COUNT = 32;
    
private:
    struct TimerItem {
        int32_t id_;
        int32_t intervalMs_;
        int32_t repeatCount_;
        int32_t callbackCount_;
        int64_t nextCallTime_;
        std::function<void()> callback_;
    };      
private:
    int32_t TakeNextTimerId();
    int32_t AddTimerInternal(int32_t intervalMs, int32_t repeatCount, std::function<void()> callback);
    int32_t RemoveTimerInternal(int32_t timerId);
    int32_t ResetTimerInternal(int32_t timerId);
    bool IsExistInternal(int32_t timerId);
    std::unique_ptr<TimerItem>& InsertTimerInternal(std::unique_ptr<TimerItem>& timer);
    int32_t CalcNextDelayInternal();
    void ProcessTimersInternal();
       
private:
        std::list<std::unique_ptr<TimerItem>> timers_;
};
}
} // namespace OHOS::MMI
#define TimerMgr OHOS::MMI::TimerManager::GetInstance()
#endif // timer