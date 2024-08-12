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

#include "timer_manager.h"

#include <thread>

#include "define_multimodal.h"

namespace OHOS {
namespace MMI {
std::mutex TimerManager::mutex_;
std::shared_ptr<TimerManager> TimerManager::instance_;

std::shared_ptr<TimerManager> TimerManager::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> guard(mutex_);
        if (instance_ == nullptr) {
            instance_ = std::make_shared<TimerManager>();
        }
    }
    return instance_;
}

int32_t TimerManager::AddTimer(int32_t intervalMs, int32_t repeatCount, std::function<void()> callback)
{
    if (running_.load()) {
        return RET_ERR;
    }
    running_.store(true);
    std::thread([=]() mutable {
        do {
            std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs));
            if (!running_.load()) {
                break;
            }
            if (callback != nullptr) {
                callback();
            }
        } while (running_.load() && (--repeatCount > 0));
        running_.store(false);
    }).detach();
    return RET_OK;
}

int32_t TimerManager::RemoveTimer(int32_t timerId)
{
    running_.store(false);
    return RET_OK;
}

int32_t TimerManager::ResetTimer(int32_t timerId)
{
    return RET_OK;
}
} // namespace MMI
} // namespace OHOS
