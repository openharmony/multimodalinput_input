/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "inject_thread.h"

namespace OHOS {
namespace MMI {
std::mutex InjectThread::mutex_;
std::condition_variable InjectThread::conditionVariable_;
std::vector<InjectInputEvent> InjectThread::injectQueue_;

void InjectThread::InjectFunc() const
{
    std::unique_lock<std::mutex> uniqueLock(mutex_);
    while (true) {
        conditionVariable_.wait(uniqueLock);
        while (injectQueue_.size() > 0) {
            if (injectQueue_[0].deviceId == TOUCH_SCREEN_DEVICE_ID) {
                g_pTouchScreen->EmitEvent(injectQueue_[0].type, injectQueue_[0].code, injectQueue_[0].value);
            } else if (injectQueue_[0].deviceId == KEYBOARD_DEVICE_ID) {
                g_pKeyboard->EmitEvent(injectQueue_[0].type, injectQueue_[0].code, injectQueue_[0].value);
            }
            injectQueue_.erase(injectQueue_.begin());
        }
    }
}

void InjectThread::WaitFunc(InjectInputEvent injectInputEvent) const
{
    std::lock_guard<std::mutex> lockGuard(mutex_);
    injectQueue_.push_back(injectInputEvent);
    conditionVariable_.notify_one();
}
} // namespace MMI
} // namespace OHOS