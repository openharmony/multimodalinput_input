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

#ifndef THREAD_SAFE_QUEUE_H
#define THREAD_SAFE_QUEUE_H

#include <queue>
#include <shared_mutex>

namespace OHOS {
namespace MMI {

template <typename T>
class ThreadSafeQueue {
public:
    void Push(T elem)
    {
        std::unique_lock<std::shared_mutex> lock(rwMutex_);
        queue_.push(elem);
    }

    void Pop()
    {
        std::unique_lock<std::shared_mutex> lock(rwMutex_);
        queue_.pop();
    }

    T Front()
    {
        std::shared_lock<std::shared_mutex> lock(rwMutex_);
        return queue_.front();
    }

    T Rear()
    {
        std::shared_lock<std::shared_mutex> lock(rwMutex_);
        return queue_.rear();
    }

    bool Empty()
    {
        std::shared_lock<std::shared_mutex> lock(rwMutex_);
        return queue_.empty();
    }

    size_t Size()
    {
        std::shared_lock<std::shared_mutex> lock(rwMutex_);
        return queue_.size();
    }
private:
    std::queue<T> queue_;
    std::shared_mutex rwMutex_;
};
} // namespace MMI
} // namespace OHOS

#endif // THREAD_SAFE_QUEUE_H