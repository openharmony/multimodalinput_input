/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef DELEGATE_TASKS_H
#define DELEGATE_TASKS_H

#include <cinttypes>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <queue>

#include "id_factory.h"
#include "util.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr size_t FDS_SIZE = 2;
} // namespace
using DTaskCallback = std::function<int32_t()>;
class DelegateTasks {
public:
    struct TaskData {
        uint64_t tid { 0 };
        int32_t taskId { 0 };
    };
    class Task : public std::enable_shared_from_this<Task> {
    public:
        using Promise = std::promise<int32_t>;
        using Future = std::future<int32_t>;
        using TaskPtr = std::shared_ptr<DelegateTasks::Task>;
        Task(uint64_t id, DTaskCallback fun, std::shared_ptr<Promise> promise = nullptr)
            : id_(id), fun_(fun), promise_(promise) {}
        ~Task() = default;
        void ProcessTask();

        uint64_t GetId() const
        {
            return id_;
        }
        TaskPtr GetSharedPtr()
        {
            return shared_from_this();
        }
        void SetWaited()
        {
            hasWaited_ = true;
        }

    private:
        std::atomic_bool hasWaited_ { false };
        uint64_t id_ { 0 };
        DTaskCallback fun_;
        std::shared_ptr<Promise> promise_ { nullptr };
    };
    using TaskPtr = Task::TaskPtr;
    using Promise = Task::Promise;
    using Future = Task::Future;

public:
    DelegateTasks() = default;
    ~DelegateTasks();

    bool Init();
    void ProcessTasks();
    int32_t PostSyncTask(DTaskCallback callback);
    int32_t PostAsyncTask(DTaskCallback callback);

    int32_t GetReadFd() const
    {
        return fds_[0];
    }
    void SetWorkerThreadId(uint64_t tid)
    {
        workerThreadId_ = tid;
    }
    bool IsCallFromWorkerThread() const
    {
        return (GetThisThreadId() == workerThreadId_);
    }

private:
    void PopPendingTaskList(std::vector<TaskPtr> &tasks);
    TaskPtr PostTask(DTaskCallback callback, std::shared_ptr<Promise>promise = nullptr);

private:
    uint64_t workerThreadId_ { 0 };
    int32_t fds_[FDS_SIZE] = {};
    std::timed_mutex mux_;
    std::queue<TaskPtr> tasks_;
    uint64_t id_ {0};
};
} // namespace MMI
} // namespace OHOS
#endif // DELEGATE_TASKS_H