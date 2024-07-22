/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef TASK_SCHEDULER_H
#define TASK_SCHEDULER_H

#include <cinttypes>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <queue>

#include "i_task_scheduler.h"
#include "id_factory.h"
#include "include/util.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class TaskScheduler final : public ITaskScheduler,
                            public IdFactory<int32_t> {
public:
    struct TaskData {
        uint64_t tid { 0 };
        int32_t taskId { 0 };
    };
    class Task : public std::enable_shared_from_this<Task> {
    public:
        using Promise = std::promise<int32_t>;
        using Future = std::future<int32_t>;
        using TaskPtr = std::shared_ptr<TaskScheduler::Task>;
        Task(int32_t id, DTaskCallback fun, Promise *promise = nullptr)
            : id_(id), fun_(fun), promise_(promise) {}
        ~Task() = default;

        TaskPtr GetSharedPtr()
        {
            return shared_from_this();
        }
        int32_t GetId() const
        {
            return id_;
        }
        void SetWaited()
        {
            hasWaited_ = true;
        }
        void ProcessTask();

    private:
        int32_t id_ { 0 };
        std::atomic_bool hasWaited_ { false };
        DTaskCallback fun_ { nullptr };
        Promise* promise_ { nullptr };
    };
    using TaskPtr = Task::TaskPtr;
    using Promise = Task::Promise;
    using Future = Task::Future;

public:
    TaskScheduler() = default;
    ~TaskScheduler();

    bool Init();
    void ProcessTasks();
    int32_t PostSyncTask(DTaskCallback cb) override;
    int32_t PostAsyncTask(DTaskCallback callback) override;

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
    TaskPtr PostTask(DTaskCallback callback, Promise *promise = nullptr);

private:
    uint64_t workerThreadId_ { 0 };
    int32_t fds_[2] {};
    std::mutex mux_;
    std::queue<TaskPtr> tasks_;
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // TASK_SCHEDULER_H
