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

#include "task_scheduler.h"

#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "devicestatus_define.h"

#undef LOG_TAG
#define LOG_TAG "TaskScheduler"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

void TaskScheduler::Task::ProcessTask()
{
    CALL_DEBUG_ENTER;
    if (hasWaited_) {
        FI_HILOGE("Expired tasks will be discarded, id:%{public}d", id_);
        return;
    }
    int32_t ret = fun_();
    std::string taskType = ((promise_ == nullptr) ? "Async" : "Sync");
    FI_HILOGD("process:%{public}s, task id:%{public}d, ret:%{public}d", taskType.c_str(), id_, ret);
    if (!hasWaited_ && promise_ != nullptr) {
        promise_->set_value(ret);
    }
}

TaskScheduler::~TaskScheduler()
{
    if (fds_[0] >= 0) {
        if (close(fds_[0]) < 0) {
            FI_HILOGE("Close fds_[0] failed, err:%{public}s, fds_[0]:%{public}d", strerror(errno), fds_[0]);
        }
        fds_[0] = -1;
    }
    if (fds_[1] >= 0) {
        if (close(fds_[1]) < 0) {
            FI_HILOGE("Close fds_[1] failed, err:%{public}s, fds_[1]:%{public}d", strerror(errno), fds_[1]);
        }
        fds_[1] = -1;
    }
}

bool TaskScheduler::Init()
{
    CALL_DEBUG_ENTER;
    if (::pipe2(fds_, O_CLOEXEC | O_NONBLOCK) != 0) {
        FI_HILOGE("pipe2 failed, errno:%{public}s", ::strerror(errno));
        return false;
    }
    return true;
}

void TaskScheduler::ProcessTasks()
{
    CALL_DEBUG_ENTER;
    std::vector<TaskPtr> tasks;
    PopPendingTaskList(tasks);
    for (const auto &it : tasks) {
        it->ProcessTask();
    }
}

int32_t TaskScheduler::PostSyncTask(DTaskCallback cb)
{
    CALL_DEBUG_ENTER;
    CHKPR(cb, ERROR_NULL_POINTER);
    if (IsCallFromWorkerThread()) {
        return cb();
    }
    Promise promise;
    Future future = promise.get_future();
    auto task = PostTask(cb, &promise);
    CHKPR(task, ETASKS_POST_SYNCTASK_FAIL);

    static constexpr int32_t timeout = 3000;
    std::chrono::milliseconds span(timeout);
    auto res = future.wait_for(span);
    task->SetWaited();
    if (res == std::future_status::timeout) {
        FI_HILOGE("Task timeout");
        return ETASKS_WAIT_TIMEOUT;
    } else if (res == std::future_status::deferred) {
        FI_HILOGE("Task deferred");
        return ETASKS_WAIT_DEFERRED;
    }
    return future.get();
}

int32_t TaskScheduler::PostAsyncTask(DTaskCallback callback)
{
    CHKPR(callback, ERROR_NULL_POINTER);
    auto task = PostTask(callback);
    CHKPR(task, ETASKS_POST_ASYNCTASK_FAIL);
    return RET_OK;
}

void TaskScheduler::PopPendingTaskList(std::vector<TaskPtr> &tasks)
{
    static constexpr int32_t onceProcessTaskLimit = 10;
    std::lock_guard<std::mutex> guard(mux_);
    for (int32_t i = 0; i < onceProcessTaskLimit; i++) {
        if (tasks_.empty()) {
            break;
        }
        auto firstTask = tasks_.front();
        CHKPB(firstTask);
        RecoveryId(firstTask->GetId());
        tasks.push_back(firstTask->GetSharedPtr());
        tasks_.pop();
    }
}

TaskScheduler::TaskPtr TaskScheduler::PostTask(DTaskCallback callback, Promise *promise)
{
    FI_HILOGD("tasks_ size:%{public}zu", tasks_.size());
    static constexpr int32_t maxTasksLimit = 1000;
    std::lock_guard<std::mutex> guard(mux_);
    size_t tsize = tasks_.size();
    if (tsize > maxTasksLimit) {
        FI_HILOGE("The task queue is full, size:%{public}zu/%{public}d", tsize, maxTasksLimit);
        return nullptr;
    }
    int32_t id = GenerateId();
    TaskData data = { GetThisThreadId(), id };
    ssize_t res = write(fds_[1], &data, sizeof(data));
    if (res == -1) {
        RecoveryId(id);
        FI_HILOGE("Pipeline writes failed, errno:%{public}d", errno);
        return nullptr;
    }
    TaskPtr task = std::make_shared<Task>(id, callback, promise);
    tasks_.push(task);
    std::string taskType = ((promise == nullptr) ? "Async" : "Sync");
    FI_HILOGD("Post %{public}s", taskType.c_str());
    return task->GetSharedPtr();
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
