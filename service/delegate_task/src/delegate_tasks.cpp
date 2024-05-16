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

#include "delegate_tasks.h"

#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "error_multimodal.h"
#include "util.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_SERVER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "DelegateTasks"

namespace OHOS {
namespace MMI {
void DelegateTasks::Task::ProcessTask()
{
    CALL_DEBUG_ENTER;
    if (hasWaited_) {
        MMI_HILOGE("Expired tasks will be discarded. id:%{public}d", id_);
        return;
    }
    int32_t ret = fun_();
    std::string taskType = ((promise_ == nullptr) ? "Async" : "Sync");
    MMI_HILOGD("process %{public}s task id:%{public}d,ret:%{public}d", taskType.c_str(), id_, ret);
    if (!hasWaited_ && promise_ != nullptr) {
        promise_->set_value(ret);
    }
}

DelegateTasks::~DelegateTasks()
{
    if (fds_[0] >= 0) {
        close(fds_[0]);
        fds_[0] = -1;
    }
    if (fds_[1] >= 0) {
        close(fds_[1]);
        fds_[1] = -1;
    }
}

bool DelegateTasks::Init()
{
    CALL_DEBUG_ENTER;
    int32_t res = pipe(fds_);
    if (res == -1) {
        MMI_HILOGE("The pipe create failed,errno:%{public}d", errno);
        return false;
    }
    if (fcntl(fds_[0], F_SETFL, O_NONBLOCK) == -1) {
        MMI_HILOGE("The fcntl read failed,errno:%{public}d", errno);
        close(fds_[0]);
        return false;
    }
    if (fcntl(fds_[1], F_SETFL, O_NONBLOCK) == -1) {
        MMI_HILOGE("The fcntl write failed,errno:%{public}d", errno);
        close(fds_[1]);
        return false;
    }
    return true;
}

void DelegateTasks::ProcessTasks()
{
    CALL_DEBUG_ENTER;
    std::vector<TaskPtr> tasks;
    PopPendingTaskList(tasks);
    for (const auto &it : tasks) {
        it->ProcessTask();
    }
}

int32_t DelegateTasks::PostSyncTask(DTaskCallback callback)
{
    CALL_DEBUG_ENTER;
    CHKPR(callback, ERROR_NULL_POINTER);
    if (IsCallFromWorkerThread()) {
        return callback();
    }
    Promise promise;
    Future future = promise.get_future();
    auto task = PostTask(callback, &promise);
    if (task == nullptr) {
        MMI_HILOGE("Post sync task failed");
        return ETASKS_POST_SYNCTASK_FAIL;
    }

    static constexpr int32_t timeout = 3000;
    std::chrono::milliseconds span(timeout);
    auto res = future.wait_for(span);
    task->SetWaited();
    if (res == std::future_status::timeout) {
        MMI_HILOGE("Task timeout");
        return ETASKS_WAIT_TIMEOUT;
    } else if (res == std::future_status::deferred) {
        MMI_HILOGE("Task deferred");
        return ETASKS_WAIT_DEFERRED;
    }
    return future.get();
}

int32_t DelegateTasks::PostAsyncTask(DTaskCallback callback)
{
    CHKPR(callback, ERROR_NULL_POINTER);
    if (IsCallFromWorkerThread()) {
        return callback();
    }
    auto task = PostTask(callback);
    if (task == nullptr) {
        MMI_HILOGE("Post async task failed");
        return ETASKS_POST_ASYNCTASK_FAIL;
    }
    return RET_OK;
}

void DelegateTasks::PopPendingTaskList(std::vector<TaskPtr> &tasks)
{
    std::lock_guard<std::mutex> guard(mux_);
    static constexpr int32_t onceProcessTaskLimit = 10;
    for (int32_t count = 0; count < onceProcessTaskLimit; count++) {
        if (tasks_.empty()) {
            break;
        }
        auto task = tasks_.front();
        CHKPB(task);
        RecoveryId(task->GetId());
        tasks.push_back(task->GetSharedPtr());
        tasks_.pop();
    }
}

DelegateTasks::TaskPtr DelegateTasks::PostTask(DTaskCallback callback, Promise *promise)
{
    if (IsCallFromWorkerThread()) {
        MMI_HILOGE("This interface cannot be called from a worker thread.");
        return nullptr;
    }
    std::lock_guard<std::mutex> guard(mux_);
    MMI_HILOGD("tasks_ size %{public}d", static_cast<int32_t>(tasks_.size()));
    static constexpr int32_t maxTasksLimit = 1000;
    auto tsize = tasks_.size();
    if (tsize > maxTasksLimit) {
        MMI_HILOGE("The task queue is full. size:%{public}zu/%{public}d", tsize, maxTasksLimit);
        return nullptr;
    }
    int32_t id = GenerateId();
    TaskData data = { GetThisThreadId(), id };
    auto res = write(fds_[1], &data, sizeof(data));
    if (res == -1) {
        RecoveryId(id);
        MMI_HILOGE("Pipe write failed,errno:%{public}d", errno);
        return nullptr;
    }
    TaskPtr task = std::make_shared<Task>(id, callback, promise);
    tasks_.push(task);
    std::string taskType = ((promise == nullptr) ? "Async" : "Sync");
    MMI_HILOGD("Post %{public}s", taskType.c_str());
    return task->GetSharedPtr();
}
} // namespace MMI
} // namespace OHOS