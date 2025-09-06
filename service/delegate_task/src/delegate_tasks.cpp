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
#include <unistd.h>

#include "backtrace_local.h"
#include "error_multimodal.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_SERVER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "DelegateTasks"

namespace OHOS {
namespace MMI {
namespace {
    constexpr int32_t TIMED_WAIT_MS = 2;
    constexpr size_t SKIP_FRAME_NUM = 0;
} // namespace
void DelegateTasks::Task::ProcessTask()
{
    CALL_DEBUG_ENTER;
    if (hasWaited_) {
        MMI_HILOGE("Expired tasks will be discarded. id:%{public}" PRId64, id_);
        return;
    }
    int32_t ret = fun_();
    std::string taskType = ((promise_ == nullptr) ? "Async" : "Sync");
    MMI_HILOGD("Process taskType:%{public}s, taskId:%{public}" PRId64 ", ret:%{public}d", taskType.c_str(), id_, ret);
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
    if (pipe(fds_) == -1) {
        MMI_HILOGE("The pipe create failed, errno:%{public}d", errno);
        return false;
    }
    if (fcntl(fds_[0], F_SETFL, O_NONBLOCK) == -1) {
        MMI_HILOGE("The fcntl read failed, errno:%{public}d", errno);
        close(fds_[0]);
        return false;
    }
    if (fcntl(fds_[1], F_SETFL, O_NONBLOCK) == -1) {
        MMI_HILOGE("The fcntl write failed, errno:%{public}d", errno);
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
    size_t count = tasks.size();
    if (count == 0) {
        return;
    }
    for (const auto &it : tasks) {
        it->ProcessTask();
    }
    std::vector<DelegateTasks::TaskData> datas = {};
    datas.resize(count);
    auto res = read(fds_[0], datas.data(), sizeof(DelegateTasks::TaskData) * count);
    if (res == -1) {
        MMI_HILOGW("Read failed erron:%{public}d", errno);
    }
    MMI_HILOGD("count:%{public}zu", count);
}

int32_t DelegateTasks::PostSyncTask(DTaskCallback callback)
{
    CALL_DEBUG_ENTER;
    CHKPR(callback, ERROR_NULL_POINTER);
    if (IsCallFromWorkerThread()) {
        return callback();
    }
    std::shared_ptr<Promise> promise = std::make_shared<Promise>();
    Future future = promise->get_future();
    auto task = PostTask(callback, promise);
    CHKPR(task, ETASKS_POST_SYNCTASK_FAIL);

    static constexpr int32_t timeout = 3000;
    std::chrono::milliseconds span(timeout);
    auto res = future.wait_for(span);
    task->SetWaited();
    if (res == std::future_status::timeout) {
        int32_t workerThreadId = static_cast<int32_t>(workerThreadId_);
        std::string stackTrace;
        HiviewDFX::GetBacktraceStringByTid(stackTrace, workerThreadId, SKIP_FRAME_NUM, false);
        MMI_HILOGE("Task timeout, taskId:%{public}" PRId64 ", num of tasks:%{public}zu, stack of workerThread:%{public}s",
                    id_, tasks_.size(), stackTrace.c_str());
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
    CHKPR(PostTask(callback), ETASKS_POST_ASYNCTASK_FAIL);
    return RET_OK;
}

void DelegateTasks::PopPendingTaskList(std::vector<TaskPtr> &tasks)
{
    static constexpr int32_t onceProcessTaskLimit = 10;
    if (mux_.try_lock_for(std::chrono::milliseconds(TIMED_WAIT_MS))) {
        for (int32_t count = 0; count < onceProcessTaskLimit; count++) {
            if (tasks_.empty()) {
                break;
            }
            auto task = tasks_.front();
            CHKPB(task);
            tasks.push_back(task->GetSharedPtr());
            tasks_.pop();
        }
        mux_.unlock();
    }
}

DelegateTasks::TaskPtr DelegateTasks::PostTask(DTaskCallback callback, std::shared_ptr<Promise> promise)
{
    if (IsCallFromWorkerThread()) {
        MMI_HILOGE("This interface cannot be called from a worker thread");
        return nullptr;
    }
    TaskPtr taskCopy = nullptr;
    {
        std::lock_guard<std::timed_mutex> guard(mux_);
        MMI_HILOGD("tasks_ size:%{public}d", static_cast<int32_t>(tasks_.size()));
        static constexpr int32_t maxTasksLimit = 1000;
        auto tsize = tasks_.size();
        if (tsize > maxTasksLimit) {
            MMI_HILOGE("The task queue is full. size:%{public}zu, maxTasksLimit:%{public}d", tsize, maxTasksLimit);
            return nullptr;
        }
        id_++;
        TaskData data = { GetThisThreadId(), id_};
        auto res = write(fds_[1], &data, sizeof(data));
        if (res == -1) {
            MMI_HILOGE("Pipe write failed, errno:%{public}d", errno);
            return nullptr;
        }
        TaskPtr task = std::make_shared<Task>(id_, callback, promise);
        tasks_.push(task);
        taskCopy = task->GetSharedPtr();
    }
    return taskCopy;
}
} // namespace MMI
} // namespace OHOS