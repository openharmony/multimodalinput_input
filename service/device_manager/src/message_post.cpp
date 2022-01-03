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

#include "message_post.h"
#include "uds_socket.h"

namespace OHOS {
namespace MMI {
void MessagePost::SetFd(int fd)
{
    this->fd_ = fd;
}

void MessagePost::RunOnWestonThread(std::function<void(weston_compositor *)> taskItem)
{
    {
        std::lock_guard<std::mutex> guard(lk_);
        asyncTasks_.push_back(taskItem);
    }
    NotifyWestonThread();
}

void MessagePost::NotifyWestonThread()
{
    if (fd_ == -1) {
        return;
    }
    int32_t value = 0;
    write(fd_, &value, sizeof(value));
}

void MessagePost::RunTasks()
{
    while (true) {
        std::function<void(weston_compositor *)> taskItem;
        {
            std::lock_guard<std::mutex> guard(lk_);
            if (asyncTasks_.empty()) {
                return;
            }
            taskItem = asyncTasks_.front();
            asyncTasks_.pop_front();
        }
        taskItem(ec_);
    }
}

int MessagePost::RunTaskOnWestonThread(int fd, uint32_t mask, void *data)
{
    int32_t value = 0;
    read(fd, &value, sizeof(value));
    MMIMSGPOST.RunTasks();
    return 0;
}

void MessagePost::SetWestonCompositor(weston_compositor *ec)
{
    this->ec_ = ec;
}
}
}