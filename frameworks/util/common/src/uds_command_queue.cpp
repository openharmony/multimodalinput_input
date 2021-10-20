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

#include "uds_command_queue.h"

OHOS::MMI::UdsCommandQueue::UdsCommandQueue()
{
}

OHOS::MMI::UdsCommandQueue::~UdsCommandQueue()
{
}

size_t OHOS::MMI::UdsCommandQueue::GetSize() const
{
    return commandQueue_.size();
}

std::string OHOS::MMI::UdsCommandQueue::PopCommand()
{
    std::lock_guard<std::mutex> lockGuard(mux_);
    if (commandQueue_.size() > 0) {
        std::string command = commandQueue_.front();
        commandQueue_.pop_front();
        return command;
    }

    return "";
}

void OHOS::MMI::UdsCommandQueue::AddCommand(const std::string& command)
{
    std::lock_guard<std::mutex> lockGuard(mux_);
    commandQueue_.push_back(command);
}
