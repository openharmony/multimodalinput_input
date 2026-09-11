/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_INPUT_COMMAND_H
#define OHOS_INPUT_COMMAND_H

#include <cstdint>
#include <memory>
#include <string>
#include <tuple>
#include <vector>

namespace OHOS::MMI::InputCli {
using ParameterDoc = std::tuple<std::string, std::string>;

class Command {
public:
    virtual ~Command() = default;
    virtual std::string GetDevice() const = 0;
    virtual std::string GetName() const = 0;
    virtual std::string GetDescription() const = 0;
    virtual std::string GetTitle() const = 0;
    virtual std::string GetUsage() const = 0;
    virtual std::vector<ParameterDoc> GetParameters() const = 0;
    virtual std::vector<std::string> GetExamples() const = 0;
    virtual int32_t Execute(const std::vector<std::string> &args) = 0;
};

std::shared_ptr<Command> GetCommand(const std::string &device, const std::string &name);
std::vector<std::shared_ptr<Command>> GetCommandsByDevice(const std::string &device);
} // namespace OHOS::MMI::InputCli

#endif
