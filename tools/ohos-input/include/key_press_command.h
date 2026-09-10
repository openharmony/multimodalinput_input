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

#ifndef OHOS_INPUT_KEY_PRESS_COMMAND_H
#define OHOS_INPUT_KEY_PRESS_COMMAND_H

#include <cstdint>
#include <string>
#include <vector>

#include "command.h"

namespace OHOS::MMI::InputCli {
class KeyPressCommand final : public Command {
public:
    std::string GetDevice() const override;
    std::string GetName() const override;
    std::string GetDescription() const override;
    std::string GetTitle() const override;
    std::string GetUsage() const override;
    std::vector<ParameterDoc> GetParameters() const override;
    std::vector<std::string> GetExamples() const override;
    int32_t Execute(const std::vector<std::string> &args) override;
};
} // namespace OHOS::MMI::InputCli

#endif
