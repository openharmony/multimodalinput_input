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

#ifndef INPUT_ENABLEKEYSTATUS_COMMAND_H
#define INPUT_ENABLEKEYSTATUS_COMMAND_H

#include <map>
#include <vector>
#include <string>

#include "nocopyable.h"

namespace OHOS {
namespace MMI {
class InputEnableKeyStatusCommand {
public:
    InputEnableKeyStatusCommand() = default;
    ~InputEnableKeyStatusCommand() = default;
    DISALLOW_COPY_AND_MOVE(InputEnableKeyStatusCommand);

    static int32_t HandleEnableKeyStatusCommand(int32_t argc, char** argv);
private:
    bool CheckEnable(const std::string &enable);
    bool CheckTimeout(const std::string &timeout);
    bool EnableKeyStatusOption(int32_t argc, char** argv);
    int32_t RunEnableKeyStatus();
private:
    std::vector<std::string> injectArgvs_;
};
} // namespace MMI
} // namespace OHOS
#endif // INPUT_ENABLEKEYSTATUS_COMMAND_H