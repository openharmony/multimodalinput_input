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

#ifndef INPUT_SENDEVENT_COMMAND_H
#define INPUT_SENDEVENT_COMMAND_H

#include <map>
#include <string>
#include <vector>

#include "nocopyable.h"

namespace OHOS {
namespace MMI {
class InputSendeventCommand {
public:
    InputSendeventCommand() = default;
    ~InputSendeventCommand() = default;
    DISALLOW_COPY_AND_MOVE(InputSendeventCommand);

    static int32_t HandleSendEventCommand(int32_t argc, char** argv);
private:
    bool CheckDevice(const std::string &deviceNode);
    bool CheckType(const std::string &inputType);
    bool CheckCode(const std::string &inputCode);
    bool CheckValue(const std::string &inputValue);
    bool SendEventOption(int32_t argc, char** argv);
    int32_t RunSendEvent();
private:
    std::vector<std::string> injectArgvs_;
};
} // namespace MMI
} // namespace OHOS
#endif // INPUT_SENDEVENT_COMMAND_H