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

#ifndef OHOS_INPUT_PRINTER_H
#define OHOS_INPUT_PRINTER_H

#include <cstdint>
#include <string>

#include <nlohmann/json.hpp>

namespace OHOS::MMI::InputCli {
constexpr int32_t PARAMETER_EXIT = 2;
constexpr int32_t PERMISSION_EXIT = 3;
constexpr int32_t SERVICE_EXIT = 1;

class OutputPrinter {
public:
    static int32_t PrintSuccess(const nlohmann::json &data);
    static int32_t PrintError(const std::string &errCode, const std::string &errMsg, const std::string &suggestion,
        int32_t exitCode);
    static void PrintHelp(const std::string &helpText);
};

int32_t ParameterError(const std::string &detail, const std::string &suggestion);
int32_t UnknownCommandError(const std::string &token, const std::string &suggestion);
int32_t HandleControllerError(int32_t result, const std::string &operation);
} // namespace OHOS::MMI::InputCli

#endif
