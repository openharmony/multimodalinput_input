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

#include "printer.h"

#include <cstdint>
#include <iostream>

#include "error_multimodal.h"

namespace OHOS::MMI::InputCli {
int32_t OutputPrinter::PrintSuccess(const nlohmann::json &data)
{
    std::cout << nlohmann::json { { "type", "result" }, { "status", "success" }, { "data", data } }.dump()
              << std::endl;
    return 0;
}

int32_t OutputPrinter::PrintError(const std::string &errCode, const std::string &errMsg, const std::string &suggestion,
    int32_t exitCode)
{
    std::cout << nlohmann::json { { "type", "result" }, { "status", "failed" }, { "data", "" },
        { "errCode", errCode }, { "errMsg", errMsg }, { "suggestion", suggestion } }.dump()
              << std::endl;
    return exitCode;
}

void OutputPrinter::PrintHelp(const std::string &helpText)
{
    std::cout << helpText << std::endl;
}

int32_t ParameterError(const std::string &detail, const std::string &suggestion)
{
    return OutputPrinter::PrintError("ERR_PARAMETER_ERROR", "Parameter error: " + detail, suggestion, PARAMETER_EXIT);
}

int32_t UnknownCommandError(const std::string &token, const std::string &suggestion)
{
    return OutputPrinter::PrintError("ERR_PARAMETER_ERROR", "Unknown command: " + token, suggestion, PARAMETER_EXIT);
}

int32_t HandleControllerError(int32_t result, const std::string &operation)
{
    if (result == ERROR_NO_PERMISSION) {
        return OutputPrinter::PrintError("ERR_PERMISSION_DENIED",
            "Permission denied: ohos.permission.CONTROL_DEVICE is required",
            "Please grant ohos.permission.CONTROL_DEVICE permission to the caller application", PERMISSION_EXIT);
    }
    return OutputPrinter::PrintError("ERR_INPUT_SERVICE_EXCEPTION",
        "Input service exception: failed to execute " + operation,
        "Please check if the input service is running normally", SERVICE_EXIT);
}
} // namespace OHOS::MMI::InputCli
