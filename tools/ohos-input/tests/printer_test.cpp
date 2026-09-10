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

#include <cstdint>
#include <gtest/gtest.h>
#include "error_multimodal.h"
#include "printer.h"
#include <nlohmann/json.hpp>
#include <sstream>
#include <string>

#include "command_runner.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::MMI::InputCli;

class PrinterTest : public Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

HWTEST_F(PrinterTest, PrintSuccess_ContainsTypeStatusData, TestSize.Level1)
{
    std::ostringstream output;
    StdoutRedirectGuard redirectGuard(output.rdbuf());
    const int32_t code = OutputPrinter::PrintSuccess({ { "message", "success" } });

    EXPECT_EQ(code, 0);
    const auto parsed = nlohmann::json::parse(output.str());
    EXPECT_EQ(parsed["type"], "result");
    EXPECT_EQ(parsed["status"], "success");
    EXPECT_EQ(parsed["data"]["message"], "success");
}

HWTEST_F(PrinterTest, PrintError_ContainsFieldsAndExitCode, TestSize.Level1)
{
    std::ostringstream output;
    StdoutRedirectGuard redirectGuard(output.rdbuf());
    const int32_t code = OutputPrinter::PrintError("ERR_TEST", "Test error", "Try again", 9);

    EXPECT_EQ(code, 9);
    const auto parsed = nlohmann::json::parse(output.str());
    EXPECT_EQ(parsed["type"], "result");
    EXPECT_EQ(parsed["status"], "failed");
    EXPECT_EQ(parsed["data"], "");
    EXPECT_EQ(parsed["errCode"], "ERR_TEST");
    EXPECT_EQ(parsed["errMsg"], "Test error");
    EXPECT_EQ(parsed["suggestion"], "Try again");
}

HWTEST_F(PrinterTest, PrintHelp_WritesTextWithSingleNewline, TestSize.Level1)
{
    std::ostringstream output;
    StdoutRedirectGuard redirectGuard(output.rdbuf());
    OutputPrinter::PrintHelp("Usage: x");

    EXPECT_EQ(output.str(), "Usage: x\n");
}

HWTEST_F(PrinterTest, ParameterError_UsesParameterErrorCode, TestSize.Level1)
{
    std::ostringstream output;
    StdoutRedirectGuard redirectGuard(output.rdbuf());
    const int32_t code = ParameterError("bad detail", "Try harder");

    EXPECT_EQ(code, PARAMETER_EXIT);
    const auto parsed = nlohmann::json::parse(output.str());
    EXPECT_EQ(parsed["errCode"], "ERR_PARAMETER_ERROR");
    EXPECT_EQ(parsed["errMsg"], "Parameter error: bad detail");
    EXPECT_EQ(parsed["suggestion"], "Try harder");
}

HWTEST_F(PrinterTest, UnknownCommandError_NamesToken, TestSize.Level1)
{
    std::ostringstream output;
    StdoutRedirectGuard redirectGuard(output.rdbuf());
    const int32_t code = UnknownCommandError("bad", "Please use ohos-input --help");

    EXPECT_EQ(code, PARAMETER_EXIT);
    const auto parsed = nlohmann::json::parse(output.str());
    EXPECT_EQ(parsed["errCode"], "ERR_PARAMETER_ERROR");
    EXPECT_EQ(parsed["errMsg"], "Unknown command: bad");
}

HWTEST_F(PrinterTest, HandleControllerError_NoPermission_MapsToPermissionJson, TestSize.Level1)
{
    std::ostringstream output;
    StdoutRedirectGuard redirectGuard(output.rdbuf());
    const int32_t code = HandleControllerError(OHOS::MMI::ERROR_NO_PERMISSION, "CreateMouseController");

    EXPECT_EQ(code, PERMISSION_EXIT);
    const auto parsed = nlohmann::json::parse(output.str());
    EXPECT_EQ(parsed["errCode"], "ERR_PERMISSION_DENIED");
    EXPECT_EQ(parsed["data"], "");
}

HWTEST_F(PrinterTest, HandleControllerError_ServiceFailure_MapsToServiceJson, TestSize.Level1)
{
    std::ostringstream output;
    StdoutRedirectGuard redirectGuard(output.rdbuf());
    const int32_t code = HandleControllerError(-1, "MoveTo");

    EXPECT_EQ(code, SERVICE_EXIT);
    const auto parsed = nlohmann::json::parse(output.str());
    EXPECT_EQ(parsed["errCode"], "ERR_INPUT_SERVICE_EXCEPTION");
    EXPECT_TRUE(parsed["errMsg"].get<std::string>().find("MoveTo") != std::string::npos);
}
