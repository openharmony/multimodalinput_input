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

#include <gtest/gtest.h>
#include "command.h"
#include "executor.h"
#include "printer.h"
#include <sstream>
#include <string>
#include <vector>

#include "command_runner.h"
#include "mock_controller_factory.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::MMI::InputCli;

namespace {
constexpr size_t DESCRIPTION_COLUMN = 28;
constexpr size_t COLUMN_GAP_WIDTH = 2;

void ExpectHelpOptionColumnAligned(const std::string &helpText)
{
    std::istringstream stream(helpText);
    std::string line;
    while (std::getline(stream, line)) {
        if (line.rfind("  --", 0) != 0) {
            continue;
        }
        EXPECT_TRUE(line.size() > DESCRIPTION_COLUMN);
        EXPECT_EQ(line.substr(DESCRIPTION_COLUMN - COLUMN_GAP_WIDTH, COLUMN_GAP_WIDTH), "  ");
        EXPECT_NE(line[DESCRIPTION_COLUMN], ' ');
    }
}
} // namespace

class ExecutorTest : public Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

HWTEST_F(ExecutorTest, ExecuteCommand_EmptyArgs_PrintsGlobalHelp, TestSize.Level1)
{
    const CommandResult result = OHOS::MMI::InputCli::Run({});
    EXPECT_EQ(result.code, 0);
    EXPECT_TRUE(result.stdoutText.find("Usage:") != std::string::npos);
    EXPECT_TRUE(result.stdoutText.find("mouse-click") != std::string::npos);
    EXPECT_TRUE(result.stdoutText.find("key-press") != std::string::npos);
}

HWTEST_F(ExecutorTest, ExecuteCommand_TopLevelHelp_ListsCommandsAndExamples, TestSize.Level1)
{
    const CommandResult result = OHOS::MMI::InputCli::Run({ "--help" });
    EXPECT_EQ(result.code, 0);
    EXPECT_TRUE(result.stdoutText.find("Usage:") != std::string::npos);
    EXPECT_TRUE(result.stdoutText.find("mouse-click") != std::string::npos);
    EXPECT_TRUE(result.stdoutText.find("key-press") != std::string::npos);
    EXPECT_TRUE(result.stdoutText.find("--version") != std::string::npos);
    EXPECT_TRUE(result.stdoutText.find("Examples:") != std::string::npos);
    ExpectHelpOptionColumnAligned(result.stdoutText);
}

HWTEST_F(ExecutorTest, ExecuteCommand_ClickHelp_ShowsUsageAndRules, TestSize.Level1)
{
    const CommandResult result = OHOS::MMI::InputCli::Run({ "mouse-click", "--help" });
    EXPECT_EQ(result.code, 0);
    EXPECT_TRUE(result.stdoutText.find("Usage:\n  ohos-input mouse-click [options]") != std::string::npos);
    EXPECT_TRUE(result.stdoutText.find("(required, range: >=0)") != std::string::npos);
    EXPECT_TRUE(result.stdoutText.find("[left, right, middle]") != std::string::npos);
    EXPECT_TRUE(result.stdoutText.find("range: [50, 200], default: 100") != std::string::npos);
    EXPECT_TRUE(result.stdoutText.find("ctrl|shift") != std::string::npos);
    ExpectHelpOptionColumnAligned(result.stdoutText);
}

HWTEST_F(ExecutorTest, ExecuteCommand_DoubleClickHelp_ShowsIntervalRule, TestSize.Level1)
{
    const CommandResult result = OHOS::MMI::InputCli::Run({ "mouse-double-click", "--help" });
    EXPECT_EQ(result.code, 0);
    EXPECT_TRUE(result.stdoutText.find("must be greater than holdDuration") != std::string::npos);
    ExpectHelpOptionColumnAligned(result.stdoutText);
}

HWTEST_F(ExecutorTest, ExecuteCommand_ScrollHelp_ShowsClicksRule, TestSize.Level1)
{
    const CommandResult result = OHOS::MMI::InputCli::Run({ "mouse-scroll", "--help" });
    EXPECT_EQ(result.code, 0);
    EXPECT_TRUE(result.stdoutText.find("[-100, -1] or [1, 100]") != std::string::npos);
    EXPECT_TRUE(result.stdoutText.find("1 click = 15 degrees") != std::string::npos);
    ExpectHelpOptionColumnAligned(result.stdoutText);
}

HWTEST_F(ExecutorTest, ExecuteCommand_DragHelp_ShowsDurationRule, TestSize.Level1)
{
    const CommandResult result = OHOS::MMI::InputCli::Run({ "mouse-drag", "--help" });
    EXPECT_EQ(result.code, 0);
    EXPECT_TRUE(result.stdoutText.find("range: [0, 10000], 0 means instant, default: 0") != std::string::npos);
    ExpectHelpOptionColumnAligned(result.stdoutText);
}

HWTEST_F(ExecutorTest, ExecuteCommand_KeyPressHelp_ShowsKeyRules, TestSize.Level1)
{
    const CommandResult result = OHOS::MMI::InputCli::Run({ "key-press", "--help" });
    EXPECT_EQ(result.code, 0);
    EXPECT_TRUE(result.stdoutText.find("Usage:\n  ohos-input key-press [options]") != std::string::npos);
    EXPECT_TRUE(result.stdoutText.find("range: >=1") != std::string::npos);
    EXPECT_TRUE(result.stdoutText.find("[0, 10000], 0 means instant release") != std::string::npos);
    ExpectHelpOptionColumnAligned(result.stdoutText);
}

HWTEST_F(ExecutorTest, ExecuteCommand_HelpAnywhereInOptions_ShortCircuits, TestSize.Level1)
{
    MockControllerFixture fixture;
    std::vector<RecordedCall> calls;
    fixture.Configure(calls);
    const CommandResult result = OHOS::MMI::InputCli::Run({ "mouse-click", "--x", "1", "--help" });
    EXPECT_EQ(result.code, 0);
    EXPECT_TRUE(result.stdoutText.find("Usage:") != std::string::npos);
    EXPECT_TRUE(result.stdoutText.find("--holdDuration") != std::string::npos);
    EXPECT_TRUE(calls.empty());
}

HWTEST_F(ExecutorTest, ExecuteCommand_Version_PrintsVersion, TestSize.Level1)
{
    const CommandResult result = OHOS::MMI::InputCli::Run({ "--version" });
    EXPECT_EQ(result.code, 0);
    EXPECT_EQ(result.stdoutText, std::string(OHOS_INPUT_VERSION) + "\n");
}

HWTEST_F(ExecutorTest, ExecuteCommand_UnknownCommand_ParameterErrorJson, TestSize.Level1)
{
    const CommandResult result = OHOS::MMI::InputCli::Run({ "unknown" });
    EXPECT_EQ(result.code, PARAMETER_EXIT);
    const auto parsed = ParseJson(result);
    EXPECT_EQ(parsed["errCode"], "ERR_PARAMETER_ERROR");
    EXPECT_EQ(parsed["errMsg"], "Unknown command: unknown");
    EXPECT_EQ(parsed["data"], "");
}

HWTEST_F(ExecutorTest, ExecuteCommand_MissingRequiredOption_ParameterErrorJson, TestSize.Level1)
{
    const CommandResult result = OHOS::MMI::InputCli::Run({ "mouse-click", "--y", "2" });
    EXPECT_EQ(result.code, PARAMETER_EXIT);
    const auto parsed = ParseJson(result);
    EXPECT_EQ(parsed["status"], "failed");
    EXPECT_EQ(parsed["errCode"], "ERR_PARAMETER_ERROR");
    EXPECT_EQ(parsed["data"], "");
}

HWTEST_F(ExecutorTest, AllCommands_Available, TestSize.Level2)
{
    const std::vector<std::string> names = {
        "mouse-click", "mouse-double-click", "mouse-scroll", "mouse-move", "mouse-drag", "key-press"
    };
    for (const auto &name : names) {
        EXPECT_TRUE(GetCommand(name) != nullptr) << name << " not registered";
    }
}
