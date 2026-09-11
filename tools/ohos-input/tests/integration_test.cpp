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
#include "modifier.h"
#include "printer.h"
#include <algorithm>
#include <string>
#include <vector>

#include "command_runner.h"
#include "mock_controller_factory.h"

#include "key_event.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::MMI::InputCli;
using OHOS::MMI::KeyEvent;

namespace {
void ExpectSuccess(const CommandResult &result, const std::string &action)
{
    EXPECT_EQ(result.code, 0);
    const auto parsed = ParseJson(result);
    EXPECT_EQ(parsed["type"], "result");
    EXPECT_EQ(parsed["status"], "success");
    EXPECT_EQ(parsed["data"]["action"], action);
}
} // namespace

class IntegrationTest : public Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

HWTEST_F(IntegrationTest, KeyPress_CallsControllerInModifierOrder, TestSize.Level1)
{
    MockControllerFixture fixture;
    std::vector<RecordedCall> calls;
    fixture.Configure(calls);
    const CommandResult result = OHOS::MMI::InputCli::Run({
        "key", "press", "--key", "2049", "--holdDuration", "0", "--modifier",
        "ctrl|shift" });
    ExpectSuccess(result, "key press");
    ExpectCalls(calls, { { "PressKey", { KeyEvent::KEYCODE_CTRL_LEFT } },
        { "PressKey", { KeyEvent::KEYCODE_SHIFT_LEFT } },
        { "PressKey", { 2049 } }, { "ReleaseKey", { 2049 } },
        { "ReleaseKey", { KeyEvent::KEYCODE_SHIFT_LEFT } },
        { "ReleaseKey", { KeyEvent::KEYCODE_CTRL_LEFT } } });
}

HWTEST_F(IntegrationTest, KeyPress_PrimaryKeyDuplicatedInModifier_RejectedBeforeControllerCreation, TestSize.Level1)
{
    struct DuplicateKeyCase {
        int32_t key;
        const char *modifier;
    };
    const DuplicateKeyCase cases[] = {
        { KeyEvent::KEYCODE_CTRL_LEFT, "ctrl" },
        { KeyEvent::KEYCODE_ALT_LEFT, "alt" },
        { KeyEvent::KEYCODE_SHIFT_LEFT, "shift" },
        { KeyEvent::KEYCODE_META_LEFT, "meta" },
    };
    MockControllerFixture fixture;
    std::vector<RecordedCall> calls;
    fixture.Configure(calls);
    for (const DuplicateKeyCase &testCase : cases) {
        const CommandResult result = OHOS::MMI::InputCli::Run({ "key", "press", "--key", std::to_string(testCase.key),
            "--modifier", testCase.modifier });
        EXPECT_EQ(result.code, PARAMETER_EXIT);
        EXPECT_EQ(ParseJson(result)["errCode"], "ERR_PARAMETER_ERROR");
    }
    EXPECT_EQ(fixture.MouseCreateCount(), 0);
    EXPECT_EQ(fixture.KeyboardCreateCount(), 0);
    EXPECT_TRUE(calls.empty());
}

HWTEST_F(IntegrationTest, KeyPress_MalformedModifier_RejectedBeforeControllerCreation, TestSize.Level1)
{
    const char *values[] = { "", "ctrl|" };
    MockControllerFixture fixture;
    std::vector<RecordedCall> calls;
    fixture.Configure(calls);
    for (const char *value : values) {
        const CommandResult result = OHOS::MMI::InputCli::Run({ "key", "press", "--key", "2049", "--modifier", value });
        EXPECT_EQ(result.code, PARAMETER_EXIT);
        EXPECT_EQ(ParseJson(result)["errCode"], "ERR_PARAMETER_ERROR");
    }
    EXPECT_EQ(fixture.MouseCreateCount(), 0);
    EXPECT_EQ(fixture.KeyboardCreateCount(), 0);
    EXPECT_TRUE(calls.empty());
}

HWTEST_F(IntegrationTest, UnknownOptions_RejectedBeforeControllerCreation, TestSize.Level1)
{
    MockControllerFixture fixture;
    std::vector<RecordedCall> calls;
    fixture.Configure(calls);
    const CommandResult key = OHOS::MMI::InputCli::Run({ "key", "press", "--key", "1", "--unknown", "x" });
    EXPECT_EQ(key.code, PARAMETER_EXIT);
    EXPECT_EQ(ParseJson(key)["errCode"], "ERR_PARAMETER_ERROR");
    EXPECT_EQ(fixture.MouseCreateCount(), 0);
    EXPECT_EQ(fixture.KeyboardCreateCount(), 0);
}

HWTEST_F(IntegrationTest, ControllerPermissionFailure_MapsToPermissionJsonAndExitCode, TestSize.Level1)
{
    MockControllerFixture fixture;
    std::vector<RecordedCall> calls;
    fixture.Configure(calls, { 0, -201 });
    const CommandResult result = OHOS::MMI::InputCli::Run({ "key", "press", "--key", "2049" });
    EXPECT_EQ(result.code, PERMISSION_EXIT);
    const auto parsed = ParseJson(result);
    EXPECT_EQ(parsed["errCode"], "ERR_PERMISSION_DENIED");
    EXPECT_EQ(parsed["data"], "");
    EXPECT_TRUE(calls.empty());
}

HWTEST_F(IntegrationTest, ControllerFailure_EmitsOneJsonAndDestroysControllers, TestSize.Level1)
{
    MockControllerFixture fixture;
    std::vector<RecordedCall> calls;
    fixture.Configure(calls, { 0, 0, "", 0, true, "PressKey", -1 });
    const CommandResult result = OHOS::MMI::InputCli::Run({ "key", "press", "--key", "2049" });
    EXPECT_EQ(result.code, SERVICE_EXIT);
    EXPECT_EQ(std::count(result.stdoutText.begin(), result.stdoutText.end(), '\n'), 1);
    EXPECT_EQ(ParseJson(result)["errCode"], "ERR_INPUT_SERVICE_EXCEPTION");
    ExpectCalls(calls, { { "PressKey", { 2049 } }, { "DestroyKeyboard", {} } });
}

HWTEST_F(IntegrationTest, ReleaseFailureAfterModifierPress_EmitsOneJsonAndDestroysControllers, TestSize.Level1)
{
    MockControllerFixture fixture;
    std::vector<RecordedCall> calls;
    fixture.Configure(calls, { 0, 0, "", 0, true, "ReleaseKey", -1 });
    const CommandResult result = OHOS::MMI::InputCli::Run({
        "key", "press", "--key", "2049", "--holdDuration", "0", "--modifier", "ctrl" });
    EXPECT_EQ(result.code, SERVICE_EXIT);
    EXPECT_EQ(std::count(result.stdoutText.begin(), result.stdoutText.end(), '\n'), 1);
    EXPECT_EQ(ParseJson(result)["errCode"], "ERR_INPUT_SERVICE_EXCEPTION");
    ExpectCalls(calls, { { "PressKey", { KeyEvent::KEYCODE_CTRL_LEFT } }, { "PressKey", { 2049 } },
        { "ReleaseKey", { 2049 } }, { "DestroyKeyboard", {} } });
}
