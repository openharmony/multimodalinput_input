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
#include "key_event.h"
#include "mock_controller_factory.h"

using namespace testing;
using namespace testing::ext;
using OHOS::MMI::KeyEvent;
using namespace OHOS::MMI::InputCli;

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

HWTEST_F(IntegrationTest, Click_CallsControllersInModifierOrder, TestSize.Level1)
{
    MockControllerFixture fixture;
    std::vector<RecordedCall> calls;
    fixture.Configure(calls);
    const CommandResult result = OHOS::MMI::InputCli::Run({
        "mouse-click", "--x", "10", "--y", "20", "--holdDuration", "50",
        "--modifier", "ctrl|shift" });
    ExpectSuccess(result, "mouse-click");
    ExpectCalls(calls, { { "MoveTo", { 0, 10, 20 } }, { "PressKey", { KeyEvent::KEYCODE_CTRL_LEFT } },
        { "PressKey", { KeyEvent::KEYCODE_SHIFT_LEFT } }, { "PressButton", { 0 } }, { "ReleaseButton", { 0 } },
        { "ReleaseKey", { KeyEvent::KEYCODE_SHIFT_LEFT } }, { "ReleaseKey", { KeyEvent::KEYCODE_CTRL_LEFT } } });
}

HWTEST_F(IntegrationTest, DoubleClick_RightButtonPressedTwice, TestSize.Level1)
{
    MockControllerFixture fixture;
    std::vector<RecordedCall> calls;
    fixture.Configure(calls);
    const CommandResult result = OHOS::MMI::InputCli::Run({
        "mouse-double-click", "--x", "10", "--y", "20", "--button", "right",
        "--holdDuration", "50", "--clickInterval", "100" });
    ExpectSuccess(result, "mouse-double-click");
    ExpectCalls(calls, { { "MoveTo", { 0, 10, 20 } }, { "PressButton", { 1 } }, { "ReleaseButton", { 1 } },
        { "PressButton", { 1 } }, { "ReleaseButton", { 1 } } });
}

HWTEST_F(IntegrationTest, Scroll_OneTwoAndMinusTwoClicks_MatchConfirmedSequences, TestSize.Level1)
{
    MockControllerFixture fixture;
    std::vector<RecordedCall> calls;
    fixture.Configure(calls);
    ExpectSuccess(OHOS::MMI::InputCli::Run({ "mouse-scroll", "--clicks", "1" }), "mouse-scroll");
    ExpectCalls(calls, { { "BeginAxis", { 1, 15 } }, { "EndAxis", { 1 } } });

    calls.clear();
    ExpectSuccess(OHOS::MMI::InputCli::Run({ "mouse-scroll", "--clicks", "2" }), "mouse-scroll");
    ExpectCalls(calls, { { "BeginAxis", { 1, 15 } }, { "UpdateAxis", { 1, 15 } }, { "EndAxis", { 1 } } });

    calls.clear();
    ExpectSuccess(OHOS::MMI::InputCli::Run({ "mouse-scroll", "--clicks", "-2" }), "mouse-scroll");
    ExpectCalls(calls, { { "BeginAxis", { 1, -15 } }, { "UpdateAxis", { 1, -15 } }, { "EndAxis", { 1 } } });
}

HWTEST_F(IntegrationTest, ConsecutiveActions_DoNotReusePriorActionState, TestSize.Level1)
{
    MockControllerFixture fixture;
    std::vector<RecordedCall> calls;
    fixture.Configure(calls);
    ExpectSuccess(OHOS::MMI::InputCli::Run({ "mouse-scroll", "--clicks", "2" }), "mouse-scroll");
    ExpectCalls(calls, { { "BeginAxis", { 1, 15 } }, { "UpdateAxis", { 1, 15 } }, { "EndAxis", { 1 } } });

    calls.clear();
    ExpectSuccess(OHOS::MMI::InputCli::Run({
        "mouse-move-to", "--displayId", "2", "--x", "7", "--y", "8" }), "mouse-move-to");
    ExpectCalls(calls, { { "MoveTo", { 2, 7, 8 } } });
}

HWTEST_F(IntegrationTest, MoveAndDrag_CallExpectedMouseOperations, TestSize.Level1)
{
    MockControllerFixture fixture;
    std::vector<RecordedCall> calls;
    fixture.Configure(calls);
    ExpectSuccess(OHOS::MMI::InputCli::Run({
        "mouse-move-to", "--displayId", "1", "--x", "10", "--y", "20", "--modifier", "ctrl" }),
        "mouse-move-to");
    ExpectCalls(calls, { { "PressKey", { KeyEvent::KEYCODE_CTRL_LEFT } }, { "MoveTo", { 1, 10, 20 } },
        { "ReleaseKey", { KeyEvent::KEYCODE_CTRL_LEFT } } });

    calls.clear();
    ExpectSuccess(OHOS::MMI::InputCli::Run({
        "mouse-drag", "--srcX", "1", "--srcY", "2", "--dstDisplayId", "1", "--dstX", "3",
        "--dstY", "4", "--duration", "0" }), "mouse-drag");
    ExpectCalls(calls, { { "MoveTo", { 0, 1, 2 } }, { "PressButton", { 0 } }, { "MoveTo", { 1, 3, 4 } },
        { "ReleaseButton", { 0 } } });

    calls.clear();
    ExpectSuccess(OHOS::MMI::InputCli::Run({ "mouse-drag", "--srcDisplayId", "0", "--srcX", "10", "--srcY", "20",
        "--dstDisplayId", "1", "--dstX", "10", "--dstY", "20", "--duration", "32" }), "mouse-drag");
    ExpectCalls(calls, { { "MoveTo", { 0, 10, 20 } }, { "PressButton", { 0 } },
        { "MoveToGlobal", { 510, 20 } }, { "MoveToGlobal", { 1010, 20 } },
        { "ReleaseButton", { 0 } } });
}

HWTEST_F(IntegrationTest, Drag_StepMoveFailure_EmitsOneJsonAndDestroysControllers, TestSize.Level1)
{
    MockControllerFixture fixture;
    std::vector<RecordedCall> calls;
    fixture.Configure(calls, { 0, 0, "MoveToGlobal", -1, true });
    const CommandResult result = OHOS::MMI::InputCli::Run({ "mouse-drag", "--srcDisplayId", "0",
        "--srcX", "10", "--srcY", "20", "--dstDisplayId", "1", "--dstX", "10", "--dstY", "20",
        "--duration", "32" });
    EXPECT_EQ(result.code, SERVICE_EXIT);
    EXPECT_EQ(std::count(result.stdoutText.begin(), result.stdoutText.end(), '\n'), 1);
    EXPECT_EQ(ParseJson(result)["errCode"], "ERR_INPUT_SERVICE_EXCEPTION");
    ExpectCalls(calls, { { "MoveTo", { 0, 10, 20 } }, { "PressButton", { 0 } },
        { "MoveToGlobal", { 510, 20 } }, { "ReleaseButton", { 0 } }, { "DestroyMouse", {} } });
}

HWTEST_F(IntegrationTest, KeyPress_CallsControllerInModifierOrder, TestSize.Level1)
{
    MockControllerFixture fixture;
    std::vector<RecordedCall> calls;
    fixture.Configure(calls);
    const CommandResult result = OHOS::MMI::InputCli::Run({
        "key-press", "--key", "2049", "--holdDuration", "0", "--modifier",
        "ctrl|shift" });
    ExpectSuccess(result, "key-press");
    ExpectCalls(calls, { { "PressKey", { KeyEvent::KEYCODE_CTRL_LEFT } },
        { "PressKey", { KeyEvent::KEYCODE_SHIFT_LEFT } }, { "PressKey", { 2049 } }, { "ReleaseKey", { 2049 } },
        { "ReleaseKey", { KeyEvent::KEYCODE_SHIFT_LEFT } }, { "ReleaseKey", { KeyEvent::KEYCODE_CTRL_LEFT } } });
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
        const CommandResult result = OHOS::MMI::InputCli::Run({ "key-press", "--key", std::to_string(testCase.key),
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
        const CommandResult result = OHOS::MMI::InputCli::Run({ "key-press", "--key", "2049", "--modifier", value });
        EXPECT_EQ(result.code, PARAMETER_EXIT);
        EXPECT_EQ(ParseJson(result)["errCode"], "ERR_PARAMETER_ERROR");
    }
    EXPECT_EQ(fixture.MouseCreateCount(), 0);
    EXPECT_EQ(fixture.KeyboardCreateCount(), 0);
    EXPECT_TRUE(calls.empty());
}

HWTEST_F(IntegrationTest, DoubleClick_IntervalNotExceedingHoldDuration_Rejected, TestSize.Level1)
{
    MockControllerFixture fixture;
    std::vector<RecordedCall> calls;
    fixture.Configure(calls);
    const CommandResult result = OHOS::MMI::InputCli::Run({ "mouse-double-click", "--x", "1", "--y", "2",
        "--holdDuration", "150", "--clickInterval", "150" });
    EXPECT_EQ(result.code, PARAMETER_EXIT);
    const auto parsed = ParseJson(result);
    EXPECT_EQ(parsed["errCode"], "ERR_PARAMETER_ERROR");
    EXPECT_EQ(parsed["data"], "");
    EXPECT_EQ(fixture.MouseCreateCount(), 0);
    EXPECT_TRUE(calls.empty());
}

HWTEST_F(IntegrationTest, UnknownOptions_RejectedBeforeControllerCreation, TestSize.Level1)
{
    MockControllerFixture fixture;
    std::vector<RecordedCall> calls;
    fixture.Configure(calls);
    const CommandResult mouse = OHOS::MMI::InputCli::Run({
        "mouse-click", "--x", "1", "--y", "2", "--unknown", "x" });
    EXPECT_EQ(mouse.code, PARAMETER_EXIT);
    EXPECT_EQ(ParseJson(mouse)["errCode"], "ERR_PARAMETER_ERROR");
    const CommandResult key = OHOS::MMI::InputCli::Run({ "key-press", "--key", "1", "--unknown", "x" });
    EXPECT_EQ(key.code, PARAMETER_EXIT);
    EXPECT_EQ(ParseJson(key)["errCode"], "ERR_PARAMETER_ERROR");
    EXPECT_EQ(fixture.MouseCreateCount(), 0);
    EXPECT_EQ(fixture.KeyboardCreateCount(), 0);
}

HWTEST_F(IntegrationTest, ControllerPermissionFailure_MapsToPermissionJsonAndExitCode, TestSize.Level1)
{
    MockControllerFixture fixture;
    std::vector<RecordedCall> calls;
    fixture.Configure(calls, { -201 });
    const CommandResult result = OHOS::MMI::InputCli::Run({ "mouse-move-to", "--x", "1", "--y", "2" });
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
    fixture.Configure(calls, { 0, 0, "PressButton", -1, true });
    const CommandResult result = OHOS::MMI::InputCli::Run({
        "mouse-click", "--x", "1", "--y", "2", "--holdDuration", "50",
        "--modifier", "ctrl" });
    EXPECT_EQ(result.code, SERVICE_EXIT);
    EXPECT_EQ(std::count(result.stdoutText.begin(), result.stdoutText.end(), '\n'), 1);
    EXPECT_EQ(ParseJson(result)["errCode"], "ERR_INPUT_SERVICE_EXCEPTION");
    ExpectCalls(calls, { { "MoveTo", { 0, 1, 2 } }, { "PressKey", { KeyEvent::KEYCODE_CTRL_LEFT } },
        { "PressButton", { 0 } }, { "DestroyMouse", {} }, { "DestroyKeyboard", {} } });
}

HWTEST_F(IntegrationTest, ModifierReleaseFailure_EmitsOneJsonAndDestroysControllers, TestSize.Level1)
{
    MockControllerFixture fixture;
    std::vector<RecordedCall> calls;
    fixture.Configure(calls, { 0, 0, "", 0, true, "ReleaseKey", -1 });
    const CommandResult result = OHOS::MMI::InputCli::Run({
        "mouse-click", "--x", "1", "--y", "2", "--holdDuration", "50",
        "--modifier", "ctrl" });
    EXPECT_EQ(result.code, SERVICE_EXIT);
    EXPECT_EQ(std::count(result.stdoutText.begin(), result.stdoutText.end(), '\n'), 1);
    EXPECT_EQ(ParseJson(result)["errCode"], "ERR_INPUT_SERVICE_EXCEPTION");
    ExpectCalls(calls, { { "MoveTo", { 0, 1, 2 } }, { "PressKey", { KeyEvent::KEYCODE_CTRL_LEFT } },
        { "PressButton", { 0 } }, { "ReleaseButton", { 0 } }, { "ReleaseKey", { KeyEvent::KEYCODE_CTRL_LEFT } },
        { "DestroyMouse", {} }, { "DestroyKeyboard", {} } });
}
