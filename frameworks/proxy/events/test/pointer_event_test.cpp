/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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


#include "input_manager.h"
#include <gtest/gtest.h>
#include <sstream>
#include "define_multimodal.h"
#include "multimodal_standardized_event_manager.h"
#include "key_event.h"
#include "key_event_pre.h"
#include "multimodal_event_handler.h"
#include "proto.h"
#include "pointer_event.h"
#include "run_shell_util.h"

namespace {
using namespace testing::ext;
using namespace OHOS::MMI;
using namespace OHOS;
namespace {
    // static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "PointerEventTest" };
}

class PointerEventTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}

    static int64_t GetMillisTime();
    static std::shared_ptr<PointerEvent> createPointEvent();
};

int64_t PointerEventTest::GetMillisTime()
{
    struct timespec time = { 0 };
    clock_gettime(CLOCK_MONOTONIC, &time);
    return ((static_cast<uint64_t>(time.tv_sec) * 1000000000 + time.tv_nsec) / 1000000);
}

std::shared_ptr<PointerEvent> PointerEventTest::createPointEvent()
{
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    int64_t downTime = GetMillisTime();
    PointerEvent::PointerItem item;
    item.SetPointerId(0);   // test code£¬set the PointerId = 0
    item.SetGlobalX(823);   // test code£¬set the GlobalX = 823
    item.SetGlobalY(723);   // test code£¬set the GlobalY = 723
    item.SetWidth(0);
    item.SetHeight(0);
    item.SetPressure(0);    // test code£¬set the Pressure = 5
    item.SetDeviceId(1);    // test code£¬set the DeviceId = 1
    item.SetDownTime(downTime);
    pointerEvent->AddPointerItem(item);

    pointerEvent->SetPointerId(0);  // test code£¬set the PointerId = 1
    pointerEvent->SetDeviceId(1);
    pointerEvent->SetActionTime(downTime);
    pointerEvent->SetActionStartTime(downTime);
    pointerEvent->SetTargetDisplayId(0);
    pointerEvent->SetTargetWindowId(-1);
    pointerEvent->SetAgentWindowId(-1);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetButtonId(PointerEvent::MOUSE_BUTTON_LEFT);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    return pointerEvent;
}

HWTEST_F(PointerEventTest, PointerEventTest_keyEventAndPointerEvent_001, TestSize.Level1)
{
    RunShellUtil runCommand;
    std::string log1 = "Inject pointer event ...";
    std::string log2 = "Pressed keyCode=";
    std::vector<std::string> beforeRunLogs;
    ASSERT_TRUE(runCommand.RunShellCommand(log1, beforeRunLogs) == RET_OK);
    ASSERT_TRUE(runCommand.RunShellCommand(log2, beforeRunLogs) == RET_OK);

    std::shared_ptr<PointerEvent> pointerEvent = createPointEvent();
    std::vector<int32_t> pressedKeys { OHOS::MMI::KeyEvent::KEYCODE_CTRL_LEFT };
    pointerEvent->SetPressedKeys(pressedKeys);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));
    
    std::vector<std::string> afterRunLogs;
    ASSERT_TRUE(runCommand.RunShellCommand(log1, afterRunLogs) == RET_OK);
    ASSERT_TRUE(runCommand.RunShellCommand(log2, afterRunLogs) == RET_OK);
    ASSERT_TRUE(afterRunLogs.size() > 0);
    if (beforeRunLogs.size() == 0) {
        EXPECT_TRUE(afterRunLogs.size() > beforeRunLogs.size());
        EXPECT_TRUE(afterRunLogs.back().find(log1) != afterRunLogs.back().npos);
        EXPECT_TRUE(afterRunLogs.back().find(log2) != afterRunLogs.back().npos);
    } else {
        EXPECT_TRUE(std::strcmp(afterRunLogs.back().c_str(), beforeRunLogs.back().c_str()) != 0);
    }
}

HWTEST_F(PointerEventTest, PointerEventTest_keyEventAndPointerEvent_002, TestSize.Level1)
{
    RunShellUtil runCommand;
    std::string log1 = "Inject pointer event ...";
    std::string log2 = "Pressed keyCode=";
    std::vector<std::string> beforeRunLogs;
    ASSERT_TRUE(runCommand.RunShellCommand(log1, beforeRunLogs) == RET_OK);
    ASSERT_TRUE(runCommand.RunShellCommand(log2, beforeRunLogs) == RET_OK);

    std::shared_ptr<PointerEvent> pointerEvent = createPointEvent();
    std::vector<int32_t> pressedKeys { OHOS::MMI::KeyEvent::KEYCODE_CTRL_LEFT, OHOS::MMI::KeyEvent::KEYCODE_ALT_LEFT };
    pointerEvent->SetPressedKeys(pressedKeys);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));

    std::vector<std::string> afterRunLogs;
    ASSERT_TRUE(runCommand.RunShellCommand(log1, afterRunLogs) == RET_OK);
    ASSERT_TRUE(runCommand.RunShellCommand(log2, afterRunLogs) == RET_OK);
    ASSERT_TRUE(afterRunLogs.size() > 0);
    if (beforeRunLogs.size() == 0) {
        EXPECT_TRUE(afterRunLogs.size() > beforeRunLogs.size());
        EXPECT_TRUE(afterRunLogs.back().find(log1) != afterRunLogs.back().npos);
        EXPECT_TRUE(afterRunLogs.back().find(log2) != afterRunLogs.back().npos);
    } else {
        EXPECT_TRUE(std::strcmp(afterRunLogs.back().c_str(), beforeRunLogs.back().c_str()) != 0);
    }
}
}